"""
Scan management routes.

POST /scan          — initiate a scan (async; runs via Celery or asyncio fallback)
GET  /scan/{id}     — poll scan status + vuln count
DELETE /scan/{id}   — cancel a pending scan
"""
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Literal, Optional


def _utcnow() -> datetime:
    """Timezone-aware UTC — replaces deprecated datetime.utcnow()."""
    return datetime.now(timezone.utc)

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.db import get_db
from backend.database.models import Scan, ScanStatus, Target, Vulnerability
from backend.utils import metrics
from backend.utils.audit import audit_scan_failed, audit_scan_requested
from backend.utils.logger import get_logger
from backend.utils.validators import validate_port_range, validate_target

logger = get_logger(__name__)
router = APIRouter(prefix="/scan", tags=["Scans"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """
    Body expected by POST /scan.

    scan_type choices:
      normal  — standard port + HTTP detection (balanced speed / coverage)
      safe    — HTTP-only checks, no port scan, minimal probes
      stealth — slow adaptive scan; rotates headers + uses Poisson timing
    """
    target: str = Field(
        ...,
        description="IP address, hostname, or full URL to scan",
        example="https://example.com",
    )
    scan_type: Literal["normal", "safe", "stealth"] = Field(
        default="normal",
        description="Scan intensity: normal | safe | stealth",
    )
    port_range: str = Field(
        default="1-1024",
        description="Port range string, e.g. '1-1024' or '80,443,8080'",
    )
    adaptive_mode: bool = Field(
        default=False,
        description="Enable IDS/IPS-aware low-noise scanning",
    )
    description: Optional[str] = Field(default=None, max_length=512)

    @field_validator("target", mode="before")
    @classmethod
    def clean_and_validate_target(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("target must be a non-empty string")
        v = v.strip()
        # Strip URL fragment — fragments are client-side only, not part of the request
        if "#" in v:
            v = v.split("#", 1)[0].rstrip("/")
        ok, reason = validate_target(v)
        if not ok:
            logger.warning("Target validation failed: %s | reason: %s", v, reason)
            raise ValueError(reason)
        logger.debug("Target validated: %s", v)
        return v

    @field_validator("port_range", mode="before")
    @classmethod
    def validate_port_range_field(cls, v: str) -> str:
        ok, reason = validate_port_range(v)
        if not ok:
            raise ValueError(reason)
        return v


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    message: str
    task_id: Optional[str] = None


class ScanStatusResponse(BaseModel):
    scan_id: str
    target: str
    status: str
    scan_type: str
    port_range: str
    adaptive_mode: bool
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[float]
    vulnerability_count: int
    error_message: Optional[str]


# ── Background scan runner (Celery-free fallback) ─────────────────────────────

async def _run_scan_background(
    scan_id: str, target: str, scan_config: dict
) -> None:
    """
    Execute the full scan pipeline directly via asyncio (no Celery required).

    FastAPI runs this after the 202 response is sent, inside the same event
    loop, so all async DB and HTTP calls work as normal.
    """
    from backend.automation.tasks import _orchestrate_scan
    from backend.database.db import get_db_session
    from backend.database.models import Scan, ScanStatus

    logger.info(
        "Background scan starting (asyncio path): scan_id=%s target=%s config=%s",
        scan_id, target, scan_config,
    )

    # Transition → RUNNING
    async with get_db_session() as session:
        result = await session.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if scan:
            scan.status = ScanStatus.RUNNING
            scan.started_at = _utcnow()

    try:
        await _orchestrate_scan(scan_id, target, scan_config)
        logger.info("Background scan completed: scan_id=%s", scan_id)

    except Exception as exc:
        logger.error(
            "Background scan failed: scan_id=%s error=%s", scan_id, exc, exc_info=True
        )
        audit_scan_failed(scan_id, target, str(exc))
        async with get_db_session() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan and scan.status not in (ScanStatus.COMPLETED, ScanStatus.CANCELLED):
                scan.status = ScanStatus.FAILED
                scan.error_message = str(exc)[:500]
                scan.completed_at = _utcnow()


# ── POST /scan/debug — raw body echo (no Pydantic validation) ────────────────

@router.post("/debug", include_in_schema=False)
async def debug_scan_request(request: Request) -> dict:
    """Echo the raw request body and headers — used to diagnose 422 errors."""
    body_bytes = await request.body()
    try:
        import json as _json
        body_parsed = _json.loads(body_bytes)
    except Exception:
        body_parsed = None

    return {
        "content_type": request.headers.get("content-type", ""),
        "body_raw": body_bytes.decode("utf-8", errors="replace"),
        "body_parsed": body_parsed,
        "headers": dict(request.headers),
    }


# ── POST /scan ────────────────────────────────────────────────────────────────

@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Initiate a vulnerability scan",
)
async def initiate_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """
    Queue a vulnerability scan against the specified target.

    The scan runs asynchronously — use **GET /scan/{scan_id}** to poll for
    completion, then **GET /results/{scan_id}** for the full finding set.
    """
    logger.info(
        "Scan request received | target=%s scan_type=%s port_range=%s adaptive=%s",
        request.target, request.scan_type, request.port_range, request.adaptive_mode,
    )
    client_ip = http_request.client.host if http_request.client else None
    audit_scan_requested(
        scan_id="(pending-create)",
        target=request.target,
        scan_type=request.scan_type,
        client_ip=client_ip,
    )

    # ── Upsert target record ──────────────────────────────────────────────────
    existing = await db.execute(
        select(Target).where(Target.address == request.target)
    )
    target_obj = existing.scalar_one_or_none()
    if not target_obj:
        target_obj = Target(address=request.target, description=request.description)
        db.add(target_obj)
        await db.flush()
        logger.debug("New target created: %s", request.target)

    # ── Create Scan record ────────────────────────────────────────────────────
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        target_id=target_obj.id,
        status=ScanStatus.PENDING,
        scan_type=request.scan_type,
        port_range=request.port_range,
        adaptive_mode=request.adaptive_mode,
    )
    db.add(scan)
    await db.commit()
    logger.info("Scan record created: scan_id=%s", scan_id)

    scan_config = {
        "scan_type": request.scan_type,
        "port_range": request.port_range,
        "adaptive_mode": request.adaptive_mode,
    }

    # ── Try Celery; fall back to asyncio background task ──────────────────────
    task_id: Optional[str] = None
    execution_path = "unknown"

    # Fast-fail Celery dispatch. Without this wrapper, .delay() retries the
    # broker for the full broker_transport_options.retry_policy.timeout (30 s
    # by default), which makes POST /scan look like it hung. We give the
    # broker 2 s to accept the task; if that fails we fall back to asyncio.
    try:
        from backend.automation.tasks import run_scan_task

        def _enqueue():
            return run_scan_task.apply_async(
                kwargs={
                    "scan_id":     scan_id,
                    "target":      request.target,
                    "scan_config": scan_config,
                },
                # Disable Celery's internal publish-retry loop — we own the
                # timeout via asyncio.wait_for below.
                retry=False,
            )

        task = await asyncio.wait_for(asyncio.to_thread(_enqueue), timeout=2.0)
        task_id = task.id
        execution_path = "celery"
        logger.info(
            "Scan queued via Celery: scan_id=%s task_id=%s", scan_id, task_id
        )
    except (asyncio.TimeoutError, Exception) as celery_exc:
        logger.warning(
            "Celery unavailable (%s) — falling back to asyncio background task",
            celery_exc,
        )
        background_tasks.add_task(
            _run_scan_background,
            scan_id=scan_id,
            target=request.target,
            scan_config=scan_config,
        )
        execution_path = "asyncio"

    logger.info(
        "Scan dispatched: scan_id=%s target=%s execution=%s",
        scan_id, request.target, execution_path,
    )
    metrics.SCANS_STARTED.labels(
        scan_type=request.scan_type, execution_path=execution_path,
    ).inc()

    return ScanResponse(
        scan_id=scan_id,
        target=request.target,
        status="queued",
        message=(
            f"Scan queued ({execution_path}). "
            "Poll GET /scan/{scan_id} for status, "
            "then GET /results/{scan_id} for findings."
        ),
        task_id=task_id,
    )


# ── GET /scan/{scan_id} ───────────────────────────────────────────────────────

@router.get(
    "/{scan_id}",
    response_model=ScanStatusResponse,
    summary="Poll scan status and vulnerability count",
)
async def get_scan_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> ScanStatusResponse:
    """Return current scan status, timing, and running vulnerability count."""
    from sqlalchemy import func

    result = await db.execute(
        select(Scan).where(Scan.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )

    vuln_count = await db.scalar(
        select(func.count()).select_from(Vulnerability).where(
            Vulnerability.scan_id == scan_id
        )
    ) or 0

    target_address = "unknown"
    if scan.target_id:
        t_result = await db.execute(
            select(Target).where(Target.id == scan.target_id)
        )
        t = t_result.scalar_one_or_none()
        if t:
            target_address = t.address

    logger.debug(
        "Status poll: scan_id=%s status=%s vulns=%d",
        scan_id, scan.status.value, vuln_count,
    )

    return ScanStatusResponse(
        scan_id=scan.id,
        target=target_address,
        status=scan.status.value,
        scan_type=scan.scan_type,
        port_range=scan.port_range,
        adaptive_mode=scan.adaptive_mode,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        duration_seconds=scan.duration_seconds,
        vulnerability_count=vuln_count,
        error_message=scan.error_message,
    )


# ── DELETE /scan/{scan_id} ────────────────────────────────────────────────────

@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Cancel a pending scan",
)
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Cancel a scan that has not yet started (PENDING status only)."""
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )
    if scan.status != ScanStatus.PENDING:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan in '{scan.status.value}' state.",
        )
    scan.status = ScanStatus.CANCELLED
    await db.commit()
    logger.info("Scan cancelled: scan_id=%s", scan_id)
    return {"message": f"Scan '{scan_id}' cancelled."}
