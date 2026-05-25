"""
Scan results routes.

GET /results          — list all completed scans (paginated)
GET /results/{scan_id} — get full results for one scan
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.database.db import get_db
from backend.database.models import Scan, ScanStatus, Vulnerability

router = APIRouter(prefix="/results", tags=["Results"])


class VulnSummary(BaseModel):
    id: str
    name: str
    vuln_type: str
    severity: str
    cvss_score: Optional[float]
    affected_url: Optional[str]
    affected_port: Optional[int]
    owasp_mapping: Optional[str]

    class Config:
        from_attributes = True


class ScanSummary(BaseModel):
    scan_id: str
    target: str
    status: str
    scan_type: str
    started_at: Optional[str]
    completed_at: Optional[str]
    vulnerability_count: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


class FullScanResult(BaseModel):
    scan_id: str
    target: str
    status: str
    scan_type: str
    port_range: str
    adaptive_mode: bool
    started_at: Optional[str]
    completed_at: Optional[str]
    duration_seconds: Optional[float]
    raw_results: Optional[dict]
    vulnerabilities: List[VulnSummary]
    severity_counts: dict


@router.get("", response_model=List[ScanSummary])
async def list_results(
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    status_filter: Optional[str] = Query(default=None, alias="status"),
) -> List[ScanSummary]:
    """List scan results with pagination and optional status filter."""
    query = select(Scan).order_by(desc(Scan.created_at))

    if status_filter:
        try:
            sf = ScanStatus(status_filter)
            query = query.where(Scan.status == sf)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status filter: {status_filter}")

    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query.options(selectinload(Scan.target)))
    scans = result.scalars().all()

    if not scans:
        return []

    # ── Single aggregate query for all severity counts (avoids N+1) ──────────
    from sqlalchemy import case
    scan_ids = [s.id for s in scans]
    agg_result = await db.execute(
        select(
            Vulnerability.scan_id,
            func.sum(case((Vulnerability.severity == "CRITICAL", 1), else_=0)).label("critical"),
            func.sum(case((Vulnerability.severity == "HIGH",     1), else_=0)).label("high"),
            func.sum(case((Vulnerability.severity == "MEDIUM",   1), else_=0)).label("medium"),
            func.sum(case((Vulnerability.severity == "LOW",      1), else_=0)).label("low"),
            func.sum(case((Vulnerability.severity == "INFO",     1), else_=0)).label("info"),
        ).where(Vulnerability.scan_id.in_(scan_ids))
         .group_by(Vulnerability.scan_id)
    )
    counts_by_scan = {
        row.scan_id: {
            "critical": row.critical or 0,
            "high":     row.high     or 0,
            "medium":   row.medium   or 0,
            "low":      row.low      or 0,
            "info":     row.info     or 0,
        }
        for row in agg_result
    }
    _zero = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    summaries = []
    for scan in scans:
        counts = counts_by_scan.get(scan.id, _zero)
        summaries.append(
            ScanSummary(
                scan_id=scan.id,
                target=scan.target.address if scan.target else "unknown",
                status=scan.status.value,
                scan_type=scan.scan_type,
                started_at=scan.started_at.isoformat() if scan.started_at else None,
                completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
                vulnerability_count=sum(counts.values()),
                **counts,
            )
        )

    return summaries


@router.get("/{scan_id}", response_model=FullScanResult)
async def get_full_result(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
) -> FullScanResult:
    """Retrieve the complete result set for a single scan."""
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(selectinload(Scan.target))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")

    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulns = vuln_result.scalars().all()
    counts = await _severity_counts(db, scan_id)

    return FullScanResult(
        scan_id=scan.id,
        target=scan.target.address if scan.target else "unknown",
        status=scan.status.value,
        scan_type=scan.scan_type,
        port_range=scan.port_range,
        adaptive_mode=scan.adaptive_mode,
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        duration_seconds=scan.duration_seconds,
        raw_results=scan.raw_results,
        vulnerabilities=[VulnSummary.model_validate(v) for v in vulns],
        severity_counts=counts,
    )


async def _severity_counts(db: AsyncSession, scan_id: str) -> dict:
    """Return a dict of severity → count for a given scan."""
    from sqlalchemy import case
    result = await db.execute(
        select(
            func.sum(case((Vulnerability.severity == "CRITICAL", 1), else_=0)).label("critical"),
            func.sum(case((Vulnerability.severity == "HIGH", 1), else_=0)).label("high"),
            func.sum(case((Vulnerability.severity == "MEDIUM", 1), else_=0)).label("medium"),
            func.sum(case((Vulnerability.severity == "LOW", 1), else_=0)).label("low"),
            func.sum(case((Vulnerability.severity == "INFO", 1), else_=0)).label("info"),
        ).where(Vulnerability.scan_id == scan_id)
    )
    row = result.one()
    return {
        "critical": row.critical or 0,
        "high":     row.high or 0,
        "medium":   row.medium or 0,
        "low":      row.low or 0,
        "info":     row.info or 0,
    }
