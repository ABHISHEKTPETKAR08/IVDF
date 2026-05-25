"""
Continuous-monitoring scheduler.

Runs an asyncio background task that periodically re-scans every Target whose
`auto_rescan` flag is True. The dispatch path mirrors the manual POST /scan
route — Celery first, asyncio fallback when Redis is unavailable — so the
scheduler works in both production and single-host lab deployments.

Design notes:
  * Pure asyncio (no APScheduler / Celery beat dependency). One coroutine that
    sleeps between ticks; cleanly cancellable via stop().
  * Tick is cheap: a single SQL query (`SELECT ... WHERE auto_rescan = true
    AND last_scanned_at < cutoff`).
  * Targets with an in-flight scan (PENDING / RUNNING) are skipped so we
    never double-fire.
  * Failures in one target's dispatch never abort the loop — each is wrapped
    in try/except.
  * Audit log emits `event=auto_rescan_dispatched` for forensic traceability.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from sqlalchemy import select

from backend.config import settings
from backend.database.db import get_db_session
from backend.database.models import Scan, ScanStatus, Target
from backend.utils.audit import audit_scan_requested
from backend.utils.logger import get_logger

logger = get_logger(__name__)


class RescanScheduler:
    """Asyncio-based periodic rescan dispatcher."""

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._stop = asyncio.Event()
        self._last_tick_at: Optional[datetime] = None
        self._last_dispatched: int = 0

    # ── lifecycle ────────────────────────────────────────────────────────────

    async def start(self) -> None:
        if not settings.RESCAN_ENABLED:
            logger.info("Auto-rescan disabled (RESCAN_ENABLED=false)")
            return
        if self._task and not self._task.done():
            logger.debug("RescanScheduler already running; ignoring start()")
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._loop(), name="rescan-scheduler")
        logger.info(
            "RescanScheduler started: interval=%d min, tick=%d s, "
            "default_scan_type=%s, default_port_range=%s",
            settings.RESCAN_INTERVAL_MINUTES,
            settings.RESCAN_TICK_SECONDS,
            settings.RESCAN_DEFAULT_SCAN_TYPE,
            settings.RESCAN_DEFAULT_PORT_RANGE,
        )

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except asyncio.TimeoutError:
                self._task.cancel()
                logger.warning("RescanScheduler forced-cancelled after 5 s timeout.")
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("RescanScheduler stopped.")

    # ── observability ────────────────────────────────────────────────────────

    def status(self) -> dict:
        return {
            "enabled": settings.RESCAN_ENABLED,
            "running": bool(self._task and not self._task.done()),
            "interval_minutes": settings.RESCAN_INTERVAL_MINUTES,
            "tick_seconds": settings.RESCAN_TICK_SECONDS,
            "last_tick_at": self._last_tick_at.isoformat() if self._last_tick_at else None,
            "last_dispatched": self._last_dispatched,
        }

    # ── loop body ────────────────────────────────────────────────────────────

    async def _loop(self) -> None:
        # Wait one tick before the first run so the API has time to fully boot
        # (avoids a thundering herd of rescans at startup).
        try:
            await asyncio.wait_for(
                self._stop.wait(), timeout=settings.RESCAN_TICK_SECONDS,
            )
            return  # stop was requested before first tick
        except asyncio.TimeoutError:
            pass

        while not self._stop.is_set():
            try:
                await self._tick()
            except Exception as exc:  # never let the loop die
                logger.warning("RescanScheduler tick error: %s", exc, exc_info=True)

            # Sleep until next tick OR until stop is requested
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=settings.RESCAN_TICK_SECONDS,
                )
                return  # stop set
            except asyncio.TimeoutError:
                continue

    async def _tick(self) -> None:
        self._last_tick_at = datetime.now(timezone.utc)
        due = await self._collect_due_targets()
        if not due:
            logger.debug("RescanScheduler tick: no targets due.")
            return

        logger.info(
            "RescanScheduler tick: %d target(s) due for auto-rescan: %s",
            len(due), ", ".join(t.address for t in due[:5]) + (
                f" (+{len(due)-5} more)" if len(due) > 5 else ""
            ),
        )

        dispatched = 0
        for target in due:
            try:
                await self._dispatch_rescan(target.id, target.address)
                dispatched += 1
            except Exception as exc:
                logger.warning(
                    "RescanScheduler: failed to dispatch rescan for %s (%s): %s",
                    target.address, target.id, exc,
                )
        self._last_dispatched = dispatched
        logger.info("RescanScheduler tick: dispatched %d rescan(s).", dispatched)

    # ── DB queries ───────────────────────────────────────────────────────────

    async def _collect_due_targets(self) -> List[Target]:
        """Targets with auto_rescan=True, no active scan, and stale last_scan."""
        # `last_scanned_at` is timezone-naive on existing rows (set via
        # datetime.utcnow before Phase 2 fix); compare against a naive cutoff
        # to keep this query DB-portable.
        cutoff = datetime.utcnow() - timedelta(
            minutes=settings.RESCAN_INTERVAL_MINUTES,
        )
        due: List[Target] = []
        async with get_db_session() as session:
            targets = (await session.execute(
                select(Target).where(Target.auto_rescan == True)  # noqa: E712
            )).scalars().all()

            for target in targets:
                # Stale enough?
                if target.last_scanned_at and target.last_scanned_at > cutoff:
                    continue
                # No active scan in flight?
                active = (await session.execute(
                    select(Scan).where(
                        Scan.target_id == target.id,
                        Scan.status.in_((ScanStatus.PENDING, ScanStatus.RUNNING)),
                    )
                )).scalars().first()
                if active:
                    continue
                due.append(target)
        return due

    # ── dispatch ─────────────────────────────────────────────────────────────

    async def _dispatch_rescan(self, target_id: str, address: str) -> None:
        """
        Insert a PENDING Scan row and run the orchestration pipeline.

        We deliberately bypass the Celery dispatch wrapper used by the route —
        the scheduler is the only caller, runs inside the API process, and
        Celery would just round-trip back into this same process anyway.
        """
        from backend.automation.tasks import _orchestrate_scan

        scan_id = str(uuid.uuid4())
        scan_config = {
            "scan_type":     settings.RESCAN_DEFAULT_SCAN_TYPE,
            "port_range":    settings.RESCAN_DEFAULT_PORT_RANGE,
            "adaptive_mode": False,
        }

        async with get_db_session() as session:
            scan = Scan(
                id=scan_id,
                target_id=target_id,
                status=ScanStatus.PENDING,
                scan_type=scan_config["scan_type"],
                port_range=scan_config["port_range"],
                adaptive_mode=False,
            )
            session.add(scan)
            await session.commit()

        audit_scan_requested(
            scan_id=scan_id, target=address,
            scan_type=scan_config["scan_type"], client_ip="auto-rescan",
        )
        logger.info(
            "Auto-rescan dispatched: scan_id=%s target=%s", scan_id, address,
        )

        # Fire-and-forget — keep the scheduler tick fast even if scans take
        # several minutes each. Each scan inherits the API process's event
        # loop and contextvars (request_id is None for these).
        asyncio.create_task(
            self._run_safe(scan_id, address, scan_config),
            name=f"rescan-{scan_id[:8]}",
        )

    async def _run_safe(self, scan_id: str, target: str, scan_config: dict) -> None:
        """Wrapper around _orchestrate_scan that marks the scan FAILED on error."""
        from backend.automation.tasks import _orchestrate_scan
        try:
            await _orchestrate_scan(scan_id, target, scan_config)
        except Exception as exc:
            logger.error(
                "Auto-rescan failed: scan_id=%s target=%s err=%s",
                scan_id, target, exc, exc_info=True,
            )
            try:
                async with get_db_session() as session:
                    result = await session.execute(
                        select(Scan).where(Scan.id == scan_id)
                    )
                    scan = result.scalars().first()
                    if scan and scan.status not in (
                        ScanStatus.COMPLETED, ScanStatus.CANCELLED,
                    ):
                        scan.status = ScanStatus.FAILED
                        scan.error_message = f"auto-rescan: {exc}"[:500]
                        await session.commit()
            except Exception:
                pass


# Process-wide singleton
_scheduler: Optional[RescanScheduler] = None


def get_scheduler() -> RescanScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = RescanScheduler()
    return _scheduler
