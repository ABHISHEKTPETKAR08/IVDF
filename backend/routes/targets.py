"""
Target management routes.

GET    /targets            — list all registered targets
POST   /targets            — add a target
DELETE /targets/{target_id} — remove a target
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.db import get_db
from backend.database.models import Target
from backend.utils.validators import validate_target
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/targets", tags=["Targets"])


class TargetCreate(BaseModel):
    address: str
    description: Optional[str] = None

    @field_validator("address", mode="before")
    @classmethod
    def validate_address(cls, v):
        ok, reason = validate_target(v)
        if not ok:
            raise ValueError(reason)
        return v.strip()


class TargetResponse(BaseModel):
    id: str
    address: str
    description: Optional[str]
    resolved_ip: Optional[str]
    last_scanned_at: Optional[str]
    auto_rescan: bool = True

    class Config:
        from_attributes = True


class AutoRescanToggle(BaseModel):
    enabled: bool


@router.get("", response_model=List[TargetResponse])
async def list_targets(db: AsyncSession = Depends(get_db)) -> List[TargetResponse]:
    """Return all registered targets."""
    result = await db.execute(select(Target).order_by(desc(Target.created_at)))
    targets = result.scalars().all()
    return [
        TargetResponse(
            id=t.id,
            address=t.address,
            description=t.description,
            resolved_ip=t.resolved_ip,
            last_scanned_at=t.last_scanned_at.isoformat() if t.last_scanned_at else None,
            auto_rescan=bool(t.auto_rescan),
        )
        for t in targets
    ]


# ── Continuous monitoring — per-target toggle + scheduler status ────────────

@router.patch("/{target_id}/auto-rescan", response_model=TargetResponse)
async def toggle_auto_rescan(
    target_id: str,
    body: AutoRescanToggle,
    db: AsyncSession = Depends(get_db),
) -> TargetResponse:
    """Enable or disable continuous auto-rescan for a single target."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{target_id}' not found.")
    target.auto_rescan = bool(body.enabled)
    await db.commit()
    await db.refresh(target)
    logger.info(
        "Target auto_rescan=%s for %s (%s)",
        target.auto_rescan, target.address, target.id,
    )
    return TargetResponse(
        id=target.id,
        address=target.address,
        description=target.description,
        resolved_ip=target.resolved_ip,
        last_scanned_at=target.last_scanned_at.isoformat() if target.last_scanned_at else None,
        auto_rescan=bool(target.auto_rescan),
    )


@router.get("/scheduler/status", tags=["Targets"])
async def get_scheduler_status() -> dict:
    """Return the auto-rescan scheduler's current state."""
    from backend.automation.rescan_scheduler import get_scheduler
    return get_scheduler().status()


@router.post("", response_model=TargetResponse, status_code=201)
async def add_target(
    body: TargetCreate,
    db: AsyncSession = Depends(get_db),
) -> TargetResponse:
    """Register a new target for scanning."""
    existing = await db.execute(select(Target).where(Target.address == body.address))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Target '{body.address}' already registered.")

    import asyncio
    import socket
    resolved = None
    try:
        # Off-thread DNS to keep the event loop responsive.
        resolved = await asyncio.to_thread(socket.gethostbyname, body.address)
    except socket.gaierror:
        pass

    target = Target(address=body.address, description=body.description, resolved_ip=resolved)
    db.add(target)
    await db.commit()
    await db.refresh(target)

    return TargetResponse(
        id=target.id,
        address=target.address,
        description=target.description,
        resolved_ip=target.resolved_ip,
        last_scanned_at=None,
        auto_rescan=bool(target.auto_rescan),
    )


@router.delete("/{target_id}", status_code=200)
async def delete_target(
    target_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Remove a target (and cascade-delete its scans in the future)."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail=f"Target '{target_id}' not found.")
    await db.delete(target)
    await db.commit()
    return {"message": f"Target '{target.address}' removed."}
