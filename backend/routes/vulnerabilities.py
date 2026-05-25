"""
Vulnerability query routes.

GET /vulnerabilities             — list all findings across all scans
GET /vulnerabilities/{vuln_id}   — get a single finding with full details
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.database.db import get_db
from backend.database.models import Vulnerability
from backend.ai_explanations.explainer import VulnerabilityExplainer
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

_explainer = VulnerabilityExplainer()


class VulnDetail(BaseModel):
    id: str
    scan_id: str
    name: str
    vuln_type: str
    severity: str
    cvss_score: Optional[float]
    explanation: Optional[str]
    technical_description: Optional[str]
    impact: Optional[str]
    fix: Optional[list]
    owasp_mapping: Optional[str]
    cve_references: Optional[list]
    affected_url: Optional[str]
    affected_port: Optional[int]
    payload_used: Optional[str]
    is_false_positive: bool

    class Config:
        from_attributes = True


@router.get("", response_model=List[VulnDetail])
async def list_vulnerabilities(
    db: AsyncSession = Depends(get_db),
    severity: Optional[str] = Query(default=None, description="Filter by severity"),
    scan_id: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
) -> List[VulnDetail]:
    """
    List vulnerability findings with optional filters.

    - **severity**: CRITICAL | HIGH | MEDIUM | LOW | INFO
    - **scan_id**: Filter by a specific scan
    """
    query = select(Vulnerability).order_by(desc(Vulnerability.created_at))

    if severity:
        query = query.where(Vulnerability.severity == severity.upper())
    if scan_id:
        query = query.where(Vulnerability.scan_id == scan_id)

    query = query.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(query)
    vulns = result.scalars().all()
    return [VulnDetail.model_validate(v) for v in vulns]


@router.get("/{vuln_id}", response_model=dict)
async def get_vulnerability(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Retrieve a single vulnerability finding with enriched explanation data.
    """
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail=f"Vulnerability '{vuln_id}' not found.")

    from backend.detectors.base import VulnerabilityFinding, Severity
    finding = VulnerabilityFinding(
        name=vuln.name,
        vuln_type=vuln.vuln_type,
        severity=Severity(vuln.severity.value),
        explanation=vuln.explanation or "",
        technical_description=vuln.technical_description or "",
        impact=vuln.impact or "",
        fix=vuln.fix or [],
        owasp_mapping=vuln.owasp_mapping or "",
        cve_references=vuln.cve_references or [],
        cvss_score=vuln.cvss_score,
        affected_url=vuln.affected_url,
        affected_port=vuln.affected_port,
        payload_used=vuln.payload_used,
        response_snippet=vuln.response_snippet,
    )
    explained = _explainer.explain(finding)
    explained["id"] = vuln.id
    explained["scan_id"] = vuln.scan_id
    explained["is_false_positive"] = vuln.is_false_positive
    return explained


@router.patch("/{vuln_id}/false-positive", status_code=200)
async def mark_false_positive(
    vuln_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Mark a finding as a false positive."""
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail=f"Vulnerability '{vuln_id}' not found.")
    vuln.is_false_positive = not vuln.is_false_positive
    await db.commit()
    return {
        "id": vuln_id,
        "is_false_positive": vuln.is_false_positive,
        "message": "Status updated.",
    }
