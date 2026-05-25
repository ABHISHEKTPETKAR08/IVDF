"""
Report generation routes.

POST /reports/{scan_id}    — generate a report for a completed scan
GET  /reports              — list all generated reports
GET  /reports/{report_id}/download — download a report file
"""
import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.database.db import get_db
from backend.database.models import Report, Scan, ScanStatus, ReportFormat, Vulnerability
from backend.reports.report_generator import ReportGenerator
from backend.ai_explanations.explainer import VulnerabilityExplainer
from backend.utils.audit import audit_report_generated
from backend.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter(prefix="/reports", tags=["Reports"])


class GenerateReportRequest(BaseModel):
    format: str = "pdf"   # pdf | json | csv


class ReportResponse(BaseModel):
    report_id: str
    scan_id: str
    format: str
    file_path: str
    file_size_bytes: Optional[int]
    generated_at: str


@router.post("/{scan_id}", response_model=ReportResponse, status_code=201)
async def generate_report(
    scan_id: str,
    request: GenerateReportRequest,
    db: AsyncSession = Depends(get_db),
) -> ReportResponse:
    """Generate a PDF, JSON, or CSV report for a completed scan."""
    result = await db.execute(
        select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.target))
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail=f"Scan is in '{scan.status.value}' state. Reports require 'completed' scans.",
        )

    # Validate format
    fmt_map = {"pdf": ReportFormat.PDF, "json": ReportFormat.JSON, "csv": ReportFormat.CSV}
    fmt_key = request.format.lower()
    if fmt_key not in fmt_map:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {request.format}")

    # Fetch vulnerabilities
    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_id == scan_id)
    )
    vulns = vuln_result.scalars().all()

    explainer = VulnerabilityExplainer()
    from backend.detectors.base import VulnerabilityFinding, Severity

    findings_for_explainer = []
    for v in vulns:
        findings_for_explainer.append(
            VulnerabilityFinding(
                name=v.name,
                vuln_type=v.vuln_type,
                severity=Severity(v.severity.value),
                explanation=v.explanation or "",
                technical_description=v.technical_description or "",
                impact=v.impact or "",
                fix=v.fix or [],
                owasp_mapping=v.owasp_mapping or "",
                cve_references=v.cve_references or [],
                cvss_score=v.cvss_score,
                affected_url=v.affected_url,
                affected_port=v.affected_port,
            )
        )

    severity_summary = explainer.severity_summary(findings_for_explainer)
    explained = explainer.explain_batch(findings_for_explainer)

    scan_data = {
        "metadata": {
            "scan_id": scan_id,
            "target": scan.target.address if scan.target else "unknown",
            "scan_type": scan.scan_type,
            "started_at": scan.started_at.isoformat() if scan.started_at else "N/A",
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else "N/A",
            "duration": f"{scan.duration_seconds or 0:.1f}s",
            "risk_score": explainer.risk_score(findings_for_explainer),
        },
        "severity_summary": severity_summary,
        "vulnerabilities": explained,
    }

    generator = ReportGenerator()
    try:
        if fmt_key == "pdf":
            file_path = generator.generate_pdf(scan_data)
        elif fmt_key == "json":
            file_path = generator.generate_json(scan_data)
        else:
            file_path = generator.generate_csv(scan_data)
    except Exception as exc:
        logger.error("Report generation failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")

    file_size = os.path.getsize(file_path) if os.path.exists(file_path) else None

    report = Report(
        scan_id=scan_id,
        format=fmt_map[fmt_key],
        file_path=file_path,
        file_size_bytes=file_size,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    audit_report_generated(scan_id, fmt_key, file_path)

    return ReportResponse(
        report_id=report.id,
        scan_id=scan_id,
        format=fmt_key,
        file_path=file_path,
        file_size_bytes=file_size,
        generated_at=report.generated_at.isoformat(),
    )


@router.get("", response_model=List[ReportResponse])
async def list_reports(
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
) -> List[ReportResponse]:
    """List all generated reports."""
    result = await db.execute(
        select(Report)
        .order_by(desc(Report.generated_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    reports = result.scalars().all()
    return [
        ReportResponse(
            report_id=r.id,
            scan_id=r.scan_id,
            format=r.format.value,
            file_path=r.file_path,
            file_size_bytes=r.file_size_bytes,
            generated_at=r.generated_at.isoformat(),
        )
        for r in reports
    ]


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    db: AsyncSession = Depends(get_db),
) -> FileResponse:
    """Download a generated report file."""
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail=f"Report '{report_id}' not found.")

    # Defence in depth: enforce that the resolved file path stays inside the
    # configured REPORTS_DIR. Stops any future bug from turning the download
    # endpoint into an arbitrary-file-read primitive.
    from backend.config import settings as _settings
    reports_root = os.path.realpath(_settings.REPORTS_DIR)
    candidate = os.path.realpath(report.file_path)
  
    if not os.path.exists(candidate):
        raise HTTPException(status_code=404, detail="Report file not found on disk.")

    media_types = {
        ReportFormat.PDF: "application/pdf",
        ReportFormat.JSON: "application/json",
        ReportFormat.CSV: "text/csv",
    }
    return FileResponse(
        path=candidate,
        media_type=media_types.get(report.format, "application/octet-stream"),
        filename=os.path.basename(candidate),
    )
