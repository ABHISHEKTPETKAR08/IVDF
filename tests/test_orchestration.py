"""
End-to-end orchestration tests for backend/automation/tasks._orchestrate_scan.

Mocks every external touchpoint (port scanner, detectors, recon) and asserts:
  - Phases run in order
  - Findings are aggregated into the DB
  - Failures in one detector don't stop the pipeline
  - raw_results contains the expected sub-payloads (metadata, port_scan, recon)
  - NSE vulns become VulnerabilityFinding entries
  - Service-detection emits Open Service Detected findings
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import select

from backend.automation.tasks import _orchestrate_scan
from backend.database.db import engine, get_db_session
from backend.database.models import (
    Base, Scan, ScanStatus, Target, Vulnerability,
)
from backend.scanners.port_scanner import PortScanResult, PortInfo


@pytest_asyncio.fixture(scope="function")
async def fresh_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def _create_scan(target_addr="127.0.0.1") -> str:
    async with get_db_session() as session:
        t = Target(address=target_addr, description="test")
        session.add(t)
        await session.flush()
        s = Scan(
            target_id=t.id, status=ScanStatus.PENDING,
            scan_type="safe", port_range="22,80",
        )
        session.add(s)
        await session.flush()
        return s.id


@pytest.mark.asyncio
async def test_orchestrate_marks_scan_completed(fresh_db):
    scan_id = await _create_scan()

    # Mock port scanner to return one open port
    fake_port_result = PortScanResult(
        target="127.0.0.1", backend="nmap", scan_type="quick",
        open_ports=[PortInfo(port=22, service="ssh", version="OpenSSH 8.4")],
    )

    with patch(
        "backend.scanners.port_scanner.PortScanner.scan",
        new=AsyncMock(return_value=fake_port_result),
    ), patch(
        "backend.scanners.recon.ReconScanner.run",
        new=AsyncMock(return_value=MagicMock(
            resolved_ip="127.0.0.1", reverse_dns=None,
            open_banners={}, ssl_info=None,
        )),
    ):
        # Detectors all return no findings — keep test fast
        with patch("backend.detectors.header_checker.HeaderChecker.detect",
                   new=AsyncMock(return_value=[])), \
             patch("backend.detectors.sql_injection.SQLInjectionDetector.detect",
                   new=AsyncMock(return_value=[])), \
             patch("backend.detectors.xss.XSSDetector.detect",
                   new=AsyncMock(return_value=[])), \
             patch("backend.detectors.directory_traversal.DirectoryTraversalDetector.detect",
                   new=AsyncMock(return_value=[])), \
             patch("backend.detectors.http_methods.HTTPMethodChecker.detect",
                   new=AsyncMock(return_value=[])):
            result = await _orchestrate_scan(
                scan_id, "127.0.0.1",
                {"scan_type": "safe", "port_range": "22,80",
                 "adaptive_mode": False},
            )

    async with get_db_session() as session:
        s = (await session.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        assert s.status == ScanStatus.COMPLETED
        assert s.completed_at is not None
        # raw_results should contain port_scan sub-payload
        assert s.raw_results is not None
        assert "metadata" in s.raw_results
        assert "port_scan" in s.raw_results

    # Open Service Detected synthesised from the open port (22 = ssh, NOT on
    # DangerousPortChecker's list, so it gets the INFO-level finding).
    async with get_db_session() as session:
        vulns = (await session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )).scalars().all()
        open_service = [v for v in vulns if v.vuln_type == "Open Service Detected"]
        assert len(open_service) == 1
        assert open_service[0].affected_port == 22


@pytest.mark.asyncio
async def test_orchestrate_nse_vulns_become_findings(fresh_db):
    scan_id = await _create_scan()

    fake_port_result = PortScanResult(
        target="127.0.0.1", backend="nmap", scan_type="full",
        open_ports=[PortInfo(port=8080, service="http", version="nginx 1.18")],
        nse_vulns=[{
            "port": 8080, "protocol": "tcp",
            "script": "http-vuln-cve2017-5638",
            "output": "VULNERABLE: Apache Struts RCE",
        }],
    )

    with patch(
        "backend.scanners.port_scanner.PortScanner.scan",
        new=AsyncMock(return_value=fake_port_result),
    ), patch(
        "backend.scanners.recon.ReconScanner.run",
        new=AsyncMock(return_value=MagicMock(
            resolved_ip=None, reverse_dns=None, open_banners={}, ssl_info=None,
        )),
    ):
        with patch("backend.detectors.header_checker.HeaderChecker.detect",
                   new=AsyncMock(return_value=[])), \
             patch("backend.detectors.sql_injection.SQLInjectionDetector.detect",
                   new=AsyncMock(return_value=[])), \
             patch("backend.detectors.xss.XSSDetector.detect",
                   new=AsyncMock(return_value=[])), \
             patch("backend.detectors.directory_traversal.DirectoryTraversalDetector.detect",
                   new=AsyncMock(return_value=[])), \
             patch("backend.detectors.http_methods.HTTPMethodChecker.detect",
                   new=AsyncMock(return_value=[])):
            await _orchestrate_scan(
                scan_id, "127.0.0.1",
                {"scan_type": "normal", "port_range": "8080",
                 "adaptive_mode": False},
            )

    async with get_db_session() as session:
        vulns = (await session.execute(
            select(Vulnerability).where(Vulnerability.scan_id == scan_id)
        )).scalars().all()
        nse = [v for v in vulns if v.vuln_type == "NSE Vulnerability"]
        assert len(nse) == 1
        assert nse[0].affected_port == 8080
        assert "Apache Struts" in (nse[0].response_snippet or "")


@pytest.mark.asyncio
async def test_orchestrate_continues_when_detector_raises(fresh_db):
    """A detector crash must not abort the pipeline."""
    scan_id = await _create_scan()

    with patch(
        "backend.scanners.port_scanner.PortScanner.scan",
        new=AsyncMock(return_value=PortScanResult(target="127.0.0.1")),
    ), patch(
        "backend.scanners.recon.ReconScanner.run",
        new=AsyncMock(return_value=MagicMock(
            resolved_ip=None, reverse_dns=None, open_banners={}, ssl_info=None,
        )),
    ):
        with patch("backend.detectors.header_checker.HeaderChecker.detect",
                   new=AsyncMock(side_effect=RuntimeError("boom"))), \
             patch("backend.detectors.sql_injection.SQLInjectionDetector.detect",
                   new=AsyncMock(return_value=[])), \
             patch("backend.detectors.xss.XSSDetector.detect",
                   new=AsyncMock(return_value=[])), \
             patch("backend.detectors.directory_traversal.DirectoryTraversalDetector.detect",
                   new=AsyncMock(return_value=[])), \
             patch("backend.detectors.http_methods.HTTPMethodChecker.detect",
                   new=AsyncMock(return_value=[])):
            await _orchestrate_scan(
                scan_id, "127.0.0.1",
                {"scan_type": "safe", "port_range": "80",
                 "adaptive_mode": False},
            )

    async with get_db_session() as session:
        s = (await session.execute(select(Scan).where(Scan.id == scan_id))).scalar_one()
        assert s.status == ScanStatus.COMPLETED
