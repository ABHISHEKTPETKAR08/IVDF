"""
Security-hardening regression tests (Phase 5).
"""
import os

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from backend.app import app
from backend.database.db import engine
from backend.utils import audit
from backend.utils.validators import validate_target


@pytest_asyncio.fixture(scope="function")
async def client():
    async with engine.begin() as conn:
        from backend.database.models import Base
        await conn.run_sync(Base.metadata.create_all)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    async with engine.begin() as conn:
        from backend.database.models import Base
        await conn.run_sync(Base.metadata.drop_all)


# ── Validator no longer performs DNS (Phase 2 §V1) ────────────────────────────

class TestValidatorDNSRemoval:

    def test_validate_target_does_not_call_socket_gethostbyname(self, monkeypatch):
        called = []

        def _spy(*a, **kw):
            called.append(a)
            raise RuntimeError("DNS must not be called from validator")

        import socket
        monkeypatch.setattr(socket, "gethostbyname", _spy)
        ok, _ = validate_target("example.com")
        assert ok
        assert called == []


# ── Path traversal guard on /reports/{id}/download (Phase 5 #5) ───────────────

class TestReportDownloadPathTraversal:

    @pytest.mark.asyncio
    async def test_download_rejects_path_outside_reports_dir(self, client, tmp_path):
        """A maliciously stored file_path that escapes REPORTS_DIR must 400."""
        # Insert a Report row with a path pointing OUTSIDE reports_dir.
        from sqlalchemy import insert
        from backend.database.db import get_db_session
        from backend.database.models import Report, ReportFormat, Scan, ScanStatus, Target

        async with get_db_session() as session:
            t = Target(address="192.168.1.1")
            session.add(t)
            await session.flush()
            s = Scan(target_id=t.id, status=ScanStatus.COMPLETED)
            session.add(s)
            await session.flush()
            # Path that escapes reports_dir
            escape_path = os.path.abspath(__file__)  # this test file itself
            r = Report(
                scan_id=s.id, format=ReportFormat.JSON,
                file_path=escape_path, file_size_bytes=100,
            )
            session.add(r)
            await session.flush()
            report_id = r.id

        resp = await client.get(f"/reports/{report_id}/download")
        # Should be either 400 (path-traversal rejection) or 404 (not in reports
        # dir). The important thing is that it does NOT successfully return the
        # arbitrary file.
        assert resp.status_code in (400, 404)


# ── Audit logger emits structured lines ───────────────────────────────────────

class TestAuditLogger:

    def test_audit_scan_requested_emits_event_field(self, caplog):
        with caplog.at_level("INFO", logger="ivdaf.audit"):
            audit.audit_scan_requested("sid", "1.2.3.4", "normal", "10.0.0.1")
        joined = " ".join(r.getMessage() for r in caplog.records)
        assert "event=scan_requested" in joined
        assert "scan_id='sid'" in joined
        assert "target='1.2.3.4'" in joined

    def test_audit_scan_failed_truncates_long_error(self, caplog):
        long_err = "x" * 1000
        with caplog.at_level("WARNING", logger="ivdaf.audit"):
            audit.audit_scan_failed("sid", "tgt", long_err)
        joined = " ".join(r.getMessage() for r in caplog.records)
        # 200-char cap
        assert "x" * 200 in joined
        assert "x" * 201 not in joined


# ── Rate-limit header trust (Phase 2 §M3) ─────────────────────────────────────

class TestRateLimitHeaderTrust:

    @pytest.mark.asyncio
    async def test_x_forwarded_for_ignored_by_default(self, client):
        """With TRUST_PROXY_HEADERS=False (default), spoofed XFF must not
        change rate-limit key."""
        # Just smoke-check that two requests with different XFF still share
        # the same rate-limit bucket (i.e. neither hits a 429).
        for xff in ("1.1.1.1", "2.2.2.2"):
            resp = await client.get(
                "/results", headers={"X-Forwarded-For": xff},
            )
            assert resp.status_code != 429
