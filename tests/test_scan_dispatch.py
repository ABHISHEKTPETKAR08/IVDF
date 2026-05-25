"""
Phase-5 fast-fail Celery dispatch + audit log emission tests.
"""
import asyncio
import logging
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from backend.app import app
from backend.database.db import engine
from backend.database.models import Base


@pytest_asyncio.fixture(scope="function")
async def client():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


class TestFastFailCeleryDispatch:

    @pytest.mark.asyncio
    async def test_celery_timeout_does_not_block_request(self, client):
        """If Celery's apply_async hangs, route must fall back within ~2 s."""
        import time

        def _slow_dispatch(*a, **kw):
            time.sleep(5)  # would block for 5 s if not wrapped in wait_for
            return MagicMock(id="never-arrives")

        with patch(
            "backend.routes.scan._run_scan_background",
        ), patch(
            "backend.automation.tasks.run_scan_task.apply_async",
            side_effect=_slow_dispatch,
        ):
            t0 = time.perf_counter()
            resp = await client.post("/scan", json={
                "target": "192.168.1.1", "scan_type": "safe",
            })
            elapsed = time.perf_counter() - t0

        assert resp.status_code == 202
        # Must complete in ~2 s (the wait_for limit) + small overhead
        assert elapsed < 4.0, f"dispatch hung for {elapsed:.1f}s"
        body = resp.json()
        # Fallback path was taken — no task_id
        assert body["task_id"] is None
        assert body["status"] == "queued"

    @pytest.mark.asyncio
    async def test_celery_immediate_failure_falls_back(self, client):
        """Broker connection error → immediate asyncio fallback."""
        with patch(
            "backend.routes.scan._run_scan_background",
        ), patch(
            "backend.automation.tasks.run_scan_task.apply_async",
            side_effect=ConnectionError("Redis refused"),
        ):
            resp = await client.post("/scan", json={
                "target": "10.0.0.5", "scan_type": "safe",
            })

        assert resp.status_code == 202
        assert resp.json()["task_id"] is None


class TestAuditLog:

    @pytest.mark.asyncio
    async def test_scan_request_emits_audit_line(self, client, caplog):
        with patch("backend.routes.scan._run_scan_background"):
            with caplog.at_level(logging.INFO, logger="ivdaf.audit"):
                await client.post("/scan", json={
                    "target": "192.168.1.100", "scan_type": "safe",
                })

        audit_lines = [r for r in caplog.records if r.name == "ivdaf.audit"]
        assert any("event=scan_requested" in r.getMessage() for r in audit_lines)

    @pytest.mark.asyncio
    async def test_audit_helpers_handle_none_fields(self):
        """Audit helpers must skip None-valued kv pairs cleanly."""
        from backend.utils.audit import audit_scan_requested
        # Should not raise
        audit_scan_requested(
            scan_id="abc", target="127.0.0.1", scan_type="safe", client_ip=None,
        )
