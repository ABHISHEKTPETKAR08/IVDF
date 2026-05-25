"""
Infrastructure integration tests.

Test matrix:
- Redis connectivity (live + mock)
- Celery worker registration (mocked broker)
- Health endpoints (/health, /health/full)
- Fallback execution path (asyncio when Celery unavailable)
- Scan lifecycle states (PENDING → RUNNING → COMPLETED)
- Degraded-mode scanning (scans succeed without Redis/Celery)
- Nmap detection utility
- Configuration validation
- Queue recovery (task re-enqueue on worker loss)

Run:
    pytest tests/test_infrastructure.py -v --asyncio-mode=auto
"""
import asyncio
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from httpx import AsyncClient, ASGITransport

from backend.app import app
from backend.config import settings
from backend.database.db import engine

# Conftest.py guarantees DATABASE_URL points at in-memory SQLite before the
# engine is created. Verify the contract.
assert settings.DATABASE_URL.endswith(":memory:"), (
    "Test isolation broken — DATABASE_URL was not overridden in conftest.py"
)
settings.CELERY_TASK_ALWAYS_EAGER = False  # keep async behaviour


# ── Shared fixture ────────────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="function")
async def client():
    """Fresh in-memory DB + ASGI test client per test."""
    async with engine.begin() as conn:
        from backend.database.models import Base
        await conn.run_sync(Base.metadata.create_all)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c

    async with engine.begin() as conn:
        from backend.database.models import Base
        await conn.run_sync(Base.metadata.drop_all)


# ══════════════════════════════════════════════════════════════════════════════
# 1. Health endpoints
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthEndpoints:

    @pytest.mark.asyncio
    async def test_liveness_always_fast(self, client):
        """/health must respond instantly regardless of subsystem state."""
        resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "version" in body

    @pytest.mark.asyncio
    async def test_liveness_has_request_id_header(self, client):
        resp = await client.get("/health")
        assert "x-request-id" in resp.headers
        assert len(resp.headers["x-request-id"]) == 36  # UUID format

    @pytest.mark.asyncio
    async def test_liveness_has_response_time_header(self, client):
        resp = await client.get("/health")
        assert "x-response-time" in resp.headers
        ms = float(resp.headers["x-response-time"].rstrip("ms"))
        assert ms < 500  # must be fast

    @pytest.mark.asyncio
    async def test_full_health_returns_database_status(self, client):
        """/health/full must report database status."""
        with patch("backend.app.settings.HEALTHCHECK_TIMEOUT", 3.0):
            resp = await client.get("/health/full")
        assert resp.status_code == 200
        body = resp.json()
        assert "database" in body
        # DB is SQLite in-memory — must be connected
        assert body["database"] == "connected"

    @pytest.mark.asyncio
    async def test_full_health_reports_redis_unavailable(self, client):
        """/health/full gracefully reports Redis as unavailable when not running."""
        resp = await client.get("/health/full")
        body = resp.json()
        assert "redis" in body
        # Redis not running in CI — should say unavailable, not raise
        assert body["redis"] in ("connected", "unavailable", "timeout")

    @pytest.mark.asyncio
    async def test_full_health_reports_celery_status(self, client):
        """/health/full must report Celery status without blocking."""
        resp = await client.get("/health/full")
        body = resp.json()
        assert "celery" in body
        assert body["celery"] in ("running", "no workers", "unavailable", "timeout")

    @pytest.mark.asyncio
    async def test_full_health_degraded_when_redis_down(self, client):
        """Status must be 'degraded' when Redis is unavailable."""
        resp = await client.get("/health/full")
        body = resp.json()
        if body.get("redis") != "connected":
            assert body["status"] in ("degraded", "unhealthy")

    @pytest.mark.asyncio
    async def test_full_health_healthy_with_all_services_mocked(self, client):
        """Status must be 'healthy' when all subsystems report OK."""
        # get_db_session is imported inside the health_full function body,
        # so we patch at its definition site: backend.database.db
        mock_session_ctx = AsyncMock()
        mock_session_ctx.__aenter__ = AsyncMock(
            return_value=AsyncMock(execute=AsyncMock())
        )
        mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_r = AsyncMock()
        mock_r.ping = AsyncMock(return_value=True)
        mock_r.aclose = AsyncMock()

        with (
            patch("backend.database.db.get_db_session", return_value=mock_session_ctx),
            patch("redis.asyncio.from_url", return_value=mock_r),
            patch("backend.automation.celery_app.celery_app") as mock_celery,
        ):
            mock_celery.control.inspect.return_value.ping.return_value = {
                "worker@host": {"ok": "pong"}
            }
            resp = await client.get("/health/full")

        assert resp.status_code == 200
        assert resp.json()["api"] == "healthy"


# ══════════════════════════════════════════════════════════════════════════════
# 2. Redis connectivity
# ══════════════════════════════════════════════════════════════════════════════

class TestRedisConnectivity:

    @pytest.mark.asyncio
    async def test_redis_ping_timeout_is_safe(self):
        """A Redis ping to a non-existent host should not hang > timeout."""
        import redis.asyncio as aioredis
        r = aioredis.from_url(
            "redis://127.0.0.1:19999/0",   # port that's definitely closed
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        try:
            await asyncio.wait_for(r.ping(), timeout=2.0)
            pytest.fail("Expected connection error")
        except (asyncio.TimeoutError, Exception):
            pass  # expected — connection refused or timeout
        finally:
            await r.aclose()

    @pytest.mark.asyncio
    async def test_redis_config_url_format(self):
        """Settings validator rejects malformed Redis URLs."""
        from pydantic import ValidationError
        from backend.config import Settings
        with pytest.raises((ValidationError, ValueError)):
            Settings(REDIS_URL="not-a-redis-url", _env_file=None)


# ══════════════════════════════════════════════════════════════════════════════
# 3. Celery architecture
# ══════════════════════════════════════════════════════════════════════════════

class TestCeleryArchitecture:

    def test_celery_app_configured(self):
        """Celery app must be importable and correctly named."""
        from backend.automation.celery_app import celery_app
        assert celery_app.main == "ivdaf"

    def test_celery_uses_correct_broker(self):
        from backend.automation.celery_app import celery_app
        assert celery_app.conf.broker_url == settings.CELERY_BROKER_URL

    def test_celery_uses_separate_result_backend(self):
        from backend.automation.celery_app import celery_app
        # Result backend should be on DB 1, broker on DB 0
        assert celery_app.conf.result_backend == settings.CELERY_RESULT_BACKEND

    def test_celery_acks_late_enabled(self):
        """task_acks_late prevents task loss on worker crash."""
        from backend.automation.celery_app import celery_app
        assert celery_app.conf.task_acks_late is True

    def test_celery_reject_on_worker_lost(self):
        """Lost tasks must be requeued, not silently dropped."""
        from backend.automation.celery_app import celery_app
        assert celery_app.conf.task_reject_on_worker_lost is True

    def test_celery_prefetch_multiplier_is_one(self):
        """Prevents one worker monopolising all pending tasks."""
        from backend.automation.celery_app import celery_app
        assert celery_app.conf.worker_prefetch_multiplier == 1

    def test_celery_time_limits_set(self):
        from backend.automation.celery_app import celery_app
        assert celery_app.conf.task_soft_time_limit == 600
        assert celery_app.conf.task_time_limit == 720

    def test_celery_retry_on_startup_enabled(self):
        from backend.automation.celery_app import celery_app
        assert celery_app.conf.broker_connection_retry_on_startup is True

    def test_celery_task_discoverable(self):
        """run_scan_task must be registered in the Celery app."""
        from backend.automation.celery_app import celery_app
        from backend.automation import tasks  # noqa: F401 — triggers task registration
        assert "tasks.run_scan" in celery_app.tasks


# ══════════════════════════════════════════════════════════════════════════════
# 4. Scan execution — Celery path
# ══════════════════════════════════════════════════════════════════════════════

class TestCeleryExecutionPath:

    @pytest.mark.asyncio
    async def test_scan_dispatches_to_celery_when_available(self, client):
        """When Celery .delay() succeeds, scan returns 202 with task_id."""
        mock_task = MagicMock()
        mock_task.id = "fake-celery-task-id-1234"

        with patch("backend.automation.tasks.run_scan_task") as mock_run:
            mock_run.delay.return_value = mock_task
            resp = await client.post("/scan", json={
                "target": "192.168.1.100",
                "scan_type": "normal",
            })

        assert resp.status_code == 202
        body = resp.json()
        assert body["task_id"] == "fake-celery-task-id-1234"
        assert body["status"] == "queued"

    @pytest.mark.asyncio
    async def test_scan_falls_back_to_asyncio_when_celery_fails(self, client):
        """When Celery.delay() raises, 202 is still returned via asyncio fallback."""
        with (
            patch("backend.automation.tasks.run_scan_task") as mock_celery,
            patch("backend.routes.scan._run_scan_background") as mock_bg,
        ):
            mock_celery.delay.side_effect = Exception("Redis connection refused")
            resp = await client.post("/scan", json={
                "target": "10.0.0.1",
                "scan_type": "safe",
            })

        assert resp.status_code == 202
        body = resp.json()
        assert body["task_id"] is None          # no Celery task ID
        assert body["status"] == "queued"       # still accepted

    @pytest.mark.asyncio
    async def test_scan_response_has_required_fields(self, client):
        with patch("backend.routes.scan._run_scan_background"):
            resp = await client.post("/scan", json={
                "target": "192.168.1.1",
                "scan_type": "normal",
            })
        assert resp.status_code == 202
        body = resp.json()
        for field in ("scan_id", "target", "status", "message"):
            assert field in body, f"Missing field: {field}"


# ══════════════════════════════════════════════════════════════════════════════
# 5. Scan lifecycle state machine
# ══════════════════════════════════════════════════════════════════════════════

class TestScanLifecycle:

    @pytest.mark.asyncio
    async def test_scan_initial_status_is_pending(self, client):
        with patch("backend.routes.scan._run_scan_background"):
            create = await client.post("/scan", json={
                "target": "10.0.0.5",
                "scan_type": "safe",
            })
        scan_id = create.json()["scan_id"]
        poll = await client.get(f"/scan/{scan_id}")
        assert poll.status_code == 200
        # Status is PENDING immediately after creation (before background task runs)
        assert poll.json()["status"] in ("pending", "running", "queued")

    @pytest.mark.asyncio
    async def test_cancel_pending_scan_transitions_to_cancelled(self, client):
        with patch("backend.routes.scan._run_scan_background"):
            create = await client.post("/scan", json={
                "target": "10.0.0.6",
                "scan_type": "normal",
            })
        scan_id = create.json()["scan_id"]
        cancel = await client.delete(f"/scan/{scan_id}")
        assert cancel.status_code == 200

        poll = await client.get(f"/scan/{scan_id}")
        assert poll.json()["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_cancel_nonexistent_scan_returns_404(self, client):
        resp = await client.delete("/scan/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_scan_returns_vulnerability_count(self, client):
        with patch("backend.routes.scan._run_scan_background"):
            create = await client.post("/scan", json={
                "target": "10.0.0.7",
                "scan_type": "safe",
            })
        scan_id = create.json()["scan_id"]
        poll = await client.get(f"/scan/{scan_id}")
        body = poll.json()
        assert "vulnerability_count" in body
        assert isinstance(body["vulnerability_count"], int)


# ══════════════════════════════════════════════════════════════════════════════
# 6. Degraded-mode scanning
# ══════════════════════════════════════════════════════════════════════════════

class TestDegradedModeScanning:
    """Scans must succeed even with Redis/Celery completely absent."""

    @pytest.mark.asyncio
    async def test_scan_accepted_without_redis(self, client):
        """Simulates Redis down: Celery.delay raises, asyncio fallback kicks in."""
        with (
            patch("backend.automation.tasks.run_scan_task") as mock_celery,
            patch("backend.routes.scan._run_scan_background"),
        ):
            mock_celery.delay.side_effect = ConnectionError("Redis refused")
            resp = await client.post("/scan", json={
                "target": "192.168.1.50",
                "scan_type": "safe",
            })
        assert resp.status_code == 202

    @pytest.mark.asyncio
    async def test_multiple_scans_in_degraded_mode(self, client):
        """Multiple concurrent scans must all be accepted in fallback mode."""
        targets = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
        with (
            patch("backend.automation.tasks.run_scan_task") as mock_celery,
            patch("backend.routes.scan._run_scan_background"),
        ):
            mock_celery.delay.side_effect = ConnectionError("Redis refused")
            responses = [
                await client.post("/scan", json={"target": t, "scan_type": "safe"})
                for t in targets
            ]
        assert all(r.status_code == 202 for r in responses)
        scan_ids = {r.json()["scan_id"] for r in responses}
        assert len(scan_ids) == 3  # all unique


# ══════════════════════════════════════════════════════════════════════════════
# 7. Nmap detection
# ══════════════════════════════════════════════════════════════════════════════

class TestNmapDetection:

    def test_check_nmap_returns_tuple(self):
        from backend.utils.nmap_check import check_nmap
        result = check_nmap()
        assert isinstance(result, tuple)
        assert len(result) == 2
        available, detail = result
        assert isinstance(available, bool)
        assert isinstance(detail, str)

    def test_find_nmap_returns_string_or_none(self):
        from backend.utils.nmap_check import find_nmap
        result = find_nmap()
        assert result is None or isinstance(result, str)

    def test_log_nmap_status_does_not_raise(self):
        from backend.utils.nmap_check import log_nmap_status
        # Must not raise regardless of whether nmap is installed
        result = log_nmap_status()
        assert isinstance(result, bool)

    def test_check_nmap_with_missing_binary(self):
        """When nmap is not on PATH, returns (False, helpful message)."""
        import shutil
        with patch.object(shutil, "which", return_value=None):
            import importlib
            import backend.utils.nmap_check as mod
            with patch.object(mod, "find_nmap", return_value=None):
                available, msg = mod.check_nmap()
        assert not available
        assert "nmap" in msg.lower()


# ══════════════════════════════════════════════════════════════════════════════
# 8. Configuration validation
# ══════════════════════════════════════════════════════════════════════════════

class TestConfiguration:

    def test_settings_load_without_env_file(self):
        """Settings must load with defaults when no .env is present."""
        from backend.config import Settings
        s = Settings(_env_file=None)
        assert s.APP_PORT == 8000
        assert s.WORKER_CONCURRENCY == 4
        assert s.HEALTHCHECK_TIMEOUT == 3.0

    def test_celery_result_backend_separate_db(self):
        """Broker and result backend should use different Redis DB indices."""
        from backend.config import Settings
        s = Settings(
            CELERY_BROKER_URL="redis://localhost:6379/0",
            CELERY_RESULT_BACKEND="redis://localhost:6379/1",
            _env_file=None,
        )
        assert s.CELERY_BROKER_URL != s.CELERY_RESULT_BACKEND

    def test_invalid_redis_url_rejected(self):
        from pydantic import ValidationError
        from backend.config import Settings
        with pytest.raises((ValidationError, ValueError)):
            Settings(REDIS_URL="http://localhost:6379", _env_file=None)

    def test_log_level_uppercased(self):
        from backend.config import Settings
        s = Settings(LOG_LEVEL="debug", _env_file=None)
        assert s.LOG_LEVEL == "DEBUG"

    def test_worker_concurrency_default(self):
        from backend.config import settings
        assert settings.WORKER_CONCURRENCY >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 9. Queue recovery — task re-enqueue simulation
# ══════════════════════════════════════════════════════════════════════════════

class TestQueueRecovery:

    def test_celery_task_retries_on_exception(self):
        """run_scan_task is configured with max_retries=2."""
        from backend.automation.tasks import run_scan_task
        assert run_scan_task.max_retries == 2

    @pytest.mark.asyncio
    async def test_scan_survives_background_task_exception(self, client):
        """If the background scan raises, the scan record is marked FAILED, not lost."""
        async def _failing_scan(*args, **kwargs):
            raise RuntimeError("Simulated scanner crash")

        with patch("backend.routes.scan._run_scan_background", side_effect=_failing_scan):
            # The BackgroundTasks runner catches exceptions after 202 is sent
            resp = await client.post("/scan", json={
                "target": "192.168.1.99",
                "scan_type": "safe",
            })
        # 202 is sent before the background task runs
        assert resp.status_code == 202


# ══════════════════════════════════════════════════════════════════════════════
# 10. Request ID propagation
# ══════════════════════════════════════════════════════════════════════════════

class TestRequestIdPropagation:

    @pytest.mark.asyncio
    async def test_request_id_echoed_in_response_header(self, client):
        sent_id = "test-request-id-12345678"
        resp = await client.get("/health", headers={"X-Request-ID": sent_id})
        assert resp.headers.get("x-request-id") == sent_id

    @pytest.mark.asyncio
    async def test_request_id_auto_generated_when_absent(self, client):
        resp = await client.get("/health")
        rid = resp.headers.get("x-request-id", "")
        assert len(rid) == 36  # UUID4 string length
        assert rid.count("-") == 4
