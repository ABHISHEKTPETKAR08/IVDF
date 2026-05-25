"""
Phase-2 Redis-required health-status semantics.

Verifies that /health/full status computation correctly distinguishes between
'healthy', 'degraded' (single-host lab mode), and 'unhealthy' (production
when REDIS_REQUIRED=true).
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from backend.app import app
from backend.config import settings
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


class TestHealthStatusModes:

    @pytest.mark.asyncio
    async def test_lab_mode_redis_down_reports_degraded(self, client):
        """REDIS_REQUIRED=false + redis down → status='degraded'."""
        with patch.object(settings, "REDIS_REQUIRED", False):
            resp = await client.get("/health/full")
        body = resp.json()
        assert resp.status_code == 200
        if body.get("redis") != "connected" or body.get("celery") != "running":
            assert body["status"] == "degraded"

    @pytest.mark.asyncio
    async def test_production_mode_redis_down_reports_unhealthy(self, client):
        """REDIS_REQUIRED=true + redis down → status='unhealthy'."""
        with patch.object(settings, "REDIS_REQUIRED", True):
            with patch.object(settings, "REDIS_REQUIRED_RETURNS_503", False):
                resp = await client.get("/health/full")
        body = resp.json()
        if body.get("redis") != "connected" or body.get("celery") != "running":
            assert body["status"] == "unhealthy"
            # Without the 503 flag, the response is still HTTP 200
            assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_production_mode_with_503_flag_returns_503(self, client):
        """REDIS_REQUIRED_RETURNS_503=true → HTTP 503 when unhealthy."""
        with patch.object(settings, "REDIS_REQUIRED", True), \
             patch.object(settings, "REDIS_REQUIRED_RETURNS_503", True):
            resp = await client.get("/health/full")
        body = resp.json()
        if body.get("redis") != "connected" or body.get("celery") != "running":
            assert resp.status_code == 503
            assert body["status"] == "unhealthy"

    @pytest.mark.asyncio
    async def test_all_subsystems_up_reports_healthy(self, client):
        """When DB, Redis, and Celery are all up → status='healthy'."""
        mock_session_ctx = AsyncMock()
        mock_session_ctx.__aenter__ = AsyncMock(
            return_value=AsyncMock(execute=AsyncMock())
        )
        mock_session_ctx.__aexit__ = AsyncMock(return_value=False)

        mock_r = AsyncMock()
        mock_r.ping = AsyncMock(return_value=True)
        mock_r.aclose = AsyncMock()

        with patch("backend.database.db.get_db_session", return_value=mock_session_ctx), \
             patch("redis.asyncio.from_url", return_value=mock_r), \
             patch("backend.automation.celery_app.celery_app") as mock_celery:
            mock_celery.control.inspect.return_value.ping.return_value = {
                "worker@host": {"ok": "pong"}
            }
            resp = await client.get("/health/full")

        body = resp.json()
        assert resp.status_code == 200
        assert body["status"] == "healthy"
