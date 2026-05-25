"""
FastAPI integration tests — IVDAF vulnerability scanner.

Runs against an in-memory SQLite database; no Celery or Redis required.
All scan background tasks are patched so the tests remain unit-speed.
"""
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch
from httpx import AsyncClient, ASGITransport

from backend.app import app
from backend.database.db import engine
from backend.config import settings

# Conftest.py sets DATABASE_URL=sqlite+aiosqlite:///:memory: before backend.*
# is imported, so the engine above is already pointed at in-memory SQLite.
assert settings.DATABASE_URL.endswith(":memory:"), (
    "Test isolation broken — DATABASE_URL was not overridden in conftest.py"
)


@pytest_asyncio.fixture(scope="function")
async def test_client():
    """Fresh in-memory database + ASGI test client per test function."""
    async with engine.begin() as conn:
        from backend.database.models import Base
        await conn.run_sync(Base.metadata.create_all)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    async with engine.begin() as conn:
        from backend.database.models import Base
        await conn.run_sync(Base.metadata.drop_all)


# ── Health ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health_ok(test_client):
    resp = await test_client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body


@pytest.mark.asyncio
async def test_root_ok(test_client):
    resp = await test_client.get("/")
    assert resp.status_code == 200
    assert "docs" in resp.json()


# ── Targets ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_targets_empty(test_client):
    resp = await test_client.get("/targets")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_add_private_target(test_client):
    resp = await test_client.post("/targets", json={
        "address": "192.168.1.100",
        "description": "DVWA test instance",
    })
    assert resp.status_code == 201
    body = resp.json()
    assert body["address"] == "192.168.1.100"
    assert "id" in body


@pytest.mark.asyncio
async def test_add_public_target_accepted(test_client):
    """Public IPs are now accepted by the validator (authorisation is the operator's responsibility)."""
    resp = await test_client.post("/targets", json={"address": "8.8.8.8"})
    assert resp.status_code == 201   # validator no longer blocks public IPs


@pytest.mark.asyncio
async def test_add_duplicate_target(test_client):
    await test_client.post("/targets", json={"address": "192.168.1.100"})
    resp = await test_client.post("/targets", json={"address": "192.168.1.100"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_delete_target(test_client):
    create = await test_client.post("/targets", json={"address": "10.0.0.1"})
    tid    = create.json()["id"]
    assert (await test_client.delete(f"/targets/{tid}")).status_code == 200


@pytest.mark.asyncio
async def test_delete_nonexistent_target(test_client):
    resp = await test_client.delete("/targets/does-not-exist")
    assert resp.status_code == 404


# ── POST /scan — validation ───────────────────────────────────────────────────

# Patch _run_scan_background so no real scan runs during API tests
_BG_PATCH = patch(
    "backend.routes.scan._run_scan_background",
    new_callable=lambda: lambda *a, **kw: None,  # no-op sync stub
)


@pytest.mark.asyncio
async def test_scan_valid_private_target(test_client):
    """Private IP with valid scan_type → 202 Accepted."""
    with patch("backend.routes.scan._run_scan_background"):
        resp = await test_client.post("/scan", json={
            "target":       "192.168.1.100",
            "scan_type":    "normal",
            "port_range":   "80,443",
            "adaptive_mode": False,
        })
    assert resp.status_code == 202
    body = resp.json()
    assert "scan_id" in body
    assert body["status"] == "queued"
    assert body["target"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_scan_valid_public_url(test_client):
    """Public URL (with fragment stripped) must be accepted → 202."""
    with patch("backend.routes.scan._run_scan_background"):
        resp = await test_client.post("/scan", json={
            "target":    "https://fastapi.tiangolo.com/#example-upgrade",
            "scan_type": "safe",
            "port_range": "443",
        })
    assert resp.status_code == 202
    body = resp.json()
    assert "scan_id" in body
    # Fragment must have been stripped
    assert "#" not in body["target"]


@pytest.mark.asyncio
async def test_scan_all_scan_types(test_client):
    """Each allowed scan_type must return 202."""
    for stype in ("normal", "safe", "stealth"):
        with patch("backend.routes.scan._run_scan_background"):
            resp = await test_client.post("/scan", json={
                "target":    "10.0.0.1",
                "scan_type": stype,
            })
        assert resp.status_code == 202, f"scan_type={stype!r} returned {resp.status_code}"


@pytest.mark.asyncio
async def test_scan_invalid_scan_type(test_client):
    """Unknown scan_type values must be rejected → 422."""
    for bad in ("nuclear", "full", "quick", "aggressive", ""):
        resp = await test_client.post("/scan", json={
            "target":    "10.0.0.1",
            "scan_type": bad,
        })
        assert resp.status_code == 422, f"scan_type={bad!r} should return 422, got {resp.status_code}"


@pytest.mark.asyncio
async def test_scan_empty_target(test_client):
    """Empty target string must return 422."""
    resp = await test_client.post("/scan", json={"target": ""})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_scan_invalid_port_range(test_client):
    """Malformed port range must return 422."""
    resp = await test_client.post("/scan", json={
        "target":     "192.168.1.1",
        "port_range": "not-a-port",
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_scan_port_range_out_of_bounds(test_client):
    resp = await test_client.post("/scan", json={
        "target":     "192.168.1.1",
        "port_range": "1-99999",
    })
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_scan_url_with_fragment(test_client):
    """URL fragment (#...) must be silently stripped, not cause a 422."""
    with patch("backend.routes.scan._run_scan_background"):
        resp = await test_client.post("/scan", json={
            "target": "http://192.168.1.1/page#section",
        })
    assert resp.status_code == 202


@pytest.mark.asyncio
async def test_scan_missing_target(test_client):
    """Request without 'target' field must return 422."""
    resp = await test_client.post("/scan", json={"scan_type": "normal"})
    assert resp.status_code == 422


# ── GET /scan/{id} ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_scan_status(test_client):
    with patch("backend.routes.scan._run_scan_background"):
        create = await test_client.post("/scan", json={
            "target":    "10.0.0.5",
            "scan_type": "safe",
        })
    scan_id = create.json()["scan_id"]
    resp    = await test_client.get(f"/scan/{scan_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["scan_id"] == scan_id
    assert body["status"] in ("pending", "queued", "running", "completed", "failed")


@pytest.mark.asyncio
async def test_get_nonexistent_scan(test_client):
    resp = await test_client.get("/scan/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


# ── DELETE /scan/{id} ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cancel_pending_scan(test_client):
    with patch("backend.routes.scan._run_scan_background"):
        create = await test_client.post("/scan", json={
            "target":    "10.0.0.6",
            "scan_type": "normal",
        })
    scan_id = create.json()["scan_id"]
    resp    = await test_client.delete(f"/scan/{scan_id}")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_cancel_nonexistent_scan(test_client):
    resp = await test_client.delete("/scan/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


# ── Results ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_results_empty(test_client):
    resp = await test_client.get("/results")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_list_results_status_filter_completed(test_client):
    resp = await test_client.get("/results?status=completed")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_list_results_invalid_status(test_client):
    resp = await test_client.get("/results?status=notastatus")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_get_full_result_not_found(test_client):
    resp = await test_client.get("/results/00000000-0000-0000-0000-000000000000")
    assert resp.status_code == 404


# ── Vulnerabilities ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_vulnerabilities_empty(test_client):
    resp = await test_client.get("/vulnerabilities")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_list_vulnerabilities_severity_filter(test_client):
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        resp = await test_client.get(f"/vulnerabilities?severity={sev}")
        assert resp.status_code == 200, f"severity={sev}"


@pytest.mark.asyncio
async def test_get_nonexistent_vulnerability(test_client):
    resp = await test_client.get("/vulnerabilities/nonexistent-id")
    assert resp.status_code == 404


# ── Reports ───────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_reports_empty(test_client):
    resp = await test_client.get("/reports")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_generate_report_scan_not_found(test_client):
    resp = await test_client.post(
        "/reports/00000000-0000-0000-0000-000000000000",
        json={"format": "json"},
    )
    assert resp.status_code == 404


# ── Validator unit tests ──────────────────────────────────────────────────────

def test_validate_target_accepts_private_ip():
    from backend.utils.validators import validate_target
    ok, _ = validate_target("192.168.1.1")
    assert ok


def test_validate_target_accepts_public_url():
    from backend.utils.validators import validate_target
    ok, _ = validate_target("https://fastapi.tiangolo.com/#example-upgrade")
    assert ok


def test_validate_target_strips_fragment():
    """validate_target should not reject a URL just because it has a fragment."""
    from backend.utils.validators import validate_target
    ok, _ = validate_target("https://example.com/#section")
    assert ok


def test_validate_target_rejects_empty():
    from backend.utils.validators import validate_target
    ok, reason = validate_target("")
    assert not ok
    assert "non-empty" in reason.lower()


def test_validate_port_range_valid():
    from backend.utils.validators import validate_port_range
    assert validate_port_range("1-1024")[0]
    assert validate_port_range("80,443,8080")[0]
    assert validate_port_range("22")[0]


def test_validate_port_range_invalid():
    from backend.utils.validators import validate_port_range
    assert not validate_port_range("0-1024")[0]    # port 0 invalid
    assert not validate_port_range("abc")[0]
    assert not validate_port_range("1-99999")[0]


# ── Rate limiting ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rate_limit_not_triggered_under_normal_load(test_client):
    for _ in range(5):
        resp = await test_client.get("/health")
        assert resp.status_code == 200
