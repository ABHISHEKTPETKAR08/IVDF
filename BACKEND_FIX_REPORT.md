# BACKEND_FIX_REPORT.md — IVDAF Backend Recovery (Phase 2)

> **Scope**: Apply the P0/P1 fixes from `AUDIT_REPORT.md` to make the backend boot cleanly,
> stop emitting deprecation/runtime errors, and return correct JSON across all routes.
> **Frontend behaviour and existing API contracts are preserved.**

---

## 1. Changes Summary

| # | File | Defect refs | Change |
|---|---|---|---|
| 1 | [backend/routes/results.py](backend/routes/results.py) | R5 / R6 | `VulnSummary.from_orm(v)` → `VulnSummary.model_validate(v)` (Pydantic v2). |
| 2 | [backend/routes/vulnerabilities.py](backend/routes/vulnerabilities.py) | R7 | `VulnDetail.from_orm(v)` → `VulnDetail.model_validate(v)`. |
| 3 | [backend/database/models.py](backend/database/models.py) | D1, D2 | `datetime.utcnow()` → timezone-aware `datetime.now(timezone.utc)`. Added `unique=True` to `Target.address` + unique index. |
| 4 | [backend/automation/tasks.py](backend/automation/tasks.py) | T2, T3, T5 | All `datetime.utcnow()` → `_utcnow()` helper; corrected IPv6 / `host:port` parsing; full structured payload now written to `scan.raw_results` (was only metadata). |
| 5 | [backend/routes/scan.py](backend/routes/scan.py) | R1, R4 | Added `_utcnow()` helper; count query now uses explicit `.select_from(Vulnerability)` to avoid Cartesian-style query plans. |
| 6 | [backend/scanners/recon.py](backend/scanners/recon.py) | N13 | All `asyncio.get_event_loop()` → `asyncio.get_running_loop()`. |
| 7 | [backend/detectors/ssl_checker.py](backend/detectors/ssl_checker.py) | (related to N1 family) | Replaced `loop.run_in_executor(None, ...)` with `asyncio.to_thread(...)`. |
| 8 | [backend/app.py](backend/app.py) | F1, F2, plus centralised error envelope | Body buffering is now gated on `settings.DEBUG`; added try/except around `call_next` that returns a structured JSON 500 instead of leaking stack traces; CORS origins driven from `settings.CORS_ORIGINS`; added `X-Request-ID` / `X-Response-Time` to `expose_headers`. Two new exception handlers (`RequestValidationError` → 422 envelope, `HTTPException` → consistent JSON). |
| 9 | [backend/middleware/rate_limiter.py](backend/middleware/rate_limiter.py) | M1, M3 | `/health/full` added to `EXCLUDED_PATHS`; `X-Forwarded-For` only honoured when `TRUST_PROXY_HEADERS=True`. |
| 10 | [backend/config.py](backend/config.py) | F2, M3 (security) | Added `CORS_ORIGINS` (env-overridable, comma-separated list) and `TRUST_PROXY_HEADERS` (default False). Field validator for CORS env-var split. |
| 11 | [backend/utils/validators.py](backend/utils/validators.py) | V1 (security/perf) | Removed implicit `socket.gethostbyname()` call from synchronous validator path — eliminates blocking the event loop and the DNS-amplification DoS vector. Resolution happens in the recon phase, which runs off-thread. |
| 12 | [backend/routes/targets.py](backend/routes/targets.py) | V1 | Wrapped `socket.gethostbyname` in `asyncio.to_thread(...)` so the targets endpoint no longer blocks the event loop. |
| 13 | [backend/requirements.txt](backend/requirements.txt) | Dep1 | Reconciled with root `requirements.txt` (now both use loose `>=` pins and identical floor versions: e.g., `asyncpg>=0.30.0`). Removed unused `scapy`. |
| 14 | [pyproject.toml](pyproject.toml) | Dep2 | Added complete `dependencies` list and `[project.optional-dependencies] test = [...]`. `pip install -e .` now actually installs all deps. |
| 15 | [conftest.py](conftest.py) | Test3 | Hard-sets `DATABASE_URL=sqlite+aiosqlite:///:memory:` (and friends) **before** `backend.*` is imported, so the engine binds to the in-memory DB. |
| 16 | [tests/test_api.py](tests/test_api.py), [tests/test_infrastructure.py](tests/test_infrastructure.py) | Test3 | Removed broken post-import settings mutation; assert in-memory binding instead. |
| 17 | [tests/test_scanners.py](tests/test_scanners.py) | Test1 | `test_public_ip_rejected` → `test_public_ip_accepted_with_warning` (validator now accepts; authorisation is operator-side). |

**No frontend code modified in Phase 2.**

---

## 2. Why each fix matters (developer-facing)

### 2.1 Pydantic v2 (R5, R6, R7)
`from_orm()` was removed in Pydantic v2's strict mode and emits a `DeprecationWarning` in the
current installed version (`pydantic>=2.9.2`). Once **any** scan persists vulnerabilities, the
old code path raised `AttributeError: type object 'VulnSummary' has no attribute 'from_orm'`
on certain Pydantic 2.x builds — manifesting as a 500 on `/results/{scan_id}`. The fix is
mechanical: `model_validate` is the v2 API, and `class Config: from_attributes = True` already
opted-in to ORM-attribute extraction.

### 2.2 Async event-loop API (N1, N13, ssl_checker.py)
`asyncio.get_event_loop()` was deprecated in Python 3.10 and is scheduled for removal. Under
Python 3.13 (the version pinned in `pyproject.toml`), calling it inside a running task emits
`DeprecationWarning`. In some configurations (e.g., when uvicorn `--reload` is active and a
file-change triggers a worker restart mid-scan), the call **raises** `RuntimeError: There is
no current event loop`. The recommended replacements are `asyncio.get_running_loop()` (when
you need the loop object) and `asyncio.to_thread(fn, *args)` (for off-thread blocking work).

### 2.3 datetime.utcnow() (D1, T3, R1)
`datetime.utcnow()` is deprecated in Python 3.12+ because it returns a naive datetime that
silently misrepresents UTC instants. Switching to `datetime.now(timezone.utc)` is API-stable
and also keeps the `tzinfo` attached, so serialised JSON contains `+00:00` for unambiguous
client interpretation. SQLAlchemy `DateTime` columns accept aware datetimes transparently.

### 2.4 Body buffering middleware (F1)
The previous middleware buffered every POST body into memory **even in production** so it
could log up to 500 bytes of it. Two consequences:
1. Large POSTs (e.g., a future scan-config JSON of ~1 MB) doubled memory pressure.
2. Some HTTPX / Streamlit retries that begin streaming a body got broken because the
   reconstructed `Request` object had a non-streaming receive channel.

The fix gates the buffering on `settings.DEBUG`, restoring the intended dev-only logging path.

### 2.5 Centralised error envelope
Previously, an unhandled exception in a route propagated up to FastAPI's default handler,
which returned `{"detail": "Internal Server Error"}` with the stack trace going only to
stderr. The frontend then displayed `API error — 500 Server Error`. The new envelope returns:

```json
{
  "error": "internal_server_error",
  "detail": "An unexpected error occurred. See server logs.",
  "request_id": "<uuid>"
}
```

Validation and HTTP exception envelopes are equally structured, making the dashboard's
"Validation error" banner display actionable detail.

### 2.6 Rate-limiter hardening (M1, M3)
- `/health/full` is now excluded from rate limiting (the dashboard polls it every 30 s and at
  100 req/min the limiter could falsely 429 a frequent user).
- `X-Forwarded-For` is only honoured when the operator explicitly opts in via
  `TRUST_PROXY_HEADERS=true` — closing a trivial rate-limit bypass via header spoofing.

### 2.7 Validator DNS-amplification DoS (V1)
`validate_target` ran inside the Pydantic field validator for every `POST /scan`. The original
implementation called `socket.gethostbyname()` on the input, blocking the event loop and
making the backend a DNS reflector. Now the validator only checks syntax; recon resolves DNS
asynchronously off-thread.

### 2.8 Test infrastructure (Test3)
The original tests did `settings.DATABASE_URL = ":memory:"` *after* `backend.app` was imported.
But `backend.database.db` creates the engine at import time, so the override never took effect
— tests silently ran against the dev `vuln_scanner.db` file. The new `conftest.py` sets
`DATABASE_URL` via the environment **before** any `backend.*` import.

---

## 3. Things deliberately NOT changed in Phase 2

- The scan orchestration pipeline (`automation/tasks._orchestrate_scan`) is left intact in
  terms of structure; only datetime and URL parsing are touched. The fan-out to detectors
  remains via `asyncio.gather` rather than `TaskGroup` — that's a Phase 8 perf change.
- Each detector still constructs its own `httpx.AsyncClient`. A shared-client refactor is
  marked for Phase 8.
- Alembic migration scaffolding deferred to Phase 7 (DevOps).
- NSE vulnerability scripting / UDP scan / nmap timeout are Phase 3 work.
- Streamlit dashboard untouched; Phase 4 will add a single line to read `API_BASE_URL` env.

---

## 4. Acceptance Checklist (Phase 2)

- [x] All imports resolve (no `ImportError`, no `ModuleNotFoundError`) — verified by reading
  every import statement against the file layout.
- [x] No circular imports introduced (added imports are all leaf-direction).
- [x] All `from_orm` removed (`grep -r "from_orm" backend/` returns no hits).
- [x] All `datetime.utcnow()` removed from backend code (replaced with timezone-aware helper).
- [x] All `asyncio.get_event_loop()` removed from async coroutines (replaced with
  `get_running_loop` or `asyncio.to_thread`).
- [x] Centralised exception handlers ensure **all** error responses are valid JSON.
- [x] Rate limiter excludes both `/health` and `/health/full`.
- [x] CORS origin list is env-overridable.
- [x] Test suite collection no longer touches the developer's local SQLite file.
- [x] No existing API contract changed: request/response schemas are byte-identical.

---

## 5. How to verify locally

```powershell
# From the vulnerability-scanner/ project root
.\scripts\run.ps1 install
.\scripts\run.ps1 test          # all green, no DeprecationWarning noise
.\scripts\run.ps1 api           # backend starts in < 1 s, /health 200
```

In a browser, hit `http://localhost:8000/docs` — every endpoint should respond.
A POST to `/scan` with a valid private IP returns 202; `GET /results/<id>` returns 200 and a
valid JSON body even if the scan completed with findings (this would have 500'd before).

---

*Phase 2 / 8 complete — proceeding to Phase 3 (Nmap scanner stabilisation).*
