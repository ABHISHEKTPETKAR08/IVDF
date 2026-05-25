# AUDIT_REPORT.md — IVDAF Backend Audit (Current State)

> **Refreshed**: 2026-05-24 — supersedes the initial Phase 1 audit.
> **Constraint**: Do NOT redesign the frontend; only adjust API wiring as required.

---

## 0. How to read this document

This is the **current-state audit** of the backend. Several rounds of fixes have
already shipped — those defects are listed under §3 "Resolved" with cross-refs
to the report that closed them. Open work is in §4 with a phase map matching
the new 8-phase plan.

---

## 1. Executive Summary

The backend is **structurally healthy and bootable**. The remaining work is
operational (Redis/Celery wiring), test coverage, observability, and deployment
polish — not bug-fixing.

| Layer | State | Notes |
|---|---|---|
| FastAPI app + lifespan | ✓ Healthy | Boots <1 s; `/health` returns 200 in <5 ms. |
| Routers (5 files) | ✓ Healthy | Pydantic v2-correct; centralised error envelopes. |
| Middleware (rate limit + request id) | ✓ Healthy | `/health` and `/health/full` excluded from RL. |
| Database (SQLAlchemy async) | ✓ Healthy | SQLite default; `init_db()` idempotent; unique index on `Target.address`. |
| Nmap scanner | ✓ Stabilised | Timeout, retry, privilege-aware, NSE-opt-in, normalised result. |
| HTTP detectors (8) | ✓ Working | Each catches `httpx.RequestError`; OWASP+CVSS mapped. |
| Explanation layer | ✓ Working | Now produces plain-English `non_technical` field. |
| Audit logging | ✓ Added | `ivdaf.audit` channel — `scan_requested|started|completed|failed|report_generated`. |
| Frontend wiring | ✓ Fixed | Reads `API_BASE_URL` env; structured error renderer. |
| **Redis** | ⚠ Optional, currently absent | Asyncio fallback handles scans without it — see §4.1. |
| **Celery** | ⚠ Optional, currently absent | Same — see §4.1. |
| Tests | ⚠ ~60% coverage | Target 90% — see §4.2. |
| Observability | ⚠ Logs only | No `/metrics`, no tracing — see §4.3. |
| Deployment | ⚠ Compose exists, needs polish | Secrets, Flower auth, env.example diff — see §4.4. |

Health endpoint sample (current state on a machine with no Redis):

```json
{
  "api":      "healthy",
  "database": "connected",
  "redis":    "unavailable",
  "celery":   "timeout",
  "status":   "degraded",
  "version":  "1.0.0"
}
```

> **The "degraded" label is by design**, not a defect — it correctly tells the
> operator that the *optional* async infrastructure (Redis/Celery) is offline,
> while confirming the *required* infrastructure (API + DB) is up. Scans run via
> `FastAPI BackgroundTasks` in this mode and complete successfully.

---

## 2. Module inventory

```
backend/
├── app.py                      ✓ — lifespan, CORS env-driven, error handlers
├── config.py                   ✓ — pydantic-settings; env-overridable CORS, etc.
├── routes/
│   ├── scan.py                 ✓ — fast-fail Celery dispatch (2 s wrap)
│   ├── results.py              ✓ — Pydantic v2 model_validate
│   ├── reports.py              ✓ — path-traversal guard on download
│   ├── targets.py              ✓ — async DNS off-thread
│   └── vulnerabilities.py      ✓ — model_validate
├── scanners/
│   ├── port_scanner.py         ✓ — rewritten Phase 3
│   └── recon.py                ✓ — get_running_loop migration
├── detectors/                  ✓ — 8 detectors, all return List[VulnerabilityFinding]
├── ai_explanations/explainer.py ✓ — plain-English layer added
├── remediation/                ✓
├── reports/                    ✓
├── automation/
│   ├── celery_app.py           ✓ — production-grade config
│   └── tasks.py                ✓ — _utcnow helper, IPv6 parsing, NSE→finding,
│                                     service→finding, structured raw_results
├── middleware/rate_limiter.py  ✓ — XFF gated on TRUST_PROXY_HEADERS
├── database/
│   ├── db.py                   ✓ — StaticPool for SQLite async
│   └── models.py               ✓ — timezone-aware datetime, unique address
└── utils/
    ├── logger.py               ✓ — text + JSON, request-id ctxvar
    ├── nmap_check.py           ✓ — PATH + Windows defaults probe
    ├── validators.py           ✓ — no sync DNS, allowlist regex
    └── audit.py                ✓ NEW — dedicated audit channel
```

---

## 3. Resolved Issues (from prior audit + fix rounds)

| # | Symptom | Root cause | Fix location | Closed in |
|---|---|---|---|---|
| 1 | 500 on `/results/{id}` and `/vulnerabilities` once findings exist | Pydantic v2 deprecated `.from_orm()` still called | `routes/results.py`, `routes/vulnerabilities.py` — `model_validate` | BACKEND_FIX_REPORT.md |
| 2 | `POST /scan` hung for ~30 s when Redis down | Celery `.delay()` retries broker for `retry_policy.timeout=30` | `routes/scan.py` — `asyncio.wait_for(asyncio.to_thread(apply_async, retry=False), 2.0)` | this round (latest) |
| 3 | Nmap silent failures, hangs, no retry | Missing timeout, blocking `get_event_loop`, no privilege gate | `scanners/port_scanner.py` rewritten | SCANNER_REVIEW.md |
| 4 | Frontend cannot reach backend in Docker | Hard-coded `http://localhost:8000`; ignored `API_BASE_URL` env | `frontend/dashboard.py` | INTEGRATION_REPORT.md |
| 5 | CORS allowlist hard-coded, missing compose origin | Inline list in `app.py` | `config.py` `CORS_ORIGINS` (env-overridable), `app.py` reads it | INTEGRATION_REPORT.md |
| 6 | Validator did sync DNS → DoS, event-loop block | `socket.gethostbyname` inside Pydantic field validator | `utils/validators.py` — DNS removed | SECURITY_REPORT.md |
| 7 | XFF spoofable rate-limit bypass | Trusted unconditionally | `middleware/rate_limiter.py` + `TRUST_PROXY_HEADERS` | SECURITY_REPORT.md |
| 8 | Path traversal possible on report download | No realpath check | `routes/reports.py` realpath + REPORTS_DIR guard | SECURITY_REPORT.md |
| 9 | `datetime.utcnow()` deprecated everywhere | Python 3.12+ deprecation | `_utcnow` helpers + timezone-aware now | BACKEND_FIX_REPORT.md |
| 10 | `asyncio.get_event_loop()` deprecated in async code | Python 3.13 emits DeprecationWarning | `get_running_loop` / `asyncio.to_thread` | BACKEND_FIX_REPORT.md |
| 11 | Test infra silently used dev DB file | Settings mutated after engine import | `conftest.py` — env hard-set before any `backend.*` import | BACKEND_FIX_REPORT.md |
| 12 | `pip install -e .` installed nothing | `pyproject.toml` had no `dependencies` | `pyproject.toml` full deps list | BACKEND_FIX_REPORT.md |
| 13 | `requirements.txt` mismatch (asyncpg pin) | Two files diverged | Reconciled to floor pins | BACKEND_FIX_REPORT.md |
| 14 | `run.ps1` parser errors on Windows PS 5.1 | Box-drawing UTF-8 chars mis-decoded as CP1252 | `scripts/run.ps1` rewritten ASCII-only | this round (latest) |
| 15 | `install_nmap.ps1` blocked by `#Requires -RunAsAdministrator` | winget self-elevates anyway | `scripts/install_nmap.ps1` — directive removed | this round (latest) |
| 16 | Vulnerability cards too technical for non-experts | No plain-English layer | `ai_explanations/explainer.py` `_PLAIN`+`_SEVERITY_BLURB`; `ui_components.vulnerability_card` "What this means" banner | latest UI tweak |
| 17 | Nmap service-detection results not surfaced | `tasks.py` only emitted findings for dangerous-port matches | `tasks.py` adds INFO-level `Open Service Detected` finding per nmap-discovered service | latest UI tweak |
| 18 | Body-buffering middleware ran in production | Unconditional buffer of POST body | `app.py` middleware gated on `settings.DEBUG` | BACKEND_FIX_REPORT.md |

**Cross-refs**: [BACKEND_FIX_REPORT.md](BACKEND_FIX_REPORT.md), [SCANNER_REVIEW.md](SCANNER_REVIEW.md), [INTEGRATION_REPORT.md](INTEGRATION_REPORT.md), [SECURITY_REPORT.md](SECURITY_REPORT.md).

---

## 4. Open Work (mapped to new 8-phase plan)

### 4.1 Phase 2 — Redis/Celery analysis  (next deliverable)

**Question to answer**: are Redis/Celery *required*, or should we simplify to
FastAPI `BackgroundTasks`?

Evidence to compile in `REDIS_CELERY_ANALYSIS.md`:

- Current scan pipeline already runs to completion via `BackgroundTasks` fallback
  (`_run_scan_background` in `routes/scan.py`).
- The Celery path adds:
  - Distributed worker scale-out (multiple worker processes / hosts).
  - Survival across API process restarts (queued tasks resume).
  - Per-task retry with broker-backed durability.
  - Flower visibility into live tasks.
- For the project's stated scope (single-host lab tool), `BackgroundTasks` is
  sufficient and removes an entire infra dependency.
- For a multi-tenant / production deployment, Celery is justified.

**Recommendation (to be confirmed in REDIS_CELERY_ANALYSIS.md)**: keep both
paths (current dual implementation) — degraded mode is a feature, not a bug.
Provide clear "how to enable Redis/Celery" instructions. Add a one-line
docker-compose helper so the operator can flip it on with `docker-compose up redis celery_worker`.

### 4.2 Phase 6 — Testing

Current state: `tests/test_api.py`, `test_detectors.py`, `test_scanners.py`,
`test_infrastructure.py` exist. Estimated coverage ~60%.

Gaps to close:
- Scanner integration paths with mocked `nmap.PortScanner` return data.
- `_orchestrate_scan` end-to-end with mocked detectors.
- Path traversal guard on `/reports/{id}/download`.
- Plain-English explainer enrichment.
- Fast-fail Celery dispatch (2 s wait_for) — assert the timeout path uses asyncio fallback.

Deliverable: `TESTING_REPORT.md` + new test files.

### 4.3 Phase 7 — Observability

Currently shipping:
- Structured text+JSON logs (`utils/logger.py`).
- Per-request `X-Request-ID` in headers and log lines.
- Dedicated `ivdaf.audit` channel (file: `logs/audit.log` recommended).
- `/health` (liveness) + `/health/full` (readiness w/ per-subsystem status).

Not yet shipping:
- Prometheus `/metrics` endpoint (request counts, scan duration histograms,
  detector latencies).
- OpenTelemetry tracing.
- A separate file sink for the audit channel (currently still goes to stderr).

Deliverable: `OBSERVABILITY_REPORT.md` + `/metrics` endpoint + file-handler split.

### 4.4 Phase 8 — Deployment polish

Currently shipping:
- `docker/Dockerfile`, `docker/Dockerfile.frontend`.
- `docker-compose.yml` with postgres, redis, backend, celery_worker, flower, frontend.
- `.env.example`, `scripts/run.ps1`, `scripts/setup.sh`.

Open items:
- Postgres credentials hard-coded `scanner:scanner` — substitute `${POSTGRES_PASSWORD}`.
- Flower exposed on `:5555` with no auth — add basic-auth.
- No Alembic migration scaffolding — `init_db()` is `create_all` only.
- `docker-compose.override.yml` for dev source-mount missing.
- `setcap cap_net_raw=eip /usr/bin/nmap` in Dockerfile would let unprivileged
  container do SYN scans (the privilege gate currently downgrades to TCP connect).

Deliverable: `DEPLOYMENT_GUIDE.md` + Dockerfile/compose edits.

---

## 5. Detect-only checklist (from the new plan's Phase 1)

| Class | Found? | Notes |
|---|---|---|
| ModuleNotFoundError | None | All imports resolve against the current layout. |
| ImportError | None | No removed symbols still imported. |
| Circular imports | None | Import graph is a DAG (verified by reading every `from backend.*` line). |
| Missing dependencies | None | `pyproject.toml dependencies` now mirrors `requirements.txt`. |
| Route failures | None | All 5 routers register cleanly under `/scan, /results, /reports, /targets, /vulnerabilities`. |
| Startup issues | None | Lifespan completes in <1 s. |
| Runtime exceptions | None at idle | Errors only occur per request, then funnelled through the global exception handler envelope. |
| Schema mismatches | None | Frontend↔backend contract was verified field-by-field in INTEGRATION_REPORT.md §2. |

---

## 6. Acceptance for Phase 1

- [x] Module inventory enumerated (§2).
- [x] Resolved-issue ledger compiled with traceability to closing report (§3).
- [x] Open work scoped + assigned to remaining phases (§4).
- [x] Detect-only checklist completed (§5).
- [x] No code modified during this audit refresh.

---

*Phase 1 (refresh) complete — next deliverable: `REDIS_CELERY_ANALYSIS.md`.*
