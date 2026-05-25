# INTEGRATION_REPORT.md — Frontend/Backend Integration (Phase 4)

> **Constraint**: Do NOT modify the Streamlit UI design. Only adjust API wiring
> and error rendering as required to make the frontend work against the fixed
> backend (Phases 2-3).

---

## 1. Issues Closed

| # | Ref | Issue | Fix |
|---|---|---|---|
| 1 | I1 (audit) | Dashboard hard-coded `http://localhost:8000`, ignored `API_BASE_URL` env var → frontend unreachable in Docker compose | [dashboard.py:59-63](frontend/dashboard.py#L59-L63) — read `API_BASE_URL` env var, fall back to localhost. Session-state override still works for the `⚙ SETTINGS` panel. |
| 2 | I4 (audit) | CORS allowlist missing `http://frontend:8501` (compose) and not env-configurable | [config.py](backend/config.py) added `CORS_ORIGINS` (list, env-overridable). [app.py:107](backend/app.py#L107) reads it instead of a hard-coded list. Default includes `http://frontend:8501` for docker-compose. |
| 3 | (audit §11) | `api_get` / `api_post` swallowed structured backend errors and showed generic `API error — <exc>` | [dashboard.py](frontend/dashboard.py) — added `_render_api_error()` that decodes the centralised backend envelope (`{"error", "detail", "request_id"}`) and renders 4xx/5xx with category-appropriate Streamlit widgets (warning vs error). Timeout and connection errors get explicit messages. |
| 4 | (related to R5/R7) | `/results/{id}` and `/vulnerabilities` returned 500 once any finding existed (Pydantic v2 `.from_orm` bug) | Already fixed in Phase 2 — the frontend now actually receives the JSON it expects. |
| 5 | (related to M1) | Dashboard polls `/health/full` every 30 s — could trip rate limiter under fast user navigation | Phase 2 added `/health/full` to rate-limiter excludes. |

---

## 2. Contract Verification

Each API call from `dashboard.py` was cross-checked against the corresponding route handler.

| Frontend call | Backend route | Expected shape | Status |
|---|---|---|---|
| `GET  /health` | `app.health` | `{"status":"ok","version":"..."}` | ✓ matches |
| `GET  /health/full` | `app.health_full` | `{"api","database","redis","celery","status"}` | ✓ matches |
| `GET  /results?per_page=N` | `results.list_results` | `List[ScanSummary]` with `scan_id, target, status, scan_type, started_at, completed_at, vulnerability_count, critical, high, medium, low, info` | ✓ matches |
| `GET  /results/{id}` | `results.get_full_result` | `FullScanResult` with `vulnerabilities: List[VulnSummary]`, `severity_counts: dict` | ✓ matches (now that Pydantic v2 fix is in) |
| `GET  /scan/{id}` | `scan.get_scan_status` | `ScanStatusResponse` with `scan_id, target, status, scan_type, port_range, adaptive_mode, started_at, completed_at, duration_seconds, vulnerability_count, error_message` | ✓ matches |
| `POST /scan` | `scan.initiate_scan` | `ScanResponse` with `scan_id, target, status, message, task_id` | ✓ matches |
| `GET  /vulnerabilities?…` | `vulnerabilities.list_vulnerabilities` | `List[VulnDetail]` | ✓ matches |
| `POST /reports/{id}` | `reports.generate_report` | `ReportResponse` with `report_id, scan_id, format, file_path, file_size_bytes, generated_at` | ✓ matches |
| `GET  /reports` | `reports.list_reports` | `List[ReportResponse]` | ✓ matches |

No frontend field is missing or renamed.

---

## 3. CORS Configuration

Default allowlist (extensible via env):

```
CORS_ORIGINS=http://localhost:8501,http://127.0.0.1:8501,http://localhost:3000,http://frontend:8501
```

In `docker-compose.yml` the `frontend` service is on the same `vuln_network` as `backend`, so
the browser-side fetches the dashboard at `http://localhost:8501` (host port mapping) — the
Streamlit page itself is served from the user's browser, and Streamlit's API calls go
*server-side* from the `frontend` container to `http://backend:8000` (via `API_BASE_URL`).
This means CORS is **not actually triggered** in the typical compose deployment — but it is
triggered when developers run the Streamlit dashboard outside Docker against a Dockerised
backend, hence the broader allowlist.

For a stricter deployment, set:

```bash
export CORS_ORIGINS="https://your-dashboard.example.com"
```

---

## 4. Error Rendering Improvements

Before:
```
API error — 500 Server Error: Internal Server Error for url: http://...
```

After (now driven by the backend's centralised envelope):
```
Backend error (500) — An unexpected error occurred. See server logs.
Request ID: 6b21a4ad-bf3c-4e0a-9d68-2bf17af83c4e
```

Categories rendered distinctly:
- **422** → `st.error("Validation error (422) …")` with the structured `detail` list and the original payload in an expander.
- **429** → `st.warning("Rate limited (429) — retry after Ns.")` reading the `Retry-After` header.
- **404** → `st.warning("Not found (404) — …")`.
- **5xx** → `st.error` with the `request_id` so the operator can grep the backend log.
- Network failures → explicit "API unreachable" / "API timeout" messages.

---

## 5. Loading / Polling States — already in place

The "NEW SCAN" page already implements a polling loop with 6-minute cap, a radar UI element,
a progress bar, and a final-status branch (`completed | failed | cancelled | timeout`). No
changes needed — the previous backend simply returned 500s that surfaced as "completed with
no findings". With Phase 2/3 fixes the polling now sees real `vulnerability_count` deltas.

---

## 6. Files Modified

| File | Lines | Change |
|---|---|---|
| [frontend/dashboard.py](frontend/dashboard.py) | 58-63 | Read `API_BASE_URL` env var. |
| [frontend/dashboard.py](frontend/dashboard.py) | 120-185 | Replaced `api_get` / `api_post` with structured-error variants; added `_render_api_error` helper. |
| [backend/config.py](backend/config.py) | (Phase 2) | New `CORS_ORIGINS` + `TRUST_PROXY_HEADERS` settings. |
| [backend/app.py](backend/app.py) | (Phase 2) | CORS middleware driven from `settings.CORS_ORIGINS`. |

**No UI markup, layout, page structure, theme, charts, or navigation changed.**

---

## 7. Verification Steps

```powershell
# 1. Backend
.\scripts\run.ps1 api
# Expect: "Database initialised." and "nmap available: ..." on stdout

# 2. Frontend (new terminal)
.\scripts\run.ps1 frontend
# Expect: Streamlit at http://localhost:8501

# 3. In the browser, hit the dashboard:
# - "DASHBOARD" page should show KPI row populated.
# - "NEW SCAN" with target 127.0.0.1, scan_type=safe → status transitions
#   queued → running → completed within ~30 s.
# - "VULNERABILITIES" page should render findings (previously 500'd here).

# 4. In Docker:
docker-compose up --build
# Backend on :8000, dashboard on :8501. The frontend container has
# API_BASE_URL=http://backend:8000 — dashboard.py now respects it.
```

---

*Phase 4 / 8 complete — proceeding to Phase 5 (Security hardening).*
