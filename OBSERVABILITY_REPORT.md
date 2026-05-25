# OBSERVABILITY_REPORT.md — Phase 7

> **Goal**: Make the running system answerable to "is it healthy?", "what just
> happened?", and "where did time go?" — without external dependencies that
> haven't been requested.

---

## 1. Three pillars (current state)

| Pillar | Status | Surface |
|---|---|---|
| **Logs**   | ✓ Shipping | Console + rotating file; text or JSON; per-request `X-Request-ID` propagation via `contextvars` |
| **Metrics** | ✓ Added in Phase 7 | Prometheus exposition at `/metrics`; HTTP request counter / latency histogram; scan started/completed/duration; active-scan gauge; per-finding counter |
| **Audit**  | ✓ Shipping | Dedicated `ivdaf.audit` logger; emits to stderr **and** `LOGS_DIR/audit.log` (rotated, 10×10 MB) |
| **Traces** | ⚠ Not in scope | OpenTelemetry deferred — request-id already correlates logs across services. |

---

## 2. Structured logging

`backend/utils/logger.py`:
- Two formatters: `_TextFormatter` (human-readable) and `_JsonFormatter` (Loki/ELK).
- Toggled via `LOG_JSON=true` env var.
- Console + rotating file handlers (10 MB × 5 backups).
- Per-request `X-Request-ID` context variable injected at the middleware boundary
  (`backend/app.py:_request_middleware`) and rendered in every subsequent log line.
- Noisy third-party loggers (`httpx`, `urllib3`, `kombu`, …) clamped to WARNING
  in non-DEBUG mode.

**New in Phase 7**: `backend/utils/scan_logger.py` adds `scan_logger(base, scan_id=...)`
— a `LoggerAdapter` that binds `scan_id` and `target` to every emitted line.
This makes it trivial to correlate a 10-minute scan's logs without polluting
the base logger signature:

```python
from backend.utils.scan_logger import scan_logger
log = scan_logger(logger, scan_id=scan_id, target=target)
log.info("Phase 2: Reconnaissance")
# → "... | INFO | [scan_id=5d2a... target=127.0.0.1] Phase 2: Reconnaissance"
```

---

## 3. Audit log

`backend/utils/audit.py` (extended Phase 7):

- Dedicated logger `ivdaf.audit` — `propagate=False` so it never gets
  drowned in `DEBUG` noise.
- Handlers: stream (stderr) **plus** rotating file at `LOGS_DIR/audit.log`
  (10 MB × 10 backups).
- Events emitted:
  - `event=scan_requested  scan_id=... target=... scan_type=... client_ip=...`
  - `event=scan_started    scan_id=... target=...`
  - `event=scan_completed  scan_id=... target=... findings=N duration_s=12.3`
  - `event=scan_failed     scan_id=... target=... error="..."`
  - `event=report_generated scan_id=... fmt=pdf path=...`

Grep-friendly: `grep "event=scan_failed" logs/audit.log` produces a
chronological list of every failed scan and its proximate cause.

For long-term retention, ship `audit.log` to a WORM bucket (S3 object lock,
Loki immutable streams, etc.). The rotation policy keeps ~100 MB of
recent history on the local volume.

---

## 4. Metrics — `/metrics`

`backend/utils/metrics.py` exposes Prometheus exposition. The module is
soft-dependent on `prometheus_client`; if the package is absent the metric
objects collapse to no-ops so the rest of the backend keeps running.

| Metric | Type | Labels | Purpose |
|---|---|---|---|
| `ivdaf_http_requests_total` | Counter | `method`, `path`, `status` | HTTP traffic mix |
| `ivdaf_http_request_duration_seconds` | Histogram | `method`, `path` | API latency SLO |
| `ivdaf_scans_started_total` | Counter | `scan_type`, `execution_path` | Throughput per scan type / Celery-vs-asyncio split |
| `ivdaf_scans_completed_total` | Counter | `scan_type`, `status` | Success vs failure ratio |
| `ivdaf_scan_duration_seconds` | Histogram | `scan_type` | Scan wall-clock distribution |
| `ivdaf_active_scans` | Gauge | — | Concurrency live counter |
| `ivdaf_detector_findings_total` | Counter | `vuln_type`, `severity` | Finding mix over time |

**Cardinality note**: `path` is taken from the matched route template
(`/scan/{scan_id}` not `/scan/5d2a...`) to bound label cardinality. Verified
in `backend/app.py:_request_middleware`.

`/metrics` is excluded from rate-limiting and from OpenAPI schema generation.

### 4.1 Scrape config example (Prometheus)

```yaml
scrape_configs:
  - job_name: ivdaf
    scrape_interval: 15s
    static_configs:
      - targets: ['backend:8000']
```

### 4.2 Sample Grafana alerts

- `rate(ivdaf_http_requests_total{status=~"5.."}[5m]) > 0.5` — 5xx burst
- `rate(ivdaf_scans_completed_total{status="failed"}[10m]) / rate(ivdaf_scans_completed_total[10m]) > 0.2` — scan failure ratio
- `histogram_quantile(0.95, sum by (le) (rate(ivdaf_http_request_duration_seconds_bucket[5m]))) > 1` — p95 latency over 1 s

---

## 5. Health endpoints (Phase 2 + 7)

| Endpoint | Purpose | Latency target | Returns |
|---|---|---|---|
| `/health` | Kubernetes liveness probe | < 5 ms | `{"status":"ok"}` always |
| `/health/full` | Readiness probe | < timeout (3 s default) | per-subsystem state + overall `healthy/degraded/unhealthy` |
| `/metrics` | Prometheus scrape | < 50 ms | exposition format |

Subsystem checks in `/health/full`:
- `api`: always `"healthy"` if the process is responsive.
- `database`: `SELECT 1` round-trip inside `asyncio.wait_for(..., timeout=3)`.
- `redis`: `redis.asyncio.from_url(...).ping()` with 2 s socket timeout.
- `celery`: `inspect(timeout=1.5).ping()` in a thread executor.

---

## 6. Request tracing (without OpenTelemetry)

Every request gets:
- `X-Request-ID` header (echoed back; auto-generated if absent).
- `X-Response-Time` header in milliseconds.
- `contextvars`-propagated request-ID into every log line in the request's call tree.

For multi-service correlation, set up your reverse proxy to inject a known
header (e.g. nginx's `$request_id`) and the backend will adopt it. The same ID
flows into the audit log automatically.

---

## 7. What's deliberately not added

| Item | Why deferred |
|---|---|
| OpenTelemetry traces | Requires an OTLP collector and is heavyweight for the current scale. Logs + request-id already give end-to-end correlation. |
| Sentry error reporting | Adds external dependency + secret. Logging-only path is sufficient until the operator opts in. |
| Slack / PagerDuty webhooks | Alerting belongs in Grafana/Prometheus — not in-app. |
| OpenTelemetry exporter for Celery | If/when traces are added, instrument both `routes/*` and `automation/tasks.py` together. |

---

## 8. Files changed in this phase

| File | Change |
|---|---|
| [backend/utils/metrics.py](backend/utils/metrics.py) | NEW — Prometheus metric definitions with no-op fallback when `prometheus_client` is absent. |
| [backend/utils/scan_logger.py](backend/utils/scan_logger.py) | NEW — `LoggerAdapter` binding `scan_id` + `target`. |
| [backend/utils/audit.py](backend/utils/audit.py) | Added rotating file handler at `LOGS_DIR/audit.log`. |
| [backend/app.py](backend/app.py) | Mounted `/metrics` route; request middleware records `HTTP_REQUESTS` + `HTTP_LATENCY`. |
| [backend/middleware/rate_limiter.py](backend/middleware/rate_limiter.py) | `/metrics` added to exclude list. |
| [backend/routes/scan.py](backend/routes/scan.py) | Increments `SCANS_STARTED` counter at dispatch. |
| [backend/automation/tasks.py](backend/automation/tasks.py) | `ACTIVE_SCANS`, `SCANS_COMPLETED`, `SCAN_DURATION`, `DETECTOR_FINDINGS`. |
| [requirements.txt](requirements.txt), [pyproject.toml](pyproject.toml) | Added `prometheus_client>=0.20.0`. |

---

## 9. Verification

```powershell
# 1. Restart the backend
.\scripts\run.ps1 api

# 2. Hit a few endpoints
Invoke-RestMethod http://localhost:8000/health
Invoke-RestMethod http://localhost:8000/health/full
$body = @{target="127.0.0.1"; scan_type="safe"; port_range="22,80"} | ConvertTo-Json
Invoke-RestMethod -Method POST http://localhost:8000/scan `
    -ContentType "application/json" -Body $body | Out-Null

# 3. Scrape metrics
Invoke-WebRequest http://localhost:8000/metrics |
    Select-Object -ExpandProperty Content |
    Select-String -Pattern "ivdaf_"
# Expect counters: ivdaf_http_requests_total{...}, ivdaf_scans_started_total{...}, etc.

# 4. Tail the audit log
Get-Content .\logs\audit.log -Tail 20
```

---

*Phase 7 / 8 complete — proceeding to Phase 8 (Deployment).*
