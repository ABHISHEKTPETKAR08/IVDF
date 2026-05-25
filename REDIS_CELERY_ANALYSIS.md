# REDIS_CELERY_ANALYSIS.md — Phase 2

> **Operator decision (this project)**: Redis + Celery are **mandatory** in
> production multi-host deployments. The single-host asyncio fallback remains
> as a safety net for local development, gated by `REDIS_REQUIRED=false`.

---

## 1. Are Redis and Celery required?

### 1.1 What Celery actually buys us
| Capability | Without Celery | With Celery |
|---|---|---|
| Scan completes after `POST /scan` returns 202 | ✓ via `BackgroundTasks` | ✓ |
| Survive API process restart mid-scan | ✗ scan dies | ✓ broker holds task |
| Parallel scans across multiple worker processes | bounded by single-process event loop | ✓ horizontal |
| Retry on transient failure (broker-backed) | ✗ best-effort in-process | ✓ ack-late + `task_reject_on_worker_lost` |
| Live task introspection (Flower) | ✗ | ✓ |
| Time-limit kill (`task_soft_time_limit`) per scan | ✗ relies on `asyncio.wait_for` only | ✓ supervised |
| Schedule recurring scans (`beat`) | ✗ | ✓ |

### 1.2 What Redis brings
- The broker for Celery (mandatory if Celery is used).
- The result backend (`CELERY_RESULT_BACKEND` on DB index 1).
- Future: shared rate-limit state across multi-worker deployments
  (currently in-memory, single-process — flagged in AUDIT_REPORT.md §5).
- Future: cache for repeated scan results.

### 1.3 Decision matrix

| Deployment shape | Redis required? | Celery required? |
|---|---|---|
| Local dev / single laptop | No (set `REDIS_REQUIRED=false`) | No |
| Single VM, low-volume lab | No | Optional |
| Multi-VM / Kubernetes / >1 scan/min | **Yes** | **Yes** |
| CI / pytest | No | No (`task_always_eager` in tests) |

**This project's target = production multi-host → Redis + Celery REQUIRED.**

---

## 2. Current configuration audit

| Item | Setting | File | Status |
|---|---|---|---|
| Broker URL | `redis://localhost:6379/0` | `config.py:CELERY_BROKER_URL` | ✓ |
| Result backend | `redis://localhost:6379/1` (separate DB index) | `config.py:CELERY_RESULT_BACKEND` | ✓ |
| Worker concurrency | `WORKER_CONCURRENCY=4` | `config.py` | ✓ |
| `task_acks_late` | True | `celery_app.py` | ✓ (lost tasks re-queued) |
| `task_reject_on_worker_lost` | True | `celery_app.py` | ✓ |
| `worker_prefetch_multiplier` | 1 | `celery_app.py` | ✓ (fair dispatch) |
| `worker_max_tasks_per_child` | 50 | `celery_app.py` | ✓ (leak prevention) |
| `task_soft_time_limit` | 600 s | `celery_app.py` | ✓ |
| `task_time_limit` | 720 s (SIGKILL) | `celery_app.py` | ✓ |
| `broker_connection_retry_on_startup` | True | `celery_app.py` | ✓ |
| `broker_heartbeat` | 10 s | `celery_app.py` | ✓ |
| `result_expires` | 86 400 s (24 h) | `celery_app.py` | ✓ |
| `result_extended` | True (args stored for debug) | `celery_app.py` | ✓ |
| `worker_send_task_events` / `task_send_sent_event` | True | `celery_app.py` | ✓ (Flower) |
| `event_queue_ttl` | 5 s | `celery_app.py` | ✓ |
| Per-scan publish timeout | **2 s wait_for + `retry=False`** | `routes/scan.py` | ✓ Phase 5 fix |
| Task: `tasks.run_scan` | Registered in `include=` | `celery_app.py` | ✓ |
| Health endpoint integration | `inspect(timeout=1.5).ping()` in thread-executor | `app.py:_inspect_celery` | ✓ |

The Celery config is **production-grade** — no defects.

---

## 3. Why "redis: unavailable, celery: timeout" currently appears

It is the expected output when:
1. The user is running the backend **without** the Redis container.
2. `REDIS_REQUIRED` was previously not in scope; status said "degraded" (the
   asyncio fallback handles scans).

With Phase 2 changes:
- `REDIS_REQUIRED=true` (default) → `/health/full` now returns `"status":"unhealthy"`
  when Redis is down.
- `REDIS_REQUIRED_RETURNS_503=true` (optional) → HTTP 503 instead of 200, for
  Kubernetes readiness probes.

For local development, set `REDIS_REQUIRED=false` in `.env` and the legacy
"degraded but functional" semantics are restored.

---

## 4. How the fast-fail dispatch interacts with Redis

```python
# routes/scan.py (current)
try:
    task = await asyncio.wait_for(
        asyncio.to_thread(run_scan_task.apply_async, kwargs={...}, retry=False),
        timeout=2.0,
    )
    execution_path = "celery"
except (asyncio.TimeoutError, Exception):
    background_tasks.add_task(_run_scan_background, ...)
    execution_path = "asyncio"
```

- When Redis is **up**: `apply_async` returns in ~10 ms → Celery path.
- When Redis is **down**: `apply_async` raises `ConnectionError` immediately
  (we passed `retry=False`); the `asyncio.wait_for` upper bound is just a
  belt-and-braces safety against pathological broker behaviour.

**Trade-off**: if you set `REDIS_REQUIRED=true` but Redis is briefly flapping,
the route still falls back to asyncio so the user's scan succeeds. The next
`/health/full` call will surface the issue to monitoring. This is the right
default — **never** drop a scan because of infra flakiness, but **always** tell
the operator about it via the health endpoint and audit log.

---

## 5. Recommended docker-compose startup (production)

```bash
# 1. Copy the example and fill in secrets
cp .env.example .env

# Edit .env:
#   POSTGRES_PASSWORD=<strong>
#   SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
#   FLOWER_PASSWORD=<strong>
#   REDIS_REQUIRED=true
#   REDIS_REQUIRED_RETURNS_503=true

# 2. Bring up the full stack
docker-compose up --build -d

# 3. Watch for all services 'healthy'
docker-compose ps

# 4. Verify
curl http://localhost:8000/health/full | jq
# {
#   "api": "healthy",
#   "database": "connected",
#   "redis": "connected",
#   "celery": "running",
#   "status": "healthy"
# }

# 5. Flower UI (Celery introspection)
# Open http://localhost:5555  - basic auth: admin / <FLOWER_PASSWORD>
```

### Single-host lab override

```bash
echo "REDIS_REQUIRED=false" >> .env
echo "REDIS_REQUIRED_RETURNS_503=false" >> .env
docker-compose up backend frontend postgres   # skip redis + celery_worker + flower
# /health/full now reports 'degraded' (informational) rather than 'unhealthy'
```

---

## 6. Worker startup quick reference

```bash
# Local (after .\scripts\run.ps1 install)
.\.venv\Scripts\python.exe -m celery -A backend.automation.celery_app worker `
    --loglevel=info --concurrency=4

# Multiple workers on same host
.\.venv\Scripts\python.exe -m celery -A backend.automation.celery_app worker `
    --loglevel=info --concurrency=4 --hostname=worker1@%h
.\.venv\Scripts\python.exe -m celery -A backend.automation.celery_app worker `
    --loglevel=info --concurrency=4 --hostname=worker2@%h

# Flower
.\.venv\Scripts\python.exe -m celery -A backend.automation.celery_app flower `
    --basic-auth=admin:CHANGE_ME --port=5555
```

---

## 7. Queue routing audit

The current implementation uses the **default queue** (`celery`) for all tasks.
That's correct for the present feature set (single task type: `tasks.run_scan`).
If we add report generation, periodic NSE-rule refresh, or other workloads,
introduce dedicated queues:

```python
celery_app.conf.task_routes = {
    "tasks.run_scan":         {"queue": "scans"},
    "tasks.generate_report":  {"queue": "reports"},
    "tasks.refresh_nse":      {"queue": "maintenance"},
}
```

Workers can then be scaled per workload:

```bash
celery -A backend.automation.celery_app worker -Q scans  --concurrency=8
celery -A backend.automation.celery_app worker -Q reports --concurrency=2
```

**Not implemented yet** — flagged for Phase 8 (Deployment).

---

## 8. Changes in this Phase

| File | Change | Why |
|---|---|---|
| [backend/config.py](backend/config.py) | Added `REDIS_REQUIRED` (default `True`) and `REDIS_REQUIRED_RETURNS_503` (default `False`). | Production-mode contract — Redis is mandatory. Single-host lab can opt out. |
| [backend/app.py](backend/app.py) | `/health/full` honours `REDIS_REQUIRED` when computing overall `status`; optionally returns HTTP 503. | Load-balancer / Kubernetes readiness probe correctness. |
| [.env.example](.env.example) | Documented `REDIS_REQUIRED` and `REDIS_REQUIRED_RETURNS_503`; split `CELERY_RESULT_BACKEND` to DB 1. | Operator clarity. |

**No code change to the scan dispatch path** — Phase 5's 2-second fast-fail wrap
already gives the right behaviour for both production (Redis up) and lab (Redis
down) modes.

---

## 9. Open follow-ups (Phase 8 / Deployment)

1. **Docker compose secrets** — substitute hard-coded `scanner:scanner` Postgres
   credentials with `${POSTGRES_PASSWORD}`.
2. **Flower basic-auth** — currently exposed open. Compose should pass
   `--basic-auth=${FLOWER_USER}:${FLOWER_PASSWORD}`.
3. **Queue separation** — when adding report/maintenance workloads.
4. **Worker auto-scaling** — if running on K8s, use HPA on Celery queue depth
   (Redis `LLEN` metric).
5. **Migrate rate-limiter state to Redis** — currently in-memory, single-process
   only. With multi-worker production, the limit is enforced per-process which
   is incorrect.

---

*Phase 2 / 8 complete — proceeding to Phase 3 (Scanner audit refresh).*
