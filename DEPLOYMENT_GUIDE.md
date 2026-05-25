# DEPLOYMENT_GUIDE.md — Phase 8

> Production-grade docker-compose deployment of IVDAF. Per the Phase 2
> decision, **Redis + Celery are mandatory** — the default compose brings up
> the entire stack and `/health/full` reports `unhealthy` (HTTP 503) when any
> required subsystem is down.

---

## 1. Prerequisites

| Component | Version |
|---|---|
| Docker Desktop / Engine | 24+ |
| Docker Compose | v2 (built-in) |
| Disk | ~2 GB for images |
| RAM | 2 GB free |
| Host ports | 8000 (API), 8501 (frontend); 5432 / 6379 / 5555 bound to loopback |

---

## 2. First-time setup

```powershell
cd "c:\ABHISHEK DOC\Cyber-mini\vulnerability-scanner"

# 1. Copy template
Copy-Item .env.example .env

# 2. Generate a strong SECRET_KEY
$secret = & python -c "import secrets; print(secrets.token_hex(32))"
(Get-Content .env) -replace "SECRET_KEY=.*", "SECRET_KEY=$secret" |
    Set-Content .env

# 3. Set Postgres + Flower passwords in .env:
#       POSTGRES_PASSWORD=<strong>
#       FLOWER_USER=admin
#       FLOWER_PASSWORD=<strong>

# 4. Tighten for production (defaults are already prod-friendly):
#       REDIS_REQUIRED=true
#       REDIS_REQUIRED_RETURNS_503=true
#       TRUST_PROXY_HEADERS=true   # only if behind a reverse proxy
#       DEBUG=false

# 5. Build & boot
docker-compose up --build -d

# 6. Watch services come up
docker-compose ps   # all rows should show 'Up (healthy)' within ~30 s

# 7. Smoke-test
curl http://localhost:8000/health
curl http://localhost:8000/health/full
```

Expected `/health/full` when fully up:
```json
{
  "api": "healthy",
  "database": "connected",
  "redis": "connected",
  "celery": "running",
  "status": "healthy",
  "version": "1.0.0"
}
```

---

## 3. Services in the compose stack

| Service | Image | Port (host) | Purpose | Healthcheck |
|---|---|---|---|---|
| `postgres` | postgres:15-alpine | `127.0.0.1:5432` | Persistence | `pg_isready` parametric |
| `redis` | redis:7-alpine | `127.0.0.1:6379` | Broker + result backend | `redis-cli ping` |
| `backend` | local (`docker/Dockerfile`) | `0.0.0.0:8000` | FastAPI + 2 uvicorn workers | `curl /health` |
| `celery_worker` | local (reuses backend image) | — | Scan task execution | broker heartbeat |
| `flower` | local (reuses backend image) | `127.0.0.1:5555` | Celery introspection (basic-auth) | — |
| `frontend` | local (`docker/Dockerfile.frontend`) | `0.0.0.0:8501` | Streamlit dashboard | `curl /_stcore/health` |

**Loopback-only bindings** for Postgres / Redis / Flower mean they're only
reachable from the host. Externally-exposed services are API (`:8000`) and
dashboard (`:8501`).

---

## 4. Production hardening summary

| Surface | Setting |
|---|---|
| Postgres password | `${POSTGRES_PASSWORD}` from `.env` (no insecure default in compose). |
| `SECRET_KEY` | `${SECRET_KEY}` substituted; lifespan warns when placeholder. |
| Flower auth | `--basic_auth=${FLOWER_USER}:${FLOWER_PASSWORD}` |
| CORS | `CORS_ORIGINS` env-driven; default includes `frontend:8501`. |
| `X-Forwarded-*` trust | `TRUST_PROXY_HEADERS` default `false`; enable only behind a known proxy. |
| Reverse-proxy ready | uvicorn launched with `--proxy-headers --forwarded-allow-ips '*'`. |
| Redis mandatory | `REDIS_REQUIRED=true` + `REDIS_REQUIRED_RETURNS_503=true` → LB probes correctly fail unready pods. |
| Container user | `scanner:scanner`, non-root. |
| Nmap capabilities | `setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap` + `NMAP_PRIVILEGED=true`. |
| Audit log | Rotated 10 MB × 10 files at `/app/logs/audit.log` (volume `logs_data`). |
| Prometheus | `/metrics` exposed; rate-limit-excluded. |
| Postgres / Redis exposure | Bound to `127.0.0.1` only. |

---

## 5. Reverse-proxy in front (recommended for public deploys)

Example nginx config terminating TLS and forwarding to the compose stack:

```nginx
server {
    listen 443 ssl http2;
    server_name ivdaf.example.com;
    ssl_certificate     /etc/letsencrypt/live/ivdaf.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ivdaf.example.com/privkey.pem;

    location /api/ {
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Host $host;
        proxy_read_timeout 300;
    }

    location / {
        # Streamlit WebSocket needs Upgrade.
        proxy_pass http://127.0.0.1:8501/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
```

With `TRUST_PROXY_HEADERS=true`, the rate limiter + audit log see real client IPs.

---

## 6. Operations cheatsheet

```powershell
# Tail backend logs
docker-compose logs -f backend

# Tail audit log (host-side via volume)
docker exec vuln_backend tail -f /app/logs/audit.log

# Scale Celery workers
docker-compose up -d --scale celery_worker=4

# Restart only the backend
docker-compose restart backend

# Run tests inside the container
docker exec vuln_backend pytest tests/ --asyncio-mode=auto

# Debug shell
docker exec -it vuln_backend bash

# Confirm setcap applied
docker exec vuln_backend getcap /usr/bin/nmap
# → /usr/bin/nmap = cap_net_bind_service,cap_net_admin,cap_net_raw+eip

# DB init (placeholder for Alembic — see §10 follow-ups)
docker exec vuln_backend python scripts/init_db.py

# Postgres backup
docker exec vuln_postgres pg_dump -U scanner vulnscanner > backup.sql

# Tear down (keep volumes)
docker-compose down

# Destructive tear down (wipes DB + reports)
docker-compose down -v
```

---

## 7. Verifying the privileged-nmap path

```powershell
$body = @{target="127.0.0.1"; scan_type="stealth"; port_range="1-1024"} |
        ConvertTo-Json
$r = Invoke-RestMethod -Method POST http://localhost:8000/scan `
        -ContentType "application/json" -Body $body
Start-Sleep 10
$full = Invoke-RestMethod "http://localhost:8000/results/$($r.scan_id)"
$full.raw_results.port_scan.backend       # → 'nmap'
```

Then confirm the privilege gate did NOT degrade:
```powershell
docker-compose logs celery_worker | Select-String "Process is not privileged"
# No match expected — the process IS privileged (setcap + NMAP_PRIVILEGED=true).
```

---

## 8. Kubernetes (sketch)

The compose stack maps to a Helm chart with five `Deployment`s plus stateful
Redis + Postgres. Recommended probes:

```yaml
readinessProbe:
  httpGet: { path: /health/full, port: 8000 }
  initialDelaySeconds: 15
  periodSeconds: 10
  failureThreshold: 3
livenessProbe:
  httpGet: { path: /health, port: 8000 }
  initialDelaySeconds: 30
  periodSeconds: 30
```

`REDIS_REQUIRED_RETURNS_503=true` makes the readiness probe correctly remove
the pod from service when Redis is unreachable.

---

## 9. CI/CD

`.github/workflows/tests.yml` runs the test suite on push / PR with
`--cov-fail-under=85`. To wire image builds:

```yaml
- name: Build and push image
  uses: docker/build-push-action@v5
  with:
    context: .
    file: docker/Dockerfile
    push: true
    tags: ghcr.io/${{ github.repository }}/ivdaf-backend:${{ github.sha }}
```

---

## 10. Open follow-ups

| # | Item | Priority |
|---|---|---|
| 1 | Alembic migration scaffolding (replace `init_db()` `create_all`) | MEDIUM |
| 2 | Rate-limiter state in Redis (currently per-process in-memory; incorrect under multi-worker) | MEDIUM |
| 3 | Helm chart in `deploy/k8s/` | LOW |
| 4 | Distributed tracing (OpenTelemetry) | LOW |
| 5 | Container image signing (Cosign / Sigstore) | LOW |

---

*Phase 8 / 8 complete — all eight deliverables shipped.*
