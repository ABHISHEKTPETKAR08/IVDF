# Complete Production Deployment Guide

> **READ SECURITY_CHECKLIST.md FIRST before deploying to production**

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Backend Deployment (Render.com)](#backend-deployment-rendercom)
3. [Backend Deployment (Railway.app)](#backend-deployment-railwayapp)
4. [Frontend Deployment (Netlify)](#frontend-deployment-netlify)
5. [Database Setup](#database-setup)
6. [Redis/Celery Configuration](#rediscelery-configuration)
7. [Domain & SSL/TLS](#domain--ssltls)
8. [Monitoring & Alerts](#monitoring--alerts)
9. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

### Production Stack

```
┌─────────────────────────────────────────────────┐
│           Netlify (Frontend)                     │
│  - Streamlit dashboard compiled to static       │
│  - API_BASE_URL points to backend               │
│  - Auto-deploys on Git push                      │
└──────────────────┬──────────────────────────────┘
                   │ HTTPS
                   ↓
┌─────────────────────────────────────────────────┐
│    CloudFlare / AWS CloudFront (CDN)            │
│  - SSL/TLS termination                          │
│  - DDoS protection                              │
│  - Caching                                      │
└──────────────────┬──────────────────────────────┘
                   │ HTTPS
                   ↓
┌─────────────────────────────────────────────────┐
│      Render / Railway (Backend API)             │
│  - FastAPI + Uvicorn                            │
│  - Auto-scaling                                 │
│  - Health checks                                │
└──────┬──────────────────────────┬───────────────┘
       │                          │
       ↓                          ↓
┌──────────────────┐    ┌────────────────────┐
│  AWS RDS / Cloud │    │  Redis Cloud /     │
│  PostgreSQL      │    │  AWS ElastiCache   │
│  - Automated     │    │  - Celery broker   │
│  - Backups       │    │  - Result backend  │
│  - Replication   │    │  - Job queue       │
└──────────────────┘    └────────────────────┘
```

### Recommended Providers

| Component | Recommended Provider | Alternative | Cost |
|-----------|---------------------|-------------|------|
| **Backend** | Render.com | Railway.app, Heroku | $12-50/month |
| **Frontend** | Netlify | Vercel, GitHub Pages | FREE tier |
| **Database** | AWS RDS | DigitalOcean, Railway | $15-100/month |
| **Redis** | Redis Cloud | AWS ElastiCache, DigitalOcean | $15-50/month |
| **Domain** | Namecheap, Route53 | GoDaddy | $10-15/year |
| **SSL/TLS** | Let's Encrypt (free) | AWS ACM (free) | FREE |
| **Monitoring** | Sentry.io | Datadog, New Relic | FREE tier |

---

## Backend Deployment (Render.com)

### 1. Prepare Backend for Render

Create `render.yaml` in repository root:

```yaml
services:
  - type: web
    name: ivdaf-backend
    env: python
    region: oregon  # Choose closest to your users
    plan: standard
    buildCommand: >
      pip install -r backend/requirements.txt &&
      python backend/database/init_db.py
    startCommand: >
      uvicorn backend.app:app
      --host 0.0.0.0
      --port $PORT
    healthCheckPath: /health
    healthCheckInterval: 30
    envVars:
      - key: PYTHON_VERSION
        value: 3.11
      - key: DATABASE_URL
        scope: runtime
      - key: REDIS_URL
        scope: runtime
      - key: SECRET_KEY
        scope: runtime
      - key: DEBUG
        value: false
      - key: LOG_LEVEL
        value: INFO
    autoDeploy: true

  - type: pserv
    name: ivdaf-celery-worker
    env: python
    buildCommand: >
      pip install -r backend/requirements.txt
    startCommand: >
      celery -A backend.automation.celery_app worker
      --loglevel=info
      --concurrency=4
      --time-limit=600
      --soft-time-limit=540
    envVars:
      - key: PYTHON_VERSION
        value: 3.11
      - key: CELERY_BROKER_URL
        scope: runtime
      - key: CELERY_RESULT_BACKEND
        scope: runtime
      - key: DATABASE_URL
        scope: runtime
```

### 2. Connect Render Account

1. Go to https://render.com/register
2. Sign up with GitHub
3. Click "Dashboard" → "New" → "Web Service"
4. Select GitHub repository
5. Choose "Use blueprint" (if you have `render.yaml`)

### 3. Configure Environment Variables

In Render Dashboard → Settings → Environment:

```
DATABASE_URL=postgresql://user:password@hostname:5432/dbname
REDIS_URL=redis://:password@hostname:6379/0
SECRET_KEY=<generate-with-python-secrets>
CELERY_BROKER_URL=redis://:password@hostname:6379/0
CELERY_RESULT_BACKEND=redis://:password@hostname:6379/1
CORS_ORIGINS=https://your-frontend.netlify.app,https://your-domain.com
```

### 4. Set Up Health Checks

In Render Dashboard → Settings → Health Checks:

- **HTTP Path:** `/health`
- **Poll Interval:** 30 seconds
- **Timeout:** 10 seconds
- **Failure Threshold:** 3
- **Grace Period:** 30 seconds

### 5. Deploy

```powershell
# Push to GitHub
git push origin main

# Render auto-deploys when render.yaml is present
# Monitor: https://dashboard.render.com
```

---

## Backend Deployment (Railway.app)

### 1. Create Procfile

Create `Procfile` in repository root:

```
web: uvicorn backend.app:app --host 0.0.0.0 --port $PORT --workers 4
worker: celery -A backend.automation.celery_app worker --loglevel=info --concurrency=4
```

### 2. Create railway.json

```json
{
  "$schema": "https://railway.app/railway.schema.json",
  "build": {
    "builder": "nixpacks",
    "buildCommand": "pip install -r backend/requirements.txt"
  },
  "deploy": {
    "startCommand": "uvicorn backend.app:app --host 0.0.0.0 --port $PORT",
    "restartPolicyType": "always",
    "restartPolicyMaxRetries": 5
  },
  "httpServer": {
    "healthchecks": {
      "enabled": true,
      "path": "/health"
    }
  }
}
```

### 3. Deploy to Railway

```powershell
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Create project
railway init

# Configure environment variables
railway variables
# Add: DATABASE_URL, REDIS_URL, SECRET_KEY, etc.

# Deploy
railway up

# View logs
railway logs
```

---

## Frontend Deployment (Netlify)

### 1. Create netlify.toml

Create `netlify.toml` in repository root:

```toml
[build]
# Build command to create static frontend
command = """
pip install streamlit plotly pandas requests &&
python scripts/build_streamlit.py
"""
publish = "build"
functions = "netlify/functions"

# Environment variables
[build.environment]
PYTHON_VERSION = "3.11"
NODE_VERSION = "18"

# Redirects for SPA
[[redirects]]
from = "/*"
to = "/index.html"
status = 200

# Headers for security
[[headers]]
for = "/*"
[headers.values]
"X-Content-Type-Options" = "nosniff"
"X-Frame-Options" = "DENY"
"X-XSS-Protection" = "1; mode=block"
"Strict-Transport-Security" = "max-age=31536000; includeSubDomains"

# API redirect to backend
[[redirects]]
from = "/api/*"
to = "https://your-backend-api.com/api/:splat"
status = 200
force = false

# Environment variables by context
[context.production]
environment = { API_BASE_URL = "https://your-api.domain.com" }

[context.deploy-preview]
environment = { API_BASE_URL = "https://dev-api.domain.com" }

[context.branch-deploy]
environment = { API_BASE_URL = "http://localhost:8000" }
```

### 2. Deploy to Netlify

**Option A: Via GitHub Integration (Recommended)**

1. Go to https://netlify.com
2. Click "New site from Git"
3. Choose GitHub
4. Select repository
5. Netlify auto-detects `netlify.toml`
6. Click "Deploy"

**Option B: Via Netlify CLI**

```powershell
# Install Netlify CLI
npm install -g netlify-cli

# Login
netlify login

# Deploy
netlify deploy --prod
```

### 3. Configure Netlify Environment

In Netlify Settings → Build & deploy → Environment:

```
API_BASE_URL = https://your-api-domain.com
FRONTEND_URL = https://your-frontend-domain.com
```

### 4. Set Up Auto-Deploy

In Netlify Settings → Build & deploy → Continuous Deployment:

- **GitHub Branch:** `main`
- **Deploy on push:** ✅ Enabled
- **Deploy previews:** ✅ Enabled

---

## Database Setup

### Option 1: AWS RDS (PostgreSQL)

```powershell
# Install AWS CLI
winget install Amazon.AWSCLI

# Configure credentials
aws configure

# Create RDS instance
aws rds create-db-instance `
  --db-instance-identifier "ivdaf-db" `
  --db-instance-class "db.t3.micro" `
  --engine "postgres" `
  --master-username "admin" `
  --master-user-password "CHANGE-ME-use-strong-password" `
  --allocated-storage 20 `
  --publicly-accessible false `
  --multi-az false

# Get endpoint
aws rds describe-db-instances `
  --db-instance-identifier "ivdaf-db" `
  --query 'DBInstances[0].Endpoint.Address'

# Set DATABASE_URL
$DATABASE_URL="postgresql+asyncpg://admin:password@ivdaf-db.xxxxx.us-east-1.rds.amazonaws.com:5432/vulnscanner"
```

### Option 2: DigitalOcean Managed Database

1. Go to DigitalOcean → Databases → Create
2. Choose PostgreSQL
3. Select region and size (Starter Plan: $15/month)
4. Copy connection string
5. Set DATABASE_URL

### Option 3: Railway.app PostgreSQL

```powershell
# Railway includes managed PostgreSQL
# In Railway dashboard:
# - Add service → PostgreSQL
# - Copy DATABASE_URL from variables
```

---

## Redis/Celery Configuration

### Option 1: Redis Cloud

1. Go to https://redis.com/try-free/
2. Create free database (30MB)
3. Copy connection string
4. Set REDIS_URL environment variable

### Option 2: AWS ElastiCache

```powershell
aws elasticache create-cache-cluster `
  --cache-cluster-id "ivdaf-redis" `
  --engine "redis" `
  --cache-node-type "cache.t3.micro" `
  --num-cache-nodes 1 `
  --engine-version "7.0"

# Get endpoint
aws elasticache describe-cache-clusters `
  --cache-cluster-id "ivdaf-redis" `
  --show-cache-node-info
```

### Option 3: Managed Celery (No self-hosted workers)

If Celery is problematic, simplify to use FastAPI BackgroundTasks:

```python
# Replace Celery with FastAPI background tasks
from fastapi import BackgroundTasks

@app.post("/scan")
async def start_scan(target: str, background_tasks: BackgroundTasks):
    scan_id = create_scan_record()
    background_tasks.add_task(run_scan_async, scan_id, target)
    return {"scan_id": scan_id, "status": "queued"}

async def run_scan_async(scan_id: str, target: str):
    # Scan runs in background
    pass
```

---

## Domain & SSL/TLS

### 1. Register Domain

- Namecheap: https://www.namecheap.com
- AWS Route 53: https://aws.amazon.com/route53/
- GoDaddy: https://www.godaddy.com

Example: `your-api.domain.com`, `your-frontend.domain.com`

### 2. Configure DNS

For Netlify Frontend:

```
CNAME: your-frontend.domain.com → your-site.netlify.app
```

For Render Backend:

```
CNAME: your-api.domain.com → your-service.onrender.com
```

### 3. SSL/TLS Certificate

Most platforms auto-provide SSL/TLS:
- Netlify: Auto-issued Let's Encrypt certificate
- Render: Auto-issued Let's Encrypt certificate
- AWS: Use AWS Certificate Manager (free)

Verify HTTPS:
```powershell
curl -I https://your-api.domain.com
# Should show: HTTP/2 200
```

---

## Monitoring & Alerts

### 1. Sentry.io (Error Tracking)

```python
# In backend/app.py
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration

sentry_sdk.init(
    dsn="https://YOUR-KEY@sentry.io/YOUR-PROJECT-ID",
    integrations=[FastApiIntegration()],
    traces_sample_rate=0.1,
    environment="production",
)
```

### 2. Health Check Monitoring

```python
# Set up external health check monitoring
# Use service like:
# - UptimeRobot (free): https://uptimerobot.com
# - Pingdom: https://www.pingdom.com
# - AWS CloudWatch: https://aws.amazon.com/cloudwatch/

# Add to monitoring:
https://your-api.domain.com/health
https://your-api.domain.com/health/full
```

### 3. Log Aggregation

```bash
# Option 1: Render built-in logs
# View at: https://dashboard.render.com/services/YOUR-SERVICE/logs

# Option 2: Papertrail
# Push logs to: logs.papertrailapp.com:PORT
# Environment: PAPERTRAIL_API_TOKEN=YOUR-TOKEN

# Option 3: CloudWatch (AWS)
# Install CloudWatch agent in docker image
```

---

## Production Checklist

Before going live:

- [ ] Database backups enabled (daily)
- [ ] Redis cache warmed up
- [ ] Monitoring alerts configured
- [ ] Error tracking (Sentry) active
- [ ] Health checks responding
- [ ] SSL/TLS certificate valid
- [ ] CORS configured for production domains
- [ ] Rate limiting enabled
- [ ] Logging sanitized (no secrets)
- [ ] Database connection pooling optimal
- [ ] Celery workers running (if needed)
- [ ] Frontend API_BASE_URL points to production backend

---

## Scaling Strategy

### Phase 1: MVP (Month 1-2)

- **Backend:** Render Starter ($12/month)
- **Frontend:** Netlify Free
- **Database:** AWS RDS t3.micro ($25/month)
- **Redis:** Redis Cloud Free (30MB)
- **Total Cost:** ~$37/month

### Phase 2: Growth (Month 3-6)

- **Backend:** Render Standard ($50/month) + worker
- **Frontend:** Netlify Pro ($20/month)
- **Database:** AWS RDS t3.small ($50/month)
- **Redis:** Redis Cloud $15/month (100MB)
- **CDN:** CloudFlare ($20/month) for caching
- **Total Cost:** ~$155/month

### Phase 3: Enterprise (Month 6+)

- **Backend:** Kubernetes (EKS/GKE) or Lambda + RDS Multi-AZ
- **Frontend:** CloudFront + S3 for static content
- **Database:** RDS Multi-AZ with read replicas
- **Redis:** ElastiCache cluster with replication
- **Monitoring:** DataDog or New Relic
- **Total Cost:** $500+/month depending on traffic

---

## Troubleshooting

### Issue: Database connection timeout

```python
# Solution: Add connection pooling
# In docker-compose.yml or deployment config:
DATABASE_URL=postgresql+asyncpg://user:pass@host/db?pool_size=20&max_overflow=10
```

### Issue: Celery workers not processing tasks

```bash
# Check worker status
celery -A backend.automation.celery_app inspect active

# Monitor queue
celery -A backend.automation.celery_app events
```

### Issue: Frontend can't reach backend API

```javascript
// Check CORS headers
fetch('https://your-api.com/health')
  .then(r => r.json())
  .catch(e => console.error('CORS issue:', e))
```

### Issue: High memory usage

```bash
# Monitor: ps aux | grep python
# Solution: Enable memory limits in deployment platform
# Reduce: MAX_CONCURRENT_SCANS or WORKER_CONCURRENCY
```

---

## Resources

- Render Deployment: https://docs.render.com/
- Railway Documentation: https://docs.railway.app/
- Netlify Documentation: https://docs.netlify.com/
- AWS RDS: https://docs.aws.amazon.com/rds/
- FastAPI Production: https://fastapi.tiangolo.com/deployment/
- Celery Production: https://docs.celeryproject.io/en/stable/

---

**Next Steps:**
1. Choose hosting platforms
2. Set up database and Redis
3. Deploy backend
4. Deploy frontend
5. Configure monitoring
6. Set up CI/CD pipeline
7. Plan disaster recovery

---

**Last Updated:** 2026-05-24
