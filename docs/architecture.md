# IVDAF System Architecture

## Component Diagram

```
                          ┌──────────────────────────────────────────┐
                          │           User / Analyst                  │
                          └─────────────┬────────────────────────────┘
                                        │
              ┌─────────────────────────▼────────────────────────────┐
              │               Streamlit Dashboard                     │
              │     dashboard.py  |  charts.py  |  ui_components.py  │
              └─────────────────────────┬────────────────────────────┘
                                        │ HTTP REST
              ┌─────────────────────────▼────────────────────────────┐
              │                 FastAPI Backend                       │
              │  /scan  /results  /vulnerabilities  /reports          │
              │  /targets  /health                                    │
              │                                                       │
              │  Middleware:  RateLimiter  |  CORS  |  Logging       │
              └────┬─────────────┬────────────────────┬──────────────┘
                   │             │                    │
     ┌─────────────▼──┐   ┌──────▼──────────┐  ┌────▼─────────────┐
     │ SQLAlchemy ORM │   │  Celery Worker  │  │  Report Generator│
     │ (Async)        │   │  (Scan Tasks)   │  │  PDF/JSON/CSV    │
     │                │   │                 │  └──────────────────┘
     │  Users         │   │  ┌────────────┐ │
     │  Targets       │   │  │ Recon      │ │
     │  Scans         │   │  ├────────────┤ │
     │  Vulnerabilities│  │  │ Port Scan  │ │
     │  Reports       │   │  ├────────────┤ │
     └────────┬───────┘   │  │ Adaptive   │ │
              │           │  │ Engine     │ │
     ┌────────▼───────┐   │  ├────────────┤ │
     │ PostgreSQL     │   │  │ Detectors  │ │
     │   or           │   │  │ (8 types)  │ │
     │ SQLite         │   │  ├────────────┤ │
     └────────────────┘   │  │ Explainer  │ │
                          │  ├────────────┤ │
     ┌──────────────────┐ │  │ Remediation│ │
     │      Redis       │ │  └────────────┘ │
     │  (Broker +       │◄│                 │
     │   Results)       │ └─────────────────┘
     └──────────────────┘

```

## Scan Lifecycle

```
POST /scan
    │
    ▼
Validate target (RFC 1918 check)
    │
    ▼
Create Scan record (status=PENDING)
    │
    ▼
Enqueue Celery task (run_scan_task)
    │
    ▼
Return 202 { scan_id, task_id }
    │
    ▼ (async, in worker)
Phase 1: Reconnaissance
    │  DNS, WHOIS, banner grab, SSL info
    ▼
Phase 2: Port Scanning
    │  nmap / asyncio TCP, service detection
    ▼
Phase 3: Vulnerability Detection (concurrent)
    │  ┌─ SQL Injection
    │  ├─ XSS
    │  ├─ Security Headers
    │  ├─ SSL/TLS
    │  ├─ Dangerous Ports
    │  ├─ SSH Configuration
    │  ├─ Directory Traversal
    │  └─ HTTP Methods
    ▼
Phase 4: Enrichment
    │  Explainer + Remediation per finding
    ▼
Phase 5: Persistence
    │  Write Vulnerability records to DB
    │  Update Scan status = COMPLETED
    ▼
Client polls GET /scan/{scan_id}
    │
    ▼
status = "completed"
```

## Data Flow

```
HTTP Request
    │
    ▼ Pydantic validation
Router Handler (async)
    │
    ├──► DB Session (get_db dependency)
    │         │
    │         ▼
    │    SQLAlchemy async query
    │         │
    │         ▼
    │    PostgreSQL / SQLite
    │
    └──► Celery .delay() call
              │
              ▼
         Redis broker
              │
              ▼
         Celery Worker
              │
              ▼
         Scan pipeline
              │
              ▼
         DB write (asyncpg/aiosqlite)
```

## Module Dependencies

```
app.py
  ├── config.py
  ├── database/db.py
  │     └── database/models.py
  ├── middleware/rate_limiter.py
  ├── utils/logger.py
  └── routes/
        ├── scan.py
        │     ├── database/models.py
        │     └── utils/validators.py
        ├── results.py
        ├── reports.py
        │     ├── reports/report_generator.py
        │     └── ai_explanations/explainer.py
        ├── targets.py
        └── vulnerabilities.py

automation/tasks.py (Celery worker)
  ├── scanners/recon.py
  ├── scanners/port_scanner.py
  ├── adaptive_scanner/adaptive_engine.py
  ├── detectors/
  │     ├── sql_injection.py
  │     ├── xss.py
  │     ├── header_checker.py
  │     ├── ssl_checker.py
  │     ├── port_checker.py
  │     ├── ssh_checker.py
  │     ├── directory_traversal.py
  │     └── http_methods.py
  ├── ai_explanations/explainer.py
  └── remediation/remediation_engine.py
```
