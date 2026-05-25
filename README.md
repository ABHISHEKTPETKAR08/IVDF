# Intelligent Vulnerability Detection and Analysis Framework

> **Educational / Lab Use Only** — Designed for DVWA, OWASP Juice Shop, and Metasploitable.  
> Only private RFC 1918 addresses are accepted as scan targets.

A production-grade Python cybersecurity assessment framework featuring:
- Multi-phase scanning (recon → ports → 8 vulnerability detectors)
- Adaptive low-noise scanning engine (IDS/IPS-aware)
- Explainable findings with OWASP mapping and CVE references
- Auto-remediation with code examples and config snippets
- FastAPI REST backend + Streamlit dashboard
- Celery background tasks + Redis
- PDF / JSON / CSV report generation
- Docker Compose deployment

---

## Quick Start (Local — No Docker)

### Prerequisites

- Python 3.11+
- Redis (optional — for background scans)
- nmap (optional — falls back to pure-Python scanner)

```bash
# 1. Clone and enter the project
cd vulnerability-scanner

# 2. Run the setup script
bash scripts/setup.sh

# 3. Activate the virtual environment
source .venv/bin/activate   # Linux/macOS
# or
.venv\Scripts\activate      # Windows

# 4. Start the backend
python -m backend.app

# 5. Start the Streamlit dashboard (new terminal)
streamlit run frontend/dashboard.py
```

| Service | URL |
|---------|-----|
| API | http://localhost:8000 |
| Swagger Docs | http://localhost:8000/docs |
| Dashboard | http://localhost:8501 |

---

## Quick Start (Docker)

```bash
# Build and start all services
bash scripts/setup.sh --docker

# Or directly with Docker Compose
docker-compose up --build
```

Services started:
| Container | URL |
|-----------|-----|
| Backend (FastAPI) | http://localhost:8000 |
| Frontend (Streamlit) | http://localhost:8501 |
| PostgreSQL | localhost:5432 |
| Redis | localhost:6379 |
| Celery Worker | (background) |

---

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio pytest-cov httpx

# Run all tests
pytest tests/ -v --asyncio-mode=auto

# With coverage
pytest tests/ -v --asyncio-mode=auto --cov=backend --cov-report=term-missing
```

---

## Making a Scan (API)

```bash
# 1. Initiate a scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.100",
    "scan_type": "full",
    "port_range": "1-1024",
    "adaptive_mode": false
  }'

# Response:
# { "scan_id": "abc123...", "status": "pending", ... }

# 2. Poll for results
curl http://localhost:8000/scan/abc123...

# 3. View vulnerabilities
curl http://localhost:8000/vulnerabilities?scan_id=abc123...

# 4. Generate PDF report
curl -X POST http://localhost:8000/reports/abc123... \
  -H "Content-Type: application/json" \
  -d '{"format": "pdf"}'
```

---

## Project Structure

```
vulnerability-scanner/
├── backend/
│   ├── app.py                    FastAPI application entry-point
│   ├── config.py                 Settings (pydantic-settings)
│   ├── requirements.txt
│   ├── routes/                   API endpoint routers
│   │   ├── scan.py
│   │   ├── results.py
│   │   ├── reports.py
│   │   ├── targets.py
│   │   └── vulnerabilities.py
│   ├── scanners/                 Recon and port scanning
│   │   ├── recon.py
│   │   └── port_scanner.py
│   ├── adaptive_scanner/         IDS-aware scanning engine
│   │   └── adaptive_engine.py
│   ├── detectors/                Vulnerability detection modules
│   │   ├── base.py
│   │   ├── sql_injection.py
│   │   ├── xss.py
│   │   ├── header_checker.py
│   │   ├── ssl_checker.py
│   │   ├── port_checker.py
│   │   ├── ssh_checker.py
│   │   ├── directory_traversal.py
│   │   └── http_methods.py
│   ├── ai_explanations/          Explainable vulnerability engine
│   │   └── explainer.py
│   ├── remediation/              Auto-remediation guidance
│   │   └── remediation_engine.py
│   ├── reports/                  PDF/JSON/CSV generator
│   │   └── report_generator.py
│   ├── automation/               Celery tasks
│   │   ├── celery_app.py
│   │   └── tasks.py
│   ├── database/                 SQLAlchemy models and session
│   │   ├── models.py
│   │   └── db.py
│   ├── middleware/               Rate limiter
│   │   └── rate_limiter.py
│   └── utils/                   Logger and validators
│       ├── logger.py
│       └── validators.py
│
├── frontend/
│   ├── dashboard.py              Streamlit main dashboard
│   ├── charts.py                 Plotly chart builders
│   └── ui_components.py          Reusable UI components
│
├── tests/
│   ├── test_api.py               FastAPI integration tests
│   ├── test_detectors.py         Detector unit tests
│   └── test_scanners.py          Scanner + adaptive engine tests
│
├── docs/
│   ├── architecture.md
│   ├── api_documentation.md
│   └── ieee_writeup.md
│
├── docker/
│   ├── Dockerfile                Backend image
│   └── Dockerfile.frontend       Streamlit image
│
├── scripts/
│   ├── setup.sh                  One-command setup
│   └── init_db.py                Database initialisation
│
├── docker-compose.yml
├── .gitignore
└── README.md
```

---

## Vulnerability Coverage

| Vulnerability | Severity | OWASP | Detector |
|--------------|----------|-------|---------|
| SQL Injection | HIGH | A03:2021 | `sql_injection.py` |
| Reflected XSS | HIGH | A03:2021 | `xss.py` |
| Missing Security Headers (7 types) | LOW–HIGH | A05:2021 | `header_checker.py` |
| Weak SSL/TLS (protocol, cipher, expiry) | MEDIUM–CRITICAL | A02:2021 | `ssl_checker.py` |
| Dangerous Open Ports (17 types) | LOW–CRITICAL | A05:2021 | `port_checker.py` |
| Weak SSH Configuration | LOW–CRITICAL | A06:2021 | `ssh_checker.py` |
| Directory Traversal | HIGH | A01:2021 | `directory_traversal.py` |
| Insecure HTTP Methods | MEDIUM–HIGH | A05:2021 | `http_methods.py` |

---

## Configuration

All settings are loaded from environment variables or `.env`:

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `sqlite+aiosqlite:///./vuln_scanner.db` | Database connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis URL |
| `SECRET_KEY` | (generated) | Application secret |
| `LOG_LEVEL` | `INFO` | Logging level |
| `SCAN_TIMEOUT` | `30` | Per-probe timeout (seconds) |
| `ADAPTIVE_SCAN_DELAY_MIN` | `0.5` | Minimum scan delay |
| `ADAPTIVE_SCAN_DELAY_MAX` | `3.0` | Maximum scan delay |
| `RATE_LIMIT_REQUESTS` | `100` | Requests per rate-limit window |

---

## Ethical Usage

This tool is provided for:
- Academic learning and research
- Portfolio demonstration
- Authorised penetration testing in lab environments

**Never use this tool against systems you do not own or lack explicit written permission to test.**

---

## License

MIT License — see [LICENSE](LICENSE) for details.
