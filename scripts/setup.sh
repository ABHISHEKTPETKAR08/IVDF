#!/usr/bin/env bash
# ── IVDAF Setup Script ────────────────────────────────────────────────────────
# Installs dependencies, creates .env, initialises the database,
# and optionally starts all services via Docker Compose.
#
# Usage:  bash scripts/setup.sh [--docker]
set -euo pipefail

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

info "Intelligent Vulnerability Detection and Analysis Framework — Setup"
echo "=================================================================="

# ── Python version check ──────────────────────────────────────────────────────
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
REQUIRED="3.11"
if [[ "$(printf '%s\n' "$REQUIRED" "$PYTHON_VERSION" | sort -V | head -1)" != "$REQUIRED" ]]; then
    error "Python $REQUIRED+ required. Found: $PYTHON_VERSION"
fi
ok "Python $PYTHON_VERSION detected."

# ── Nmap check ────────────────────────────────────────────────────────────────
if command -v nmap &>/dev/null; then
    ok "nmap $(nmap --version | head -1 | grep -oP '\d+\.\d+')"
else
    warn "nmap not found. Port scanning will use the pure-Python fallback."
    warn "Install with: sudo apt-get install nmap (Linux) or brew install nmap (macOS)"
fi

# ── Virtual environment ───────────────────────────────────────────────────────
if [[ ! -d ".venv" ]]; then
    info "Creating virtual environment…"
    python3 -m venv .venv
fi
source .venv/bin/activate
ok "Virtual environment activated."

# ── Install dependencies ──────────────────────────────────────────────────────
info "Installing backend dependencies…"
pip install --upgrade pip -q
pip install -r backend/requirements.txt -q
ok "Backend dependencies installed."

info "Installing frontend dependencies…"
pip install streamlit plotly pandas -q
ok "Frontend dependencies installed."

# ── .env file ────────────────────────────────────────────────────────────────
if [[ ! -f ".env" ]]; then
    info "Creating .env from template…"
    cat > .env <<EOF
# IVDAF Environment Configuration
DATABASE_URL=sqlite+aiosqlite:///./vuln_scanner.db
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
LOG_LEVEL=INFO
DEBUG=false
REPORTS_DIR=./reports
LOGS_DIR=./logs
EOF
    ok ".env created with a random SECRET_KEY."
else
    warn ".env already exists — skipping creation."
fi

# ── Directories ───────────────────────────────────────────────────────────────
mkdir -p reports logs
ok "Storage directories created."

# ── Database ──────────────────────────────────────────────────────────────────
info "Initialising database…"
python3 scripts/init_db.py
ok "Database initialised."

# ── Docker Compose ────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--docker" ]]; then
    info "Starting services with Docker Compose…"
    if command -v docker-compose &>/dev/null; then
        docker-compose up --build -d
        ok "All services started."
        echo ""
        info "Services:"
        echo "  API:      http://localhost:8000"
        echo "  Docs:     http://localhost:8000/docs"
        echo "  Frontend: http://localhost:8501"
    else
        error "docker-compose not found. Install Docker Desktop."
    fi
else
    echo ""
    ok "Setup complete!"
    echo ""
    info "Start the API server:"
    echo "  source .venv/bin/activate"
    echo "  python -m backend.app"
    echo ""
    info "Start the Streamlit dashboard:"
    echo "  streamlit run frontend/dashboard.py"
    echo ""
    info "Start a Celery worker (optional — needs Redis):"
    echo "  celery -A backend.automation.celery_app worker --loglevel=info"
fi
