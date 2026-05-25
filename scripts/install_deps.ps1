# ── Install All Python Dependencies ───────────────────────────────────────────
# Run once after cloning or when requirements.txt changes.
# Creates a .venv virtualenv and installs everything.

param(
    [switch]$System   # skip venv creation and install into system Python
)

Write-Host ""
Write-Host "=== IVDAF — Dependency Installer ===" -ForegroundColor Cyan
Write-Host ""

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
Set-Location $ProjectDir

# ── Check Python ──────────────────────────────────────────────────────────────
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: python not found. Install Python 3.11+ from https://python.org" -ForegroundColor Red
    exit 1
}
$pyVer = python --version
Write-Host "Python: $pyVer" -ForegroundColor DarkGray

# ── Create virtualenv ─────────────────────────────────────────────────────────
if (-not $System) {
    if (-not (Test-Path ".venv")) {
        Write-Host "Creating virtualenv (.venv)..." -ForegroundColor Yellow
        python -m venv .venv
    }
    Write-Host "Activating virtualenv..." -ForegroundColor Yellow
    & ".venv\Scripts\Activate.ps1"
}

# ── Upgrade pip ───────────────────────────────────────────────────────────────
Write-Host "Upgrading pip..." -ForegroundColor Yellow
python -m pip install --upgrade pip --quiet

# ── Install requirements ──────────────────────────────────────────────────────
Write-Host "Installing requirements.txt..." -ForegroundColor Yellow
pip install -r requirements.txt

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "Some packages failed. Trying individual installs for known-tricky packages..." -ForegroundColor Yellow

    # psycopg2-binary can fail on some Python 3.13 builds — skip silently
    pip install psycopg2-binary 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  psycopg2-binary skipped (not needed for SQLite dev mode)" -ForegroundColor DarkGray
    }

    # asyncpg also sometimes needs compiler — skip silently
    pip install asyncpg 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  asyncpg skipped (not needed for SQLite dev mode)" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "Core packages installed. Verifying..." -ForegroundColor Yellow

$packages = @("fastapi", "uvicorn", "sqlalchemy", "celery", "redis", "streamlit", "httpx", "pydantic")
foreach ($pkg in $packages) {
    $ver = python -c "import $pkg; print($pkg.__version__)" 2>$null
    if ($ver) {
        Write-Host "  [OK] $pkg $ver" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] $pkg" -ForegroundColor Red
    }
}

# ── python-nmap / python-whois ────────────────────────────────────────────────
Write-Host ""
Write-Host "Checking optional scan libraries..." -ForegroundColor Yellow

$nmapVer = python -c "import nmap; print(nmap.__version__)" 2>$null
if ($nmapVer) {
    Write-Host "  [OK] python-nmap $nmapVer" -ForegroundColor Green
} else {
    Write-Host "  [MISSING] python-nmap — installing..." -ForegroundColor Yellow
    pip install python-nmap
}

$whoisVer = python -c "import whois; print('ok')" 2>$null
if ($whoisVer) {
    Write-Host "  [OK] python-whois" -ForegroundColor Green
} else {
    Write-Host "  [MISSING] python-whois — installing..." -ForegroundColor Yellow
    pip install python-whois
}

Write-Host ""
Write-Host "=== Installation complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Install nmap binary   : scripts\install_nmap.ps1" -ForegroundColor White
Write-Host "  2. Start Redis           : scripts\start_redis.ps1" -ForegroundColor White
Write-Host "  3. Start backend         : scripts\start_backend.ps1" -ForegroundColor White
Write-Host "  4. Start Celery worker   : scripts\start_worker.ps1" -ForegroundColor White
Write-Host "  5. Start frontend        : scripts\start_frontend.ps1" -ForegroundColor White
Write-Host ""
