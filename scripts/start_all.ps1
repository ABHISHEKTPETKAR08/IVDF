# ── IVDAF — Start All Services (Windows / Local Dev) ──────────────────────────
# Launches Redis, FastAPI backend, Celery worker, and Streamlit frontend
# in separate PowerShell windows.
#
# Prerequisites:
#   - Docker Desktop running  (for Redis)
#   - Python 3.11+ installed
#   - pip install -r requirements.txt done  (scripts\install_deps.ps1)
#   - nmap installed  (scripts\install_nmap.ps1 — optional)

param(
    [switch]$NoWorker,   # skip Celery worker (asyncio fallback used instead)
    [switch]$NoFrontend, # skip Streamlit
    [switch]$Debug       # backend in debug/reload mode
)

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   IVDAF — Intelligent Vulnerability Framework        ║" -ForegroundColor Cyan
Write-Host "║   Starting all services...                           ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$ScriptDir  = $PSScriptRoot
$ProjectDir = Split-Path -Parent $ScriptDir

function Start-ServiceWindow {
    param([string]$Title, [string]$Command)
    Start-Process powershell -ArgumentList `
        "-NoExit", "-Command", "cd '$ProjectDir'; `$host.ui.RawUI.WindowTitle = '$Title'; $Command"
}

# ── 1. Redis ──────────────────────────────────────────────────────────────────
Write-Host "[1/4] Starting Redis..." -ForegroundColor Yellow
& "$ScriptDir\start_redis.ps1"
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Redis failed to start. Aborting." -ForegroundColor Red
    exit 1
}

# ── 2. FastAPI Backend ────────────────────────────────────────────────────────
Write-Host "[2/4] Starting FastAPI backend in new window..." -ForegroundColor Yellow
$backendCmd = if ($Debug) {
    "& '$ScriptDir\start_backend.ps1' -Debug -Reload"
} else {
    "& '$ScriptDir\start_backend.ps1'"
}
Start-ServiceWindow -Title "IVDAF Backend" -Command $backendCmd

# Wait for backend to be ready
Write-Host "      Waiting for backend to be ready..." -ForegroundColor DarkGray
$maxWait = 30
for ($i = 0; $i -lt $maxWait; $i++) {
    Start-Sleep -Seconds 1
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:8000/health" -TimeoutSec 2 -ErrorAction Stop
        if ($r.StatusCode -eq 200) {
            Write-Host "      Backend ready!" -ForegroundColor Green
            break
        }
    } catch {}
    if ($i -eq $maxWait - 1) {
        Write-Host "      WARNING: Backend not responding after ${maxWait}s — continuing anyway." -ForegroundColor Yellow
    }
}

# ── 3. Celery Worker ──────────────────────────────────────────────────────────
if (-not $NoWorker) {
    Write-Host "[3/4] Starting Celery worker in new window..." -ForegroundColor Yellow
    Start-ServiceWindow -Title "IVDAF Celery Worker" -Command "& '$ScriptDir\start_worker.ps1'"
    Start-Sleep -Seconds 2
} else {
    Write-Host "[3/4] Celery worker skipped (asyncio fallback active)." -ForegroundColor DarkGray
}

# ── 4. Streamlit Frontend ─────────────────────────────────────────────────────
if (-not $NoFrontend) {
    Write-Host "[4/4] Starting Streamlit frontend in new window..." -ForegroundColor Yellow
    Start-ServiceWindow -Title "IVDAF Frontend" -Command "& '$ScriptDir\start_frontend.ps1'"
    Start-Sleep -Seconds 3
} else {
    Write-Host "[4/4] Frontend skipped." -ForegroundColor DarkGray
}

# ── Ready ─────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   ALL SERVICES STARTED                               ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard  : http://localhost:8501" -ForegroundColor Cyan
Write-Host "  API docs   : http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "  Health     : http://localhost:8000/health" -ForegroundColor Cyan
if (-not $NoWorker) {
    Write-Host "  Flower     : celery -A backend.automation.celery_app flower" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  Health check: scripts\health_check.ps1" -ForegroundColor DarkGray
Write-Host "  Stop Redis  : docker stop vuln-redis" -ForegroundColor DarkGray
Write-Host ""
