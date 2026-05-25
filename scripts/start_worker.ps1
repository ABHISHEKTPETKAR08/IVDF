# ── Start Celery Worker ────────────────────────────────────────────────────────
# Run from the vulnerability-scanner/ directory.
# Redis must be running first (scripts\start_redis.ps1).

param(
    [int]   $Concurrency = 4,
    [string]$LogLevel    = "info"
)

Write-Host ""
Write-Host "=== IVDAF — Starting Celery Worker ===" -ForegroundColor Cyan
Write-Host "  Concurrency : $Concurrency" -ForegroundColor DarkGray
Write-Host "  LogLevel    : $LogLevel"    -ForegroundColor DarkGray
Write-Host ""

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
Set-Location $ProjectDir

# ── Activate virtualenv ───────────────────────────────────────────────────────
$venvActivate = Join-Path $ProjectDir ".venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) { & $venvActivate }

# ── Verify Redis is reachable ─────────────────────────────────────────────────
Write-Host "Checking Redis connection..." -ForegroundColor Yellow
$ping = docker exec vuln-redis redis-cli ping 2>$null
if ($ping -ne "PONG") {
    Write-Host "WARNING: Redis container not responding. Run scripts\start_redis.ps1 first." -ForegroundColor Yellow
}

$env:PYTHONPATH = $ProjectDir

Write-Host "Starting Celery worker..." -ForegroundColor Yellow
Write-Host "  Monitor : http://localhost:5555  (start Flower separately)" -ForegroundColor DarkGray
Write-Host ""

celery -A backend.automation.celery_app worker `
    --loglevel=$LogLevel `
    --concurrency=$Concurrency `
    --queues=celery `
    --hostname="worker@%h"
