# ── Start Celery Flower (task monitor) ────────────────────────────────────────
# Flower provides a real-time web UI for monitoring Celery tasks.
# Access at: http://localhost:5555

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
Set-Location $ProjectDir

$venvActivate = Join-Path $ProjectDir ".venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) { & $venvActivate }

$env:PYTHONPATH = $ProjectDir

Write-Host ""
Write-Host "=== IVDAF — Starting Flower Task Monitor ===" -ForegroundColor Cyan
Write-Host "  UI : http://localhost:5555" -ForegroundColor Green
Write-Host ""

celery -A backend.automation.celery_app flower --port=5555
