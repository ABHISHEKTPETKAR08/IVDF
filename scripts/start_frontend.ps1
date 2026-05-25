# ── Start Streamlit Frontend ───────────────────────────────────────────────────

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
Set-Location $ProjectDir

$venvActivate = Join-Path $ProjectDir ".venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) { & $venvActivate }

$env:PYTHONPATH = $ProjectDir

Write-Host ""
Write-Host "=== IVDAF — Starting Streamlit Frontend ===" -ForegroundColor Cyan
Write-Host "  URL : http://localhost:8501" -ForegroundColor Green
Write-Host ""

streamlit run frontend/dashboard.py `
    --server.port=8501 `
    --server.address=localhost `
    --browser.gatherUsageStats=false
