# ── Start FastAPI Backend ──────────────────────────────────────────────────────
# Run from the vulnerability-scanner/ directory.
# Activates the virtualenv if present, then starts Uvicorn.

param(
    [string]$Host    = "0.0.0.0",
    [int]   $Port    = 8000,
    [switch]$Debug,
    [switch]$Reload
)

Write-Host ""
Write-Host "=== IVDAF — Starting FastAPI Backend ===" -ForegroundColor Cyan
Write-Host "  Host : $Host"  -ForegroundColor DarkGray
Write-Host "  Port : $Port"  -ForegroundColor DarkGray
Write-Host ""

# ── Resolve project root ──────────────────────────────────────────────────────
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
Set-Location $ProjectDir

# ── Activate virtualenv if present ───────────────────────────────────────────
$venvActivate = Join-Path $ProjectDir ".venv\Scripts\Activate.ps1"
if (Test-Path $venvActivate) {
    Write-Host "Activating virtualenv..." -ForegroundColor Yellow
    & $venvActivate
} else {
    Write-Host "No .venv found — using system Python." -ForegroundColor DarkGray
}

# ── Ensure .env is loaded ─────────────────────────────────────────────────────
if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Write-Host "WARNING: .env not found — copying from .env.example" -ForegroundColor Yellow
        Copy-Item ".env.example" ".env"
    }
}

# ── Build uvicorn arguments ───────────────────────────────────────────────────
$logLevel  = if ($Debug) { "debug" } else { "info" }
$reloadArg = if ($Reload -or $Debug) { "--reload" } else { "" }

Write-Host "Starting Uvicorn..." -ForegroundColor Yellow
Write-Host "  Docs : http://localhost:$Port/docs" -ForegroundColor Green
Write-Host "  Health: http://localhost:$Port/health" -ForegroundColor Green
Write-Host ""

$env:PYTHONPATH = $ProjectDir

if ($reloadArg) {
    uvicorn backend.app:app --host $Host --port $Port --log-level $logLevel --reload
} else {
    uvicorn backend.app:app --host $Host --port $Port --log-level $logLevel
}
