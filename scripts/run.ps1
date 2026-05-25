# IVDAF Windows PowerShell Run Script
# Run from the vulnerability-scanner\ directory.
#
# Usage:
#   .\scripts\run.ps1 api        -> start FastAPI backend
#   .\scripts\run.ps1 frontend   -> start Streamlit dashboard
#   .\scripts\run.ps1 worker     -> start Celery worker
#   .\scripts\run.ps1 install    -> create venv + install all deps
#   .\scripts\run.ps1 test       -> run test suite

param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("install","api","frontend","worker","beat","test","docker")]
    [string]$Command
)

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $ProjectRoot

function Activate-Venv {
    $activate = Join-Path $ProjectRoot ".venv\Scripts\Activate.ps1"
    if (Test-Path $activate) { & $activate }
    else { Write-Warning "No .venv found - run: .\scripts\run.ps1 install" }
}

switch ($Command) {

    "install" {
        Write-Host "[install] Creating virtual environment..." -ForegroundColor Cyan
        python -m venv .venv
        & .venv\Scripts\python.exe -m pip install --upgrade pip
        & .venv\Scripts\python.exe -m pip install -r requirements.txt
        # Editable install puts the project root on sys.path permanently.
        & .venv\Scripts\python.exe -m pip install -e .
        Write-Host "[install] Done. Run: .\scripts\run.ps1 api" -ForegroundColor Green
    }

    "api" {
        Activate-Venv
        Write-Host "[api] Starting FastAPI backend on http://localhost:8000" -ForegroundColor Cyan
        & .venv\Scripts\python.exe -m uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
    }

    "frontend" {
        Activate-Venv
        Write-Host "[frontend] Starting Streamlit dashboard on http://localhost:8501" -ForegroundColor Cyan
        $env:PYTHONPATH = $ProjectRoot
        & .venv\Scripts\python.exe -m streamlit run frontend\dashboard.py --server.port 8501 --server.address 0.0.0.0
    }

    "worker" {
        Activate-Venv
        Write-Host "[worker] Starting Celery worker..." -ForegroundColor Cyan
        & .venv\Scripts\python.exe -m celery -A backend.automation.celery_app worker --loglevel=info --concurrency=4
    }

    "beat" {
        Activate-Venv
        Write-Host "[beat] Starting Celery beat scheduler..." -ForegroundColor Cyan
        & .venv\Scripts\python.exe -m celery -A backend.automation.celery_app beat --loglevel=info
    }

    "test" {
        Activate-Venv
        Write-Host "[test] Running test suite..." -ForegroundColor Cyan
        & .venv\Scripts\python.exe -m pytest tests\ -v --asyncio-mode=auto
    }

    "docker" {
        Write-Host "[docker] Building and starting all services..." -ForegroundColor Cyan
        docker-compose up --build
    }
}
