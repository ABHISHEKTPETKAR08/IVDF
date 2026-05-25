# ── System Health Check ────────────────────────────────────────────────────────
# Checks all IVDAF subsystems and reports their status.

param(
    [string]$ApiUrl = "http://localhost:8000"
)

Write-Host ""
Write-Host "=== IVDAF — System Health Check ===" -ForegroundColor Cyan
Write-Host "  API : $ApiUrl" -ForegroundColor DarkGray
Write-Host ""

$ok  = "[OK]"
$err = "[FAIL]"
$warn = "[WARN]"
$all_ok = $true

# ── FastAPI Backend ───────────────────────────────────────────────────────────
Write-Host "Checking FastAPI backend..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$ApiUrl/health/full" -TimeoutSec 15 -ErrorAction Stop
    Write-Host "  $ok  FastAPI         : $($health.status)" -ForegroundColor Green
    Write-Host "  $ok  Database        : $($health.database)" -ForegroundColor Green

    if ($health.redis -like "connected*") {
        Write-Host "  $ok  Redis           : $($health.redis)" -ForegroundColor Green
    } else {
        Write-Host "  $warn Redis           : $($health.redis)" -ForegroundColor Yellow
        $all_ok = $false
    }

    if ($health.celery -eq "running") {
        Write-Host "  $ok  Celery workers : running" -ForegroundColor Green
    } elseif ($health.celery -eq "no workers") {
        Write-Host "  $warn Celery workers : no workers active (asyncio fallback in use)" -ForegroundColor Yellow
    } else {
        Write-Host "  $warn Celery         : $($health.celery)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  $err FastAPI backend not reachable at $ApiUrl" -ForegroundColor Red
    Write-Host "       Error: $_" -ForegroundColor DarkGray
    Write-Host "       Start with: scripts\start_backend.ps1" -ForegroundColor Yellow
    $all_ok = $false
}
Write-Host ""

# ── Redis ─────────────────────────────────────────────────────────────────────
Write-Host "Checking Redis..." -ForegroundColor Yellow
$redisRunning = docker ps --filter "name=vuln-redis" --format "{{.Names}}" 2>$null
if ($redisRunning -eq "vuln-redis") {
    $ping = docker exec vuln-redis redis-cli ping 2>$null
    if ($ping -eq "PONG") {
        Write-Host "  $ok  Redis container : running (PONG)" -ForegroundColor Green
    } else {
        Write-Host "  $err Redis container : not responding" -ForegroundColor Red
        $all_ok = $false
    }
} else {
    Write-Host "  $err Redis container 'vuln-redis' not running" -ForegroundColor Red
    Write-Host "       Start with: scripts\start_redis.ps1" -ForegroundColor Yellow
    $all_ok = $false
}
Write-Host ""

# ── Nmap ──────────────────────────────────────────────────────────────────────
Write-Host "Checking Nmap..." -ForegroundColor Yellow
$nmapCmd = Get-Command nmap -ErrorAction SilentlyContinue
if ($nmapCmd) {
    $nmapVer = & nmap --version 2>&1 | Select-Object -First 1
    Write-Host "  $ok  nmap binary : $nmapVer" -ForegroundColor Green
} else {
    Write-Host "  $warn nmap binary not found — port scanning will use pure-Python fallback" -ForegroundColor Yellow
    Write-Host "       Install: scripts\install_nmap.ps1 (run as Administrator)" -ForegroundColor DarkGray
}
Write-Host ""

# ── Python packages ───────────────────────────────────────────────────────────
Write-Host "Checking Python packages..." -ForegroundColor Yellow
$pkgs = @{
    "fastapi"    = "fastapi"
    "sqlalchemy" = "sqlalchemy"
    "celery"     = "celery"
    "redis"      = "redis"
    "httpx"      = "httpx"
    "nmap"       = "nmap"          # python-nmap
    "whois"      = "whois"         # python-whois
    "streamlit"  = "streamlit"
}
foreach ($label in $pkgs.Keys) {
    $mod = $pkgs[$label]
    $ver = python -c "import $mod; v=getattr($mod,'__version__','?'); print(v)" 2>$null
    if ($ver) {
        Write-Host "  $ok  $label ($ver)" -ForegroundColor Green
    } else {
        Write-Host "  $warn $label not installed" -ForegroundColor Yellow
    }
}
Write-Host ""

# ── Streamlit ─────────────────────────────────────────────────────────────────
Write-Host "Checking Streamlit frontend..." -ForegroundColor Yellow
try {
    $st = Invoke-WebRequest -Uri "http://localhost:8501/_stcore/health" -TimeoutSec 3 -ErrorAction Stop
    Write-Host "  $ok  Streamlit : running at http://localhost:8501" -ForegroundColor Green
} catch {
    Write-Host "  $warn Streamlit not running" -ForegroundColor Yellow
    Write-Host "       Start with: scripts\start_frontend.ps1" -ForegroundColor DarkGray
}
Write-Host ""

# ── Summary ───────────────────────────────────────────────────────────────────
if ($all_ok) {
    Write-Host "=== ALL CORE SYSTEMS HEALTHY ===" -ForegroundColor Green
} else {
    Write-Host "=== SOME SYSTEMS NEED ATTENTION (see above) ===" -ForegroundColor Yellow
}
Write-Host ""
