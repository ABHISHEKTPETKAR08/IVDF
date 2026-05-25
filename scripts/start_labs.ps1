# ── Start Vulnerable Lab Targets (Docker) ─────────────────────────────────────
# Runs DVWA, OWASP Juice Shop, and Metasploitable 2 in isolated containers.
# These are intentionally vulnerable apps for EDUCATIONAL use ONLY.
#
# WARNING: Keep these containers on a host-only / isolated network.
#          NEVER expose them to the public internet.

Write-Host ""
Write-Host "=== IVDAF — Starting Vulnerable Lab Targets ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "WARNING: These containers are intentionally vulnerable." -ForegroundColor Yellow
Write-Host "         Only use on a private/isolated network." -ForegroundColor Yellow
Write-Host ""

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Docker not found." -ForegroundColor Red
    exit 1
}

# ── Create isolated lab network ───────────────────────────────────────────────
$labNet = "vuln-labs"
$netExists = docker network ls --filter "name=$labNet" --format "{{.Name}}" 2>$null
if ($netExists -ne $labNet) {
    Write-Host "Creating isolated Docker network '$labNet'..." -ForegroundColor Yellow
    docker network create --driver bridge --internal $labNet | Out-Null
}

# ── DVWA (Damn Vulnerable Web Application) ────────────────────────────────────
Write-Host "Starting DVWA..." -ForegroundColor Yellow
$dvwaRunning = docker ps --filter "name=dvwa" --format "{{.Names}}" 2>$null
if ($dvwaRunning -ne "dvwa") {
    docker run -d `
        --name dvwa `
        --network $labNet `
        -p 8081:80 `
        --restart unless-stopped `
        vulnerables/web-dvwa
    Write-Host "  [OK] DVWA started" -ForegroundColor Green
    Write-Host "       URL  : http://localhost:8081" -ForegroundColor Cyan
    Write-Host "       Login: admin / password" -ForegroundColor DarkGray
} else {
    Write-Host "  [RUNNING] DVWA already running at http://localhost:8081" -ForegroundColor Green
}
Write-Host ""

# ── OWASP Juice Shop ──────────────────────────────────────────────────────────
Write-Host "Starting OWASP Juice Shop..." -ForegroundColor Yellow
$jsRunning = docker ps --filter "name=juiceshop" --format "{{.Names}}" 2>$null
if ($jsRunning -ne "juiceshop") {
    docker run -d `
        --name juiceshop `
        --network $labNet `
        -p 3000:3000 `
        --restart unless-stopped `
        bkimminich/juice-shop
    Write-Host "  [OK] Juice Shop started" -ForegroundColor Green
    Write-Host "       URL : http://localhost:3000" -ForegroundColor Cyan
} else {
    Write-Host "  [RUNNING] Juice Shop already running at http://localhost:3000" -ForegroundColor Green
}
Write-Host ""

# ── Metasploitable 2 (tleemcjr image — light alternative) ────────────────────
Write-Host "Starting Metasploitable 2..." -ForegroundColor Yellow
$msRunning = docker ps --filter "name=metasploitable" --format "{{.Names}}" 2>$null
if ($msRunning -ne "metasploitable") {
    docker run -d `
        --name metasploitable `
        --network $labNet `
        -p 2222:22 `
        -p 8082:80 `
        -p 2121:21 `
        --restart unless-stopped `
        tleemcjr/metasploitable2
    Write-Host "  [OK] Metasploitable 2 started" -ForegroundColor Green
    Write-Host "       HTTP : http://localhost:8082" -ForegroundColor Cyan
    Write-Host "       SSH  : ssh msfadmin@localhost -p 2222 (pw: msfadmin)" -ForegroundColor DarkGray
} else {
    Write-Host "  [RUNNING] Metasploitable already running" -ForegroundColor Green
}
Write-Host ""

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host "=== Lab Environment Ready ===" -ForegroundColor Green
Write-Host ""
Write-Host "Scan targets for IVDAF:" -ForegroundColor Cyan
Write-Host "  DVWA         : http://localhost:8081" -ForegroundColor White
Write-Host "  Juice Shop   : http://localhost:3000" -ForegroundColor White
Write-Host "  Metasploitable: http://localhost:8082" -ForegroundColor White
Write-Host ""
Write-Host "Stop all labs: docker stop dvwa juiceshop metasploitable" -ForegroundColor DarkGray
Write-Host ""
