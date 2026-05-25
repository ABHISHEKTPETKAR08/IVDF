# ── Start Redis via Docker ─────────────────────────────────────────────────────
# Starts a Redis 7 container on the default port 6379.
# Requires Docker Desktop to be running.

$CONTAINER = "vuln-redis"
$PORT      = 6379

Write-Host ""
Write-Host "=== IVDAF — Starting Redis ===" -ForegroundColor Cyan

# Check Docker is available
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/" -ForegroundColor Red
    exit 1
}

# Remove stopped container with same name if it exists
$existing = docker ps -a --filter "name=$CONTAINER" --format "{{.Names}}" 2>$null
if ($existing -eq $CONTAINER) {
    $state = docker inspect -f "{{.State.Status}}" $CONTAINER 2>$null
    if ($state -eq "running") {
        Write-Host "Redis container '$CONTAINER' already running." -ForegroundColor Green
    } else {
        Write-Host "Removing stopped container '$CONTAINER'..." -ForegroundColor Yellow
        docker rm $CONTAINER | Out-Null
    }
}

# Start fresh container
$state = docker inspect -f "{{.State.Status}}" $CONTAINER 2>$null
if ($state -ne "running") {
    Write-Host "Starting Redis container on port $PORT..." -ForegroundColor Yellow
    docker run -d `
        --name $CONTAINER `
        -p "${PORT}:6379" `
        --restart unless-stopped `
        redis:7-alpine `
        redis-server --save 60 1 --loglevel warning
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to start Redis container." -ForegroundColor Red
        exit 1
    }
}

# Wait for Redis to be ready
Write-Host "Waiting for Redis to be ready..." -ForegroundColor Yellow
$retries = 10
for ($i = 0; $i -lt $retries; $i++) {
    $ping = docker exec $CONTAINER redis-cli ping 2>$null
    if ($ping -eq "PONG") {
        Write-Host "Redis is ready! (PONG received)" -ForegroundColor Green
        Write-Host ""
        Write-Host "  URL : redis://localhost:$PORT/0" -ForegroundColor Cyan
        Write-Host "  Stop: docker stop $CONTAINER" -ForegroundColor DarkGray
        Write-Host ""
        exit 0
    }
    Start-Sleep -Seconds 1
}

Write-Host "ERROR: Redis did not respond after $retries seconds." -ForegroundColor Red
exit 1
