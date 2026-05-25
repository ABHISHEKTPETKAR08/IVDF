# Install Nmap on Windows
# Downloads and installs the official Nmap binary.
# winget will self-elevate with a UAC prompt - no need to start an admin PowerShell.

Write-Host ""
Write-Host "=== IVDAF - Nmap Installer ===" -ForegroundColor Cyan
Write-Host ""

# Check if already installed
$nmapCmd = Get-Command nmap -ErrorAction SilentlyContinue
if ($nmapCmd) {
    $ver = & nmap --version 2>&1 | Select-Object -First 1
    Write-Host "[OK] Nmap already installed: $ver" -ForegroundColor Green
    exit 0
}

# Try winget (Windows 11 / Windows 10 with App Installer)
Write-Host "Attempting install via winget (UAC prompt may appear)..." -ForegroundColor Yellow
$winget = Get-Command winget -ErrorAction SilentlyContinue
if ($winget) {
    winget install --id Insecure.Nmap `
        --accept-source-agreements `
        --accept-package-agreements `
        --silent
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Nmap installed via winget." -ForegroundColor Green
        # Refresh PATH for current session
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH", "User")
        $ver = & nmap --version 2>&1 | Select-Object -First 1
        Write-Host "Version: $ver" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "IMPORTANT: close and reopen your terminal so nmap is on PATH." -ForegroundColor Yellow
        exit 0
    }
}

# Manual installer download fallback
Write-Host "winget not available. Falling back to direct download..." -ForegroundColor Yellow

$nmapVersion   = "7.95"
$installerUrl  = "https://nmap.org/dist/nmap-${nmapVersion}-setup.exe"
$installerPath = "$env:TEMP\nmap-setup.exe"

Write-Host "Downloading from $installerUrl ..." -ForegroundColor DarkGray
try {
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing
} catch {
    Write-Host "ERROR: Download failed - $_" -ForegroundColor Red
    Write-Host "Manual install: https://nmap.org/download.html" -ForegroundColor Yellow
    exit 1
}

Write-Host "Launching installer (UAC prompt will appear)..." -ForegroundColor Yellow
# /S = silent. The .exe itself triggers UAC.
Start-Process -FilePath $installerPath -ArgumentList "/S" -Wait

# Add Nmap to PATH for the current session
$nmapDir = "C:\Program Files (x86)\Nmap"
if (-not (Test-Path $nmapDir)) { $nmapDir = "C:\Program Files\Nmap" }
if (Test-Path $nmapDir) {
    $env:PATH += ";$nmapDir"
    Write-Host "[OK] $nmapDir on PATH (current session)." -ForegroundColor Green
}

# Verify
$ver = & nmap --version 2>&1 | Select-Object -First 1
if ($ver) {
    Write-Host "[OK] Nmap installed: $ver" -ForegroundColor Green
} else {
    Write-Host "WARNING: nmap not on PATH yet. Close and reopen your terminal." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
