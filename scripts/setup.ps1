# ==========================================================================
#  RAG Scan Stack — Windows Setup Script (PowerShell)
# ==========================================================================
#  Single command from fresh clone to running stack.
#
#  Usage:
#    .\scripts\setup.ps1                  # Full setup
#    .\scripts\setup.ps1 -NoStart         # Build only
#    .\scripts\setup.ps1 -SkipGoTools     # Skip Go binary compilation
#    .\scripts\setup.ps1 -Force           # Force rebuild Go tools
#
#  Requirements:
#    - Docker Desktop for Windows (running)
#    - PowerShell 5.1+ or PowerShell Core 7+
# ==========================================================================

param(
    [switch]$SkipGoTools,
    [switch]$Force,
    [switch]$NoStart,
    [switch]$Help
)

if ($Help) {
    Write-Host "Usage: .\scripts\setup.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -SkipGoTools    Skip Go binary compilation"
    Write-Host "  -Force          Force rebuild Go tools"
    Write-Host "  -NoStart        Build only, don't start services"
    Write-Host "  -Help           Show this help"
    exit 0
}

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $ProjectRoot

# ── Helpers ──────────────────────────────────────────────────────────────

function Write-Ok($msg)   { Write-Host "  [OK]    $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [WARN]  $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "  [ERR]   $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "  [INFO]  $msg" -ForegroundColor Cyan }

function Write-Banner($phase, $title) {
    Write-Host ""
    Write-Host ("=" * 62) -ForegroundColor Blue
    Write-Host "  [$phase/7] $title" -ForegroundColor Blue
    Write-Host ("=" * 62) -ForegroundColor Blue
    Write-Host ""
}

function Get-RandomHex($length) {
    $bytes = New-Object byte[] ($length / 2)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return ($bytes | ForEach-Object { $_.ToString("x2") }) -join ''
}

function Get-RandomBase64($length) {
    $bytes = New-Object byte[] $length
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes).Substring(0, $length)
}

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 1 — Dependency Check
# ══════════════════════════════════════════════════════════════════════════
Write-Banner 1 "Checking dependencies"

$depPass = 0
$depFail = 0
$depWarn = 0
$installHints = @()

Write-Host "  Required:" -ForegroundColor White

# Docker
if (Get-Command docker -ErrorAction SilentlyContinue) {
    $dockerVer = docker --version 2>&1 | Select-Object -First 1
    Write-Host "  $([char]0x2713) Docker: $dockerVer" -ForegroundColor Green
    $depPass++
} else {
    Write-Host "  X Docker: NOT FOUND" -ForegroundColor Red
    $installHints += "  Docker Desktop: https://docs.docker.com/desktop/install/windows-install/"
    $depFail++
}

# Docker Compose v2
try {
    $composeVer = docker compose version 2>&1 | Select-Object -First 1
    Write-Host "  $([char]0x2713) Docker Compose: $composeVer" -ForegroundColor Green
    $depPass++
} catch {
    Write-Host "  X Docker Compose v2: NOT FOUND" -ForegroundColor Red
    $installHints += "  Docker Compose: included with Docker Desktop"
    $depFail++
}

# Docker daemon running
try {
    $null = docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  $([char]0x2713) Docker daemon is running" -ForegroundColor Green
        $depPass++
    } else { throw "not running" }
} catch {
    Write-Host "  X Docker daemon is NOT running" -ForegroundColor Red
    $installHints += "  Start Docker Desktop first"
    $depFail++
}

# Git
if (Get-Command git -ErrorAction SilentlyContinue) {
    $gitVer = git --version 2>&1 | Select-Object -First 1
    Write-Host "  $([char]0x2713) Git: $gitVer" -ForegroundColor Green
    $depPass++
} else {
    Write-Host "  X Git: NOT FOUND" -ForegroundColor Red
    $installHints += "  Git: https://git-scm.com/download/win"
    $depFail++
}

# docker-compose.yml
if (Test-Path "docker-compose.yml") {
    Write-Host "  $([char]0x2713) docker-compose.yml found" -ForegroundColor Green
    $depPass++
} else {
    Write-Host "  X docker-compose.yml not found" -ForegroundColor Red
    $installHints += "  Run from the project root: cd path\to\rag-scan-stack"
    $depFail++
}

Write-Host ""
Write-Host "  Optional:" -ForegroundColor White

# NVIDIA GPU — needs both nvidia-smi AND nvidia container runtime registered
$script:GpuAvailable = $false
if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) {
    $gpuName = nvidia-smi --query-gpu=name --format=csv,noheader 2>&1 | Select-Object -First 1
    Write-Host "  $([char]0x2713) NVIDIA GPU: $gpuName" -ForegroundColor Green
    $depPass++
    $dockerInfo = docker info 2>&1 | Out-String
    if ($dockerInfo -match "Runtimes.*nvidia") {
        Write-Host "  $([char]0x2713) nvidia-container-toolkit installed" -ForegroundColor Green
        $script:GpuAvailable = $true
    } else {
        Write-Host "  o nvidia-container-toolkit not found — Ollama will use CPU only" -ForegroundColor Yellow
        $depWarn++
    }
} else {
    Write-Host "  o No NVIDIA GPU detected (gpu compose profile will stay off)" -ForegroundColor Yellow
    $depWarn++
}

# Disk space
$drive = (Get-Item $ProjectRoot).PSDrive
$freeGB = [math]::Round($drive.Free / 1GB)
if ($freeGB -lt 20) {
    Write-Host "  o Disk space: ${freeGB}GB available (recommend 20GB+)" -ForegroundColor Yellow
    $depWarn++
} else {
    Write-Host "  $([char]0x2713) Disk space: ${freeGB}GB available" -ForegroundColor Green
    $depPass++
}

# RAM
$ramGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)
if ($ramGB -lt 8) {
    Write-Host "  o RAM: ${ramGB}GB (recommend 8GB+)" -ForegroundColor Yellow
    $depWarn++
} else {
    Write-Host "  $([char]0x2713) RAM: ${ramGB}GB" -ForegroundColor Green
    $depPass++
}

# Summary
Write-Host ""
Write-Host "  ────────────────────────────────────"
Write-Host "  Pass: $depPass  Warn: $depWarn  Fail: $depFail"
Write-Host ""

if ($depFail -gt 0) {
    Write-Host "  Missing required dependencies:" -ForegroundColor Red
    foreach ($hint in $installHints) {
        Write-Host "  -> $hint" -ForegroundColor Red
    }
    Write-Host ""
    Write-Err "Fix the above issues before continuing."
    exit 1
}

Write-Ok "All required dependencies present"
Write-Ok "Platform: Windows $(if ([Environment]::Is64BitOperatingSystem) {'x64'} else {'x86'})"

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 2 — Go Tool Build
# ══════════════════════════════════════════════════════════════════════════
Write-Banner 2 "Go Tool Build"

if ($SkipGoTools) {
    Write-Info "Skipping Go tool build (--SkipGoTools)"
} else {
    $hasBinaries = (Test-Path "osint_runner/bin/subfinder") -and (Test-Path "pd_runner/bin/httpx")
    if ($hasBinaries -and -not $Force) {
        Write-Ok "Go binaries already exist (use -Force to rebuild)"
    } else {
        Write-Info "Building Go tools via Docker... (this takes 10-15 minutes on first run)"
        & bash scripts/build-go-tools.sh $(if ($Force) { "--force" })
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "Go tool build had issues — some tools may not be available"
        } else {
            Write-Ok "Go tools built successfully"
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 3 — Environment Setup
# ══════════════════════════════════════════════════════════════════════════
Write-Banner 3 "Environment Setup"

if (Test-Path ".env") {
    Write-Ok ".env already exists (keeping current config)"
} else {
    Write-Info "Generating .env with secure credentials..."

    $apiKey = Get-RandomHex 32
    $pgPass = Get-RandomBase64 24
    $zapKey = Get-RandomHex 32
    $chiselPass = Get-RandomBase64 16
    $msfPass = Get-RandomBase64 16
    $edbPass = Get-RandomBase64 16

    $envContent = Get-Content ".env.example" -Raw
    $envContent = $envContent -replace "API_KEY=changeme", "API_KEY=$apiKey"
    $envContent = $envContent -replace "POSTGRES_PASSWORD=app", "POSTGRES_PASSWORD=$pgPass"
    $envContent = $envContent -replace "DB_DSN=postgresql://app:app@", "DB_DSN=postgresql://app:${pgPass}@"
    $envContent = $envContent -replace "ZAP_API_KEY=changeme", "ZAP_API_KEY=$zapKey"
    $envContent = $envContent -replace "CHISEL_PASSWORD=changeme", "CHISEL_PASSWORD=$chiselPass"
    $envContent = $envContent -replace "MSF_RPC_PASS=msf", "MSF_RPC_PASS=$msfPass"
    $envContent = $envContent -replace "EDB_RW_PASSWORD=changeme", "EDB_RW_PASSWORD=$edbPass"

    Set-Content -Path ".env" -Value $envContent
    Write-Ok ".env generated with secure random credentials"
}

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 4 — Infrastructure
# ══════════════════════════════════════════════════════════════════════════
Write-Banner 4 "Infrastructure Setup"

# Docker network
try {
    docker network inspect agents_net *>&1 | Out-Null
    Write-Ok "Docker network 'agents_net' exists"
} catch {
    docker network create agents_net | Out-Null
    Write-Ok "Created Docker network 'agents_net'"
}

# Required directories
$dirs = @(
    "nmap_out", "web_reports", "nuclei_reports", "scan_results",
    "playwright_screenshots", "playwright_reports",
    "autogen_logs", "autogen_cache", "ollama-data",
    "import/swagger", "ssh-keys", "pd_reports",
    "brutus_reports", "osint_reports",
    # Vault container layout (only used when --profile vault is enabled)
    "vault/config", "vault/data", "vault/init", "vault/logs"
)
foreach ($d in $dirs) {
    if (-not (Test-Path $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}
Write-Ok "Data directories created ($($dirs.Count) dirs)"

# SSH key placeholder
if (-not (Test-Path "ssh-keys/id_rsa")) {
    Set-Content -Path "ssh-keys/id_rsa" -Value "# Placeholder — replace with your SSH key"
    Write-Info "Created placeholder SSH key (replace with real key for tunnels)"
}

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 5 — Docker Build
# ══════════════════════════════════════════════════════════════════════════
Write-Banner 5 "Docker Build"

Write-Info "Building all containers (this may take 15-30 minutes on first run)..."
docker compose build
if ($LASTEXITCODE -ne 0) {
    Write-Err "Docker build failed — check errors above"
    exit 1
}
Write-Ok "All containers built successfully"

if ($NoStart) {
    Write-Info "Build complete. Use 'docker compose up -d' to start services."
    exit 0
}

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 6 — Start Services
# ══════════════════════════════════════════════════════════════════════════
Write-Banner 6 "Starting Services"

# Compose profiles: local-db is on by default; gpu is on when a usable GPU
# was detected. Skip local-db when DB_DSN points at a non-rag-postgres host.
$composeProfiles = @("--profile", "local-db")
if (Test-Path .env) {
    $dsnLine = Get-Content .env | Where-Object { $_ -match "^DB_DSN=" }
    if ($dsnLine -and ($dsnLine -notmatch "rag-postgres")) {
        Write-Info "DB_DSN does not reference rag-postgres — disabling local-db profile"
        $composeProfiles = @()
    }
}
if ($script:GpuAvailable) {
    Write-Info "Enabling gpu profile (ollama + embedder-gpu + ollama-init)"
    $composeProfiles += @("--profile", "gpu")
}

Write-Info "Using: docker compose $($composeProfiles -join ' ') up -d"
docker compose @composeProfiles up -d
if ($LASTEXITCODE -ne 0) {
    Write-Err "Failed to start services"
    exit 1
}
Write-Ok "Services starting..."

# Wait for Postgres
Write-Info "Waiting for PostgreSQL to accept connections..."
$pgReady = $false
for ($i = 0; $i -lt 30; $i++) {
    try {
        $result = docker exec rag-postgres pg_isready 2>&1
        if ($result -match "accepting") { $pgReady = $true; break }
    } catch {}
    Start-Sleep -Seconds 2
}
if ($pgReady) {
    Write-Ok "PostgreSQL is ready"
} else {
    Write-Warn "PostgreSQL not ready after 60s — schema may need manual application"
}

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 7 — Health Checks
# ══════════════════════════════════════════════════════════════════════════
Write-Banner 7 "Health Checks"

Write-Info "Waiting 15 seconds for services to initialize..."
Start-Sleep -Seconds 15

$endpoints = @(
    @{ Name = "Dashboard";   URL = "http://localhost:3002" },
    @{ Name = "RAG API";     URL = "http://localhost:8000/docs" },
    @{ Name = "Nmap Scanner"; URL = "http://localhost:8012/health" },
    @{ Name = "Web Scanner";  URL = "http://localhost:8010/health" }
)

$healthy = 0
$total = $endpoints.Count
foreach ($ep in $endpoints) {
    try {
        $resp = Invoke-WebRequest -Uri $ep.URL -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($resp.StatusCode -lt 400) {
            Write-Host "  $([char]0x2713) $($ep.Name): OK" -ForegroundColor Green
            $healthy++
        } else {
            Write-Host "  X $($ep.Name): HTTP $($resp.StatusCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  X $($ep.Name): not responding" -ForegroundColor Yellow
    }
}

# ══════════════════════════════════════════════════════════════════════════
#  Summary
# ══════════════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host ("=" * 62) -ForegroundColor Blue
Write-Host "  Setup Complete!" -ForegroundColor Green
Write-Host ("=" * 62) -ForegroundColor Blue
Write-Host ""
Write-Host "  Dashboard:    http://localhost:3002" -ForegroundColor Cyan
Write-Host "  RAG API:      http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "  Health:       $healthy/$total services responding" -ForegroundColor $(if ($healthy -eq $total) {"Green"} else {"Yellow"})
Write-Host ""
Write-Host ""
Write-Host ("=" * 62) -ForegroundColor Yellow
Write-Host "  First time here? Start with these 4 steps" -ForegroundColor Yellow
Write-Host ("=" * 62) -ForegroundColor Yellow
Write-Host ""
Write-Host "  Detected platform: Windows (PowerShell)" -ForegroundColor White
Write-Host ""
Write-Host "  1. Open the dashboard:    http://localhost:3002"
Write-Host "  2. Create an engagement:  Engagements -> New (sets the scope)"
Write-Host "  3. Configure your proxy:  Settings -> General -> Burp/ZAP preset + Test Proxy"
Write-Host "  4. Launch your first scan: Scans -> target -> category -> scan"
Write-Host ""
Write-Host "  Read these next (in this order):" -ForegroundColor White
Write-Host "    - Docs\README.md                     - project overview"
Write-Host "    - Docs\START_HERE.md                 - operator orientation"
Write-Host "    - Docs\QUICKSTART-WINDOWS.md         - Windows-specific install/start steps"
Write-Host "    - Docs\QUICKSTART-SAMPLE-WORKFLOW.md - end-to-end scan->triage->export walkthrough"
Write-Host ""
Write-Host "  Windows note: Docker Desktop must be running. For better Linux-tooling"
Write-Host "                parity, consider running setup from WSL2 (./scripts/setup.sh)."
Write-Host ""
Write-Host "  Stuck?  bash scripts/post-install-check.sh  (run from WSL) for an end-to-end audit."
Write-Host ""
Write-Host ("=" * 62) -ForegroundColor Yellow
Write-Host ""
