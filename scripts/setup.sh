#!/usr/bin/env bash
# ==========================================================================
#  RAG Scan Stack — Unified Setup Script
# ==========================================================================
#  Single command from fresh clone to running stack.
#
#  Usage:
#    ./scripts/setup.sh                  # Full setup (build + start)
#    ./scripts/setup.sh --no-start       # Build only, don't start services
#    ./scripts/setup.sh --skip-go-tools  # Skip Go binary compilation
#    ./scripts/setup.sh --force          # Rebuild Go tools even if they exist
#    ./scripts/setup.sh --non-interactive # No prompts, use defaults
#
#  Phases:
#    1. Prerequisites     — check docker, compose, GPU
#    2. Go Tool Build     — compile Go security tools (~10-15 min first time)
#    3. Environment       — generate .env with secure credentials
#    4. Infrastructure    — create network, directories, kong config
#    5. Docker Build      — docker compose build
#    6. Start Services    — docker compose up -d
#    7. Database Schema   — wait for postgres, apply schema
#    8. Health Check      — verify services are responding
# ==========================================================================

set -euo pipefail
cd "$(dirname "$0")/.."
PROJECT_ROOT="$(pwd)"

# ── Install log (single file, timestamped) ────────────────────────────────
# Everything from this point is tee'd to logs/setup-<ts>.log so a failing
# run leaves behind a complete transcript that's easy to attach to a bug
# report.  The log path is printed at the start and end of the run.
#
# logs/ is .gitignore'd; we create it lazily here in case fresh clones
# don't have the directory yet.
mkdir -p "$PROJECT_ROOT/logs"
LOG_FILE="$PROJECT_ROOT/logs/setup-$(date +%Y%m%d-%H%M%S).log"
# Use process substitution so both stdout and stderr land in the log while
# still being visible on the operator's terminal.  Works in bash 4+ which
# is the floor for macOS (via brew) and every supported Linux/WSL distro.
exec > >(tee -a "$LOG_FILE") 2>&1
echo "Full setup log: $LOG_FILE"
echo ""

# ── Seed db-config.json as a FILE ─────────────────────────────────────────
# docker-compose bind-mounts ./db-config.json into container-logs and
# pentest-dashboard (`./db-config.json:/app/db-config.json`).  If the host
# path does not exist when `docker compose up` first runs, Docker silently
# creates it as a *directory* -- which then makes _write_db_config() fail
# with IsADirectoryError and blocks every DB mode switch.  Pre-create it as
# a file (default local mode) before any compose run so the mount is a file.
DB_CONFIG_FILE="$PROJECT_ROOT/db-config.json"
if [ -d "$DB_CONFIG_FILE" ]; then
    # A previous run (or a compose up before this fix) left a directory here.
    # Only safe to remove if empty; rmdir fails loudly otherwise.
    if rmdir "$DB_CONFIG_FILE" 2>/dev/null; then
        echo '{"mode": "local"}' > "$DB_CONFIG_FILE"
        echo "Replaced stray db-config.json directory with a seeded file"
    else
        echo "WARNING: db-config.json exists as a non-empty directory -- " \
             "please inspect and replace it with a JSON file ({\"mode\":\"local\"})"
    fi
elif [ ! -f "$DB_CONFIG_FILE" ]; then
    echo '{"mode": "local"}' > "$DB_CONFIG_FILE"
    echo "Seeded db-config.json (default local mode)"
fi

# ── Flags ──────────────────────────────────────────────────────────────────
SKIP_GO_TOOLS=false
FORCE_GO_TOOLS=false
NO_START=false
NON_INTERACTIVE=false
GPU_OVERRIDE=auto   # auto | force | skip — Phase 1 sets GPU_AVAILABLE; Phase 6 honors this
SKIP_DEP_INSTALL=false   # Phase 1 auto-installs missing host deps (Docker, CLIs); --no-install disables

for arg in "$@"; do
    case "$arg" in
        --skip-go-tools)  SKIP_GO_TOOLS=true ;;
        --force)          FORCE_GO_TOOLS=true ;;
        --no-start)       NO_START=true ;;
        --non-interactive) NON_INTERACTIVE=true ;;
        --gpu)            GPU_OVERRIDE=force ;;
        --no-gpu)         GPU_OVERRIDE=skip ;;
        --no-install)     SKIP_DEP_INSTALL=true ;;
        -h|--help)
            echo "Usage: ./scripts/setup.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-go-tools    Skip Phase 2 (Go binary compilation)"
            echo "  --force            Rebuild Go tools even if binaries exist"
            echo "  --no-start         Stop after Docker build (Phase 5)"
            echo "  --non-interactive  No prompts, use defaults everywhere"
            echo "  --gpu              Force-enable the gpu compose profile (ollama + embedder-gpu)"
            echo "  --no-gpu           Skip the gpu profile even if a GPU is detected"
            echo "  --no-install       Do NOT auto-install missing host deps (Docker, CLIs, GPU toolkit)"
            echo "  -h, --help         Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $arg (use --help for usage)"
            exit 1
            ;;
    esac
done

# ── Colors ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

banner() {
    echo ""
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  [$1/9] $2${NC}"
    echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

log_ok()   { echo -e "  ${GREEN}[OK]${NC}    $1"; }
log_skip() { echo -e "  ${YELLOW}[SKIP]${NC}  $1"; }
log_info() { echo -e "  ${BLUE}[INFO]${NC}  $1"; }
log_warn() { echo -e "  ${YELLOW}[WARN]${NC}  $1"; }
log_err()  { echo -e "  ${RED}[ERR]${NC}   $1"; }

PHASE_STATUS=()
record_phase() { PHASE_STATUS+=("$1"); }

SECONDS=0  # bash built-in timer

# ── Platform detection ────────────────────────────────────────────────────
IS_MAC=false
IS_APPLE_SILICON=false
IS_WSL=false
IS_LINUX=false
PLATFORM_LABEL="linux"
MAC_CHIP_NAME=""
MAC_TOTAL_RAM_GB=0
COMPOSE_FILES="-f docker-compose.yml"

# Compose profiles to include. `local-db` is on by default so a fresh install
# brings up rag-postgres without the user knowing about profiles. When DB_DSN
# already points at a remote database, we skip this profile (see Phase 6).
COMPOSE_PROFILES="--profile local-db"

detect_platform() {
    if [ "$(uname -s)" != "Darwin" ]; then
        IS_LINUX=true
        PLATFORM_LABEL="linux"
        # WSL detection — /proc/version contains "Microsoft" or "WSL" on WSL1/2
        if grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null; then
            IS_WSL=true
            PLATFORM_LABEL="wsl"
        fi
        return
    fi
    IS_MAC=true
    PLATFORM_LABEL="macos"

    # Detect Apple Silicon chip name (M1/M2/M3/M4/M5 etc.)
    local chip
    chip=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "")
    if echo "$chip" | grep -qi "apple"; then
        IS_APPLE_SILICON=true
        # Extract the chip marketing name from system_profiler
        MAC_CHIP_NAME=$(system_profiler SPHardwareDataType 2>/dev/null \
            | awk -F': ' '/Chip/ {print $2; exit}' | xargs)
        if [ -z "$MAC_CHIP_NAME" ]; then
            MAC_CHIP_NAME="Apple Silicon"
        fi
    fi

    # Total RAM in GB
    local ram_bytes
    ram_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
    if [ "$ram_bytes" -gt 0 ] 2>/dev/null; then
        MAC_TOTAL_RAM_GB=$((ram_bytes / 1073741824))
    fi

    # Use mac compose overlay
    if [ -f "docker-compose.mac.yml" ]; then
        COMPOSE_FILES="-f docker-compose.yml -f docker-compose.mac.yml"
    fi
}

detect_platform

# ══════════════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════════════
#  Preflight: strict host gates + (on supported hosts) Docker auto-install
# ══════════════════════════════════════════════════════════════════════════
#
# Two-stage preflight before Phase 1:
#
#   1. OS gate (strict): macOS any, or WSL2 Ubuntu 22.04/24.04 only.
#      Refuses bare-metal Linux, WSL1, non-Ubuntu WSL distros, other
#      Ubuntu versions.  Set first so the auto-installer (step 2) never
#      runs on hosts where the stack isn't validated.
#
#   2. Host dependency provisioning: when the OS gate passes, auto-install
#      Docker Engine + Compose v2 plugin if absent (Ubuntu/WSL2 + RHEL
#      family).  Scoped to genuine host prerequisites only -- the
#      language toolchains (Go, Node, Python) and per-tool security
#      binaries are deliberately NOT installed here: every build runs
#      inside containers, so the host never needs them.
#
#   3. Remaining gates (Docker daemon, Compose v2 >= 2.20, resource
#      floors RAM/CPU/disk, BuildKit/buildx).  If any of these still
#      fail after the auto-installer ran, exit with a summary so the
#      operator can fix the root cause and re-run -- no half-installed
#      stack.
#
# All output (including the gate transcript) is tee'd to logs/setup-
# <ts>.log via the exec redirection at the top of this script.

# ── Host dependency provisioning (#17/#26) ─────────────────────────────────
#  Host dependency provisioning
# ──────────────────────────────────────────────────────────────────────────
#  Makes setup.sh a single entry point: it installs everything the host needs
#  to BUILD and RUN the stack, then verifies it below. Scoped to genuine host
#  prerequisites only — Docker + Docker Compose, a handful of CLIs, and the
#  optional NVIDIA toolkit. The language toolchains (Go, Node, Python) and the
#  per-tool security binaries are deliberately NOT installed here: every build
#  runs inside containers, so the host never needs them.
# ══════════════════════════════════════════════════════════════════════════
_sudo() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

PKG_MGR=""
_detect_pkg_mgr() {
    local m
    for m in apt-get dnf yum apk brew; do
        if command -v "$m" &>/dev/null; then PKG_MGR="$m"; return 0; fi
    done
    return 1
}

# Generic package install across the supported managers.
_pm_install() {
    [ $# -eq 0 ] && return 0
    case "$PKG_MGR" in
        apt-get) _sudo apt-get install -y -qq "$@" ;;
        dnf)     _sudo dnf install -y "$@" ;;
        yum)     _sudo yum install -y "$@" ;;
        apk)     _sudo apk add --no-cache "$@" ;;
        brew)    brew install "$@" ;;
        *)       return 1 ;;
    esac
}

# Install Docker Engine + Compose v2 plugin when absent. On WSL the daemon
# normally comes from Docker Desktop integration, so we don't fight that.
_install_docker() {
    if command -v docker &>/dev/null && docker compose version &>/dev/null; then
        return 0
    fi
    if [ "$IS_WSL" = true ] && [ -f /proc/sys/fs/binfmt_misc/WSLInterop ]; then
        log_warn "Docker not found under WSL — enable Docker Desktop's WSL integration"
        log_warn "  (Docker Desktop → Settings → Resources → WSL Integration), then re-run."
        return 1
    fi
    case "$PKG_MGR" in
        apt-get)
            log_info "Installing Docker Engine + Compose plugin (apt)..."
            _sudo install -m 0755 -d /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
                | _sudo gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
            _sudo chmod a+r /etc/apt/keyrings/docker.gpg
            # download.docker.com lags new Ubuntu releases; pin a known-good
            # codename for very recent / non-LTS versions.
            local codename arch
            codename=$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-}")
            case "$codename" in
                focal|jammy|noble|bookworm|bullseye) ;;          # supported as-is
                *) log_info "No Docker repo for '$codename' — falling back to noble (24.04)"; codename="noble" ;;
            esac
            arch=$(dpkg --print-architecture)
            echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable" \
                | _sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
            _sudo apt-get update -qq
            _sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
        dnf|yum)
            log_info "Installing Docker Engine + Compose plugin ($PKG_MGR)..."
            _sudo "$PKG_MGR" install -y dnf-plugins-core || true
            _sudo "$PKG_MGR" config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo 2>/dev/null || true
            _sudo "$PKG_MGR" install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
        *)
            log_warn "Cannot auto-install Docker with '$PKG_MGR' — install it manually: https://docs.docker.com/engine/install/"
            return 1
            ;;
    esac
    # Start + enable the daemon (systemd hosts) and grant the user docker access.
    if command -v systemctl &>/dev/null; then
        _sudo systemctl enable --now docker 2>/dev/null || true
    fi
    if [ "$(id -u)" -ne 0 ] && ! groups 2>/dev/null | grep -qw docker; then
        _sudo usermod -aG docker "${USER:-$(id -un)}" 2>/dev/null || true
        log_warn "Added ${USER:-$(id -un)} to the 'docker' group — log out/in for it to take effect."
    fi
}

# Install the NVIDIA Container Toolkit so containers can use the GPU. Mirrors
# the upstream install guide; configures the docker runtime and restarts it.
_install_nvidia_toolkit() {
    case "$PKG_MGR" in
        apt-get)
            curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
                | _sudo gpg --dearmor --yes -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
            curl -fsSL https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
                | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
                | _sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list >/dev/null
            _sudo apt-get update -qq
            _sudo apt-get install -y -qq nvidia-container-toolkit
            ;;
        dnf|yum)
            curl -fsSL https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo \
                | _sudo tee /etc/yum.repos.d/nvidia-container-toolkit.repo >/dev/null
            _sudo "$PKG_MGR" install -y nvidia-container-toolkit
            ;;
        *) return 1 ;;
    esac
    _sudo nvidia-ctk runtime configure --runtime=docker 2>/dev/null || true
    if command -v systemctl &>/dev/null; then
        _sudo systemctl restart docker 2>/dev/null || true
    fi
}

# Provision the base host dependencies. Best-effort: per-package failures warn
# rather than abort, so the Phase 1 checks below remain the source of truth.
_install_host_deps() {
    if [ "$SKIP_DEP_INSTALL" = true ]; then
        log_skip "Host dependency install disabled (--no-install)"
        return 0
    fi
    if ! _detect_pkg_mgr; then
        log_warn "No supported package manager found — skipping auto-install (checks below still run)"
        return 0
    fi
    log_info "Provisioning host dependencies via ${PKG_MGR} (use --no-install to skip)"

    # Base CLIs the build/run actually uses. ssh-keygen ← openssh-client;
    # gnupg/ca-certificates are needed to add the Docker apt repo.
    local base
    case "$PKG_MGR" in
        apt-get) base="curl wget git unzip jq openssl ca-certificates gnupg lsb-release software-properties-common openssh-client" ;;
        apk)     base="curl wget git unzip jq openssl ca-certificates gnupg openssh" ;;
        *)       base="curl wget git unzip jq openssl ca-certificates gnupg openssh-clients" ;;
    esac

    # Install only what's missing to keep re-runs fast and quiet. On apt the
    # authoritative installed-check is `dpkg -s`; elsewhere fall back to probing
    # for the relevant binary (some packages ship no same-named command).
    local want=() pkg bin
    for pkg in $base; do
        if [ "$PKG_MGR" = "apt-get" ]; then
            dpkg -s "$pkg" &>/dev/null && continue
        else
            case "$pkg" in
                openssh-client|openssh|openssh-clients)                    bin="ssh-keygen" ;;
                gnupg)                                                     bin="gpg" ;;
                ca-certificates|lsb-release|apt-transport-https|software-properties-common) bin="" ;;
                *)                                                         bin="$pkg" ;;
            esac
            if [ -n "$bin" ] && command -v "$bin" &>/dev/null; then continue; fi
        fi
        want+=("$pkg")
    done
    # Refresh apt metadata only when we actually have something to install.
    [ "$PKG_MGR" = "apt-get" ] && [ ${#want[@]} -gt 0 ] && { _sudo apt-get update -qq || true; }
    if [ ${#want[@]} -gt 0 ]; then
        log_info "Installing base packages: ${want[*]}"
        _pm_install "${want[@]}" || log_warn "Some base packages failed to install — see checks below"
    else
        log_ok "Base CLI packages already present"
    fi

    # Docker Engine + Compose
    _install_docker || true
}



# ── Preflight gate definitions ─────────────────────────────────────────────
PREFLIGHT_BLOCKERS=()
preflight_block() { PREFLIGHT_BLOCKERS+=("$1"); }

# ── Gate 1: supported host (macOS any, or WSL2 Ubuntu 22.04/24.04) ───────
gate_os_supported() {
    if [ "$IS_MAC" = true ]; then
        log_ok "Host: macOS (${MAC_CHIP_NAME:-Intel/unknown}, ${MAC_TOTAL_RAM_GB}GB RAM)"
        return
    fi

    if [ "$IS_WSL" != true ]; then
        log_err "Host is bare-metal Linux -- only macOS or WSL2 Ubuntu are supported by this installer."
        log_err "  Bare-metal Linux installs work but aren't validated; if you want to proceed anyway,"
        log_err "  comment out the gate_os_supported call in scripts/setup.sh and re-run."
        preflight_block "Unsupported host (bare-metal Linux)"
        return
    fi

    # Distinguish WSL1 from WSL2 -- WSL2 kernel string contains "WSL2"
    if ! /usr/bin/uname -r 2>/dev/null | /usr/bin/grep -qiE "WSL2|microsoft-standard-WSL"; then
        log_err "Host is WSL1 -- only WSL2 is supported (WSL1 lacks docker integration)."
        log_err "  Upgrade with: wsl --set-version <distro> 2"
        preflight_block "WSL1 detected (need WSL2)"
        return
    fi

    # Distinguish Ubuntu version (22.04 or 24.04 only)
    local distro="" version=""
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        distro="${ID:-}"
        version="${VERSION_ID:-}"
    fi
    if [ "$distro" != "ubuntu" ]; then
        log_err "WSL distro is '${distro:-unknown}' -- only Ubuntu is supported."
        log_err "  Install Ubuntu 22.04 LTS or 24.04 LTS from the Microsoft Store, then re-run."
        preflight_block "WSL distro is not Ubuntu (got '${distro:-unknown}')"
        return
    fi
    case "$version" in
        22.04|24.04)
            log_ok "Host: WSL2 Ubuntu $version"
            ;;
        *)
            log_err "WSL Ubuntu version $version is not supported -- need 22.04 or 24.04 (LTS only)."
            log_err "  20.04 is past mainstream support; non-LTS versions are not validated."
            preflight_block "Unsupported Ubuntu version ($version)"
            ;;
    esac
}

# ── Gate 2: Docker daemon reachable ──────────────────────────────────────
gate_docker_daemon() {
    if ! command -v docker &>/dev/null; then
        log_err "Docker CLI not installed."
        log_err "  macOS:        brew install --cask docker  (then launch Docker.app)"
        log_err "  WSL2 Ubuntu:  install Docker Desktop on Windows host with WSL integration enabled"
        preflight_block "Docker CLI missing"
        return
    fi
    if ! docker info >/dev/null 2>&1; then
        log_err "Docker daemon is not reachable -- the CLI is installed but \`docker info\` fails."
        log_err "  macOS:        launch Docker Desktop (or run: open -a Docker)"
        log_err "  WSL2:         start Docker Desktop on Windows + enable WSL integration"
        log_err "  Linux:        sudo systemctl start docker"
        preflight_block "Docker daemon not reachable"
        return
    fi
    log_ok "Docker daemon reachable"
}

# ── Gate 3: Compose v2 + version >= 2.20 ─────────────────────────────────
gate_compose_v2() {
    if ! docker compose version >/dev/null 2>&1; then
        log_err "Docker Compose v2 (the \`docker compose\` subcommand) is not available."
        log_err "  This repo requires Compose v2.  The standalone \`docker-compose\` (with hyphen)"
        log_err "  is Compose v1 and is NOT compatible -- it lacks features used by this stack."
        preflight_block "Compose v2 subcommand missing"
        return
    fi
    # Parse version (e.g. "Docker Compose version v2.27.0" -> 2.27.0)
    local raw major minor
    raw=$(docker compose version 2>/dev/null | /usr/bin/awk '{for(i=1;i<=NF;i++) if ($i ~ /^v?[0-9]+\.[0-9]+/) {print $i; exit}}' | /usr/bin/tr -d 'v')
    major=$(echo "$raw" | /usr/bin/awk -F. '{print $1+0}')
    minor=$(echo "$raw" | /usr/bin/awk -F. '{print $2+0}')
    if [ -z "$raw" ] || [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 20 ]; }; then
        log_err "Docker Compose version is '$raw' -- need >= 2.20."
        log_err "  Upgrade Docker Desktop, or apt-get install --only-upgrade docker-compose-plugin"
        preflight_block "Compose version too old (have $raw, need >=2.20)"
        return
    fi
    log_ok "Docker Compose v$raw"
}

# ── Gate 4: resource floors (RAM, CPU, disk available to Docker) ─────────
gate_docker_resources() {
    # `docker info --format` returns the limits Docker actually has, which
    # matters more than the host's bare metal (Docker Desktop on macOS
    # caps memory + CPU per its own settings).
    local d_ncpu d_mem_bytes d_mem_gb avail_gb
    d_ncpu=$(docker info --format '{{.NCPU}}' 2>/dev/null || echo 0)
    d_mem_bytes=$(docker info --format '{{.MemTotal}}' 2>/dev/null || echo 0)
    d_mem_gb=$((d_mem_bytes / 1073741824))

    if [ "$d_ncpu" -lt 4 ]; then
        log_err "Docker has only $d_ncpu CPU(s) allocated -- need >= 4."
        log_err "  macOS:  Docker Desktop -> Settings -> Resources -> CPUs"
        log_err "  WSL2:   adjust .wslconfig: [wsl2] processors=4"
        preflight_block "Docker CPU allocation $d_ncpu (need >=4)"
    else
        log_ok "Docker CPUs: $d_ncpu"
    fi

    if [ "$d_mem_gb" -lt 16 ]; then
        log_err "Docker has only ${d_mem_gb}GB RAM allocated -- need >= 16GB."
        log_err "  macOS:  Docker Desktop -> Settings -> Resources -> Memory"
        log_err "  WSL2:   adjust .wslconfig: [wsl2] memory=16GB"
        preflight_block "Docker RAM allocation ${d_mem_gb}GB (need >=16GB)"
    else
        log_ok "Docker RAM: ${d_mem_gb}GB"
    fi

    # Available disk under the project root.  df -k is portable; the
    # fourth column is "available" in 1K blocks.
    avail_gb=$(/bin/df -k "$PROJECT_ROOT" 2>/dev/null | /usr/bin/awk 'NR==2 {print int($4/1048576)}')
    if [ -z "$avail_gb" ] || [ "$avail_gb" -lt 50 ]; then
        log_err "Disk available under $PROJECT_ROOT: ${avail_gb:-0}GB -- need >= 50GB."
        log_err "  Free up disk or move the checkout to a larger filesystem before re-running."
        preflight_block "Insufficient disk (${avail_gb:-0}GB free, need >=50GB)"
    else
        log_ok "Disk available: ${avail_gb}GB"
    fi
}

# ── Gate 5: BuildKit + buildx ────────────────────────────────────────────
gate_buildkit() {
    if ! docker buildx version >/dev/null 2>&1; then
        log_err "docker buildx not available -- this repo's Dockerfiles use multi-stage builds"
        log_err "that need BuildKit.  Upgrade Docker Desktop, or install docker-buildx-plugin."
        preflight_block "buildx missing"
        return
    fi
    log_ok "docker buildx available"
}


# ── Preflight execution ────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${BLUE}  Preflight: host + Docker checks                              ${NC}"
echo -e "${BOLD}${BLUE}══════════════════════════════════════════════════════════════${NC}"
echo ""

# Stage 1: OS gate FIRST.  If the host isn't supported, refuse before
# touching anything else -- the auto-installer below would otherwise
# try to apt-get install on the wrong distro.
gate_os_supported

# Stage 2: on supported hosts, auto-install Docker + Compose if missing.
# Skip entirely if the OS gate already failed.
if [ ${#PREFLIGHT_BLOCKERS[@]} -eq 0 ]; then
    if [ "$IS_LINUX" = true ] || [ "$IS_WSL" = true ]; then
        # Only the Linux/WSL path actually invokes _install_host_deps --
        # on macOS, Docker Desktop is a GUI .app that we can't apt-install,
        # so we just verify it via gate_docker_daemon below.
        _install_host_deps || log_warn "Host dependency provisioning hit warnings (see above)"
    fi
fi

# Stage 3: remaining Docker-side gates.  These verify that whatever the
# auto-installer did (or didn't do) actually produced a working Docker.
gate_docker_daemon
if [ ${#PREFLIGHT_BLOCKERS[@]} -eq 0 ] || \
   ! printf '%s\n' "${PREFLIGHT_BLOCKERS[@]}" | grep -q "Docker daemon"; then
    gate_compose_v2
    gate_docker_resources
    gate_buildkit
fi

echo ""
if [ ${#PREFLIGHT_BLOCKERS[@]} -gt 0 ]; then
    echo -e "${BOLD}${RED}══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${RED}  Preflight FAILED -- ${#PREFLIGHT_BLOCKERS[@]} blocker(s); not proceeding   ${NC}"
    echo -e "${BOLD}${RED}══════════════════════════════════════════════════════════════${NC}"
    echo ""
    for b in "${PREFLIGHT_BLOCKERS[@]}"; do
        echo -e "  ${RED}✗${NC} $b"
    done
    echo ""
    echo "  Fix the blockers above and re-run: ./scripts/setup.sh"
    echo "  Full log of this attempt: $LOG_FILE"
    echo ""
    exit 2
fi
echo -e "${BOLD}${GREEN}  Preflight passed -- proceeding with install${NC}"
echo ""

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 1 — Dependency Check
# ══════════════════════════════════════════════════════════════════════════
banner 1 "Checking dependencies"

DEP_PASS=0
DEP_WARN=0
DEP_FAIL=0
INSTALL_HINTS=()
# CLI tools that were missing AND are auto-installable via a package manager
# (small userspace utils — not docker/compose, which need their own installers).
MISSING_PKGS=()

check_required() {
    local name="$1" cmd="$2" install_hint="$3" pkg="${4:-$2}"
    if command -v "$cmd" &>/dev/null; then
        local ver
        ver=$("$cmd" --version 2>/dev/null | head -1 | head -c 60 || echo "installed")
        echo -e "  ${GREEN}✓${NC} $name: $ver"
        DEP_PASS=$((DEP_PASS + 1))
    else
        echo -e "  ${RED}✗${NC} $name: NOT FOUND"
        INSTALL_HINTS+=("  $name: $install_hint")
        [ -n "$pkg" ] && MISSING_PKGS+=("$pkg")
        DEP_FAIL=$((DEP_FAIL + 1))
    fi
}

# Try to install missing userspace packages via the host package manager.
# Returns 0 if an install was attempted, 1 if no usable package manager.
attempt_pkg_install() {
    local pkgs=("$@")
    [ ${#pkgs[@]} -eq 0 ] && return 0

    local SUDO=""
    if [ "$(id -u)" -ne 0 ]; then
        command -v sudo &>/dev/null && SUDO="sudo" || {
            log_warn "Not root and sudo not available — cannot auto-install: ${pkgs[*]}"
            return 1
        }
    fi

    if command -v apt-get &>/dev/null; then
        log_info "Installing missing packages via apt-get: ${pkgs[*]}"
        $SUDO apt-get update -qq && $SUDO apt-get install -y -qq "${pkgs[@]}"
    elif command -v dnf &>/dev/null; then
        log_info "Installing missing packages via dnf: ${pkgs[*]}"
        $SUDO dnf install -y "${pkgs[@]}"
    elif command -v yum &>/dev/null; then
        log_info "Installing missing packages via yum: ${pkgs[*]}"
        $SUDO yum install -y "${pkgs[@]}"
    elif command -v apk &>/dev/null; then
        log_info "Installing missing packages via apk: ${pkgs[*]}"
        $SUDO apk add --no-cache "${pkgs[@]}"
    elif command -v brew &>/dev/null; then
        log_info "Installing missing packages via brew: ${pkgs[*]}"
        brew install "${pkgs[@]}"
    else
        log_warn "No supported package manager found — cannot auto-install: ${pkgs[*]}"
        return 1
    fi
}

check_optional() {
    local name="$1" cmd="$2" install_hint="$3"
    if command -v "$cmd" &>/dev/null; then
        local ver
        ver=$("$cmd" --version 2>/dev/null | head -1 | head -c 60 || echo "installed")
        echo -e "  ${GREEN}✓${NC} $name: $ver"
        DEP_PASS=$((DEP_PASS + 1))
    else
        echo -e "  ${YELLOW}○${NC} $name: not found (optional — $install_hint)"
        DEP_WARN=$((DEP_WARN + 1))
    fi
}

echo -e "${BOLD}  Required:${NC}"
check_required "Docker" "docker" "https://docs.docker.com/engine/install/"

# Docker Compose v2 (subcommand, not standalone)
if docker compose version &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Docker Compose: $(docker compose version 2>/dev/null | head -c 60)"
    DEP_PASS=$((DEP_PASS + 1))
else
    echo -e "  ${RED}✗${NC} Docker Compose v2: NOT FOUND"
    INSTALL_HINTS+=("  Docker Compose: https://docs.docker.com/compose/install/")
    DEP_FAIL=$((DEP_FAIL + 1))
fi

check_required "openssl" "openssl" "apt install openssl / brew install openssl"
check_required "curl" "curl" "apt install curl / brew install curl"
check_required "git" "git" "apt install git / brew install git"
check_required "unzip" "unzip" "apt install unzip / brew install unzip  (needed by build-go-tools.sh for vulnx)"
check_required "jq" "jq" "apt install jq / brew install jq"

echo ""
echo -e "${BOLD}  Optional:${NC}"
if [ "$IS_MAC" = true ]; then
    check_optional "Ollama (macOS native)" "ollama" "brew install ollama"
fi
check_optional "nvidia-smi (GPU)" "nvidia-smi" "install nvidia-container-toolkit for GPU support"

# Docker daemon running
echo ""
echo -e "${BOLD}  Runtime:${NC}"
if docker info &>/dev/null; then
    echo -e "  ${GREEN}✓${NC} Docker daemon is running"
    DEP_PASS=$((DEP_PASS + 1))
else
    echo -e "  ${RED}✗${NC} Docker daemon is NOT running — start Docker Desktop first"
    INSTALL_HINTS+=("  Start Docker Desktop or run: sudo systemctl start docker")
    DEP_FAIL=$((DEP_FAIL + 1))
fi

# docker-compose.yml present
if [ -f "docker-compose.yml" ]; then
    echo -e "  ${GREEN}✓${NC} docker-compose.yml found"
    DEP_PASS=$((DEP_PASS + 1))
else
    echo -e "  ${RED}✗${NC} docker-compose.yml not found in $PROJECT_ROOT"
    INSTALL_HINTS+=("  Run from the project root: cd /path/to/rag-scan-stack")
    DEP_FAIL=$((DEP_FAIL + 1))
fi

# Disk space check (need ~20GB for images)
DISK_AVAIL_GB=$(df -BG "$PROJECT_ROOT" 2>/dev/null | awk 'NR==2{gsub(/G/,"",$4); print $4}' || echo "0")
if [ "${DISK_AVAIL_GB:-0}" -lt 20 ] 2>/dev/null; then
    echo -e "  ${YELLOW}○${NC} Disk space: ${DISK_AVAIL_GB}GB available (recommend 20GB+)"
    DEP_WARN=$((DEP_WARN + 1))
else
    echo -e "  ${GREEN}✓${NC} Disk space: ${DISK_AVAIL_GB}GB available"
    DEP_PASS=$((DEP_PASS + 1))
fi

# RAM check (recommend 8GB+)
if [ "$IS_MAC" = true ]; then
    RAM_GB=$MAC_TOTAL_RAM_GB
else
    RAM_GB=$(free -g 2>/dev/null | awk '/^Mem:/{print $2}' || echo "0")
fi
if [ "${RAM_GB:-0}" -lt 8 ] 2>/dev/null; then
    echo -e "  ${YELLOW}○${NC} RAM: ${RAM_GB}GB (recommend 8GB+)"
    DEP_WARN=$((DEP_WARN + 1))
else
    echo -e "  ${GREEN}✓${NC} RAM: ${RAM_GB}GB"
    DEP_PASS=$((DEP_PASS + 1))
fi

# Summary
echo ""
echo -e "  ────────────────────────────────────"
echo -e "  ${GREEN}Pass: $DEP_PASS${NC}  ${YELLOW}Warn: $DEP_WARN${NC}  ${RED}Fail: $DEP_FAIL${NC}"

# Auto-install any missing userspace packages (unzip, jq, curl, git, openssl)
# before failing. Docker/Compose are excluded — they need dedicated installers.
if [ $DEP_FAIL -gt 0 ] && [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo ""
    log_info "Attempting to auto-install missing packages: ${MISSING_PKGS[*]}"
    if attempt_pkg_install "${MISSING_PKGS[@]}"; then
        # Re-verify the tools we just tried to install; clear the ones now present.
        STILL_MISSING=()
        for pkg in "${MISSING_PKGS[@]}"; do
            if command -v "$pkg" &>/dev/null; then
                log_ok "$pkg now installed"
                DEP_FAIL=$((DEP_FAIL - 1))
                DEP_PASS=$((DEP_PASS + 1))
            else
                STILL_MISSING+=("$pkg")
            fi
        done
        MISSING_PKGS=("${STILL_MISSING[@]}")
    fi
fi

if [ $DEP_FAIL -gt 0 ]; then
    echo ""
    echo -e "  ${RED}Missing required dependencies:${NC}"
    for hint in "${INSTALL_HINTS[@]}"; do
        echo -e "  ${RED}→${NC}$hint"
    done
    echo ""
    log_err "Fix the above issues before continuing."
    exit 1
fi

# Platform info
echo ""
if [ "$IS_MAC" = true ]; then
    log_ok "Platform: macOS ($(uname -m))"
    if [ "$IS_APPLE_SILICON" = true ]; then
        log_ok "Chip: $MAC_CHIP_NAME — ${MAC_TOTAL_RAM_GB}GB unified memory"
        log_info "Apple Silicon detected — will use native Ollama + mac compose overlay"
    fi
    if [ -f "docker-compose.mac.yml" ]; then
        log_ok "Mac compose overlay: docker-compose.mac.yml"
    fi
else
    log_ok "Platform: $(uname -s) ($(uname -m))"
fi

# GPU detection
# GPU_AVAILABLE drives the `--profile gpu` decision in Phase 6 (ollama +
# embedder-gpu containers). On macOS we use native Ollama (no docker GPU),
# so GPU_AVAILABLE stays false there. On Linux/WSL2 we look both at the
# default PATH and at WSL2's bundled location (/usr/lib/wsl/lib/nvidia-smi).
GPU_AVAILABLE=false

# Resolve nvidia-smi: prefer PATH, fall back to the WSL2 bundled location.
NVIDIA_SMI=""
if command -v nvidia-smi &>/dev/null; then
    NVIDIA_SMI=$(command -v nvidia-smi)
elif [ -x /usr/lib/wsl/lib/nvidia-smi ]; then
    NVIDIA_SMI=/usr/lib/wsl/lib/nvidia-smi
fi

if [ "$IS_APPLE_SILICON" = true ]; then
    log_ok "GPU: $MAC_CHIP_NAME (unified memory, ${MAC_TOTAL_RAM_GB}GB total)"
    if command -v ollama &>/dev/null; then
        log_ok "Ollama CLI: $(ollama --version 2>/dev/null || echo 'installed')"
        if curl -sf --max-time 2 http://localhost:11434/api/version >/dev/null 2>&1; then
            OLLAMA_VER=$(curl -sf --max-time 2 http://localhost:11434/api/version | grep -o '"version":"[^"]*"' | cut -d'"' -f4)
            log_ok "Ollama is running (v${OLLAMA_VER}) at localhost:11434"
        else
            log_warn "Ollama installed but not running — start with: ollama serve"
        fi
    else
        log_warn "Ollama not installed — install with: brew install ollama"
    fi
elif [ -n "$NVIDIA_SMI" ]; then
    GPU_NAME=$("$NVIDIA_SMI" --query-gpu=name --format=csv,noheader 2>/dev/null | head -n1)
    if [ -n "$GPU_NAME" ]; then
        log_ok "NVIDIA GPU detected: $GPU_NAME"
    else
        log_warn "nvidia-smi present but query failed — driver/runtime mismatch?"
    fi
    if docker info 2>/dev/null | grep -q "Runtimes.*nvidia"; then
        log_ok "nvidia-container-toolkit installed"
        GPU_AVAILABLE=true
    elif [ "$SKIP_DEP_INSTALL" = false ] && _detect_pkg_mgr && [ "$PKG_MGR" != "brew" ]; then
        log_info "Installing NVIDIA Container Toolkit (GPU detected)..."
        if _install_nvidia_toolkit && docker info 2>/dev/null | grep -q "Runtimes.*nvidia"; then
            log_ok "nvidia-container-toolkit installed"
            GPU_AVAILABLE=true
        else
            log_warn "nvidia-container-toolkit install incomplete — Ollama will use CPU only"
            log_warn "  Manual: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html"
        fi
    else
        log_warn "nvidia-container-toolkit not found — Ollama will use CPU only"
        log_warn "  Install: https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html"
    fi
else
    log_warn "No GPU detected — gpu compose profile (ollama, embedder-gpu) will stay off"
    log_warn "  WSL2: install NVIDIA drivers on Windows + nvidia-container-toolkit in the distro"
fi

record_phase "Dependencies: OK ($DEP_PASS pass, $DEP_WARN warn)"

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 2 — Go Tool Build
# ══════════════════════════════════════════════════════════════════════════
banner 2 "Checking Go security tools"

OSINT_BIN="osint_runner/bin"
PD_BIN="pd_runner/bin"

# Expected binaries for each runner
OSINT_EXPECTED="subfinder dnsx httpx tlsx asnmap uncover cloudlist alterx mapcidr chaos shuffledns vulnx amass gau waybackurls trufflehog gowitness massdns"
PD_EXPECTED="httpx naabu katana tlsx ffuf"

check_go_binaries() {
    local bin_dir="$1"
    local expected="$2"
    local label="$3"
    local missing=()
    local present=0

    for tool in $expected; do
        if [ -f "$bin_dir/$tool" ]; then
            present=$((present + 1))
        else
            missing+=("$tool")
        fi
    done

    local total
    total=$(echo "$expected" | wc -w | tr -d ' ')

    if [ ${#missing[@]} -eq 0 ]; then
        log_ok "$label: all $total binaries present"
    else
        log_warn "$label: $present/$total present, missing: ${missing[*]}"
    fi

    # Return non-zero if anything is missing
    [ ${#missing[@]} -eq 0 ]
}

if [ "$SKIP_GO_TOOLS" = true ]; then
    log_skip "Go tool check skipped (--skip-go-tools)"
    record_phase "Go Tools: SKIPPED"
else
    mkdir -p "$OSINT_BIN" "$PD_BIN"

    OSINT_OK=true
    PD_OK=true
    check_go_binaries "$OSINT_BIN" "$OSINT_EXPECTED" "osint-runner" || OSINT_OK=false
    check_go_binaries "$PD_BIN"    "$PD_EXPECTED"    "pd-runner"    || PD_OK=false

    if [ "$OSINT_OK" = true ] && [ "$PD_OK" = true ] && [ "$FORCE_GO_TOOLS" = false ]; then
        log_ok "All Go binaries present — skipping build"
        record_phase "Go Tools: OK (all present)"
    else
        if [ "$FORCE_GO_TOOLS" = true ]; then
            log_info "Forcing rebuild of Go tools (--force)"
        else
            log_warn "Missing Go binaries detected — running scripts/build-go-tools.sh"
        fi

        BUILD_ARGS=""
        [ "$FORCE_GO_TOOLS" = true ] && BUILD_ARGS="--force"

        if [ -f "$PROJECT_ROOT/scripts/build-go-tools.sh" ]; then
            log_info "This takes ~10-15 minutes the first time..."
            if bash "$PROJECT_ROOT/scripts/build-go-tools.sh" $BUILD_ARGS; then
                log_ok "Go tool build complete"

                # Re-check after build
                STILL_MISSING=false
                check_go_binaries "$OSINT_BIN" "$OSINT_EXPECTED" "osint-runner (post-build)" || STILL_MISSING=true
                check_go_binaries "$PD_BIN"    "$PD_EXPECTED"    "pd-runner (post-build)"    || STILL_MISSING=true

                if [ "$STILL_MISSING" = true ]; then
                    log_warn "Some binaries still missing after build — those tools will be unavailable at runtime"
                    record_phase "Go Tools: PARTIAL"
                else
                    record_phase "Go Tools: BUILT"
                fi
            else
                log_err "Go tool build failed — continuing without missing binaries"
                log_warn "You can retry manually: ./scripts/build-go-tools.sh"
                record_phase "Go Tools: FAILED"
            fi
        else
            log_err "scripts/build-go-tools.sh not found!"
            log_warn "Cannot build missing Go binaries — Docker build may produce images with missing tools"
            record_phase "Go Tools: MISSING SCRIPT"
        fi
    fi
fi

# ── Mac .env configuration helper ─────────────────────────────────────────
_apply_mac_env_config() {
    # Ollama URL → host.docker.internal (native Ollama on Mac)
    sed -i.bak 's|^OLLAMA_URL=http://ollama:11434|OLLAMA_URL=http://host.docker.internal:11434|' .env
    # Add OLLAMA_BASE_URL if not present
    if ! grep -q "^OLLAMA_BASE_URL=" .env; then
        sed -i.bak '/^OLLAMA_URL=/a\
OLLAMA_BASE_URL=http://host.docker.internal:11434' .env
    else
        sed -i.bak 's|^OLLAMA_BASE_URL=.*|OLLAMA_BASE_URL=http://host.docker.internal:11434|' .env
    fi

    # GPU name + total memory
    if grep -q "^GPU_NAME=" .env; then
        sed -i.bak "s|^GPU_NAME=.*|GPU_NAME=${MAC_CHIP_NAME}|" .env
    else
        echo "GPU_NAME=${MAC_CHIP_NAME}" >> .env
    fi
    if grep -q "^GPU_TOTAL_MEMORY_GB=" .env; then
        sed -i.bak "s|^GPU_TOTAL_MEMORY_GB=.*|GPU_TOTAL_MEMORY_GB=${MAC_TOTAL_RAM_GB}|" .env
    else
        echo "GPU_TOTAL_MEMORY_GB=${MAC_TOTAL_RAM_GB}" >> .env
    fi

    # Recommend model size based on available RAM.  Defaults track the
    # OLLAMA_MODEL baked into docker-compose.yml (gemma4:31b) so the
    # message matches what the stack will actually pull.
    if [ "$MAC_TOTAL_RAM_GB" -ge 96 ] 2>/dev/null; then
        log_info "With ${MAC_TOTAL_RAM_GB}GB RAM you can comfortably run 70B models"
        log_info "Current default: gemma4:31b (upgrade to llama3.3:70b or qwen2.5:72b if desired)"
    elif [ "$MAC_TOTAL_RAM_GB" -ge 48 ] 2>/dev/null; then
        log_info "With ${MAC_TOTAL_RAM_GB}GB RAM, gemma4:31b is a good fit"
    elif [ "$MAC_TOTAL_RAM_GB" -ge 16 ] 2>/dev/null; then
        log_info "With ${MAC_TOTAL_RAM_GB}GB RAM, consider smaller models (gemma4:latest or qwen3:4b)"
    fi

    # Open WebUI Ollama base URL
    if grep -q "^# OLLAMA_BASE_URL=http://ollama:11434" .env; then
        sed -i.bak 's|^# OLLAMA_BASE_URL=http://ollama:11434|OLLAMA_BASE_URL=http://host.docker.internal:11434|' .env
    fi

    rm -f .env.bak
    log_ok "Ollama URL → http://host.docker.internal:11434 (native Mac)"
    log_ok "GPU → ${MAC_CHIP_NAME} / ${MAC_TOTAL_RAM_GB}GB unified memory"
}

# ── Env secret helpers ─────────────────────────────────────────────────────
# Read a value from .env ("" if the key is missing).
_get_env_val() { grep -E "^$1=" .env | head -1 | cut -d= -f2- || true; }

# Set (replace or append) a key in .env. Values are hex/alnum, never contain '|'.
_set_env_val() {
    local var="$1" val="$2"
    if grep -qE "^${var}=" .env; then
        sed -i.bak "s|^${var}=.*|${var}=${val}|" .env && rm -f .env.bak
    else
        echo "${var}=${val}" >> .env
    fi
}

_gen_alnum() { openssl rand -base64 "${1:-32}" | tr -d "=+/" | cut -c1-"${2:-32}"; }

# Backfill any critical secret that is blank/missing in an existing .env. Guards
# against a hand-edited or partial .env that would otherwise start Postgres (and
# others) with an empty password. Mirrors the generators used for a fresh .env.
_backfill_env_secrets() {
    local filled=()
    # Hex API-key style secrets
    local hex_secrets="API_KEY ZAP_API_KEY KONG_ADMIN_TOKEN VLLM_API_KEY"
    for v in $hex_secrets; do
        if [ -z "$(_get_env_val "$v")" ]; then
            _set_env_val "$v" "$(openssl rand -hex 32)"; filled+=("$v")
        fi
    done
    # Alphanumeric password style secrets
    local pw_secrets="POSTGRES_PASSWORD N8N_PASSWORD EXPLOITDB_PASSWORD SCANS_PASSWORD CHISEL_PASSWORD MSF_RPC_PASS"
    for v in $pw_secrets; do
        if [ -z "$(_get_env_val "$v")" ]; then
            _set_env_val "$v" "$(_gen_alnum 32 32)"; filled+=("$v")
        fi
    done

    # Rebuild credential strings that embed a regenerated password.
    if printf '%s\n' "${filled[@]}" | grep -qx "POSTGRES_PASSWORD"; then
        local u h p d pw
        u="$(_get_env_val POSTGRES_USER)"; u="${u:-app}"
        h="$(_get_env_val POSTGRES_HOST)"; h="${h:-rag-postgres}"
        p="$(_get_env_val POSTGRES_PORT)"; p="${p:-5432}"
        d="$(_get_env_val POSTGRES_DB)";   d="${d:-scans}"
        pw="$(_get_env_val POSTGRES_PASSWORD)"
        _set_env_val DB_DSN "postgresql://${u}:${pw}@${h}:${p}/${d}"
    fi
    if printf '%s\n' "${filled[@]}" | grep -qx "EXPLOITDB_PASSWORD"; then
        local epw; epw="$(_get_env_val EXPLOITDB_PASSWORD)"
        _set_env_val EDB_RW_PASSWORD "$epw"
        _set_env_val PG_DSN "postgres://edb_rw:${epw}@rag-postgres:5432/exploits"
    fi

    if [ ${#filled[@]} -gt 0 ]; then
        log_ok "Backfilled blank/missing secrets: ${filled[*]}"
    else
        log_skip "All critical secrets already set"
    fi
}

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 3 — Environment (.env)
# ══════════════════════════════════════════════════════════════════════════
banner 3 "Generating environment configuration"

if [ -f ".env" ]; then
    log_skip ".env already exists — keeping current credentials"
    # Even when keeping an existing .env, fill any blank critical secret with a
    # secure random value so we never boot Postgres with an empty password.
    _backfill_env_secrets
    # Still apply Mac config to existing .env if needed
    if [ "$IS_APPLE_SILICON" = true ]; then
        if grep -q "^OLLAMA_URL=http://ollama:11434" .env || ! grep -q "^GPU_NAME=" .env; then
            log_info "Applying Apple Silicon configuration to existing .env..."
            _apply_mac_env_config
        else
            log_skip "Apple Silicon config already applied"
        fi
    fi
    record_phase "Environment: SKIPPED (already exists)"
else
    log_info "Generating secure credentials..."

    API_KEY=$(openssl rand -hex 32)
    POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    ZAP_API_KEY=$(openssl rand -hex 32)
    KONG_ADMIN_TOKEN=$(openssl rand -hex 32)
    N8N_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-24)
    EXPLOITDB_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-24)
    SCANS_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-24)
    CHISEL_PASSWORD=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-24)
    MSF_RPC_PASS=$(openssl rand -base64 24 | tr -d "=+/" | cut -c1-24)
    VLLM_API_KEY=$(openssl rand -hex 32)

    cat > .env << ENVEOF
# ==========================================
# RAG SCAN STACK - SECURE CONFIGURATION
# ==========================================
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# Generated by: scripts/setup.sh
#
# SECURITY WARNING: Keep this file secure!
# - Do NOT commit to version control
# - Restrict file permissions: chmod 600 .env
# ==========================================

# ==========================================
# BUILD METADATA
# ==========================================
# Injected into service containers via docker-compose (\${BUILD_VERSION:-dev}).
# Sourced from dashboard/frontend/package.json so all three stay in sync.
BUILD_VERSION=$(grep '"version"' "$PROJECT_ROOT/dashboard/frontend/package.json" | head -1 | sed -E 's/.*"version": *"([^"]+)".*/\1/')

# ==========================================
# CRITICAL SECURITY CREDENTIALS
# ==========================================

# Docker Compose Profiles — controls which optional services start by default.
# "local-db" starts rag-postgres + wait-for-db.
# Remove "local-db" if using a remote/external database.
# Add "gpu" for Ollama/vLLM, "vault" for HashiCorp Vault, "optional" for OpenWebUI/Kong/etc.
COMPOSE_PROFILES=local-db

# Main API Key - Used by all services to authenticate with RAG API
API_KEY=${API_KEY}

# PostgreSQL Root Credentials
POSTGRES_USER=app
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
POSTGRES_DB=scans
POSTGRES_HOST=rag-postgres
POSTGRES_PORT=5432

# Constructed DSN (uses above variables)
DB_DSN=postgresql://app:${POSTGRES_PASSWORD}@rag-postgres:5432/scans

# Database Role Passwords (for multi-database setup)
N8N_PASSWORD=${N8N_PASSWORD}
EXPLOITDB_PASSWORD=${EXPLOITDB_PASSWORD}
SCANS_PASSWORD=${SCANS_PASSWORD}
EDB_RW_PASSWORD=${EXPLOITDB_PASSWORD}

# ZAP (OWASP ZAP Proxy) API Key
ZAP_API_KEY=${ZAP_API_KEY}
ZAP_ADDR=zap
ZAP_PORT=8090

# Kong API Gateway Admin Token
KONG_ADMIN_TOKEN=${KONG_ADMIN_TOKEN}

# Chisel Tunnel Credentials
CHISEL_USER=pentest
CHISEL_PASSWORD=${CHISEL_PASSWORD}

# Metasploit RPC Credentials
MSF_RPC_USER=msf
MSF_RPC_PASS=${MSF_RPC_PASS}
MSF_RPC_HOST=metasploit
MSF_RPC_PORT=55553
MSF_LHOST=
MSF_LPORT=4444

# ==========================================
# AI/RAG CONFIGURATION
# ==========================================

EMBED_MODEL=sentence-transformers/all-MiniLM-L6-v2
LLM_BACKEND=ollama
OLLAMA_MODEL=gemma4:31b
OLLAMA_URL=http://ollama:11434
OLLAMA_TIMEOUT=300
GPU_NAME=
GPU_TOTAL_MEMORY_GB=0
VLLM_URL=http://vllm:8000
VLLM_MODEL=mistralai/Mistral-7B-Instruct-v0.3
VLLM_API_KEY=${VLLM_API_KEY}
AZURE_API_KEY=
AZURE_ENDPOINT=
AZURE_MODEL=gpt-4o
AZURE_API_VERSION=2024-08-01-preview
AZURE_EMBED_MODEL=
AUTO_EXECUTE_SAFE=1

# ==========================================
# NMAP SCANNER CONFIGURATION
# ==========================================

NMAP_PORT_BATCH=100
NMAP_OUT_DIR=/app/nmap_out
NMAP_SERVICE_DETECTION=1
NMAP_VERSION_INTENSITY=9
NMAP_SCRIPTS=banner,http-title,ssl-cert,ssl-enum-ciphers,ssh2-enum-algos,vulscan/vulscan.nse
NMAP_SCANNER_URL=http://nmap_scanner:8012

# ==========================================
# WEB SCANNER CONFIGURATION
# ==========================================

WORDLIST=/opt/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
WEB_PORTS=80,443,8080,8443,8000,8888,3000,5000
DEEP_SCAN_PORTS=1001-65535
SCHEME_HINT=auto
REPORT_DIR=/reports

# ==========================================
# NUCLEI VULNERABILITY SCANNER
# ==========================================

NUCLEI_SEVERITY=medium,high,critical
NUCLEI_CONCURRENCY=50
NUCLEI_RATELIMIT=150
NUCLEI_TIMEOUT=10
NUCLEI_RETRIES=1
NUCLEI_AUTO_UPDATE=1
NUCLEI_TEMPLATES=/opt/nuclei-templates

# ==========================================
# PLAYWRIGHT BROWSER SCANNER
# ==========================================

BROWSER_TYPE=chromium
VIEWPORT_WIDTH=1920
VIEWPORT_HEIGHT=1080
USER_AGENT=Mozilla/5.0 (Playwright Security Scanner)
USE_ZAP=true
HEADLESS=true
SCREENSHOT_FORMAT=png

# ==========================================
# SERVICE URLs (Internal Docker Network)
# ==========================================

RAG_API_URL=http://rag-api:8000
API_BASE=http://rag-api:8000
WEB_SCANNER_URL=http://web-scanner:8010
NUCLEI_URL=http://nuclei-runner:8011
NMAP_URL=http://nmap_scanner:8012
SCAN_RECOMMENDER_URL=https://scan-recommender:8013
PLAYWRIGHT_URL=http://playwright-scanner:8014
AUTOGEN_URL=http://autogen-agents:8015
EXPLOIT_RUNNER_URL=http://exploit-runner:8017
PD_RUNNER_URL=http://pd-runner:8023
OSINT_RUNNER_URL=http://osint-runner:8024
BRUTUS_RUNNER_URL=http://brutus-runner:8025
NODE_MANAGER_URL=http://node-manager:8027

# ==========================================
# OSINT / EXTERNAL API KEYS
# ==========================================

SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
PDCP_API_KEY=

# ==========================================
# SSH TUNNEL CONFIGURATION
# ==========================================

SSH_REMOTE_HOST=
SSH_REMOTE_USER=root
SSH_REMOTE_PORT=22
SSH_MODE=dynamic
SSH_SOCKS_PORT=1080
SSH_REVERSE_BIND=0.0.0.0:9999
SSH_REVERSE_TARGET=pentest-dashboard:80
SSH_LOCAL_PORT=3389
SSH_LOCAL_TARGET=127.0.0.1:3389
SSH_KEY_PATH=./ssh-keys
SSH_KEY_NAME=id_rsa
SSH_TUNNEL_NAME=ssh-tunnel
SSH_EXTRA_OPTS=

# ==========================================
# RUNTIME CONFIGURATION
# ==========================================

TZ=America/New_York
SCAN_DEBUG=true
PYTHONPATH=/app
GID=1000
UID=1000

# ==========================================
# EXPLOITDB ETL CONFIGURATION
# ==========================================

PG_DSN=postgres://edb_rw:${EXPLOITDB_PASSWORD}@rag-postgres:5432/exploits
SEARCHSPLOIT_JSON=/var/lib/searchsploit/searchsploit.json

# ==========================================
# HASHICORP VAULT (optional — \`vault\` compose profile)
# ==========================================
# Leave VAULT_ADDR empty to keep using plaintext .env. Set to https://vault:8200
# AFTER running:
#   docker compose --profile vault up -d
#   ./scripts/vault-seed.sh
# Then app/rag-api/vault_client.py reads from Vault first, .env second.
VAULT_ADDR=
VAULT_TOKEN=
VAULT_KV_MOUNT=secret
VAULT_SKIP_VERIFY=true
VAULT_PORT=8200

# ==========================================
# RATE LIMITING (rag-api)
# ==========================================
# slowapi key. Format: "<int>/<period>" (e.g. 60/minute, 1000/hour). Empty = disabled.
RATE_LIMIT=120/minute

# ==========================================
# SCAN TIMEOUTS (defaults; per-job overrides + admin app_settings beat these)
# ==========================================
NMAP_TIMEOUT_FALLBACK=1800
NMAP_TIMEOUT_PROXIED=3600
NMAP_TIMEOUT_SERVICE=600
NMAP_TIMEOUT_UDP=1800
NMAP_TIMEOUT_SMB=300
NMAP_TIMEOUT_RESUME=7200
INGEST_TIMEOUT=600
INGEST_TIMEOUT_SHORT=300
SCAN_TIMEOUT_CACHE_TTL=60
STALE_JOB_TIMEOUT_HOURS=24
MAX_CONCURRENT_SCANS=5
MAX_PIPELINE_CONCURRENT=20
PIPELINE_POLL_INTERVAL=5

# ==========================================
# CONTAINER RESOURCE LIMITS
# ==========================================
# Defaults applied to most services in docker-compose.yml. Override per-service
# with RAG_API_MEM_LIMIT, AUTOGEN_MEM_LIMIT, EMBEDDER_MEM_LIMIT, VAULT_MEM_LIMIT etc.
DEFAULT_MEM_LIMIT=4g
DEFAULT_CPUS=2.0

# ==========================================
# DB CONNECTION POOL (rag-api)
# ==========================================
DB_POOL_MIN=2
DB_POOL_MAX=20

# ==========================================
# OPEN WEBUI (optional)
# ==========================================

# OLLAMA_BASE_URL=http://ollama:11434
# OPENAI_API_BASE_URL=
# OPENAI_API_KEY=

WANDB_API_KEY=

# ==========================================
# END OF CONFIGURATION
# ==========================================
ENVEOF

    chmod 600 .env
    log_ok ".env created with secure random credentials"
    log_info "API_KEY:         ${API_KEY:0:16}..."
    log_info "POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:0:12}..."

    # Auto-configure for macOS / Apple Silicon
    if [ "$IS_APPLE_SILICON" = true ]; then
        log_info "Applying Apple Silicon configuration to .env..."
        _apply_mac_env_config
    fi

    record_phase "Environment: GENERATED"
fi

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 4 — Infrastructure (network, dirs, kong)
# ══════════════════════════════════════════════════════════════════════════
banner 4 "Setting up infrastructure"

# Docker network
if docker network inspect agents_net &>/dev/null; then
    log_skip "Docker network 'agents_net' already exists"
else
    docker network create agents_net
    log_ok "Docker network 'agents_net' created"
fi

# Required directories
DIRS=(
    "nmap_out"
    "web_reports"
    "nuclei_reports"
    "playwright_screenshots"
    "playwright_reports"
    "autogen_logs"
    "autogen_cache"
    "ollama-data"
    "db_init"
    "etl"
    "scan_audit"
    "wordlists"
    "ssh-keys"
    "exploitdb"
    # Vault container (opt-in via 'vault' compose profile). Created up front
    # so the bind-mounts work even if the user never enables Vault.
    "vault/config"
    "vault/data"
    "vault/init"
    "vault/logs"
    # Brutus + osint output dirs (referenced by cleanup-old-files.sh)
    "brutus_reports"
    "osint_reports"
    "pd_reports"
)

CREATED=0
for dir in "${DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        mkdir -p "$dir"
        CREATED=$((CREATED + 1))
    fi
done
log_ok "Directories verified ($CREATED created, $((${#DIRS[@]} - CREATED)) already existed)"

# Credential-testing wordlists for brutus-runner.
# install-wordlists.sh is idempotent -- it skips files already present
# and only downloads what's missing.  brutus-runner expects wordlists
# at /wordlists/{rockyou.txt,seclists/Passwords,seclists/Usernames}.
if [ -x "scripts/install-wordlists.sh" ]; then
    log_info "Provisioning credential-testing wordlists (rockyou + sparse SecLists, ~170MB)..."
    if scripts/install-wordlists.sh 2>&1 | sed 's/^/  /'; then
        log_ok "Wordlists provisioned"
    else
        log_warn "Wordlist provisioning failed — brutus credential attacks may fall back to built-in defaults"
    fi
fi

# ExploitDB CSV (searchsploit data for software vulnerability matching)
if [ ! -f "exploitdb/files_exploits.csv" ]; then
    log_info "Downloading ExploitDB CSV for searchsploit..."
    curl -sL "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv" \
        -o "exploitdb/files_exploits.csv" 2>/dev/null && \
        log_ok "ExploitDB CSV downloaded ($(wc -l < exploitdb/files_exploits.csv) exploits)" || \
        log_warn "ExploitDB CSV download failed — searchsploit will be unavailable"
else
    log_ok "ExploitDB CSV already present ($(wc -l < exploitdb/files_exploits.csv) exploits)"
fi

# SSH placeholder key (prevents volume mount failure on fresh clone)
if [ ! -f "ssh-keys/id_rsa" ]; then
    ssh-keygen -t ed25519 -f ssh-keys/id_rsa -N "" -C "placeholder-key" >/dev/null 2>&1
    log_ok "Created placeholder SSH key (replace with real key for tunnels)"
fi

# Kong configuration
if [ -d "kong" ]; then
    # kong/kong.yml is a generated, gitignored file (it ends up holding the real
    # API key). Generate it from the committed kong.yml.template.
    if [ ! -f "kong/kong.yml" ]; then
        if [ -f "kong/kong.yml.template" ]; then
            cp kong/kong.yml.template kong/kong.yml
            log_ok "Created kong/kong.yml from kong.yml.template"
        else
            log_warn "kong/kong.yml.template not found — skipping Kong setup"
        fi
    else
        log_skip "kong/kong.yml already exists"
    fi

    # Auto-update API key in kong.yml if .env has a generated key
    if [ -f "kong/kong.yml" ] && [ -f ".env" ]; then
        CURRENT_API_KEY=$(grep "^API_KEY=" .env | cut -d= -f2)
        if [ -n "$CURRENT_API_KEY" ]; then
            if grep -q "REPLACE_WITH_YOUR_API_KEY\|change-me" kong/kong.yml 2>/dev/null; then
                sed -i.bak "s/REPLACE_WITH_YOUR_API_KEY/$CURRENT_API_KEY/g" kong/kong.yml
                sed -i.bak "s/change-me/$CURRENT_API_KEY/g" kong/kong.yml
                rm -f kong/kong.yml.bak
                log_ok "Updated API key in kong/kong.yml"
            fi
        fi
    fi
else
    log_warn "kong/ directory not found — skipping Kong setup"
fi

record_phase "Infrastructure: OK"

# ── TLS certificates for inter-service communication ──────────────────────
# Every uvicorn-based service mounts ./certs:/certs:ro and starts with
# --ssl-keyfile=/certs/server.key --ssl-certfile=/certs/server.crt. Without
# these files the containers crash-loop on FileNotFoundError. Generate them
# here (idempotent — generate-certs.sh skips if they already exist).
if [ -f "scripts/generate-certs.sh" ]; then
    log_info "Generating TLS certificates (certs/server.crt, certs/server.key)"
    if bash scripts/generate-certs.sh >/dev/null 2>&1; then
        log_ok "TLS certificates ready in certs/"
    else
        log_err "TLS certificate generation failed — services using /certs will crash-loop"
        record_phase "TLS Certs: FAILED"
        exit 1
    fi
else
    log_warn "scripts/generate-certs.sh not found — skipping TLS cert generation"
fi

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 5 — Docker Build
# ══════════════════════════════════════════════════════════════════════════
banner 5 "Building Docker images"

log_info "Using: docker compose ${COMPOSE_FILES} build"
if docker compose ${COMPOSE_FILES} build; then
    log_ok "Docker images built successfully"
    record_phase "Docker Build: OK"
else
    log_err "Docker build failed — check output above"
    record_phase "Docker Build: FAILED"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 6 — Start Services
# ══════════════════════════════════════════════════════════════════════════
banner 6 "Starting services"

if [ "$NO_START" = true ]; then
    log_skip "Service start skipped (--no-start)"
    record_phase "Start: SKIPPED"
else
    # If DB_DSN points at a non-rag-postgres host (i.e., remote DB), skip the
    # local-db profile so we don't waste resources on an unused postgres.
    if [ -f .env ]; then
        DSN_LINE=$(grep -E "^DB_DSN=" .env || true)
        if [ -n "$DSN_LINE" ] && ! echo "$DSN_LINE" | grep -q "rag-postgres"; then
            log_info "DB_DSN does not reference rag-postgres — disabling local-db profile"
            COMPOSE_PROFILES=""
        fi
    fi

    # GPU profile: starts ollama + embedder-gpu. Enabled when a GPU was
    # detected in Phase 1, or when --gpu was passed; disabled by --no-gpu.
    case "$GPU_OVERRIDE" in
        force) ENABLE_GPU=true ;;
        skip)  ENABLE_GPU=false ;;
        *)     ENABLE_GPU=$GPU_AVAILABLE ;;
    esac
    if [ "$ENABLE_GPU" = true ]; then
        log_info "Enabling gpu profile (ollama + embedder-gpu)"
        COMPOSE_PROFILES="${COMPOSE_PROFILES} --profile gpu"
    elif [ "$GPU_OVERRIDE" = "skip" ]; then
        log_info "Skipping gpu profile (--no-gpu)"
    fi

    log_info "Using: docker compose ${COMPOSE_FILES} ${COMPOSE_PROFILES} up -d"
    if docker compose ${COMPOSE_FILES} ${COMPOSE_PROFILES} up -d; then
        log_ok "Services started"
        record_phase "Start: OK"
    else
        log_err "docker compose up failed"
        record_phase "Start: FAILED"
        exit 1
    fi
fi

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 7 — Database Schema
# ══════════════════════════════════════════════════════════════════════════
banner 7 "Applying database schema"

if [ "$NO_START" = true ]; then
    log_skip "Database schema skipped (services not started)"
    record_phase "DB Schema: SKIPPED"
else
    # Wait for postgres to be ready
    log_info "Waiting for PostgreSQL to become ready..."
    PG_TIMEOUT=60
    PG_ELAPSED=0
    PG_READY=false

    while [ $PG_ELAPSED -lt $PG_TIMEOUT ]; do
        if docker exec rag-postgres pg_isready -U app -d scans &>/dev/null; then
            PG_READY=true
            break
        fi
        sleep 2
        PG_ELAPSED=$((PG_ELAPSED + 2))
        # Print dot every 10 seconds
        if [ $((PG_ELAPSED % 10)) -eq 0 ]; then
            log_info "Still waiting... (${PG_ELAPSED}s)"
        fi
    done

    if [ "$PG_READY" = false ]; then
        log_err "PostgreSQL did not become ready within ${PG_TIMEOUT}s"
        log_warn "You can run schema manually later: ./scripts/ensure_db_schema.sh"
        record_phase "DB Schema: TIMEOUT"
    else
        log_ok "PostgreSQL is ready (${PG_ELAPSED}s)"

        # Count tables before
        BEFORE=$(docker exec rag-postgres psql -U app -d scans -t -c \
            "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public';" 2>/dev/null | tr -d ' ' || echo "0")

        # Apply schema
        if docker exec rag-postgres psql -U app -d scans \
            -f /docker-entrypoint-initdb.d/ensure_all_tables.sql >/dev/null 2>&1; then
            AFTER=$(docker exec rag-postgres psql -U app -d scans -t -c \
                "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public';" 2>/dev/null | tr -d ' ' || echo "0")
            ADDED=$((AFTER - BEFORE))
            log_ok "Schema applied: $AFTER tables ($ADDED new)"
            record_phase "DB Schema: OK ($AFTER tables)"
        else
            log_warn "Schema applied with warnings (non-fatal)"
            record_phase "DB Schema: OK (with warnings)"
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 8 — Ollama models + macOS connection check
# ══════════════════════════════════════════════════════════════════════════
#
# Setup historically stopped at "the daemon is listening" without ever
# checking that the configured chat model actually exists on the Ollama
# instance.  Symptom: every RAG / agent completion fails with a model-
# not-found error that some error handlers report as a connection
# failure -- exactly the macOS confusion we keep hitting.
#
# This phase:
#   1. Reads OLLAMA_MODEL from .env (falls back to the docker-compose
#      default if unset).
#   2. Pulls OLLAMA_MODEL + nomic-embed-text on the host's native Ollama
#      (macOS path) or via the ollama-init container (Linux/WSL GPU path).
#   3. On macOS, additionally confirms that `host.docker.internal:11434`
#      resolves and responds from inside scan-recommender -- this is the
#      mac-specific failure mode (host networking misconfigured) that
#      doesn't show up in the Phase 1 host-side check.
banner 8 "Ollama models + connection check"

if [ "$NO_START" = true ]; then
    log_skip "Ollama setup skipped (services not started)"
    record_phase "Ollama: SKIPPED"
else
    # Resolve OLLAMA_MODEL from .env (fall back to the compose default).
    OLLAMA_MODEL_VAL="$(grep -E '^OLLAMA_MODEL=' .env 2>/dev/null | head -1 | cut -d= -f2- || true)"
    OLLAMA_MODEL_VAL="${OLLAMA_MODEL_VAL:-gemma4:31b}"
    REQUIRED_MODELS=("$OLLAMA_MODEL_VAL" "nomic-embed-text")

    if [ "$IS_MAC" = true ]; then
        # ── macOS: native Ollama on the host ─────────────────────────
        if ! command -v ollama &>/dev/null; then
            log_warn "Ollama CLI not installed on host — install with: brew install ollama"
            log_warn "Then re-run: ./scripts/setup.sh"
            record_phase "Ollama: NOT INSTALLED"
        elif ! curl -sf --max-time 3 http://localhost:11434/api/version >/dev/null 2>&1; then
            log_warn "Ollama daemon not running — start with: ollama serve  (or open the Ollama.app)"
            record_phase "Ollama: NOT RUNNING"
        else
            log_ok "Ollama daemon reachable at localhost:11434"
            INSTALLED_MODELS=$(curl -sf --max-time 5 http://localhost:11434/api/tags 2>/dev/null \
                | grep -oE '"name":"[^"]+"' | cut -d'"' -f4 || true)

            for m in "${REQUIRED_MODELS[@]}"; do
                if echo "$INSTALLED_MODELS" | grep -qxF "$m" \
                   || echo "$INSTALLED_MODELS" | grep -qxF "${m}:latest"; then
                    log_ok "Model present: $m"
                else
                    log_info "Pulling $m (this may take several minutes)..."
                    if ollama pull "$m"; then
                        log_ok "Pulled: $m"
                    else
                        log_warn "Failed to pull $m -- LLM ops against this model will fail until resolved"
                        log_warn "  Retry manually: ollama pull $m"
                    fi
                fi
            done

            # macOS-specific: confirm host.docker.internal resolves and
            # answers from inside a stack container.  This catches the
            # "everything works from the host, nothing works from
            # containers" failure mode that the Phase 1 host-side check
            # cannot see.
            if docker ps --format '{{.Names}}' | grep -q "^scan-recommender$"; then
                if docker exec scan-recommender curl -sf --max-time 5 \
                   http://host.docker.internal:11434/api/version >/dev/null 2>&1; then
                    log_ok "Containers can reach Ollama via host.docker.internal:11434"
                else
                    log_warn "Containers CANNOT reach host.docker.internal:11434"
                    log_warn "  In Docker Desktop → Settings → Resources → Network, ensure"
                    log_warn "  host networking is enabled.  Then: docker compose restart scan-recommender"
                fi
            fi

            # Smoke test: round-trip a one-token completion through the
            # configured chat model.  Failures here are usually OOM or
            # the model not being warmable on this hardware.
            if echo "$INSTALLED_MODELS" | grep -qxF "$OLLAMA_MODEL_VAL"; then
                log_info "Smoke-testing completion through $OLLAMA_MODEL_VAL..."
                if curl -sf --max-time 60 http://localhost:11434/api/generate \
                     -d "{\"model\":\"$OLLAMA_MODEL_VAL\",\"prompt\":\"hi\",\"stream\":false}" \
                     >/dev/null 2>&1; then
                    log_ok "Completion smoke test passed for $OLLAMA_MODEL_VAL"
                else
                    log_warn "Smoke test failed -- model may be too large for this hardware"
                fi
            fi

            record_phase "Ollama: OK (model: $OLLAMA_MODEL_VAL)"
        fi
    else
        # ── Linux / WSL2: ollama-init container handles the pull when ──
        # ── the gpu profile is active.  Without --gpu, this phase is a no-op.
        if [ "$ENABLE_GPU" = true ]; then
            log_info "Linux/WSL2 with --gpu: ollama-init container handles model pulls"
            log_info "  Watch progress with: docker logs -f ollama-init"
            record_phase "Ollama: HANDLED BY ollama-init"
        else
            log_skip "GPU profile not enabled -- Ollama not started in this stack"
            log_info "  Re-run with --gpu to start ollama + ollama-init, or point at an external Ollama"
            record_phase "Ollama: SKIPPED (no GPU profile)"
        fi
    fi
fi

# ══════════════════════════════════════════════════════════════════════════
#  PHASE 9 — Health Check
# ══════════════════════════════════════════════════════════════════════════
banner 9 "Health check"

if [ "$NO_START" = true ]; then
    log_skip "Health check skipped (services not started)"
    record_phase "Health: SKIPPED"
else
    # Give services a moment to initialize
    log_info "Waiting 10s for services to initialize..."
    sleep 10

    # rag-api now serves over TLS (https) on :8000; the dashboard BFF is http on
    # :3001. Use -k for the self-signed cert. Wrong scheme = false negative.
    HEALTH_ENDPOINTS=(
        "RAG API|https://localhost:8000/health"
        "Dashboard BFF|http://localhost:3001/health"
    )

    HEALTHY=0
    TOTAL=${#HEALTH_ENDPOINTS[@]}

    for entry in "${HEALTH_ENDPOINTS[@]}"; do
        NAME="${entry%%|*}"
        URL="${entry##*|}"
        if curl -sfk --max-time 5 "$URL" >/dev/null 2>&1; then
            log_ok "$NAME — healthy"
            HEALTHY=$((HEALTHY + 1))
        else
            log_warn "$NAME — not responding yet (may still be starting)"
        fi
    done

    # Also check docker compose ps
    log_info ""
    log_info "Container status:"
    docker compose ${COMPOSE_FILES} ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null | head -30 || true

    record_phase "Health: $HEALTHY/$TOTAL responding"
fi

# ══════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════
ELAPSED=$SECONDS
MINUTES=$((ELAPSED / 60))
SECS=$((ELAPSED % 60))

echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  Setup Complete!  (${MINUTES}m ${SECS}s)${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo ""

for i in "${!PHASE_STATUS[@]}"; do
    echo -e "  Phase $((i + 1)): ${PHASE_STATUS[$i]}"
done

echo ""
echo -e "${BOLD}Service URLs:${NC}"
echo "  Dashboard:      http://localhost:3002"
echo "  RAG API:        http://localhost:8000/docs"
echo "  API Gateway:    http://localhost:7080/docs"
echo ""
if [ "$IS_APPLE_SILICON" = true ]; then
    echo -e "${BOLD}Platform:${NC} ${MAC_CHIP_NAME} / ${MAC_TOTAL_RAM_GB}GB"
    echo -e "${BOLD}Ollama:${NC}   Native (http://localhost:11434)"
    echo ""
fi
echo -e "${BOLD}Useful commands:${NC}"
echo "  docker compose ${COMPOSE_FILES} ${COMPOSE_PROFILES} ps        # service status"
echo "  docker compose ${COMPOSE_FILES} ${COMPOSE_PROFILES} logs -f   # follow logs"
echo "  docker compose ${COMPOSE_FILES} ${COMPOSE_PROFILES} down      # stop all"
echo "  ./scripts/ensure_db_schema.sh  # re-apply DB schema"
echo ""

# ══════════════════════════════════════════════════════════════════════════
#  FIRST-TIME QUICKSTART BANNER
# ══════════════════════════════════════════════════════════════════════════
# Pick the OS-specific quickstart guide based on how the script was invoked.
case "$PLATFORM_LABEL" in
    macos) QUICKSTART_DOC="Docs/QUICKSTART-MACOS.md";       PLATFORM_PRETTY="macOS" ;;
    wsl)   QUICKSTART_DOC="Docs/QUICKSTART-WINDOWS.md";     PLATFORM_PRETTY="Windows (WSL2)" ;;
    *)     QUICKSTART_DOC="Docs/QUICKSTART-DEPLOYMENT.md";  PLATFORM_PRETTY="Linux" ;;
esac

echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${YELLOW}  First time here? Start with these 4 steps                    ${NC}"
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Detected platform: ${BOLD}${PLATFORM_PRETTY}${NC}"
echo ""
echo -e "  ${BOLD}1.${NC} Open the dashboard:    ${BLUE}http://localhost:3002${NC}"
echo -e "  ${BOLD}2.${NC} Create an engagement:  Engagements → New (sets the scope for every scan)"
echo -e "  ${BOLD}3.${NC} Configure your proxy:  Settings → General → Burp/ZAP preset + Test Proxy"
echo -e "  ${BOLD}4.${NC} Launch your first scan:  Scans → choose target → category → scan"
echo ""
echo -e "  ${BOLD}Read these next${NC} (in this order):"
echo -e "    • ${BOLD}Docs/README.md${NC}                     — project overview"
echo -e "    • ${BOLD}Docs/START_HERE.md${NC}                 — operator orientation"
if [ -f "$QUICKSTART_DOC" ]; then
    echo -e "    • ${BOLD}${QUICKSTART_DOC}${NC}   — ${PLATFORM_PRETTY}-specific install/start steps"
else
    echo -e "    • ${BOLD}Docs/QUICKSTART-DEPLOYMENT.md${NC}      — generic deployment quickstart"
fi
echo -e "    • ${BOLD}Docs/QUICKSTART-SAMPLE-WORKFLOW.md${NC} — end-to-end scan→triage→export walkthrough"
echo ""
if [ "$IS_WSL" = true ]; then
    echo -e "  ${BOLD}WSL2 note:${NC}  run all setup/start commands from inside the WSL shell, not"
    echo -e "             PowerShell. Docker Desktop must have WSL2 integration enabled."
    if [ "$ENABLE_GPU" != true ]; then
        echo -e "             For GPU/Ollama support: install nvidia-container-toolkit + re-run with --gpu."
    fi
elif [ "$IS_MAC" = true ]; then
    echo -e "  ${BOLD}macOS note:${NC} Ollama runs natively on the host (not in Docker)."
    echo -e "             Verify with: ${BLUE}curl http://localhost:11434/api/tags${NC}"
fi
echo ""
echo -e "  ${BOLD}Stuck?${NC}  ${BLUE}./scripts/post-install-check.sh${NC}  runs an end-to-end health audit."
echo ""
echo -e "  ${BOLD}Full transcript of this run:${NC}  ${BLUE}${LOG_FILE}${NC}"
echo -e "             (attach to bug reports; gitignored under logs/)"
echo ""
echo -e "${BOLD}${YELLOW}══════════════════════════════════════════════════════════════${NC}"
echo ""
