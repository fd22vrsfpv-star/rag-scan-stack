#!/usr/bin/env bash
# Build all Go security tools for BOTH arm64 and amd64 architectures.
# Binaries go into osint_runner/bin/ and pd_runner/bin/ for the local Docker arch,
# plus osint_runner/bin-amd64/ and pd_runner/bin-amd64/ (or bin-arm64/) for remote nodes.
#
# Usage:  ./scripts/build-go-tools.sh [--force] [--arch arm64|amd64|both]
#   --force         Rebuild even if binaries already exist
#   --arch <arch>   Build for specific arch only (default: both)
#
# On a new computer: run this script, then `docker compose build`.
# Binaries are gitignored — they stay on disk but not in the repo.

set -euo pipefail
cd "$(dirname "$0")/.."

FORCE=false
BUILD_ARCH="both"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force) FORCE=true; shift ;;
        --arch) BUILD_ARCH="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Prereq check — fail fast with a clear message instead of a cryptic
# "unzip: command not found" mid-build.
for cmd in docker curl unzip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: '$cmd' is required but not installed."
        case "$cmd" in
            unzip) echo "  Install: sudo apt install unzip   (or 'brew install unzip' on macOS)" ;;
            curl)  echo "  Install: sudo apt install curl    (or 'brew install curl')" ;;
            docker) echo "  Install: https://docs.docker.com/engine/install/" ;;
        esac
        exit 1
    fi
done

OSINT_BIN="osint_runner/bin"
PD_BIN="pd_runner/bin"

# Detect host arch — used to determine which is the "local" build
HOST_ARCH="amd64"
case "$(uname -m)" in
    aarch64|arm64) HOST_ARCH="arm64" ;;
esac

# Determine which arches to build
ARCHES=()
case "$BUILD_ARCH" in
    both)  ARCHES=("arm64" "amd64") ;;
    arm64) ARCHES=("arm64") ;;
    amd64) ARCHES=("amd64") ;;
    *)     echo "Invalid arch: $BUILD_ARCH (use arm64, amd64, or both)"; exit 1 ;;
esac

echo "=== Building Go security tools ==="
echo "Host: $(uname -m) | Building for: ${ARCHES[*]}"
echo "Local Docker arch: $HOST_ARCH (binaries go in bin/)"
echo ""

# OSINT tools list
OSINT_GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    "github.com/projectdiscovery/dnsx/cmd/dnsx"
    "github.com/projectdiscovery/httpx/cmd/httpx"
    "github.com/projectdiscovery/tlsx/cmd/tlsx"
    "github.com/projectdiscovery/asnmap/cmd/asnmap"
    "github.com/projectdiscovery/uncover/cmd/uncover"
    "github.com/projectdiscovery/cloudlist/cmd/cloudlist"
    "github.com/projectdiscovery/alterx/cmd/alterx"
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr"
    "github.com/projectdiscovery/chaos-client/cmd/chaos"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns"
    "github.com/owasp-amass/amass/v4/cmd/amass"
    "github.com/lc/gau/v2/cmd/gau"
    "github.com/tomnomnom/waybackurls"
    "github.com/sensepost/gowitness"
    "github.com/projectdiscovery/katana/cmd/katana"
    "github.com/PentestPad/subzy"
    "github.com/0xsha/GoLinkFinder"
)

PD_GO_TOOLS=(
    "github.com/projectdiscovery/httpx/cmd/httpx"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu"
    "github.com/projectdiscovery/katana/cmd/katana"
    "github.com/projectdiscovery/tlsx/cmd/tlsx"
    "github.com/ffuf/ffuf/v2"
)

# Cross-platform file size helper
file_size() {
    stat -c%s "$1" 2>/dev/null || stat -f%z "$1" 2>/dev/null || echo '?'
}

build_for_arch() {
    local ARCH="$1"
    local PLATFORM="linux/$ARCH"

    echo ""
    echo "###################################################################"
    echo "# Building for $PLATFORM"
    echo "###################################################################"
    echo ""

    # Determine output directories
    if [[ "$ARCH" == "$HOST_ARCH" ]]; then
        # Local arch — goes in the main bin/ directory (what Dockerfile copies)
        local OSINT_OUT="$OSINT_BIN"
        local PD_OUT="$PD_BIN"
    else
        # Remote arch — goes in bin-<arch>/ for remote node deployment
        local OSINT_OUT="osint_runner/bin-${ARCH}"
        local PD_OUT="pd_runner/bin-${ARCH}"
    fi
    mkdir -p "$OSINT_OUT" "$PD_OUT"

    # Skip if not forced and binaries exist
    if [[ "$FORCE" == false ]] && [[ -f "$OSINT_OUT/subfinder" ]]; then
        local existing_arch
        existing_arch=$(file "$OSINT_OUT/subfinder" | grep -oE 'x86-64|aarch64' || echo 'unknown')
        if [[ ("$ARCH" == "arm64" && "$existing_arch" == "aarch64") || ("$ARCH" == "amd64" && "$existing_arch" == "x86-64") ]]; then
            echo "[$ARCH] Binaries already present with correct arch. Use --force to rebuild."
            return 0
        fi
    fi

    # Download vulnx for this arch
    local vulnxARCH="$ARCH"
    [[ "$ARCH" == "arm64" ]] && vulnxARCH="arm64" || vulnxARCH="amd64"
    local vulnxURL="https://github.com/projectdiscovery/cvemap/releases/download/v1.0.0/vulnx_1.0.0_linux_${vulnxARCH}.zip"
    local vulnxZIP="vulnx_${vulnxARCH}.zip"
    if curl -fSL -o "$vulnxZIP" "$vulnxURL" 2>/dev/null; then
        unzip -qq -o "$vulnxZIP" vulnx -d "$OSINT_OUT/"
        rm -f "$vulnxZIP"
        echo "[$ARCH] vulnx installed (linux/${vulnxARCH})"
    else
        echo "[$ARCH] WARNING: vulnx download failed"
        rm -f "$vulnxZIP"
    fi

    # Build OSINT tools
    echo "[$ARCH] Building osint-runner tools (${#OSINT_GO_TOOLS[@]} Go tools + massdns + trufflehog)..."
    docker run --rm --name "go-osint-${ARCH}-$$" \
        --platform "$PLATFORM" \
        -v "$(pwd)/$OSINT_OUT:/output" \
        -e "GOARCH=$ARCH" \
        -e "GOOS=linux" \
        golang:1.25 bash -c '
set -e
apt-get update -qq && apt-get install -y -qq --no-install-recommends git ca-certificates build-essential musl >/dev/null 2>&1
export GONOSUMCHECK="*" GONOSUMDB="*" GOTOOLCHAIN=auto

# Build massdns from source
echo "[massdns] Building..."
git clone --depth 1 https://github.com/blechschmidt/massdns.git /tmp/massdns 2>/dev/null
cd /tmp/massdns && make -j$(nproc) >/dev/null 2>&1
cp bin/massdns /output/massdns
echo "[massdns] Done"

# Go tools
TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    "github.com/projectdiscovery/dnsx/cmd/dnsx"
    "github.com/projectdiscovery/httpx/cmd/httpx"
    "github.com/projectdiscovery/tlsx/cmd/tlsx"
    "github.com/projectdiscovery/asnmap/cmd/asnmap"
    "github.com/projectdiscovery/uncover/cmd/uncover"
    "github.com/projectdiscovery/cloudlist/cmd/cloudlist"
    "github.com/projectdiscovery/alterx/cmd/alterx"
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr"
    "github.com/projectdiscovery/chaos-client/cmd/chaos"
    "github.com/projectdiscovery/shuffledns/cmd/shuffledns"
    "github.com/owasp-amass/amass/v4/cmd/amass"
    "github.com/lc/gau/v2/cmd/gau"
    "github.com/tomnomnom/waybackurls"
    "github.com/sensepost/gowitness"
    "github.com/projectdiscovery/katana/cmd/katana"
)

for tool in "${TOOLS[@]}"; do
    name=$(basename "$tool")
    [[ "$name" == "v2" ]] && name=$(basename "$(dirname "$tool")")
    echo "[${name}] Installing..."
    if go install "${tool}@latest" 2>&1; then
        cp /go/bin/"$name" /output/"$name"
        echo "[${name}] Done ($(stat -c%s /output/"$name") bytes)"
    else
        echo "[${name}] FAILED — skipping"
    fi
done

# trufflehog (has replace directives, must clone+build)
echo "[trufflehog] Cloning and building..."
git clone --depth 1 https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog 2>/dev/null
cd /tmp/trufflehog
if go build -o /output/trufflehog . 2>&1; then
    echo "[trufflehog] Done ($(stat -c%s /output/trufflehog) bytes)"
else
    echo "[trufflehog] FAILED — skipping"
fi

echo ""; echo "=== OSINT tools complete ==="
ls -la /output/
'

    # Build PD tools
    echo ""
    echo "[$ARCH] Building pd-runner tools (${#PD_GO_TOOLS[@]} tools)..."
    docker run --rm --name "go-pd-${ARCH}-$$" \
        --platform "$PLATFORM" \
        -v "$(pwd)/$PD_OUT:/output" \
        -e "GOARCH=$ARCH" \
        -e "GOOS=linux" \
        golang:1.25 bash -c '
set -e
apt-get update -qq && apt-get install -y -qq --no-install-recommends git libpcap-dev build-essential >/dev/null 2>&1
export GONOSUMCHECK="*" GONOSUMDB="*"

TOOLS=(
    "github.com/projectdiscovery/httpx/cmd/httpx"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu"
    "github.com/projectdiscovery/katana/cmd/katana"
    "github.com/projectdiscovery/tlsx/cmd/tlsx"
    "github.com/ffuf/ffuf/v2"
)

for tool in "${TOOLS[@]}"; do
    name=$(basename "$tool")
    [[ "$name" == "v2" ]] && name=$(basename "$(dirname "$tool")")
    echo "[${name}] Installing..."
    if go install "${tool}@latest" 2>&1; then
        cp /go/bin/"$name" /output/"$name"
        echo "[${name}] Done ($(stat -c%s /output/"$name") bytes)"
    else
        echo "[${name}] FAILED — skipping"
    fi
done

echo ""; echo "=== PD tools complete ==="
ls -la /output/
'

    echo ""
    echo "[$ARCH] Build complete."
    echo "  OSINT: $(ls "$OSINT_OUT"/ 2>/dev/null | wc -l | tr -d ' ') binaries in $OSINT_OUT/"
    echo "  PD:    $(ls "$PD_OUT"/ 2>/dev/null | wc -l | tr -d ' ') binaries in $PD_OUT/"
}

# Build for each requested architecture
for arch in "${ARCHES[@]}"; do
    build_for_arch "$arch"
done

echo ""
echo "=== All builds complete ==="
echo ""
echo "Local Docker arch ($HOST_ARCH) — used by docker compose build:"
echo "  OSINT: $(ls "$OSINT_BIN"/ 2>/dev/null | wc -l | tr -d ' ') binaries in $OSINT_BIN/"
echo "  PD:    $(ls "$PD_BIN"/ 2>/dev/null | wc -l | tr -d ' ') binaries in $PD_BIN/"

# Show remote arch directories if they exist
for arch in arm64 amd64; do
    [[ "$arch" == "$HOST_ARCH" ]] && continue
    local_osint="osint_runner/bin-${arch}"
    local_pd="pd_runner/bin-${arch}"
    if [[ -d "$local_osint" ]]; then
        echo ""
        echo "Remote node arch ($arch) — for deploying to $arch nodes:"
        echo "  OSINT: $(ls "$local_osint"/ 2>/dev/null | wc -l | tr -d ' ') binaries in $local_osint/"
        echo "  PD:    $(ls "$local_pd"/ 2>/dev/null | wc -l | tr -d ' ') binaries in $local_pd/"
    fi
done

echo ""
echo "Next: run 'docker compose build osint-runner pd-runner' to build the containers."
