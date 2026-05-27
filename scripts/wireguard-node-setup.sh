#!/bin/bash
# WireGuard Node Pre-Installation Script
# Run this on remote nodes to pre-install WireGuard and dependencies
# Usage: ./wireguard-node-setup.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    exit 1
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

log "Starting WireGuard pre-installation for RAG Scan Stack nodes..."

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    error "Cannot detect operating system"
fi

log "Detected OS: $OS $VER"

# Set non-interactive mode
export DEBIAN_FRONTEND=noninteractive

case $OS in
    "ubuntu"|"debian")
        log "Installing for Debian/Ubuntu..."

        # Update package lists
        log "Updating package lists..."
        apt-get update -qq

        # Install WireGuard and dependencies
        log "Installing WireGuard and dependencies..."
        apt-get install -y \
            wireguard-tools \
            iproute2 \
            curl \
            netcat-openbsd \
            resolvconf \
            iptables

        log "✓ WireGuard tools installed"
        ;;

    "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
        log "Installing for RHEL/CentOS/Fedora..."

        # Install EPEL for CentOS/RHEL
        if [[ $OS == "centos" ]] || [[ $OS == "rhel" ]] || [[ $OS == "rocky" ]] || [[ $OS == "almalinux" ]]; then
            log "Installing EPEL repository..."
            dnf install -y epel-release || yum install -y epel-release
        fi

        # Install WireGuard and dependencies
        log "Installing WireGuard and dependencies..."
        dnf install -y wireguard-tools iproute curl netcat iptables || \
        yum install -y wireguard-tools iproute curl netcat iptables

        log "✓ WireGuard tools installed"
        ;;

    "arch")
        log "Installing for Arch Linux..."
        pacman -Sy --noconfirm wireguard-tools iproute2 curl netcat iptables
        log "✓ WireGuard tools installed"
        ;;

    *)
        error "Unsupported operating system: $OS"
        ;;
esac

# Install microsocks (SOCKS5 proxy)
log "Installing microsocks SOCKS5 proxy..."

MICROSOCKS_VERSION="v1.0.3"
MICROSOCKS_URL="https://github.com/rofl0r/microsocks/releases/download/${MICROSOCKS_VERSION}/microsocks-linux-x86_64"

if command -v microsocks >/dev/null 2>&1; then
    warn "microsocks already installed, skipping..."
else
    log "Downloading microsocks ${MICROSOCKS_VERSION}..."
    curl -L -o /tmp/microsocks "$MICROSOCKS_URL" || error "Failed to download microsocks"

    chmod +x /tmp/microsocks
    mv /tmp/microsocks /usr/local/bin/microsocks

    log "✓ microsocks installed to /usr/local/bin/microsocks"
fi

# Create systemd service for microsocks
log "Creating systemd service for microsocks..."
cat > /etc/systemd/system/microsocks.service << 'EOF'
[Unit]
Description=microsocks SOCKS5 proxy for WireGuard
After=network.target wg-quick@wg0.service
Wants=wg-quick@wg0.service

[Service]
Type=simple
User=nobody
Group=nogroup
ExecStart=/usr/local/bin/microsocks -i 10.66.0.0 -p 1080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# Create WireGuard directory
log "Creating WireGuard configuration directory..."
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# Enable IP forwarding (useful for routing scenarios)
log "Enabling IP forwarding..."
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wireguard.conf
sysctl -p /etc/sysctl.d/99-wireguard.conf

# Create a helper script for easy WireGuard management
log "Creating WireGuard management helper..."
cat > /usr/local/bin/wg-rag-helper << 'EOF'
#!/bin/bash
# WireGuard RAG Scan Stack Helper

case "$1" in
    start)
        echo "Starting WireGuard and microsocks..."
        wg-quick up wg0
        systemctl start microsocks
        echo "✓ WireGuard tunnel active"
        ;;
    stop)
        echo "Stopping WireGuard and microsocks..."
        systemctl stop microsocks
        wg-quick down wg0
        echo "✓ WireGuard tunnel stopped"
        ;;
    status)
        echo "=== WireGuard Status ==="
        wg show
        echo ""
        echo "=== Interface Status ==="
        ip addr show wg0 2>/dev/null || echo "wg0 interface not up"
        echo ""
        echo "=== microsocks Status ==="
        systemctl is-active microsocks
        ;;
    restart)
        echo "Restarting WireGuard..."
        $0 stop
        sleep 2
        $0 start
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart}"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/wg-rag-helper

log "✓ WireGuard pre-installation completed successfully!"
log ""
log "Next steps:"
log "1. Copy WireGuard config to /etc/wireguard/wg0.conf"
log "2. Run: wg-rag-helper start"
log "3. Test: wg-rag-helper status"
log ""
log "Available commands:"
log "  wg-rag-helper start    - Start WireGuard tunnel and SOCKS proxy"
log "  wg-rag-helper stop     - Stop WireGuard tunnel and SOCKS proxy"
log "  wg-rag-helper status   - Show status"
log "  wg-rag-helper restart  - Restart services"
log ""
warn "IMPORTANT: You still need to provide the WireGuard configuration file!"
log "The RAG Scan Stack will automatically configure this when creating WireGuard peers."