#!/bin/bash
# Standard RAG Scan Stack Node Provisioning Script
# Run this script on ALL new remote nodes for complete setup
# Usage: ./provision-standard-node.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

log "Starting RAG Scan Stack Node Provisioning..."

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

# Update system
log "Updating system packages..."
case $OS in
    "ubuntu"|"debian")
        apt-get update -qq
        apt-get upgrade -y -qq
        ;;
    "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
        dnf update -y -q || yum update -y -q
        ;;
    "arch")
        pacman -Syu --noconfirm
        ;;
esac

# Install essential packages
log "Installing essential packages..."
case $OS in
    "ubuntu"|"debian")
        apt-get install -y -qq \
            curl \
            wget \
            git \
            htop \
            tmux \
            vim \
            unzip \
            build-essential \
            software-properties-common \
            apt-transport-https \
            ca-certificates \
            gnupg \
            lsb-release
        ;;
    "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
        if [[ $OS == "centos" ]] || [[ $OS == "rhel" ]] || [[ $OS == "rocky" ]] || [[ $OS == "almalinux" ]]; then
            dnf install -y epel-release || yum install -y epel-release
        fi
        dnf install -y curl wget git htop tmux vim unzip gcc make || \
        yum install -y curl wget git htop tmux vim unzip gcc make
        ;;
    "arch")
        pacman -S --noconfirm curl wget git htop tmux vim unzip base-devel
        ;;
esac

# Install Docker
log "Installing Docker..."
if ! command -v docker >/dev/null 2>&1; then
    case $OS in
        "ubuntu"|"debian")
            curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$OS $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
            apt-get update -qq
            apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo || \
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin || \
            yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        "arch")
            pacman -S --noconfirm docker docker-compose
            ;;
    esac

    systemctl enable docker
    systemctl start docker
    log "✅ Docker installed and started"
else
    log "✅ Docker already installed"
fi

# Install WireGuard and networking tools
log "Installing WireGuard and networking tools..."
case $OS in
    "ubuntu"|"debian")
        apt-get install -y -qq \
            wireguard-tools \
            iproute2 \
            netcat-openbsd \
            resolvconf \
            iptables \
            nmap \
            tcpdump \
            netstat-nat \
            dnsutils
        ;;
    "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
        dnf install -y wireguard-tools iproute netcat iptables nmap tcpdump bind-utils || \
        yum install -y wireguard-tools iproute netcat iptables nmap tcpdump bind-utils
        ;;
    "arch")
        pacman -S --noconfirm wireguard-tools iproute2 netcat iptables nmap tcpdump dnsutils
        ;;
esac

# Install microsocks SOCKS5 proxy
log "Installing microsocks SOCKS5 proxy..."
MICROSOCKS_VERSION="v1.0.3"
MICROSOCKS_URL="https://github.com/rofl0r/microsocks/releases/download/${MICROSOCKS_VERSION}/microsocks-linux-x86_64"

if ! command -v microsocks >/dev/null 2>&1; then
    log "Downloading microsocks ${MICROSOCKS_VERSION}..."
    curl -L -o /tmp/microsocks "$MICROSOCKS_URL" || error "Failed to download microsocks"
    chmod +x /tmp/microsocks
    mv /tmp/microsocks /usr/local/bin/microsocks
    log "✅ microsocks installed"
else
    log "✅ microsocks already installed"
fi

# Install Go (for various security tools)
log "Installing Go programming language..."
if ! command -v go >/dev/null 2>&1; then
    GO_VERSION="1.21.5"
    curl -L -o /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    rm /tmp/go.tar.gz
    log "✅ Go ${GO_VERSION} installed"
else
    log "✅ Go already installed"
fi

# Install Python tools
log "Installing Python development tools..."
case $OS in
    "ubuntu"|"debian")
        apt-get install -y -qq python3 python3-pip python3-dev python3-venv
        ;;
    "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
        dnf install -y python3 python3-pip python3-devel || \
        yum install -y python3 python3-pip python3-devel
        ;;
    "arch")
        pacman -S --noconfirm python python-pip
        ;;
esac

# Install Node.js (for any web tools)
log "Installing Node.js..."
if ! command -v node >/dev/null 2>&1; then
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    case $OS in
        "ubuntu"|"debian")
            apt-get install -y nodejs
            ;;
        "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
            dnf install -y nodejs npm || yum install -y nodejs npm
            ;;
        "arch")
            pacman -S --noconfirm nodejs npm
            ;;
    esac
    log "✅ Node.js installed"
else
    log "✅ Node.js already installed"
fi

# Create systemd service for microsocks
log "Setting up systemd services..."
cat > /etc/systemd/system/microsocks.service << 'EOF'
[Unit]
Description=microsocks SOCKS5 proxy for RAG Scan Stack
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

# Create WireGuard directory
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# Enable IP forwarding
log "Configuring network settings..."
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-rag-scan-stack.conf
echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-rag-scan-stack.conf
sysctl -p /etc/sysctl.d/99-rag-scan-stack.conf

# Create RAG Scan Stack helper script
log "Installing RAG Scan Stack helper tools..."
cat > /usr/local/bin/rag-helper << 'EOF'
#!/bin/bash
# RAG Scan Stack Node Helper

case "$1" in
    wg-start)
        echo "Starting WireGuard and microsocks..."
        wg-quick up wg0
        systemctl start microsocks
        echo "✅ RAG tunnel active"
        ;;
    wg-stop)
        echo "Stopping WireGuard and microsocks..."
        systemctl stop microsocks
        wg-quick down wg0
        echo "✅ RAG tunnel stopped"
        ;;
    wg-status)
        echo "=== WireGuard Status ==="
        wg show 2>/dev/null || echo "WireGuard not running"
        echo ""
        echo "=== Interface Status ==="
        ip addr show wg0 2>/dev/null || echo "wg0 interface not up"
        echo ""
        echo "=== microsocks Status ==="
        systemctl is-active microsocks 2>/dev/null || echo "microsocks not running"
        ;;
    wg-restart)
        echo "Restarting RAG tunnel..."
        $0 wg-stop
        sleep 2
        $0 wg-start
        ;;
    info)
        echo "=== RAG Scan Stack Node Info ==="
        echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
        echo "Kernel: $(uname -r)"
        echo "Docker: $(docker --version 2>/dev/null || echo 'Not installed')"
        echo "WireGuard: $(wg --version 2>/dev/null || echo 'Not installed')"
        echo "Go: $(go version 2>/dev/null || echo 'Not installed')"
        echo "Python: $(python3 --version 2>/dev/null || echo 'Not installed')"
        echo "Node.js: $(node --version 2>/dev/null || echo 'Not installed')"
        echo "microsocks: $(/usr/local/bin/microsocks -V 2>/dev/null || echo 'Not installed')"
        ;;
    update)
        echo "Updating RAG Scan Stack node..."
        case $(cat /etc/os-release | grep ^ID= | cut -d= -f2 | tr -d '"') in
            "ubuntu"|"debian")
                apt-get update && apt-get upgrade -y
                ;;
            "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
                dnf update -y || yum update -y
                ;;
            "arch")
                pacman -Syu --noconfirm
                ;;
        esac
        ;;
    *)
        echo "RAG Scan Stack Node Helper"
        echo "Usage: $0 {wg-start|wg-stop|wg-status|wg-restart|info|update}"
        echo ""
        echo "Commands:"
        echo "  wg-start     - Start WireGuard tunnel and SOCKS proxy"
        echo "  wg-stop      - Stop WireGuard tunnel and SOCKS proxy"
        echo "  wg-status    - Show tunnel and proxy status"
        echo "  wg-restart   - Restart tunnel services"
        echo "  info         - Show node software versions"
        echo "  update       - Update system packages"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/rag-helper

# Reload systemd
systemctl daemon-reload

# Security hardening
log "Applying basic security hardening..."

# Update SSH config for better security
if [[ -f /etc/ssh/sshd_config ]]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

    # Disable root password login (keep key-based)
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config

    # Disable empty passwords
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config

    # Protocol 2 only
    echo "Protocol 2" >> /etc/ssh/sshd_config
fi

# Configure firewall (allow SSH and WireGuard)
if command -v ufw >/dev/null 2>&1; then
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow 51820/udp comment "WireGuard"
    ufw --force enable
    log "✅ UFW firewall configured"
elif command -v firewall-cmd >/dev/null 2>&1; then
    systemctl enable firewalld
    systemctl start firewalld
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-port=51820/udp
    firewall-cmd --reload
    log "✅ firewalld configured"
fi

log "✅ RAG Scan Stack node provisioning completed!"
log ""
log "Next steps:"
log "1. The node is ready for WireGuard tunnel creation"
log "2. RAG Scan Stack will automatically configure WireGuard when creating peers"
log "3. Use 'rag-helper info' to check installed software"
log "4. Use 'rag-helper wg-status' to check tunnel status after creation"
log ""
warn "IMPORTANT: Reboot recommended to ensure all kernel modules are loaded"
log "Run: sudo reboot"