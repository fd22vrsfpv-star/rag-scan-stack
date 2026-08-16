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

# SOCKS proxy: dante-server, not microsocks.
#
# microsocks was fetched from
#   github.com/rofl0r/microsocks/releases/download/v1.0.3/microsocks-linux-x86_64
# which 404s — that project ships SOURCE-ONLY releases and has never published a
# binary. `curl -L -o` without -f returns exit 0 on a 404, so the `|| error`
# guard never fired: it wrote the 9-byte "Not Found" body to
# /usr/local/bin/microsocks and marked it executable.
#
# dante-server is packaged, systemd-managed, logs to syslog, and — unlike
# microsocks, which accepts anyone who can reach its bind address — enforces
# access control, so the node is not an open SOCKS relay.
#
# Binary/config/service names differ by distro: Debian/Ubuntu ship danted +
# /etc/danted.conf, EPEL ships sockd + /etc/sockd.conf. Both are detected.
log "Installing dante-server SOCKS5 proxy..."

case $OS in
    "ubuntu"|"debian")
        apt-get install -y -qq dante-server || warn "dante-server package install reported an error"
        ;;
    "centos"|"rhel"|"fedora"|"rocky"|"almalinux")
        dnf install -y dante-server || yum install -y dante-server || \
            warn "dante-server package install reported an error"
        ;;
    "arch")
        # `dante` is AUR-only on Arch; there is no official package to install.
        warn "dante is AUR-only on Arch — install it manually (e.g. 'yay -S dante') before creating a peer"
        ;;
esac

# Resolve the binary the distro actually installed. /usr/sbin is not always on
# root's PATH under a non-login SSH shell, so probe the paths directly too.
DANTE_BIN=""
for cand in danted sockd /usr/sbin/danted /usr/sbin/sockd; do
    if command -v "$cand" >/dev/null 2>&1 || [ -x "$cand" ]; then
        DANTE_BIN="$cand"
        break
    fi
done

if [[ -z "$DANTE_BIN" ]]; then
    error "dante-server did not install — no danted/sockd binary found. The SOCKS proxy cannot start without it."
fi

case "$DANTE_BIN" in
    *sockd) DANTE_SVC="sockd"; DANTE_CONF="/etc/sockd.conf" ;;
    *)      DANTE_SVC="danted"; DANTE_CONF="/etc/danted.conf" ;;
esac

log "✅ dante-server installed (binary=$DANTE_BIN, service=$DANTE_SVC, config=$DANTE_CONF)"

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

# dante ships its own systemd unit, so there is no hand-written one to install.
# The packaged unit auto-starts against a stub config and crash-loops until a
# real one exists; the config needs the wg0 address, which is not assigned until
# a peer is created — so hold the service down here and let rag-helper start it
# once wg0 is up.
log "Setting up systemd services..."
systemctl stop "$DANTE_SVC" >/dev/null 2>&1 || true
systemctl disable "$DANTE_SVC" >/dev/null 2>&1 || true
systemctl daemon-reload

# Record what rag-helper should drive, so the helper does not have to repeat the
# distro detection at runtime.
cat > /etc/default/wg-rag-socks << EOF
# Written by provision-standard-node.sh — consumed by rag-helper.
DANTE_SVC=$DANTE_SVC
DANTE_CONF=$DANTE_CONF
WG_SUBNET=10.66.0.0/24
SOCKS_PORT=1080
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

DANTE_SVC="danted"
DANTE_CONF="/etc/danted.conf"
WG_SUBNET="10.66.0.0/24"
SOCKS_PORT="1080"
[ -r /etc/default/wg-rag-socks ] && . /etc/default/wg-rag-socks

# danted binds `internal` at startup, so wg0 must already carry its address
# before the service starts — and the address is only known after a peer config
# has been installed. Generate the config from the live interface rather than
# hardcoding it (the old unit hardcoded 10.66.0.0, a network address nothing can
# bind to, so the proxy could never have listened).
write_socks_config() {
    local wg_ip ext_if
    wg_ip="$(ip -4 -o addr show wg0 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)"
    if [ -z "$wg_ip" ]; then
        echo "ERROR: wg0 has no IPv4 address — bring the tunnel up first" >&2
        return 1
    fi

    # The external interface is whatever carries the default route; danted needs
    # it named explicitly and it is not always eth0.
    ext_if="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)"
    ext_if="${ext_if:-eth0}"

    # Accept ONLY the WireGuard subnet. Without this the node is an open SOCKS
    # relay to anyone who can reach the address.
    cat > "$DANTE_CONF" <<DANTED
logoutput: syslog
internal: $wg_ip port = $SOCKS_PORT
external: $ext_if
socksmethod: none
clientmethod: none
user.privileged: root
user.unprivileged: nobody

client pass {
    from: $WG_SUBNET to: 0.0.0.0/0
    log: connect disconnect error
}
socks pass {
    from: $WG_SUBNET to: 0.0.0.0/0
    log: connect disconnect error
}
DANTED
    echo "Wrote $DANTE_CONF (internal=$wg_ip:$SOCKS_PORT, external=$ext_if)"
}

case "$1" in
    wg-start)
        echo "Starting WireGuard and dante..."
        wg-quick up wg0
        write_socks_config || exit 1
        systemctl enable "$DANTE_SVC" >/dev/null 2>&1 || true
        systemctl restart "$DANTE_SVC" || {
            echo "ERROR: $DANTE_SVC failed to start" >&2
            journalctl -u "$DANTE_SVC" -n 20 --no-pager 2>&1 | tail -20
            exit 1
        }
        echo "✅ RAG tunnel active, SOCKS proxy listening"
        ;;
    wg-stop)
        echo "Stopping WireGuard and dante..."
        systemctl stop "$DANTE_SVC"
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
        echo "=== dante ($DANTE_SVC) Status ==="
        systemctl is-active "$DANTE_SVC" 2>/dev/null || echo "$DANTE_SVC not running"
        ss -ln 2>/dev/null | grep ":$SOCKS_PORT" || echo "not listening on port $SOCKS_PORT"
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
        if command -v "$DANTE_SVC" >/dev/null 2>&1 || [ -x "/usr/sbin/$DANTE_SVC" ]; then
            echo "dante ($DANTE_SVC): installed, $(systemctl is-active "$DANTE_SVC" 2>/dev/null || echo unknown)"
        else
            echo "dante ($DANTE_SVC): Not installed"
        fi
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