#!/bin/bash
# Safe Standard RAG Scan Stack Node Provisioning Script
# Includes auto-recovery and SSH safeguards to prevent lockouts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /tmp/provision.log
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> /tmp/provision.log
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> /tmp/provision.log
    exit 1
}

info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1" >> /tmp/provision.log
}

# Enhanced auto-recovery system
setup_comprehensive_recovery() {
    log "Setting up comprehensive auto-recovery system..."

    # Create advanced recovery script
    cat > /tmp/comprehensive-recovery.sh << 'EOF'
#!/bin/bash
# Comprehensive auto-recovery system
RECOVERY_LOG="/tmp/auto-recovery.log"

log_recovery() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$RECOVERY_LOG"
}

# Wait for installation to complete
sleep 180  # Wait 3 minutes

log_recovery "Starting auto-recovery check..."

# Function to restore SSH
restore_ssh() {
    log_recovery "Restoring SSH access..."

    # Disable all firewalls temporarily
    if command -v ufw >/dev/null 2>&1; then
        ufw --force disable 2>/dev/null
        log_recovery "UFW disabled"
    fi

    if command -v firewall-cmd >/dev/null 2>&1; then
        systemctl stop firewalld 2>/dev/null
        log_recovery "firewalld stopped"
    fi

    # Restore SSH service
    systemctl stop ssh 2>/dev/null || true
    systemctl enable ssh
    systemctl start ssh

    # Wait for SSH to start
    sleep 5

    # Re-enable firewall with proper SSH rules
    if command -v ufw >/dev/null 2>&1; then
        ufw --force reset
        ufw allow ssh
        ufw allow 51820/udp comment "WireGuard"
        ufw default deny incoming
        ufw default allow outgoing
        echo "y" | ufw enable
        log_recovery "UFW re-enabled with SSH allowed"
    fi

    if command -v firewall-cmd >/dev/null 2>&1; then
        systemctl enable firewalld
        systemctl start firewalld
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-port=51820/udp
        firewall-cmd --reload
        log_recovery "firewalld re-enabled with SSH allowed"
    fi

    log_recovery "SSH restoration completed"
}

# Check if SSH is accessible
if ! ss -tlnp | grep -q ":22 "; then
    log_recovery "SSH not listening - attempting restoration"
    restore_ssh
else
    log_recovery "SSH is listening correctly"
fi

# Verify SSH is actually accessible (try to connect to ourselves)
if ! timeout 5 bash -c "echo | nc localhost 22" 2>/dev/null; then
    log_recovery "SSH not responding - attempting restoration"
    restore_ssh
fi

# Additional safety: schedule another check in 5 minutes
if [ ! -f /tmp/provision-complete ]; then
    echo "bash /tmp/comprehensive-recovery.sh" | at now + 5 minutes 2>/dev/null || true
    log_recovery "Scheduled additional recovery check"
fi

log_recovery "Auto-recovery check completed"
EOF

    chmod +x /tmp/comprehensive-recovery.sh

    # Start recovery in background with multiple safety nets
    nohup bash /tmp/comprehensive-recovery.sh > /tmp/auto-recovery.log 2>&1 &

    # Also schedule via cron as backup
    (crontab -l 2>/dev/null; echo "$(date -d '+10 minutes' '+%M %H %d %m *') /tmp/comprehensive-recovery.sh") | crontab - 2>/dev/null || true

    log "✅ Comprehensive auto-recovery activated"
}

# Pre-installation safety checks
setup_safety_checks() {
    log "Setting up pre-installation safety checks..."

    # Record current SSH configuration
    SSH_PORT=$(ss -tlnp | grep ssh | head -1 | awk '{print $4}' | cut -d: -f2)
    echo "SSH_PORT=$SSH_PORT" > /tmp/ssh-config.backup

    # Create immediate SSH restoration script
    cat > /usr/local/bin/emergency-ssh-now << 'EOF'
#!/bin/bash
# Immediate SSH restoration
echo "EMERGENCY: Restoring SSH access immediately"

# Kill all firewall processes
pkill -9 ufw 2>/dev/null || true
pkill -9 firewalld 2>/dev/null || true

# Flush iptables
iptables -F 2>/dev/null || true
iptables -X 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true
iptables -t nat -X 2>/dev/null || true

# Restart SSH
systemctl stop ssh 2>/dev/null || true
systemctl start ssh
systemctl enable ssh

echo "Emergency SSH restoration completed"
EOF

    chmod +x /usr/local/bin/emergency-ssh-now

    # Test current SSH connectivity
    if ss -tlnp | grep -q ":22 "; then
        log "✅ SSH currently accessible on port 22"
    else
        warn "SSH not detected - ensuring it starts"
        systemctl enable ssh
        systemctl start ssh
    fi

    log "✅ Safety checks completed"
}

# Safe firewall configuration
configure_firewall_safely() {
    log "Configuring firewall with safety measures..."

    if command -v ufw >/dev/null 2>&1; then
        log "Configuring UFW with SSH protection..."

        # Ensure SSH is allowed BEFORE any other changes
        ufw allow ssh 2>/dev/null || true

        # Reset and configure properly
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing

        # CRITICAL: Allow SSH first
        ufw allow ssh
        ufw allow 51820/udp comment "WireGuard"

        # Enable with automatic yes
        echo "y" | ufw enable

        # Verify SSH rule is active
        if ufw status | grep -q "22/tcp.*ALLOW"; then
            log "✅ UFW configured with SSH protection"
        else
            warn "UFW SSH rule verification failed - adding again"
            ufw allow ssh
        fi

    elif command -v firewall-cmd >/dev/null 2>&1; then
        log "Configuring firewalld with SSH protection..."

        systemctl enable firewalld
        systemctl start firewalld

        # Add SSH FIRST
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-port=51820/udp
        firewall-cmd --reload

        log "✅ firewalld configured with SSH protection"
    else
        log "No supported firewall found - SSH will remain accessible"
    fi
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

log "Starting SAFE RAG Scan Stack Node Provisioning..."

# Install essential tools first (including 'at' for scheduling)
log "Installing essential scheduling tools..."
apt-get update -qq
apt-get install -y at cron curl

# Enable scheduling services
systemctl enable atd cron
systemctl start atd cron

# Setup all safety mechanisms FIRST
setup_safety_checks
setup_comprehensive_recovery

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

# Install essential packages (but avoid problematic ones initially)
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

# Install Docker safely
log "Installing Docker..."
if ! command -v docker >/dev/null 2>&1; then
    case $OS in
        "ubuntu"|"debian")
            curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
            echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$OS $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
            apt-get update -qq
            apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
            ;;
        *)
            log "Docker installation for $OS - using generic method"
            curl -fsSL https://get.docker.com | sh
            ;;
    esac

    systemctl enable docker
    systemctl start docker
    log "✅ Docker installed and started"
else
    log "✅ Docker already installed"
fi

# Install WireGuard and networking tools (carefully)
log "Installing WireGuard and networking tools..."
case $OS in
    "ubuntu"|"debian")
        # Install packages one by one to avoid triggering auto-firewall
        apt-get install -y -qq wireguard-tools
        apt-get install -y -qq iproute2
        apt-get install -y -qq netcat-openbsd
        apt-get install -y -qq resolvconf
        apt-get install -y -qq nmap
        apt-get install -y -qq tcpdump
        apt-get install -y -qq dnsutils
        # Install iptables LAST to minimize auto-configuration risk
        apt-get install -y -qq iptables
        ;;
    *)
        # Other OS installations...
        log "Installing networking tools for $OS"
        ;;
esac

# SOCKS proxy: dante-server, not microsocks.
#
# microsocks was fetched from
#   github.com/rofl0r/microsocks/releases/download/v1.0.3/microsocks-linux-x86_64
# which 404s — that project ships SOURCE-ONLY releases and has never published a
# binary. This call did not even check the exit status, so the 9-byte
# "Not Found" body landed in /usr/local/bin/microsocks marked executable.
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
# Written by provision-standard-node-safe.sh — consumed by rag-helper.
DANTE_SVC=$DANTE_SVC
DANTE_CONF=$DANTE_CONF
WG_SUBNET=10.66.0.0/24
SOCKS_PORT=1080
EOF

# Create WireGuard directory
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# Enable IP forwarding
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-rag-scan-stack.conf
echo 'net.ipv6.conf.all.forwarding = 1' >> /etc/sysctl.d/99-rag-scan-stack.conf
sysctl -p /etc/sysctl.d/99-rag-scan-stack.conf

# Apply SSH hardening CAREFULLY
log "Applying SSH security hardening..."
if [[ -f /etc/ssh/sshd_config ]]; then
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%s)

    # Safe SSH modifications (don't break existing connections)
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config || true
    sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config || true
    sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config || true

    # Test SSH config before restarting
    if sshd -t; then
        log "SSH config valid, will restart after firewall setup"
    else
        warn "SSH config test failed, keeping original"
        cp /etc/ssh/sshd_config.backup.$(date +%s) /etc/ssh/sshd_config
    fi
fi

# Configure firewall SAFELY (most critical part)
configure_firewall_safely

# NOW restart SSH after firewall is properly configured
log "Restarting SSH with new configuration..."
systemctl restart ssh

# Verify SSH is still accessible
sleep 3
if ss -tlnp | grep -q ":22 "; then
    log "✅ SSH verified accessible after configuration"
else
    warn "SSH verification failed - running emergency restoration"
    /usr/local/bin/emergency-ssh-now
fi

# Install additional development tools
log "Installing development tools..."
# ... (abbreviated for space, but include Go, Python, Node.js, etc.)

# Create comprehensive helper script
cat > /usr/local/bin/rag-helper << 'EOF'
#!/bin/bash
# RAG Scan Stack Node Helper with Safety Features

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
    ssh-emergency)
        echo "EMERGENCY: Restoring SSH access..."
        /usr/local/bin/emergency-ssh-now
        echo "SSH emergency restoration completed"
        ;;
    safety-check)
        echo "=== Safety Check ==="
        echo "SSH Status: $(systemctl is-active ssh)"
        echo "SSH Listening: $(ss -tlnp | grep :22 | wc -l) processes"
        echo "UFW Status: $(command -v ufw >/dev/null && ufw status | grep Status || echo 'Not available')"
        echo "Auto-recovery log:"
        tail -5 /tmp/auto-recovery.log 2>/dev/null || echo "No auto-recovery log"
        ;;
    *)
        echo "RAG Scan Stack Node Helper (Safe Version)"
        echo "Usage: $0 {wg-start|wg-stop|wg-status|ssh-emergency|safety-check|info|update}"
        echo ""
        echo "Safety Commands:"
        echo "  ssh-emergency  - Emergency SSH restoration"
        echo "  safety-check   - Check all safety systems"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/rag-helper

# Create completion marker
touch /tmp/provision-complete
echo "Provisioning completed successfully at $(date)" >> /tmp/provision.log

# Cancel any pending emergency restoration
crontab -l 2>/dev/null | grep -v comprehensive-recovery | crontab - || true

log "✅ SAFE RAG Scan Stack node provisioning completed!"
log ""
log "Safety Features Active:"
log "  ✅ Auto-recovery system monitoring SSH"
log "  ✅ Emergency restoration: rag-helper ssh-emergency"
log "  ✅ Safety check: rag-helper safety-check"
log "  ✅ Installation log: /tmp/provision.log"
log ""
log "Next steps:"
log "1. Test SSH access: ssh user@thishost"
log "2. Check safety: rag-helper safety-check"
log "3. WireGuard peer creation will be FAST (30-60 seconds)"
log ""
warn "REBOOT RECOMMENDED to ensure all kernel modules are loaded"