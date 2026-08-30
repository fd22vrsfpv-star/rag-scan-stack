#!/bin/bash
# Safe WireGuard Node Setup with Auto-Recovery
# This script includes safeguards to prevent SSH lockouts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> /tmp/wireguard-install.log
}

warn() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> /tmp/wireguard-install.log
}

error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> /tmp/wireguard-install.log
    exit 1
}

# Auto-recovery function - run in background
setup_auto_recovery() {
    log "Setting up auto-recovery mechanism..."

    # Create recovery script
    cat > /tmp/ssh-recovery.sh << 'EOF'
#!/bin/bash
# Auto-recovery script - restores SSH access if blocked
sleep 300  # Wait 5 minutes for installation to complete

# Check if SSH is accessible
if ! ss -tlnp | grep -q ":22 "; then
    echo "SSH not listening, attempting restart..."
    systemctl restart ssh
fi

# Check and fix firewall if needed
if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        if ! ufw status | grep -q "22/tcp.*ALLOW"; then
            echo "SSH not allowed in UFW, adding rule..."
            ufw allow ssh
            echo "SSH rule added to UFW"
        fi
    fi
fi

# Ensure SSH service is enabled and running
systemctl enable ssh
systemctl start ssh

echo "Auto-recovery completed at $(date)" >> /tmp/ssh-recovery.log
EOF

    chmod +x /tmp/ssh-recovery.sh

    # Run recovery script in background
    nohup bash /tmp/ssh-recovery.sh > /tmp/ssh-recovery.log 2>&1 &

    log "✅ Auto-recovery mechanism activated (will restore SSH in 5 minutes if needed)"
}

# Pre-installation SSH safeguards
setup_ssh_safeguards() {
    log "Setting up SSH safeguards..."

    # Backup current SSH config
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%s)

    # Ensure SSH is explicitly allowed before any changes
    if command -v ufw >/dev/null 2>&1; then
        # Check if UFW is active
        if ufw status | grep -q "Status: active"; then
            warn "UFW is active, ensuring SSH is allowed..."
            ufw allow ssh || true
        else
            log "UFW is inactive, no immediate SSH risk"
        fi
    fi

    # Create emergency SSH restoration script
    cat > /usr/local/bin/emergency-ssh-restore << 'EOF'
#!/bin/bash
# Emergency SSH restoration script
echo "Emergency SSH restoration started at $(date)"

# Disable UFW temporarily
if command -v ufw >/dev/null 2>&1; then
    ufw --force disable
    echo "UFW disabled"
fi

# Restart SSH service
systemctl stop ssh
systemctl start ssh
systemctl enable ssh
echo "SSH service restarted"

# Re-enable UFW with SSH allowed
if command -v ufw >/dev/null 2>&1; then
    ufw --force reset
    ufw allow ssh
    ufw allow 51820/udp
    ufw --force enable
    echo "UFW re-enabled with SSH allowed"
fi

echo "Emergency restoration completed at $(date)"
EOF

    chmod +x /usr/local/bin/emergency-ssh-restore

    # Schedule emergency restoration in 10 minutes (failsafe)
    echo "/usr/local/bin/emergency-ssh-restore" | at now + 10 minutes 2>/dev/null || {
        # If 'at' is not available, use cron
        (crontab -l 2>/dev/null; echo "$(date -d '+10 minutes' '+%M %H %d %m *') /usr/local/bin/emergency-ssh-restore") | crontab -
        log "Emergency restoration scheduled via cron (10 minutes)"
    }

    log "✅ SSH safeguards activated"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root (use sudo)"
fi

# Install 'at' command for scheduling if not present
if ! command -v at >/dev/null 2>&1; then
    log "Installing 'at' command for scheduling..."
    apt-get update -qq
    apt-get install -y at
    systemctl enable atd
    systemctl start atd
fi

# Setup safeguards FIRST
setup_ssh_safeguards
setup_auto_recovery

log "Starting SAFE WireGuard installation..."

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
            resolvconf

        # Explicitly AVOID installing iptables to prevent auto-firewall activation
        warn "Skipping iptables installation to prevent firewall auto-activation"

        log "✅ WireGuard tools installed"
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
        dnf install -y wireguard-tools iproute curl netcat || \
        yum install -y wireguard-tools iproute curl netcat

        log "✅ WireGuard tools installed"
        ;;

    "arch")
        log "Installing for Arch Linux..."
        pacman -Sy --noconfirm wireguard-tools iproute2 curl netcat
        log "✅ WireGuard tools installed"
        ;;

    *)
        error "Unsupported operating system: $OS"
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
        apt-get install -y dante-server || warn "dante-server package install reported an error"
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

# The packaged unit auto-starts against a stub config and crash-loops until a
# real one exists. The config needs the wg0 address, which is not assigned until
# a peer is created — so hold the service down here and let wg-rag-helper start
# it once wg0 is up.
systemctl stop "$DANTE_SVC" >/dev/null 2>&1 || true
systemctl disable "$DANTE_SVC" >/dev/null 2>&1 || true
systemctl daemon-reload

# Record what wg-rag-helper should drive, so the helper does not have to repeat
# the distro detection at runtime.
cat > /etc/default/wg-rag-socks << EOF
# Written by wireguard-node-setup-safe.sh — consumed by wg-rag-helper.
DANTE_SVC=$DANTE_SVC
DANTE_CONF=$DANTE_CONF
WG_SUBNET=10.66.0.0/24
SOCKS_PORT=1080
EOF

# Create WireGuard directory
log "Creating WireGuard configuration directory..."
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

# Enable IP forwarding (safe - no firewall impact)
log "Enabling IP forwarding..."
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-wireguard.conf
sysctl -p /etc/sysctl.d/99-wireguard.conf

# Create WireGuard management helper
log "Creating WireGuard management helper..."
cat > /usr/local/bin/wg-rag-helper << 'EOF'
#!/bin/bash
# WireGuard RAG Scan Stack Helper

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
    start)
        echo "Starting WireGuard and dante..."
        wg-quick up wg0
        write_socks_config || exit 1
        systemctl enable "$DANTE_SVC" >/dev/null 2>&1 || true
        systemctl restart "$DANTE_SVC" || {
            echo "ERROR: $DANTE_SVC failed to start" >&2
            journalctl -u "$DANTE_SVC" -n 20 --no-pager 2>&1 | tail -20
            exit 1
        }
        echo "✅ WireGuard tunnel active, SOCKS proxy listening"
        ;;
    stop)
        echo "Stopping WireGuard and dante..."
        systemctl stop "$DANTE_SVC"
        wg-quick down wg0
        echo "✅ WireGuard tunnel stopped"
        ;;
    status)
        echo "=== WireGuard Status ==="
        wg show
        echo ""
        echo "=== Interface Status ==="
        ip addr show wg0 2>/dev/null || echo "wg0 interface not up"
        echo ""
        echo "=== dante ($DANTE_SVC) Status ==="
        systemctl is-active "$DANTE_SVC"
        ss -ln 2>/dev/null | grep ":$SOCKS_PORT" || echo "not listening on port $SOCKS_PORT"
        ;;
    restart)
        echo "Restarting WireGuard..."
        $0 stop
        sleep 2
        $0 start
        ;;
    ssh-check)
        echo "=== SSH Status Check ==="
        systemctl status ssh
        ss -tlnp | grep :22
        if command -v ufw >/dev/null 2>&1; then
            echo "UFW Status:"
            ufw status
        fi
        ;;
    ssh-fix)
        echo "Fixing SSH access..."
        systemctl restart ssh
        if command -v ufw >/dev/null 2>&1; then
            ufw allow ssh
        fi
        echo "SSH access restored"
        ;;
    *)
        echo "WireGuard RAG Scan Stack Helper"
        echo "Usage: $0 {start|stop|status|restart|ssh-check|ssh-fix}"
        echo ""
        echo "Commands:"
        echo "  start      - Start WireGuard tunnel and SOCKS proxy"
        echo "  stop       - Stop WireGuard tunnel and SOCKS proxy"
        echo "  status     - Show status"
        echo "  restart    - Restart services"
        echo "  ssh-check  - Check SSH service status"
        echo "  ssh-fix    - Fix SSH access if blocked"
        exit 1
        ;;
esac
EOF

chmod +x /usr/local/bin/wg-rag-helper

# Final SSH verification
log "Performing final SSH verification..."
if ss -tlnp | grep -q ":22 "; then
    log "✅ SSH is listening on port 22"
else
    warn "⚠️  SSH not detected on port 22, starting SSH service..."
    systemctl enable ssh
    systemctl start ssh
fi

# Remove emergency restoration since we succeeded
crontab -l 2>/dev/null | grep -v emergency-ssh-restore | crontab - || true

# Create completion marker
touch /tmp/wireguard-installation-complete
echo "Installation completed successfully at $(date)" >> /tmp/wireguard-install.log

log "✅ SAFE WireGuard installation completed successfully!"
log ""
log "Auto-recovery features:"
log "  - SSH restoration script runs in background"
log "  - Emergency helper: wg-rag-helper ssh-fix"
log "  - Installation log: /tmp/wireguard-install.log"
log ""
log "Next steps:"
log "1. Test SSH access: ssh user@thishost"
log "2. Check status: wg-rag-helper status"
log "3. WireGuard peer creation will now be FAST (30-60 seconds)"