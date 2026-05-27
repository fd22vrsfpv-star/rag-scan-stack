#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [ $# -lt 2 ]; then
    echo "Usage: $0 <peer-name> <remote-host-ip> [ssh-user]"
    echo "Example: $0 web-server-01 192.168.1.100 root"
    exit 1
fi

PEER_NAME="$1"
REMOTE_HOST="$2"
SSH_USER="${3:-root}"
WG_PORT="51820"
API_URL="https://localhost:3002"

log_info "Creating WireGuard peer: $PEER_NAME"

# Check if WireGuard server is running
if ! docker compose ps wg-server | grep -q "Up"; then
    log_error "WireGuard server is not running"
    log_info "Starting WireGuard server..."
    docker compose --profile optional up -d wg-server
    sleep 5
fi

# Find next available IP
USED_IPS=$(docker exec wg-server grep "AllowedIPs" /config/wg_confs/wg0.conf 2>/dev/null | grep -o "10\.66\.0\.[0-9]*" | sort -V | tail -1)
if [ -z "$USED_IPS" ]; then
    NEXT_IP="10.66.0.2"
else
    LAST_OCTET=$(echo "$USED_IPS" | cut -d. -f4)
    NEXT_OCTET=$((LAST_OCTET + 1))
    NEXT_IP="10.66.0.$NEXT_OCTET"
fi

log_info "Assigned IP: $NEXT_IP"

# Generate WireGuard keys
log_info "Generating WireGuard keypair..."
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)

# Get server public key
SERVER_PUBLIC_KEY=$(docker exec wg-server cat /config/server/publickey-server 2>/dev/null || docker exec wg-server cat /config/coredns/publickey-server 2>/dev/null)

log_info "Adding peer to server configuration..."

# Add peer to server config
docker exec wg-server bash -c "cat >> /config/wg_confs/wg0.conf << EOF

[Peer]
# $PEER_NAME
PublicKey = $PUBLIC_KEY
AllowedIPs = $NEXT_IP/32
PersistentKeepalive = 25
EOF"

# Reload WireGuard config
log_info "Reloading WireGuard configuration..."
docker exec wg-server wg syncconf wg0 <(docker exec wg-server wg-quick strip wg0)

# Create client configuration
CLIENT_CONFIG="/tmp/wg-${PEER_NAME}.conf"
log_info "Creating client configuration: $CLIENT_CONFIG"

cat > "$CLIENT_CONFIG" << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $NEXT_IP/24
DNS = 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $(curl -s ifconfig.me):$WG_PORT
AllowedIPs = 10.66.0.0/24
PersistentKeepalive = 25
EOF

log_success "WireGuard peer created successfully!"
echo ""
echo "📋 Next Steps:"
echo "=============="
echo "1. Copy the configuration to your remote node:"
echo "   scp $CLIENT_CONFIG $SSH_USER@$REMOTE_HOST:/etc/wireguard/wg0.conf"
echo ""
echo "2. On the remote node, install WireGuard and microsocks:"
echo "   sudo apt-get update && sudo apt-get install -y wireguard-tools microsocks"
echo ""
echo "3. Configure microsocks to listen on WireGuard interface:"
echo "   echo 'DAEMON_OPTS=\"-i $NEXT_IP -p 1080\"' | sudo tee /etc/default/microsocks"
echo "   sudo systemctl enable --now microsocks"
echo ""
echo "4. Start WireGuard on the remote node:"
echo "   sudo wg-quick up wg0"
echo "   sudo systemctl enable wg-quick@wg0"
echo ""
echo "5. Test the connection:"
echo "   curl --socks5 127.0.0.1:1080 http://httpbin.org/ip"
echo ""
echo "🔗 Client configuration saved to: $CLIENT_CONFIG"
echo "📱 For mobile devices, generate a QR code:"
echo "   qrencode -t ansiutf8 < $CLIENT_CONFIG"
echo ""
log_warning "Remember to update your node database entry with:"
log_warning "tunnel_method = 'wireguard', wg_assigned_ip = '$NEXT_IP'"