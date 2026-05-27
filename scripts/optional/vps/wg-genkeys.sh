#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# wg-genkeys.sh — Generate WireGuard client keypair + ready-to-use config
#
# WHERE TO RUN: On your HOST machine (your laptop/desktop terminal, NOT
#               inside a Docker container). The generated wireguard/wg0.conf
#               is then mounted into Docker automatically.
#
# PREREQUISITE: wireguard-tools must be installed
#   Ubuntu/Debian/WSL2:  sudo apt install wireguard-tools
#   macOS:               brew install wireguard-tools
#   Arch:                sudo pacman -S wireguard-tools
#
# Usage:
#   ./scripts/vps/wg-genkeys.sh <client-name> [client-ip] [port]
#
# The script reads connection details from .env automatically:
#   WG_SERVER_PUBLIC_IP  — VPS public IP (for WireGuard endpoint)
#   WG_SERVER_IP         — VPN tunnel IP (default: 10.13.13.1)
#   WG_PORT              — WireGuard port (default: 51820)
#
# If SERVER_PUBLIC_KEY is not set, you'll be prompted for it
# (printed by setup-remote-db.sh when provisioning the VPS).
#
# Port selection:
#   Default 51820 works for most networks. If blocked, the VPS setup
#   script configures fallback ports: 443 (QUIC), 53 (DNS), 500 (IPsec).
#   The preflight test in Settings > Database will auto-detect working ports.
#
# Examples:
#   ./scripts/vps/wg-genkeys.sh alice                     → 10.13.13.2:51820
#   ./scripts/vps/wg-genkeys.sh bob 10.13.13.3            → 10.13.13.3:51820
#   ./scripts/vps/wg-genkeys.sh charlie 10.13.13.4 443    → 10.13.13.4:443
#
# Output:
#   wireguard/<client-name>_private.key
#   wireguard/<client-name>_public.key
#   wireguard/wg0.conf  (complete config — ready to use, no manual edits)
#   Prints [Peer] block to add to VPS server config
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Check prerequisite ────────────────────────────────────────────────
if ! command -v wg &>/dev/null; then
    echo "[ERROR] 'wg' command not found. Install wireguard-tools first:"
    echo "  Ubuntu/Debian/WSL2:  sudo apt install wireguard-tools"
    echo "  macOS:               brew install wireguard-tools"
    echo "  Arch:                sudo pacman -S wireguard-tools"
    exit 1
fi

CLIENT_NAME="${1:?Usage: $0 <client-name> [client-ip] [port]}"
CLIENT_IP="${2:-10.13.13.2}"
CLIENT_PORT="${3:-}"

# ── Load .env if present ────────────────────────────────────────────
[[ -f "$ROOT_DIR/.env" ]] && { set -a; source "$ROOT_DIR/.env"; set +a; }

# Also check db-config.json for values saved from the Settings UI
DB_CONFIG="$ROOT_DIR/wireguard/db-config.json"
if [[ -f "$DB_CONFIG" ]] && command -v python3 &>/dev/null; then
    _cfg_public_ip=$(python3 -c "import json; d=json.load(open('$DB_CONFIG')); print(d.get('wg_server_public_ip',''))" 2>/dev/null || echo "")
    _cfg_vpn_ip=$(python3 -c "import json; d=json.load(open('$DB_CONFIG')); print(d.get('wg_server_ip',''))" 2>/dev/null || echo "")
    [[ -z "${WG_SERVER_PUBLIC_IP:-}" && -n "$_cfg_public_ip" ]] && WG_SERVER_PUBLIC_IP="$_cfg_public_ip"
    [[ -z "${WG_SERVER_IP:-}" && -n "$_cfg_vpn_ip" ]] && WG_SERVER_IP="$_cfg_vpn_ip"
fi

WG_SERVER_IP="${WG_SERVER_IP:-10.13.13.1}"

# ── Resolve VPS public IP ───────────────────────────────────────────
VPS_PUBLIC_IP="${WG_SERVER_PUBLIC_IP:-}"
if [[ -z "$VPS_PUBLIC_IP" ]]; then
    echo ""
    echo "  WG_SERVER_PUBLIC_IP not found in .env or Settings."
    read -rp "  Enter VPS public IP: " VPS_PUBLIC_IP
    if [[ -z "$VPS_PUBLIC_IP" ]]; then
        echo "[ERROR] VPS public IP is required."
        exit 1
    fi
fi

# ── Resolve port ─────────────────────────────────────────────────────
WG_PORT="${CLIENT_PORT:-${WG_PORT:-51820}}"

# ── Resolve server public key ──────────────────────────────────────
SERVER_PUBKEY="${SERVER_PUBLIC_KEY:-}"
if [[ -z "$SERVER_PUBKEY" ]]; then
    echo ""
    echo "  SERVER_PUBLIC_KEY not found in environment."
    echo "  (This was printed when you ran setup-remote-db.sh on the VPS)"
    read -rp "  Enter server public key: " SERVER_PUBKEY
    if [[ -z "$SERVER_PUBKEY" ]]; then
        echo "[ERROR] Server public key is required."
        exit 1
    fi
fi

WG_DIR="$ROOT_DIR/wireguard"
WG_CONFS_DIR="$WG_DIR/wg_confs"
mkdir -p "$WG_DIR" "$WG_CONFS_DIR"

# ── Generate keypair ────────────────────────────────────────────────
PRIV_KEY_FILE="${WG_DIR}/${CLIENT_NAME}_private.key"
PUB_KEY_FILE="${WG_DIR}/${CLIENT_NAME}_public.key"

if [[ -f "$PRIV_KEY_FILE" ]]; then
    echo "[WARN] Keys for '${CLIENT_NAME}' already exist, reusing"
else
    wg genkey | tee "$PRIV_KEY_FILE" | wg pubkey > "$PUB_KEY_FILE"
    chmod 600 "$PRIV_KEY_FILE"
    echo "[OK] Generated keypair for '${CLIENT_NAME}'"
fi

CLIENT_PRIVKEY=$(cat "$PRIV_KEY_FILE")
CLIENT_PUBKEY=$(cat "$PUB_KEY_FILE")

# ── Generate complete client config ─────────────────────────────────
CONF_FILE="${WG_DIR}/wg0.conf"

cat > "$CONF_FILE" <<EOF
# WireGuard client config for: ${CLIENT_NAME}
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
#
# This file is auto-mounted into Docker via docker-compose.remote-db.yml
# To activate: Settings > Database > Switch to Remote
# Or manually: docker compose -f docker-compose.yml -f docker-compose.remote-db.yml up -d

[Interface]
Address = ${CLIENT_IP}/24
PrivateKey = ${CLIENT_PRIVKEY}

[Peer]
PublicKey = ${SERVER_PUBKEY}
Endpoint = ${VPS_PUBLIC_IP}:${WG_PORT}
AllowedIPs = ${WG_SERVER_IP}/32
PersistentKeepalive = 25
EOF

# Also copy to wg_confs/ where linuxserver/wireguard image expects it
cp "$CONF_FILE" "${WG_CONFS_DIR}/wg0.conf"
chmod 600 "$CONF_FILE" "${WG_CONFS_DIR}/wg0.conf"

echo ""
echo "[OK] Client config written to: ${CONF_FILE}"
echo "     (also copied to ${WG_CONFS_DIR}/wg0.conf for Docker)"
echo ""
echo "  Client:  ${CLIENT_NAME}"
echo "  IP:      ${CLIENT_IP}"
echo "  VPS:     ${VPS_PUBLIC_IP}:${WG_PORT}"
echo "  Tunnel:  ${WG_SERVER_IP}"
echo ""
echo "────────────────────────────────────────────────────"
echo "  Config is COMPLETE — no manual edits needed."
echo "────────────────────────────────────────────────────"
echo ""
echo "Next steps:"
echo "  1. Add this [Peer] block to the VPS /etc/wireguard/wg0.conf:"
echo ""
echo "     [Peer]"
echo "     # ${CLIENT_NAME}"
echo "     PublicKey = ${CLIENT_PUBKEY}"
echo "     AllowedIPs = ${CLIENT_IP}/32"
echo ""
echo "  2. Reload on VPS:  wg syncconf wg0 <(wg-quick strip wg0)"
echo ""
echo "  3. Switch to remote DB in the dashboard:"
echo "     Settings > Database > Switch to Remote"
echo ""
