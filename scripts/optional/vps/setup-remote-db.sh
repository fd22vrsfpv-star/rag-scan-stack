#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# setup-remote-db.sh — Provision a VPS as the shared remote database
#
# Run this ON THE VPS (Ubuntu 22.04/24.04 recommended):
#   curl -sSL <url> | sudo bash
#   — or —
#   scp scripts/vps/setup-remote-db.sh root@vps:/tmp/ && ssh root@vps bash /tmp/setup-remote-db.sh
#
# What it does:
#   1. Installs WireGuard, generates server keypair
#   2. Installs PostgreSQL 16 + pgvector from PGDG repo
#   3. Configures Postgres to listen on localhost + wg0
#   4. Installs PgBouncer for connection pooling
#   5. Creates scans + exploits databases
#   6. Configures UFW firewall
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────
WG_IFACE="wg0"
WG_PORT=51820
WG_NETWORK="10.13.13.0/24"
WG_SERVER_IP="10.13.13.1"
WG_CONF_DIR="/etc/wireguard"

# Fallback ports — iptables redirects these to WG_PORT
# UDP 443 looks like QUIC, 53 like DNS, 500 like IPsec — rarely blocked
WG_FALLBACK_PORTS=(443 53 500)

PG_VERSION=16
DB_USER="${REMOTE_DB_USER:-app}"
DB_PASSWORD="${REMOTE_DB_PASSWORD:?Set REMOTE_DB_PASSWORD env var}"
DB_NAMES=("scans" "exploits")

PGBOUNCER_PORT=6432
PGBOUNCER_POOL_SIZE=25
PGBOUNCER_MAX_CONN=200

# ── Helpers ───────────────────────────────────────────────────────────
info()  { echo -e "\033[1;34m[INFO]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
err()   { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || err "Run as root (sudo)"; }
need_root

export DEBIAN_FRONTEND=noninteractive

# ── 1. WireGuard ──────────────────────────────────────────────────────
info "Installing WireGuard..."
apt-get update -qq
apt-get install -y -qq wireguard qrencode

mkdir -p "$WG_CONF_DIR"
chmod 700 "$WG_CONF_DIR"

if [[ ! -f "$WG_CONF_DIR/server_private.key" ]]; then
    wg genkey | tee "$WG_CONF_DIR/server_private.key" | wg pubkey > "$WG_CONF_DIR/server_public.key"
    chmod 600 "$WG_CONF_DIR/server_private.key"
    info "Generated server keypair"
else
    info "Server keypair already exists, skipping"
fi

SERVER_PRIVKEY=$(cat "$WG_CONF_DIR/server_private.key")
SERVER_PUBKEY=$(cat "$WG_CONF_DIR/server_public.key")

# Build iptables rules for fallback port redirects
POSTUP_RULES=""
POSTDOWN_RULES=""
for fbport in "${WG_FALLBACK_PORTS[@]}"; do
    POSTUP_RULES+="iptables -t nat -A PREROUTING -p udp --dport ${fbport} -j REDIRECT --to-port ${WG_PORT}; "
    POSTDOWN_RULES+="iptables -t nat -D PREROUTING -p udp --dport ${fbport} -j REDIRECT --to-port ${WG_PORT}; "
done

cat > "$WG_CONF_DIR/$WG_IFACE.conf" <<WGEOF
[Interface]
Address = ${WG_SERVER_IP}/24
ListenPort = ${WG_PORT}
PrivateKey = ${SERVER_PRIVKEY}

# Fallback port redirects: UDP ${WG_FALLBACK_PORTS[*]} → ${WG_PORT}
# These make WireGuard reachable on ports that bypass restrictive firewalls
PostUp = ${POSTUP_RULES}true
PostDown = ${POSTDOWN_RULES}true

# ── Peers (add with scripts/vps/wg-genkeys.sh) ──
# [Peer]
# PublicKey = <client-pubkey>
# AllowedIPs = 10.13.13.2/32
WGEOF

chmod 600 "$WG_CONF_DIR/$WG_IFACE.conf"

systemctl enable --now wg-quick@${WG_IFACE} 2>/dev/null || {
    warn "WireGuard interface may already be up, restarting..."
    wg-quick down ${WG_IFACE} 2>/dev/null || true
    wg-quick up ${WG_IFACE}
}

info "WireGuard running on :${WG_PORT} — server pubkey: ${SERVER_PUBKEY}"

# ── 2. PostgreSQL 16 + pgvector ───────────────────────────────────────
info "Installing PostgreSQL ${PG_VERSION} + pgvector..."

# PGDG repo
if [[ ! -f /etc/apt/sources.list.d/pgdg.list ]]; then
    apt-get install -y -qq curl ca-certificates gnupg
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list
    apt-get update -qq
fi

apt-get install -y -qq "postgresql-${PG_VERSION}" "postgresql-${PG_VERSION}-pgvector"

# ── 3. Configure Postgres ─────────────────────────────────────────────
PG_CONF="/etc/postgresql/${PG_VERSION}/main/postgresql.conf"
PG_HBA="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"

info "Configuring Postgres to listen on localhost + wg0..."

# listen_addresses
sed -i "s/^#\?listen_addresses\s*=.*/listen_addresses = '127.0.0.1, ${WG_SERVER_IP}'/" "$PG_CONF"

# password_encryption
sed -i "s/^#\?password_encryption\s*=.*/password_encryption = scram-sha-256/" "$PG_CONF"

# Tuning for multi-user pentesting workload
grep -q '# RAG-SCAN-STACK TUNING' "$PG_CONF" || cat >> "$PG_CONF" <<PGEOF

# RAG-SCAN-STACK TUNING
shared_buffers = 256MB
work_mem = 16MB
maintenance_work_mem = 128MB
effective_cache_size = 512MB
max_connections = 200
PGEOF

# pg_hba — allow WireGuard subnet with scram-sha-256
grep -q "10.13.13.0/24" "$PG_HBA" || {
    echo "" >> "$PG_HBA"
    echo "# WireGuard subnet — RAG Scan Stack remote access" >> "$PG_HBA"
    echo "host    all    all    10.13.13.0/24    scram-sha-256" >> "$PG_HBA"
}

systemctl restart postgresql

# ── 4. Create databases + user ────────────────────────────────────────
info "Creating databases and user..."

sudo -u postgres psql -v ON_ERROR_STOP=1 <<SQLEOF
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${DB_USER}') THEN
        CREATE ROLE ${DB_USER} WITH LOGIN PASSWORD '${DB_PASSWORD}';
    ELSE
        ALTER ROLE ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';
    END IF;
END
\$\$;
SQLEOF

for db in "${DB_NAMES[@]}"; do
    sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='${db}'" | grep -q 1 || {
        sudo -u postgres createdb -O "${DB_USER}" "${db}"
        info "Created database: ${db}"
    }
    sudo -u postgres psql -d "${db}" -c "CREATE EXTENSION IF NOT EXISTS vector;"
    sudo -u postgres psql -d "${db}" -c "GRANT ALL ON DATABASE ${db} TO ${DB_USER};"
    sudo -u postgres psql -d "${db}" -c "GRANT ALL ON SCHEMA public TO ${DB_USER};"
    sudo -u postgres psql -d "${db}" -c "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO ${DB_USER};"
done

info "Databases ready: ${DB_NAMES[*]}"

# ── 5. Run ensure_all_tables.sql if available ─────────────────────────
SCHEMA_FILE="/tmp/ensure_all_tables.sql"
if [[ -f "$SCHEMA_FILE" ]]; then
    info "Running schema migration..."
    for db in "${DB_NAMES[@]}"; do
        PGPASSWORD="${DB_PASSWORD}" psql -h 127.0.0.1 -U "${DB_USER}" -d "${db}" -f "$SCHEMA_FILE" 2>&1 || true
    done
else
    warn "No schema file at ${SCHEMA_FILE} — tables will be created on first API start"
    warn "To pre-create: scp db_init/ensure_all_tables.sql root@vps:/tmp/"
fi

# ── 6. PgBouncer ──────────────────────────────────────────────────────
info "Installing PgBouncer..."
apt-get install -y -qq pgbouncer

cat > /etc/pgbouncer/pgbouncer.ini <<PBEOF
[databases]
scans = host=127.0.0.1 port=5432 dbname=scans
exploits = host=127.0.0.1 port=5432 dbname=exploits

[pgbouncer]
listen_addr = 127.0.0.1, ${WG_SERVER_IP}
listen_port = ${PGBOUNCER_PORT}
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
default_pool_size = ${PGBOUNCER_POOL_SIZE}
max_client_conn = ${PGBOUNCER_MAX_CONN}
ignore_startup_parameters = extra_float_digits
log_connections = 0
log_disconnections = 0
PBEOF

# Userlist for pgbouncer (uses same credentials)
PG_HASH=$(sudo -u postgres psql -tAc "SELECT rolpassword FROM pg_authid WHERE rolname='${DB_USER}'")
cat > /etc/pgbouncer/userlist.txt <<ULEOF
"${DB_USER}" "${PG_HASH}"
ULEOF
chmod 640 /etc/pgbouncer/userlist.txt
chown postgres:postgres /etc/pgbouncer/userlist.txt

systemctl enable --now pgbouncer
systemctl restart pgbouncer

info "PgBouncer running on :${PGBOUNCER_PORT}"

# ── 7. Firewall ───────────────────────────────────────────────────────
info "Configuring UFW..."
ufw --force enable 2>/dev/null || true
ufw allow 22/tcp comment "SSH"
ufw allow ${WG_PORT}/udp comment "WireGuard"
for fbport in "${WG_FALLBACK_PORTS[@]}"; do
    ufw allow ${fbport}/udp comment "WireGuard fallback"
done
# Postgres/PgBouncer only via WireGuard — no public exposure
ufw deny 5432/tcp comment "Block public Postgres"
ufw deny ${PGBOUNCER_PORT}/tcp comment "Block public PgBouncer"

info "Firewall configured"

# ── Summary ───────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  VPS Remote Database Setup Complete"
echo "============================================================"
echo ""
echo "  WireGuard:"
echo "    Server IP:      ${WG_SERVER_IP}"
echo "    Listen port:    ${WG_PORT}/udp"
echo "    Fallback ports: ${WG_FALLBACK_PORTS[*]} (UDP, redirected to ${WG_PORT})"
echo "    Server pubkey:  ${SERVER_PUBKEY}"
echo ""
echo "  PostgreSQL:"
echo "    Direct:    ${WG_SERVER_IP}:5432"
echo "    PgBouncer: ${WG_SERVER_IP}:${PGBOUNCER_PORT}"
echo "    User:      ${DB_USER}"
echo "    Databases: ${DB_NAMES[*]}"
echo ""
echo "  Next steps:"
echo "    1. Generate client keys:  ./scripts/vps/wg-genkeys.sh client1"
echo "    2. Add [Peer] block to ${WG_CONF_DIR}/${WG_IFACE}.conf"
echo "    3. wg syncconf ${WG_IFACE} <(wg-quick strip ${WG_IFACE})"
echo "    4. Copy client config to wireguard/wg0.conf"
echo "    5. docker compose -f docker-compose.yml -f docker-compose.remote-db.yml up -d"
echo "============================================================"
