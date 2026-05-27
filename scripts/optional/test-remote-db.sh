#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# test-remote-db.sh — Verify WireGuard tunnel + remote Postgres
#
# WHERE TO RUN: On your HOST machine (laptop/desktop terminal, not inside Docker)
#
# Usage:
#   ./scripts/test-remote-db.sh
#
# Checks:
#   1. WireGuard container running + healthy
#   2. Tunnel connectivity (ping VPS)
#   3. Postgres reachable on port 5432
#   4. Both databases accessible
#   5. pgvector extension loaded
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$ROOT_DIR/.env" ]]; then
    set -a
    source "$ROOT_DIR/.env"
    set +a
fi

REMOTE_HOST="${WG_SERVER_IP:-10.13.13.1}"
REMOTE_PORT="${REMOTE_DB_PORT:-5432}"
REMOTE_USER="${REMOTE_DB_USER:-app}"
REMOTE_PASS="${REMOTE_DB_PASSWORD:-}"
DATABASES=("scans" "exploits")

PASS=0
FAIL=0

check() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo -e "  \033[1;32m✓\033[0m ${label}"
        ((PASS++))
    else
        echo -e "  \033[1;31m✗\033[0m ${label}"
        ((FAIL++))
    fi
}

echo ""
echo "Remote Database Connectivity Tests"
echo "───────────────────────────────────"

# 1. WireGuard container
check "WireGuard container running" \
    docker inspect -f '{{.State.Running}}' rag-wireguard

check "WireGuard container healthy" \
    docker inspect -f '{{.State.Health.Status}}' rag-wireguard | grep -q healthy

# 2. Tunnel ping
check "Ping ${REMOTE_HOST} via WireGuard" \
    docker exec rag-wireguard ping -c 2 -W 3 "$REMOTE_HOST"

# 3. TCP connectivity to Postgres port
check "TCP connect to ${REMOTE_HOST}:${REMOTE_PORT}" \
    docker exec rag-wireguard sh -c "echo | nc -w 3 ${REMOTE_HOST} ${REMOTE_PORT}"

# 4. socat proxy listening on :5432
check "db-proxy (socat) listening on :5432" \
    docker exec rag-wireguard sh -c "echo | nc -w 3 127.0.0.1 5432"

# 5. Database access (requires psql in wireguard container)
if [[ -n "$REMOTE_PASS" ]]; then
    # Install psql if needed
    docker exec rag-wireguard sh -c "which psql >/dev/null 2>&1 || apk add --no-cache postgresql16-client >/dev/null 2>&1" || true

    for db in "${DATABASES[@]}"; do
        check "Database '${db}' accessible" \
            docker exec -e PGPASSWORD="$REMOTE_PASS" rag-wireguard \
                psql -h "$REMOTE_HOST" -p "$REMOTE_PORT" -U "$REMOTE_USER" -d "$db" -c "SELECT 1"

        check "pgvector extension in '${db}'" \
            docker exec -e PGPASSWORD="$REMOTE_PASS" rag-wireguard \
                psql -h "$REMOTE_HOST" -p "$REMOTE_PORT" -U "$REMOTE_USER" -d "$db" \
                -tAc "SELECT 1 FROM pg_extension WHERE extname='vector'"
    done
else
    echo -e "  \033[1;33m⊘\033[0m Skipping DB queries (REMOTE_DB_PASSWORD not set)"
fi

echo ""
echo "───────────────────────────────────"
echo "  Results: ${PASS} passed, ${FAIL} failed"
if [[ $FAIL -gt 0 ]]; then
    echo "  Some checks failed — see above"
    exit 1
else
    echo "  All checks passed"
fi
