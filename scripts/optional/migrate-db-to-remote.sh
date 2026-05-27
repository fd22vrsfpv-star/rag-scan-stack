#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# migrate-db-to-remote.sh — Dump local Postgres → restore to remote VPS
#
# WHERE TO RUN: On your HOST machine (laptop/desktop terminal, not inside Docker)
#
# Prerequisites:
#   - Local rag-postgres container running
#   - SSH key in ssh-keys/ (configured in .env)
#   - Remote VPS provisioned (scripts/vps/setup-remote-db.sh)
#
# Usage:
#   ./scripts/migrate-db-to-remote.sh          # full migration
#   ./scripts/migrate-db-to-remote.sh --dump   # dump only (no restore)
#
# Environment (from .env or exported):
#   POSTGRES_USER         (default: app)
#   POSTGRES_PASSWORD     (default: app)
#   REMOTE_DB_USER        (default: app)
#   REMOTE_DB_PASSWORD    (default: app)
#   REMOTE_DB_HOST        (required — VPS IP/hostname)
#   REMOTE_DB_SSH_USER    (default: azureuser)
#   REMOTE_DB_SSH_KEY     (default: remote_db.pem)
#   REMOTE_DB_PORT        (default: 5432)
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Load .env if present ──────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$ROOT_DIR/.env" ]]; then
    set -a
    source "$ROOT_DIR/.env"
    set +a
fi

# ── Config ────────────────────────────────────────────────────────────
LOCAL_USER="${POSTGRES_USER:-app}"
LOCAL_PASS="${POSTGRES_PASSWORD:-app}"
LOCAL_DB="${POSTGRES_DB:-scans}"

REMOTE_USER="${REMOTE_DB_USER:-app}"
REMOTE_PASS="${REMOTE_DB_PASSWORD:-app}"
REMOTE_HOST="${REMOTE_DB_HOST:?Set REMOTE_DB_HOST in .env}"
REMOTE_SSH_USER="${REMOTE_DB_SSH_USER:-azureuser}"
REMOTE_SSH_KEY="${REMOTE_DB_SSH_KEY:-remote_db.pem}"
REMOTE_PORT="${REMOTE_DB_PORT:-5432}"

SSH_KEY_PATH="${ROOT_DIR}/ssh-keys/${REMOTE_SSH_KEY}"

DATABASES=("$LOCAL_DB")
BACKUP_DIR="${ROOT_DIR}/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DUMP_ONLY=false

[[ "${1:-}" == "--dump" ]] && DUMP_ONLY=true

info()  { echo -e "\033[1;34m[INFO]\033[0m  $*"; }
warn()  { echo -e "\033[1;33m[WARN]\033[0m  $*"; }
err()   { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }
ok()    { echo -e "\033[1;32m[OK]\033[0m    $*"; }

# ── Preflight checks ─────────────────────────────────────────────────
command -v docker >/dev/null || err "docker not found"

info "Checking local postgres..."
docker exec rag-postgres pg_isready -U "$LOCAL_USER" >/dev/null 2>&1 \
    || err "Local rag-postgres not running. Start it: docker compose up -d rag-postgres"
ok "Local postgres is running"

if [[ ! -f "$SSH_KEY_PATH" ]]; then
    err "SSH key not found: $SSH_KEY_PATH"
fi

mkdir -p "$BACKUP_DIR"

# ── Step 1: Dump local databases ─────────────────────────────────────
for db in "${DATABASES[@]}"; do
    DUMP_FILE="${BACKUP_DIR}/${db}_${TIMESTAMP}.dump"
    info "Dumping local '${db}' → ${DUMP_FILE}"

    docker exec -e PGPASSWORD="$LOCAL_PASS" rag-postgres \
        pg_dump -U "$LOCAL_USER" -d "$db" -Fc --no-owner --no-acl \
        > "$DUMP_FILE"

    DUMP_SIZE=$(du -h "$DUMP_FILE" | cut -f1)
    ok "Dump complete: ${DUMP_SIZE}"
done

if $DUMP_ONLY; then
    echo ""
    echo "Dumps saved to: ${BACKUP_DIR}/"
    echo "Run without --dump to also restore to remote."
    exit 0
fi

# ── Step 2: Test SSH connectivity ─────────────────────────────────────
info "Testing SSH connection to ${REMOTE_SSH_USER}@${REMOTE_HOST}..."
ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o BatchMode=yes \
    -i "$SSH_KEY_PATH" "${REMOTE_SSH_USER}@${REMOTE_HOST}" "echo ssh_ok" >/dev/null 2>&1 \
    || err "SSH connection failed. Check key and host."
ok "SSH connection successful"

# ── Step 3: Helper functions ──────────────────────────────────────────
# The host may not have psql/pg_restore. We SSH into the VPS and run
# psql there (postgres is local to the VPS).
_remote_psql() {
    ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" \
        "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
        "PGPASSWORD='${REMOTE_PASS}' psql -h localhost -p ${REMOTE_PORT} -U ${REMOTE_USER} $*"
}

# ── Step 4: Ensure remote database exists ────────────────────────────
info "Checking remote database..."
_remote_psql -d postgres -tAc \
    "\"SELECT 1 FROM pg_database WHERE datname='${LOCAL_DB}'\"" 2>/dev/null | grep -q 1 || {
    info "Creating database '${LOCAL_DB}' on remote..."
    _remote_psql -d postgres -c "\"CREATE DATABASE ${LOCAL_DB}\"" 2>/dev/null || true
}

# ── Step 5: Copy dump to VPS and restore ──────────────────────────────
for db in "${DATABASES[@]}"; do
    DUMP_FILE="${BACKUP_DIR}/${db}_${TIMESTAMP}.dump"
    info "Copying dump to remote VPS..."

    scp -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" \
        "$DUMP_FILE" "${REMOTE_SSH_USER}@${REMOTE_HOST}:/tmp/pg_restore.dump"

    info "Restoring '${db}' on remote ${REMOTE_HOST}:${REMOTE_PORT}..."

    ssh -o StrictHostKeyChecking=no -i "$SSH_KEY_PATH" \
        "${REMOTE_SSH_USER}@${REMOTE_HOST}" \
        "PGPASSWORD='${REMOTE_PASS}' pg_restore -h localhost -p ${REMOTE_PORT} \
         -U ${REMOTE_USER} -d ${db} \
         --clean --if-exists --no-owner --no-acl \
         /tmp/pg_restore.dump 2>&1 | tail -10; \
         rm -f /tmp/pg_restore.dump"

    ok "Restore complete: ${db}"
done

# ── Step 6: Verify ────────────────────────────────────────────────────
info "Verifying remote databases..."
for db in "${DATABASES[@]}"; do
    TABLE_COUNT=$(_remote_psql -d "$db" -tAc \
        "\"SELECT count(*) FROM information_schema.tables WHERE table_schema='public'\"" 2>/dev/null | tr -d ' ' || echo "0")
    ROW_COUNTS=$(_remote_psql -d "$db" -tAc \
        "\"SELECT coalesce(sum(n_live_tup),0) FROM pg_stat_user_tables\"" 2>/dev/null | tr -d ' ' || echo "0")
    ok "${db}: ${TABLE_COUNT} tables, ~${ROW_COUNTS} rows"
done

echo ""
echo "============================================================"
echo "  Migration Complete"
echo "============================================================"
echo "  Backups saved to: ${BACKUP_DIR}/"
echo ""
echo "  Next: Switch to remote in the dashboard Settings → Database tab"
echo "  Or run: curl -X POST http://localhost:8018/db/switch/remote"
echo "============================================================"
