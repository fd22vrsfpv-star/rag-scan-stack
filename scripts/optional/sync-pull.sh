#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# sync-pull.sh — Pull changes from remote DB to local
#
# WHERE TO RUN: On your HOST machine (laptop/desktop terminal, not inside Docker)
#
# Usage:
#   ./scripts/sync-pull.sh [node-id]
#
# Workflow:
#   1. Open SSH tunnel to remote rag-api
#   2. Query remote for changes since last pull
#   3. Apply changes to local DB with conflict detection
#
# Prerequisites:
#   - Local rag-api running (docker compose up -d rag-api)
#   - SSH key in ssh-keys/ (configured in .env)
#   - Node registered: POST /sync/register-node on both local and remote
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[[ -f "$ROOT_DIR/.env" ]] && { set -a; source "$ROOT_DIR/.env"; set +a; }

NODE_ID="${1:-local}"
LOCAL_API="http://localhost:8000"
API_KEY="${API_KEY:-changeme}"
STRATEGY="${SYNC_STRATEGY:-last_write_wins}"

REMOTE_HOST="${REMOTE_DB_HOST:?Set REMOTE_DB_HOST in .env}"
REMOTE_SSH_USER="${REMOTE_DB_SSH_USER:-azureuser}"
REMOTE_SSH_KEY="${REMOTE_DB_SSH_KEY:-remote_db.pem}"
SSH_KEY_PATH="${ROOT_DIR}/ssh-keys/${REMOTE_SSH_KEY}"

REMOTE_API_PORT=18000
REMOTE_API="http://localhost:${REMOTE_API_PORT}"

info()  { echo -e "\033[1;34m[PULL]\033[0m $*"; }
err()   { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }
ok()    { echo -e "\033[1;32m[OK]\033[0m   $*"; }

# ── Step 1: Check local sync state ───────────────────────────────────
info "Checking local sync state for node '${NODE_ID}'..."
LOCAL_STATUS=$(curl -sf "${LOCAL_API}/sync/status?node_id=${NODE_ID}" \
    -H "x-api-key: ${API_KEY}" 2>/dev/null) || err "Cannot reach local API at ${LOCAL_API}"

LAST_LSN=$(echo "$LOCAL_STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('last_push_lsn', 0))" 2>/dev/null || echo "0")
info "Last pull LSN: ${LAST_LSN}"

# ── Step 2: Open SSH tunnel to remote rag-api ─────────────────────────
info "Opening SSH tunnel to remote rag-api..."
ssh -f -N -o StrictHostKeyChecking=no -o ServerAliveInterval=30 \
    -o ExitOnForwardFailure=yes \
    -i "$SSH_KEY_PATH" \
    -L "${REMOTE_API_PORT}:localhost:8000" \
    "${REMOTE_SSH_USER}@${REMOTE_HOST}" 2>/dev/null \
    || err "SSH tunnel failed. Check key and host."

SSH_PID=$(lsof -ti :${REMOTE_API_PORT} 2>/dev/null | head -1)
cleanup() { [[ -n "${SSH_PID:-}" ]] && kill "$SSH_PID" 2>/dev/null || true; }
trap cleanup EXIT
sleep 2
ok "SSH tunnel established"

# ── Step 3: Fetch changes from remote ─────────────────────────────────
info "Fetching changes from remote since LSN ${LAST_LSN}..."
CHANGES=$(curl -sf "${REMOTE_API}/sync/changes?since_lsn=${LAST_LSN}&limit=5000" \
    -H "x-api-key: ${API_KEY}" 2>/dev/null) || err "Cannot reach remote API"

COUNT=$(echo "$CHANGES" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
info "Found ${COUNT} changes to pull"

if [[ "$COUNT" -eq 0 ]]; then
    ok "Already up to date"
    exit 0
fi

# ── Step 4: Apply changes to local ────────────────────────────────────
info "Applying ${COUNT} changes (strategy: ${STRATEGY})..."
RESULT=$(echo "$CHANGES" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(json.dumps({'changes': data['changes']}))
" | curl -sf -X POST "${LOCAL_API}/sync/apply?node_id=${NODE_ID}&strategy=${STRATEGY}" \
    -H "x-api-key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d @- 2>/dev/null) || err "Failed to apply changes"

APPLIED=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Applied: {d[\"applied\"]}, Conflicts: {d[\"conflicts\"]}, Skipped: {d[\"skipped\"]}')")
ok "$APPLIED"

echo ""
echo "Pull complete."
