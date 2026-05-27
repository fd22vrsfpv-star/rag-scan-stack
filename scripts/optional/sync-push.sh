#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# sync-push.sh — Push local changes to remote DB via sync API
#
# WHERE TO RUN: On your HOST machine (laptop/desktop terminal, not inside Docker)
#
# Usage:
#   ./scripts/sync-push.sh [node-id]
#
# Workflow:
#   1. Get local changes since last push (from sync_log)
#   2. Start SSH tunnel to remote
#   3. Send changes to remote /sync/apply
#   4. Update local push watermark
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

# Remote rag-api port (forwarded through SSH tunnel)
REMOTE_API_PORT=18000
REMOTE_API="http://localhost:${REMOTE_API_PORT}"

info()  { echo -e "\033[1;34m[PUSH]\033[0m $*"; }
err()   { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; exit 1; }
ok()    { echo -e "\033[1;32m[OK]\033[0m   $*"; }

# ── Step 1: Collect local changes ─────────────────────────────────────
info "Collecting local changes for node '${NODE_ID}'..."
PUSH_DATA=$(curl -sf -X POST "${LOCAL_API}/sync/push?node_id=${NODE_ID}" \
    -H "x-api-key: ${API_KEY}" 2>/dev/null) || err "Cannot reach local API at ${LOCAL_API}"

COUNT=$(echo "$PUSH_DATA" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
MAX_LSN=$(echo "$PUSH_DATA" | python3 -c "import sys,json; print(json.load(sys.stdin)['max_lsn'])")
info "Found ${COUNT} changes to push (up to LSN ${MAX_LSN})"

if [[ "$COUNT" -eq 0 ]]; then
    ok "Nothing to push — already in sync"
    exit 0
fi

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

# ── Step 3: Push to remote ────────────────────────────────────────────
info "Pushing ${COUNT} changes to remote (strategy: ${STRATEGY})..."
RESULT=$(echo "$PUSH_DATA" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(json.dumps({'changes': data['changes']}))
" | curl -sf -X POST "${REMOTE_API}/sync/apply?node_id=${NODE_ID}&strategy=${STRATEGY}" \
    -H "x-api-key: ${API_KEY}" \
    -H "Content-Type: application/json" \
    -d @- 2>/dev/null) || err "Failed to push to remote"

APPLIED=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Applied: {d[\"applied\"]}, Conflicts: {d[\"conflicts\"]}, Skipped: {d[\"skipped\"]}')")
ok "$APPLIED"

echo ""
echo "Push complete."
