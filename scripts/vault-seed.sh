#!/usr/bin/env bash
# Seed Vault with initial secrets read from .env (one-time migration helper).
#
# Usage:
#   ./scripts/vault-seed.sh                 # uses ./.env
#   ENV_FILE=.env.production ./scripts/vault-seed.sh
#
# After seeding, you can remove the secret values from .env (keep VAULT_ADDR
# pointing at the vault container) and the app will read from Vault on next
# restart.

set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INIT_FILE="$ROOT/vault/init/init.json"

if [ ! -f "$INIT_FILE" ]; then
  echo "vault init.json not found at $INIT_FILE — bring vault profile up first:" >&2
  echo "  docker compose --profile vault up -d" >&2
  exit 1
fi

if [ ! -f "$ROOT/$ENV_FILE" ]; then
  echo "env file not found: $ROOT/$ENV_FILE" >&2
  exit 1
fi

# Extract token from init.json (single-key-share format)
TOKEN=$(sed -n 's/.*"root_token": *"\([^"]*\)".*/\1/p' "$INIT_FILE" | head -n1)
if [ -z "$TOKEN" ]; then
  echo "could not parse root_token from $INIT_FILE" >&2
  exit 1
fi

VAULT_PORT="${VAULT_PORT:-8200}"
VAULT_URL="https://127.0.0.1:${VAULT_PORT}"

put_kv() {
  local path="$1"; shift
  local payload='{"data":{'
  local first=1
  for kv in "$@"; do
    local k="${kv%%=*}"
    local v="${kv#*=}"
    [ "$first" = "1" ] || payload+=","
    first=0
    # JSON-escape value (basic — assumes no unescaped quotes)
    payload+="\"$k\":\"${v//\"/\\\"}\""
  done
  payload+='}}'
  echo "[seed] secret/$path → $(echo "$@" | tr ' ' ',' | sed 's/=[^,]*/=***/g')"
  curl -sk -X POST -H "X-Vault-Token: $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$payload" \
    "$VAULT_URL/v1/secret/data/$path" >/dev/null
}

# Source env file
set -a
# shellcheck disable=SC1090
. "$ROOT/$ENV_FILE"
set +a

# Map env vars → vault paths.
# Add new mappings here as more services migrate to Vault.
RAG_API_ARGS=()
[ -n "${API_KEY:-}" ]   && RAG_API_ARGS+=("API_KEY=$API_KEY")
[ -n "${DB_DSN:-}" ]    && RAG_API_ARGS+=("DB_DSN=$DB_DSN")
[ -n "${NVD_API_KEY:-}" ] && RAG_API_ARGS+=("NVD_API_KEY=$NVD_API_KEY")
[ ${#RAG_API_ARGS[@]} -gt 0 ] && put_kv "rag-api" "${RAG_API_ARGS[@]}"

DB_ARGS=()
[ -n "${POSTGRES_USER:-}" ]     && DB_ARGS+=("POSTGRES_USER=$POSTGRES_USER")
[ -n "${POSTGRES_PASSWORD:-}" ] && DB_ARGS+=("POSTGRES_PASSWORD=$POSTGRES_PASSWORD")
[ -n "${EDB_RW_PASSWORD:-}" ]   && DB_ARGS+=("EDB_RW_PASSWORD=$EDB_RW_PASSWORD")
[ ${#DB_ARGS[@]} -gt 0 ] && put_kv "database" "${DB_ARGS[@]}"

LLM_ARGS=()
[ -n "${ANTHROPIC_API_KEY:-}" ] && LLM_ARGS+=("ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY")
[ -n "${AZURE_API_KEY:-}" ]     && LLM_ARGS+=("AZURE_API_KEY=$AZURE_API_KEY")
[ -n "${OPENAI_API_KEY:-}" ]    && LLM_ARGS+=("OPENAI_API_KEY=$OPENAI_API_KEY")
[ ${#LLM_ARGS[@]} -gt 0 ] && put_kv "llm" "${LLM_ARGS[@]}"

echo "[seed] done. Verify:"
echo "  curl -sk -H 'X-Vault-Token: <token>' $VAULT_URL/v1/secret/data/rag-api"
