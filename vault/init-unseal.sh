#!/bin/sh
# Auto-init + auto-unseal sidecar for HashiCorp Vault.
#
# Behavior:
#   1. Wait for Vault HTTP to respond
#   2. If uninitialized → init with 1 key share (single-operator mode), persist
#      keys + root token to /vault/init/init.json (mode 0600)
#   3. If sealed → read keys from init.json, unseal
#   4. If KV v2 mount missing at "secret/" → enable
#   5. Idle (sleep infinity) so docker keeps the sidecar running
#
# WARNING: Single-key-share + persisted unseal key on disk is a SINGLE-OPERATOR
# convenience trade-off. For multi-operator / production HA, switch to:
#   - 5 key shares, threshold 3, distributed manually
#   - Or auto-unseal via cloud KMS (awskms / azurekeyvault)

set -eu

VAULT_ADDR="${VAULT_ADDR:-https://vault:8200}"
INIT_FILE="/vault/init/init.json"
export VAULT_ADDR VAULT_SKIP_VERIFY=true

echo "[vault-init] waiting for $VAULT_ADDR ..."
i=0
until vault status >/dev/null 2>&1 || [ "$(vault status -format=json 2>/dev/null | sed -n 's/.*"initialized": \(true\|false\).*/\1/p' | head -n1)" != "" ]; do
  i=$((i+1))
  if [ "$i" -gt 60 ]; then
    echo "[vault-init] timed out waiting for vault" >&2
    exit 1
  fi
  sleep 2
done

STATUS_JSON="$(vault status -format=json 2>/dev/null || true)"
INITIALIZED=$(echo "$STATUS_JSON" | sed -n 's/.*"initialized": *\(true\|false\).*/\1/p' | head -n1)
SEALED=$(echo "$STATUS_JSON" | sed -n 's/.*"sealed": *\(true\|false\).*/\1/p' | head -n1)

if [ "$INITIALIZED" = "false" ]; then
  echo "[vault-init] initializing vault (1 key share, threshold 1)"
  vault operator init -format=json -key-shares=1 -key-threshold=1 > "$INIT_FILE"
  chmod 600 "$INIT_FILE"
  INITIALIZED=true
  SEALED=true
fi

if [ "$SEALED" = "true" ]; then
  if [ ! -f "$INIT_FILE" ]; then
    echo "[vault-init] vault is sealed but $INIT_FILE missing — cannot auto-unseal" >&2
    exit 1
  fi
  KEY=$(sed -n 's/.*"unseal_keys_b64": *\[ *"\([^"]*\)".*/\1/p' "$INIT_FILE" | head -n1)
  echo "[vault-init] unsealing"
  vault operator unseal "$KEY" >/dev/null
fi

ROOT_TOKEN=$(sed -n 's/.*"root_token": *"\([^"]*\)".*/\1/p' "$INIT_FILE" | head -n1)
export VAULT_TOKEN="$ROOT_TOKEN"

# Ensure KV v2 secret store at "secret/"
if ! vault secrets list -format=json 2>/dev/null | grep -q '"secret/"'; then
  echo "[vault-init] enabling kv v2 at secret/"
  vault secrets enable -path=secret -version=2 kv || true
fi

echo "[vault-init] ready (root token in $INIT_FILE)"
exec sleep infinity
