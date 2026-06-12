#!/usr/bin/env bash
#
# refresh-db-connection.sh — rebuild DB_DSN and reconnect the stack to the DB,
# without using the Settings → Database UI.
#
# Use this when you changed the remote DB password (or mode) on disk / on the
# remote server and need the running services to pick it up. It mirrors what
# the Settings → Database "switch" action does:
#   1. Read the active mode + credentials from db-config.json
#   2. Rebuild DB_DSN in .env (remote creds + sslmode=require for remote_direct,
#      because the rag-db-tunnel socat sidecar is a plaintext pipe and libpq
#      must negotiate TLS end-to-end; local/SSH-tunnel modes use no sslmode)
#   3. Force-recreate the DB-consumer containers so psycopg2 pools reconnect
#      (a plain `docker restart` keeps the stale env + cached sockets)
#   4. Verify the connection and emit a webhook event
#
# Usage:
#   ./scripts/optional/refresh-db-connection.sh [options]
#
# Options:
#   --password <pw>   Override the DB password (also persisted to db-config.json
#                     with --persist; otherwise applied to DB_DSN only)
#   --mode <m>        Override mode: local | remote | remote_direct
#                     (default: read from db-config.json)
#   --persist         Write the --password value back into db-config.json too
#   --no-recreate     Update .env only; do not recreate containers
#   --dry-run         Show what would change; write nothing
#   -h, --help        Show this help
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$PROJECT_ROOT"

ENV_FILE="$PROJECT_ROOT/.env"
DB_CONFIG="$PROJECT_ROOT/db-config.json"
COMPOSE_PROJECT="${COMPOSE_PROJECT:-$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project" }}' container-logs 2>/dev/null || basename "$PROJECT_ROOT")}"

# DB-consumer services — mirror container_logs.py _DB_CONSUMER_SERVICES.
DB_CONSUMERS=(rag-api pentest-dashboard scan-recommender autogen-agents node-manager
  nmap_scanner nuclei-runner web-scanner osint-runner pd-runner brutus-runner
  playwright-scanner exploit-runner kali-listener news-runner)

MODE_OVERRIDE=""; PW_OVERRIDE=""; PERSIST=0; DO_RECREATE=1; DRY_RUN=0

usage() { sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --password) PW_OVERRIDE="${2:-}"; shift 2 ;;
    --mode)     MODE_OVERRIDE="${2:-}"; shift 2 ;;
    --persist)  PERSIST=1; shift ;;
    --no-recreate) DO_RECREATE=0; shift ;;
    --dry-run)  DRY_RUN=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "❌ Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

[[ -f "$ENV_FILE" ]]   || { echo "❌ .env not found at $ENV_FILE" >&2; exit 1; }
[[ -f "$DB_CONFIG" ]]  || { echo "❌ db-config.json not found (or is a directory) at $DB_CONFIG" >&2; exit 1; }
command -v python3 >/dev/null || { echo "❌ python3 is required" >&2; exit 1; }

echo "🔧 Refreshing DB connection (project: $COMPOSE_PROJECT)"

# ── Rebuild DB_DSN in .env via python (safe quoting for passwords) ──────────
SYNC_OUTPUT="$(MODE_OVERRIDE="$MODE_OVERRIDE" PW_OVERRIDE="$PW_OVERRIDE" PERSIST="$PERSIST" \
  DRY_RUN="$DRY_RUN" ENV_FILE="$ENV_FILE" DB_CONFIG="$DB_CONFIG" python3 - <<'PYEOF'
import json, os, re
from urllib.parse import quote

env_file = os.environ["ENV_FILE"]; cfg_file = os.environ["DB_CONFIG"]
mode_override = os.environ.get("MODE_OVERRIDE", "")
pw_override = os.environ.get("PW_OVERRIDE", "")
persist = os.environ.get("PERSIST") == "1"
dry = os.environ.get("DRY_RUN") == "1"

raw = json.load(open(cfg_file))
flat = raw.get("config") if isinstance(raw.get("config"), dict) else raw
mode = mode_override or raw.get("mode") or flat.get("mode") or "local"
if mode not in ("local", "remote", "remote_direct"):
    raise SystemExit(f"invalid mode: {mode}")

def env_val(key, default=""):
    for line in open(env_file):
        s = line.strip()
        if s.startswith(f"{key}="):
            return s.split("=", 1)[1]
    return default

dbname = env_val("POSTGRES_DB", "scans") or "scans"
if mode in ("remote", "remote_direct"):
    user = flat.get("remote_db_user") or "app"
    pw = pw_override or flat.get("remote_db_password") or ""
else:
    user = env_val("POSTGRES_USER", "app") or "app"
    pw = pw_override or env_val("POSTGRES_PASSWORD", "app") or "app"

dsn = f"postgresql://{quote(user, safe='')}:{quote(pw, safe='')}@rag-postgres:5432/{dbname}"
if mode == "remote_direct":
    dsn += "?sslmode=require"

def set_line(path, key, value):
    lines = open(path).read().splitlines(keepends=True)
    out, found, changed = [], False, False
    nl = f"{key}={value}\n"
    for line in lines:
        st = line.strip()
        if st.startswith(f"{key}=") or st.startswith(f"# {key}="):
            found = True
            if line != nl: changed = True
            out.append(nl)
        else:
            out.append(line)
    if not found:
        out.append(nl); changed = True
    if changed and not dry:
        open(path, "w").writelines(out)
    return changed

changed = set_line(env_file, "DB_DSN", dsn)

if persist and pw_override and mode in ("remote", "remote_direct"):
    # keep db-config.json + REMOTE_DB_PASSWORD in sync with the new password
    if not dry:
        if isinstance(raw.get("config"), dict):
            raw["config"]["remote_db_password"] = pw_override
        else:
            raw["remote_db_password"] = pw_override
        json.dump(raw, open(cfg_file, "w"), indent=2)
    set_line(env_file, "REMOTE_DB_PASSWORD", pw_override)

masked = re.sub(r"://([^:]+):[^@]*@", r"://\1:****@", dsn)
print(f"MODE={mode}")
print(f"DSN={masked}")
print(f"CHANGED={'1' if changed else '0'}")
PYEOF
)"

echo "$SYNC_OUTPUT" | sed 's/^/   /'
MODE="$(echo "$SYNC_OUTPUT" | sed -n 's/^MODE=//p')"
CHANGED="$(echo "$SYNC_OUTPUT" | sed -n 's/^CHANGED=//p')"

if [[ "$DRY_RUN" == "1" ]]; then
  echo "✅ Dry run complete — no files written, no containers recreated."
  exit 0
fi

# ── Force-recreate DB-consumer containers so they re-read DB_DSN ────────────
if [[ "$DO_RECREATE" == "1" ]]; then
  AVAILABLE="$(docker compose -p "$COMPOSE_PROJECT" --env-file "$ENV_FILE" config --services 2>/dev/null || true)"
  TARGETS=()
  for svc in "${DB_CONSUMERS[@]}"; do
    if grep -qx "$svc" <<<"$AVAILABLE"; then TARGETS+=("$svc"); fi
  done
  if [[ ${#TARGETS[@]} -eq 0 ]]; then
    echo "⚠️  No DB-consumer services found in compose; skipping recreate."
  else
    echo "♻️  Force-recreating ${#TARGETS[@]} DB consumer(s): ${TARGETS[*]}"
    docker compose -p "$COMPOSE_PROJECT" --env-file "$ENV_FILE" up -d \
      --force-recreate --no-deps "${TARGETS[@]}"
  fi
else
  echo "ℹ️  --no-recreate set; .env updated but containers not recreated."
fi

# ── Verify ──────────────────────────────────────────────────────────────────
echo "🔌 Verifying connection from rag-api..."
sleep 4
if docker exec rag-api python3 -c "import os,psycopg2; psycopg2.connect(os.environ['DB_DSN']); print('ok')" 2>/dev/null | grep -q ok; then
  echo "✅ Database connection OK ($MODE)"
  VERIFY="ok"
else
  echo "❌ Connection still failing — check the password and 'docker logs rag-api'."
  VERIFY="fail"
fi

# ── Webhook (best-effort) ────────────────────────────────────────────────────
API_KEY="$(grep -E '^API_KEY=' "$ENV_FILE" | head -1 | cut -d= -f2- || true)"
curl -s -k -X POST "https://localhost:8000/webhooks/emit" \
  -H "Content-Type: application/json" \
  -H "x-api-key: ${API_KEY:-changeme}" \
  -d "{\"event_type\":\"database_dsn_synced\",\"source\":\"host_script\",\"data\":{\"mode\":\"$MODE\",\"dsn_changed\":\"$CHANGED\",\"verify\":\"$VERIFY\",\"method\":\"refresh-db-connection.sh\"}}" \
  >/dev/null 2>&1 || true

[[ "$VERIFY" == "ok" ]]
