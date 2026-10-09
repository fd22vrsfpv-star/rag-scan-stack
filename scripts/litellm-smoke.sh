#!/usr/bin/env bash
# litellm-smoke.sh — PR 4/4 of the LiteLLM migration (Docs/plans/LITELLM_MIGRATION.md).
#
# For every provider the operator has configured through Settings → LLM,
# fires ONE 10-token "say OK" prompt through llm_query /api/generate and
# verifies the response + checks which path (`litellm` or `hand_rolled`)
# actually served the call. This is the operator-runnable gate the plan
# requires before the hand-rolled helpers can be deleted — the output
# should show `path=litellm` for every provider the migration covers.
#
# Reads provider aliases from GET /litellm-status (returns the exact
# alias set the Router registered), so it stays in sync with whatever
# the operator has configured — no hard-coded provider list.
#
# Usage:
#   ./scripts/litellm-smoke.sh                   # probe inside the compose network
#   LLM_QUERY_URL=http://remote:8002 ./scripts/litellm-smoke.sh
#   SKIP_PROVIDERS="azure-main:gpt-5" ./scripts/litellm-smoke.sh
#
# Exits 0 only when every attempted provider served through `path=litellm`.
# A single `path=hand_rolled` is a FAIL (LiteLLM couldn't serve → the
# cleanup-PR still has a reason to wait). An HTTP error is reported but
# counted separately: a provider whose endpoint is down is a config
# issue, not a LiteLLM issue.
#
# Reads the per-call path from `docker compose logs llm_query` (the
# path telemetry PR 2 added). Must have `docker compose` on the PATH;
# falls back to `docker-compose` if present.
set -euo pipefail

LLM_QUERY_URL="${LLM_QUERY_URL:-http://localhost:8002}"
# llm_query mounts its handler router at /ollama (OpenAI-compat path too), so
# `/litellm-status` lives under both /ollama and /api — pick /ollama because
# /api is the generic shim and may be unmounted in some deployments.
STATUS_PATH="${STATUS_PATH:-/ollama/litellm-status}"
GENERATE_PATH="${GENERATE_PATH:-/api/generate}"
PROMPT="${PROMPT:-Return only the two-letter word OK.}"
SKIP_PROVIDERS="${SKIP_PROVIDERS:-}"
TIMEOUT_SEC="${TIMEOUT_SEC:-120}"

RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; CYAN=$'\e[36m'; RESET=$'\e[0m'

_dc() {
  if docker compose version >/dev/null 2>&1; then docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then docker-compose "$@"
  else echo "ERR: neither 'docker compose' nor 'docker-compose' available" >&2; return 127
  fi
}

# --- 1. Confirm the LiteLLM path is even reachable ------------------------
printf "%s[1/3]%s Checking %s%s …\n" "$CYAN" "$RESET" "$LLM_QUERY_URL" "$STATUS_PATH"
status=$(curl -sfS --max-time 10 "$LLM_QUERY_URL$STATUS_PATH" || true)
if [ -z "$status" ]; then
  printf "%sFAIL%s: could not reach %s%s\n" "$RED" "$RESET" "$LLM_QUERY_URL" "$STATUS_PATH"
  exit 2
fi
echo "$status" | python3 -m json.tool
kill_switch=$(printf '%s' "$status" | python3 -c "import json,sys;print(json.load(sys.stdin).get('kill_switch_enabled'))")
router_ok=$(printf '%s' "$status" | python3 -c "import json,sys;print(json.load(sys.stdin).get('router_available'))")
path=$(printf '%s' "$status" | python3 -c "import json,sys;print(json.load(sys.stdin).get('path_in_use'))")
if [ "$kill_switch" != "True" ] || [ "$router_ok" != "True" ] || [ "$path" != "litellm" ]; then
  printf "%sFAIL%s: path_in_use is '%s' (kill_switch=%s router_available=%s). " "$RED" "$RESET" "$path" "$kill_switch" "$router_ok"
  printf "Fix before smoke-testing providers — unset LITELLM_ROUTER_ENABLED or re-check settings.\n"
  exit 2
fi

# --- 2. For each registered alias, fire one generate call -----------------
aliases=$(printf '%s' "$status" | python3 -c "import json,sys;print('\\n'.join(json.load(sys.stdin).get('aliases') or []))")
if [ -z "$aliases" ]; then
  printf "%sFAIL%s: no aliases registered. Configure at least one provider in Settings → LLM.\n" "$RED" "$RESET"
  exit 2
fi
printf "%s[2/3]%s Probing %d aliases …\n" "$CYAN" "$RESET" "$(printf '%s\n' "$aliases" | wc -l)"

pass_litellm=0
fail_hand_rolled=0
http_errors=0
skipped=0

# Timestamp before we start firing calls — the log tail filter uses it to
# drop pre-run `path=` lines (which belong to a previous probe or to the
# agent sessions still running in the background).
run_start_epoch=$(date -u +%s)

while IFS= read -r alias; do
  [ -z "$alias" ] && continue
  if [ -n "$SKIP_PROVIDERS" ] && printf '%s\n' "$SKIP_PROVIDERS" | tr ',' '\n' | grep -Fxq -- "$alias"; then
    printf "  %sSKIP%s %s (SKIP_PROVIDERS)\n" "$YELLOW" "$RESET" "$alias"
    skipped=$((skipped+1))
    continue
  fi
  # Fire one generate call with the alias as the explicit model.
  # Timeout keeps a stuck provider from blocking the whole script.
  resp=$(curl -sS --max-time "$TIMEOUT_SEC" -X POST "$LLM_QUERY_URL$GENERATE_PATH" \
           -H 'Content-Type: application/json' \
           -d "$(python3 -c 'import json,sys;print(json.dumps({"model":sys.argv[1],"prompt":sys.argv[2],"stream":False}))' "$alias" "$PROMPT")" \
           2>&1 || true)
  if ! printf '%s' "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if (d.get('response') or '').strip() else 1)" >/dev/null 2>&1; then
    printf "  %sHTTP-ERR%s %-40s %s\n" "$RED" "$RESET" "$alias" "$(printf '%s' "$resp" | head -c 160)"
    http_errors=$((http_errors+1))
    continue
  fi
  # Figure out which path served it by reading the llm_query logs for
  # entries since run_start_epoch mentioning this (backend,model). The
  # path telemetry log line format is: `path=litellm backend=X model=Y`.
  backend="${alias%%:*}"
  model="${alias#*:}"
  # Give the log a moment to flush before grep.
  sleep 0.3
  logline=$(_dc logs llm_query --since "${run_start_epoch}" 2>/dev/null | \
            grep -F "backend=$backend model=$model" | tail -1 || true)
  if printf '%s' "$logline" | grep -q 'path=litellm'; then
    printf "  %sPASS%s     %-40s %s\n" "$GREEN" "$RESET" "$alias" "(served via LiteLLM)"
    pass_litellm=$((pass_litellm+1))
  elif printf '%s' "$logline" | grep -q 'path=hand_rolled'; then
    printf "  %sFAIL%s     %-40s %s\n" "$RED" "$RESET" "$alias" "(LiteLLM errored → hand_rolled took over — check llm_query logs)"
    fail_hand_rolled=$((fail_hand_rolled+1))
  else
    printf "  %sUNKNOWN%s  %-40s %s\n" "$YELLOW" "$RESET" "$alias" "(no path= log line found; log rotation?)"
    fail_hand_rolled=$((fail_hand_rolled+1))
  fi
done <<< "$aliases"

# --- 3. Verdict -----------------------------------------------------------
printf "\n%s[3/3]%s Verdict\n" "$CYAN" "$RESET"
printf "  LiteLLM-served : %d\n" "$pass_litellm"
printf "  hand_rolled fallback : %d\n" "$fail_hand_rolled"
printf "  HTTP errors : %d\n" "$http_errors"
printf "  skipped : %d\n" "$skipped"
if [ "$fail_hand_rolled" -eq 0 ] && [ "$pass_litellm" -gt 0 ]; then
  printf "\n%sGO%s — every attempted provider served through LiteLLM. " "$GREEN" "$RESET"
  printf "The hand-rolled helpers (DEPRECATED markers in llm_query.py) can be deleted in the next PR.\n"
  exit 0
fi
printf "\n%sNO-GO%s — hand-rolled fallback served at least one provider. " "$RED" "$RESET"
printf "Inspect `docker compose logs llm_query | grep 'LiteLLM path failed'` for the failure reason before shipping deletions.\n"
exit 1
