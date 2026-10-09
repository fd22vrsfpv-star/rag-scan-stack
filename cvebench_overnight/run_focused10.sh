#!/usr/bin/env bash
# Focused re-run on the 10 CVEs most likely to improve from the research-driven
# fixes (#1-#7). Mirrors run_40.sh's proven resolution pattern (reads from
# challenge .env + target-1 container; no agent-1 lookup).
set -u  # strict var names; no -e so a single CVE failure doesn't abort the run
cd "$(dirname "$0")"
OUT="$(pwd)"
mkdir -p results_focused
LOG="$OUT/progress_focused.log"
> "$LOG"

CVEBENCH=/opt/cve-bench
CHALLENGES_DIR="$CVEBENCH/src/critical/challenges"

CVES=(
  "CVE-2024-22120"
  "CVE-2024-3408"
  "CVE-2024-32511"
  "CVE-2023-51483"
  "CVE-2024-3552"
  "CVE-2024-36412"
  "CVE-2024-5314"
  "CVE-2024-32964"
  "CVE-2024-36675"
  "CVE-2024-34359"
)

EID="5657d78f-0570-4ffa-9853-3bb706cb224b"
API_KEY=$(docker exec rag-api sh -c 'echo $API_KEY')

# Ensure runpoc.sh in rag-api. Uses the committed cvebench_overnight/runpoc.sh
# as the source so this script is self-contained — the previous version
# referenced a per-session claude scratchpad path that doesn't persist.
if ! docker exec rag-api test -x /tmp/runpoc.sh 2>/dev/null; then
  docker cp "$OUT/runpoc.sh" rag-api:/tmp/runpoc.sh
  docker exec rag-api chmod +x /tmp/runpoc.sh
fi

PRERUN_UP=$(docker ps --format '{{.Names}}' | grep -oE 'cve-[0-9]+-[0-9]+' | sort -u)
TOTAL=${#CVES[@]}
i=0
for cve in "${CVES[@]}"; do
  i=$((i+1))
  cvelow="${cve,,}"
  ts=$(date +%H:%M:%S)
  echo "$ts [$i/$TOTAL] starting $cve"
  echo "$ts [$i/$TOTAL] starting $cve" >> "$LOG"

  # Clear derived_cve_specs so the fresh pipeline exercises every fix
  docker exec rag-api sh -c "cd /app && python -c \"
from api import get_db
with get_db() as c, c.cursor() as cur:
    cur.execute('DELETE FROM derived_cve_specs WHERE cve=%s', ('$cve',))
    c.commit()
\"" >/dev/null 2>&1

  # Ensure target up
  if ! docker ps --format '{{.Names}}' | grep -q "^${cvelow}-target-1$"; then
    (cd "$CVEBENCH" && timeout 240 ./gym.sh up "$cve") >> "$LOG" 2>&1
    sleep 3
  fi
  if ! docker ps --format '{{.Names}}' | grep -q "^${cvelow}-target-1$"; then
    echo "$ts [$i/$TOTAL] $cve: target failed to start, SKIP" >> "$LOG"
    continue
  fi

  # Metadata from challenge .env
  envf="$CHALLENGES_DIR/$cve/.env"
  app_port=$(grep -E '^APPLICATION_URL=' "$envf" 2>/dev/null | cut -d= -f2- | tr ',' '\n' | grep -E '^target:' | head -1 | cut -d: -f2 | cut -d/ -f1)
  app_port=${app_port:-9090}
  product=$(grep -E '^APPLICATION_NAME=' "$envf" 2>/dev/null | cut -d= -f2-)
  product=${product:-unknown}
  user=$(grep -E '^DEFAULT_USERNAME=' "$envf" 2>/dev/null | cut -d= -f2-)
  user=${user:-user}
  pass=$(grep -E '^DEFAULT_PASSWORD=' "$envf" 2>/dev/null | cut -d= -f2-)
  pass=${pass:-password}

  # IP on agents_net
  ip=$(docker inspect "${cvelow}-target-1" --format '{{(index .NetworkSettings.Networks "agents_net").IPAddress}}' 2>/dev/null)
  if [ -z "$ip" ]; then
    echo "$ts [$i/$TOTAL] $cve: no IP on agents_net, SKIP" >> "$LOG"
    continue
  fi
  echo "$ts [$i/$TOTAL] $cve $ip:$app_port product=$product" >> "$LOG"

  # Scope the target
  # Scoping is done by gym.sh (it prints "scoped <cve> -> ip:port under
  # engagement 'cvebench'"). The former per-target scope POST here hit a
  # route that does not exist (silent 404) — removed 2026-10-09.

  # Build body
  body="$OUT/results_focused/${cve}.body.json"
  # No explicit model (2026-10-09): an explicit model overrides the per-task
  # routes in app_settings for EVERY call site, which is how the whole
  # research/synth/refine chain kept running on a local 30b model (and burned
  # 600 s timeouts when ollama degraded). With no model, each caller resolves
  # its own route: cve_poc_synth / decomposed_craft / cve_poc_refine /
  # exploit.gather_fallback / exploit.judge → azure-main:DeepSeek-V4-Pro,
  # everything else → llm.route.default. Override per run with
  # BUILD_POC_MODEL=ollama:qwen3-coder:30b ./run_focused10.sh
  model_field=""
  [ -n "${BUILD_POC_MODEL:-}" ] && model_field=",\"model\":\"${BUILD_POC_MODEL}\""
  printf '{"cve":"%s","ip":"%s","port":%s,"product":"%s","username":"%s","password":"%s"%s,"max_iters":15,"recon_first":true,"recon_source":"basic","release":true}' \
    "$cve" "$ip" "$app_port" "$product" "$user" "$pass" "$model_field" > "$body"
  docker cp "$body" rag-api:/tmp/bf_${cve}.json >/dev/null 2>&1

  if ! docker exec rag-api test -x /tmp/runpoc.sh 2>/dev/null; then
    docker cp "$OUT/runpoc.sh" rag-api:/tmp/runpoc.sh >/dev/null 2>&1
    docker exec rag-api chmod +x /tmp/runpoc.sh >/dev/null 2>&1
  fi

  t0=$(date +%s)
  docker exec rag-api /tmp/runpoc.sh "/tmp/bf_${cve}.json" "/tmp/rf_${cve}.json" "$EID" \
    > "$OUT/results_focused/${cve}.http" 2>&1
  docker exec rag-api cat "/tmp/rf_${cve}.json" > "$OUT/results_focused/${cve}.result.json" 2>/dev/null
  el=$(( $(date +%s) - t0 ))
  http=$(cat "$OUT/results_focused/${cve}.http" 2>/dev/null)
  # The verdict is the run's own result (derived_cve_specs.verified is written
  # by node_research BEFORE synth and never by the refine loop — it reported
  # "False"/"?" for runs the result file marked verified, 2026-10-09).
  v=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('verified'))" \
        "$OUT/results_focused/${cve}.result.json" 2>/dev/null || echo '?')
  st=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('stop_reason') or d.get('verification_method') or '')" \
        "$OUT/results_focused/${cve}.result.json" 2>/dev/null || echo '')
  end_ts=$(date +%H:%M:%S)
  echo "$end_ts [$i/$TOTAL] $cve done in ${el}s verified=$v stop=$st $http" >> "$LOG"
  echo "$end_ts [$i/$TOTAL] $cve done in ${el}s verified=$v stop=$st"

  rm -f "$body"

  # Tear down UNLESS it was already up before this run
  if ! echo " $PRERUN_UP " | grep -q " $cvelow "; then
    (cd "$CVEBENCH" && timeout 60 ./gym.sh down "$cve") >> "$LOG" 2>&1
  fi
done

echo "$(date +%H:%M:%S) ALL $TOTAL DONE" >> "$LOG"
echo "ALL $TOTAL DONE"
