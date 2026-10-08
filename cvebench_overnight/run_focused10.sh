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
  docker exec rag-api sh -c "curl -sk -H 'x-api-key: $API_KEY' -H 'Content-Type: application/json' \
    -X POST https://localhost:8000/engagements/$EID/scope-add \
    -d '{\"target\":\"$ip\"}'" >/dev/null 2>&1

  # Build body
  body="$OUT/results_focused/${cve}.body.json"
  # Model is prefixed with the provider id (`ollama:…`) so the dispatcher
  # routes to Ollama regardless of the global `llm.backend` setting — this
  # was previously implicit when global defaulted to ollama; now that the
  # stack defaults to Azure, the bare name 404s on `DeploymentNotFound`.
  printf '{"cve":"%s","ip":"%s","port":%s,"product":"%s","username":"%s","password":"%s","model":"ollama:qwen3-coder:30b","max_iters":15,"recon_first":true,"recon_source":"basic","release":true}' \
    "$cve" "$ip" "$app_port" "$product" "$user" "$pass" > "$body"
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
  v=$(docker exec rag-api sh -c "cd /app && python -c \"
from api import get_db
with get_db() as c, c.cursor() as cur:
    cur.execute('SELECT verified FROM derived_cve_specs WHERE cve=%s', ('$cve',))
    r = cur.fetchone()
    print(r[0] if r else '?')
\"" 2>&1 | grep -v -i deprecat | grep -v regex | tail -1)
  end_ts=$(date +%H:%M:%S)
  echo "$end_ts [$i/$TOTAL] $cve done in ${el}s derive-verified=$v $http" >> "$LOG"
  echo "$end_ts [$i/$TOTAL] $cve done in ${el}s derive-verified=$v"

  rm -f "$body"

  # Tear down UNLESS it was already up before this run
  if ! echo " $PRERUN_UP " | grep -q " $cvelow "; then
    (cd "$CVEBENCH" && timeout 60 ./gym.sh down "$cve") >> "$LOG" 2>&1
  fi
done

echo "$(date +%H:%M:%S) ALL $TOTAL DONE" >> "$LOG"
echo "ALL $TOTAL DONE"
