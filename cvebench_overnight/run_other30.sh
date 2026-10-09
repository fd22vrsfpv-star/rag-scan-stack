#!/usr/bin/env bash
# Complement of run_focused10.sh — the 30 CVE-Bench targets NOT in the
# focused-10 set. Launched after focused-10 completes so both runs operate
# under the same scan-telemetry gather (api.py 2026-10-08 follow-on 2).
#
# Separate output surface so progress + results do not collide:
#   results_other30/<cve>.{http,result.json,body.json}
#   progress_other30.log
#
# Same resolution pattern as run_focused10.sh (reads from challenge .env +
# target-1 container; routes LLM to ollama/qwen3-coder:30b at the request
# level, but the per-task exploit.* routes still send build-poc through the
# DeepSeek-V4-Pro deployment via app_settings — see llm_settings).
set -u
cd "$(dirname "$0")"
OUT="$(pwd)"
mkdir -p results_other30
LOG="$OUT/progress_other30.log"
> "$LOG"

CVEBENCH=/opt/cve-bench
CHALLENGES_DIR="$CVEBENCH/src/critical/challenges"

CVES=(
  "CVE-2023-37999"
  "CVE-2024-2359"
  "CVE-2024-25641"
  "CVE-2024-2624"
  "CVE-2024-2771"
  "CVE-2024-30542"
  "CVE-2024-31611"
  "CVE-2024-32167"
  "CVE-2024-3234"
  "CVE-2024-32980"
  "CVE-2024-32986"
  "CVE-2024-34070"
  "CVE-2024-34340"
  "CVE-2024-34716"
  "CVE-2024-3495"
  "CVE-2024-35187"
  "CVE-2024-36779"
  "CVE-2024-36858"
  "CVE-2024-37388"
  "CVE-2024-37831"
  "CVE-2024-37849"
  "CVE-2024-4223"
  "CVE-2024-4320"
  "CVE-2024-4323"
  "CVE-2024-4442"
  "CVE-2024-4443"
  "CVE-2024-4701"
  "CVE-2024-5084"
  "CVE-2024-5315"
  "CVE-2024-5452"
)

EID="5657d78f-0570-4ffa-9853-3bb706cb224b"
API_KEY=$(docker exec rag-api sh -c 'echo $API_KEY')

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

  docker exec rag-api sh -c "cd /app && python -c \"
from api import get_db
with get_db() as c, c.cursor() as cur:
    cur.execute('DELETE FROM derived_cve_specs WHERE cve=%s', ('$cve',))
    c.commit()
\"" >/dev/null 2>&1

  if ! docker ps --format '{{.Names}}' | grep -q "^${cvelow}-target-1$"; then
    (cd "$CVEBENCH" && timeout 240 ./gym.sh up "$cve") >> "$LOG" 2>&1
    sleep 3
  fi
  if ! docker ps --format '{{.Names}}' | grep -q "^${cvelow}-target-1$"; then
    echo "$ts [$i/$TOTAL] $cve: target failed to start, SKIP" >> "$LOG"
    continue
  fi

  envf="$CHALLENGES_DIR/$cve/.env"
  app_port=$(grep -E '^APPLICATION_URL=' "$envf" 2>/dev/null | cut -d= -f2- | tr ',' '\n' | grep -E '^target:' | head -1 | cut -d: -f2 | cut -d/ -f1)
  app_port=${app_port:-9090}
  product=$(grep -E '^APPLICATION_NAME=' "$envf" 2>/dev/null | cut -d= -f2-)
  product=${product:-unknown}
  user=$(grep -E '^DEFAULT_USERNAME=' "$envf" 2>/dev/null | cut -d= -f2-)
  user=${user:-user}
  pass=$(grep -E '^DEFAULT_PASSWORD=' "$envf" 2>/dev/null | cut -d= -f2-)
  pass=${pass:-password}

  ip=$(docker inspect "${cvelow}-target-1" --format '{{(index .NetworkSettings.Networks "agents_net").IPAddress}}' 2>/dev/null)
  if [ -z "$ip" ]; then
    echo "$ts [$i/$TOTAL] $cve: no IP on agents_net, SKIP" >> "$LOG"
    continue
  fi
  echo "$ts [$i/$TOTAL] $cve $ip:$app_port product=$product" >> "$LOG"

  docker exec rag-api sh -c "curl -sk -H 'x-api-key: $API_KEY' -H 'Content-Type: application/json' \
    -X POST https://localhost:8000/engagements/$EID/scope-add \
    -d '{\"target\":\"$ip\"}'" >/dev/null 2>&1

  body="$OUT/results_other30/${cve}.body.json"
  printf '{"cve":"%s","ip":"%s","port":%s,"product":"%s","username":"%s","password":"%s","model":"ollama:qwen3-coder:30b","max_iters":15,"recon_first":true,"recon_source":"basic","release":true}' \
    "$cve" "$ip" "$app_port" "$product" "$user" "$pass" > "$body"
  docker cp "$body" rag-api:/tmp/bf_${cve}.json >/dev/null 2>&1

  if ! docker exec rag-api test -x /tmp/runpoc.sh 2>/dev/null; then
    docker cp "$OUT/runpoc.sh" rag-api:/tmp/runpoc.sh >/dev/null 2>&1
    docker exec rag-api chmod +x /tmp/runpoc.sh >/dev/null 2>&1
  fi

  t0=$(date +%s)
  docker exec rag-api /tmp/runpoc.sh "/tmp/bf_${cve}.json" "/tmp/rf_${cve}.json" "$EID" \
    > "$OUT/results_other30/${cve}.http" 2>&1
  docker exec rag-api cat "/tmp/rf_${cve}.json" > "$OUT/results_other30/${cve}.result.json" 2>/dev/null
  el=$(( $(date +%s) - t0 ))
  http=$(cat "$OUT/results_other30/${cve}.http" 2>/dev/null)
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

  if ! echo " $PRERUN_UP " | grep -q " $cvelow "; then
    (cd "$CVEBENCH" && timeout 60 ./gym.sh down "$cve") >> "$LOG" 2>&1
  fi
done

echo "$(date +%H:%M:%S) ALL $TOTAL DONE" >> "$LOG"
echo "ALL $TOTAL DONE"
