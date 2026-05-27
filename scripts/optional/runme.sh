

#!/usr/bin/env bash
set -euo pipefail

# Config (override via env or pass IP as first arg)
API_BASE="${API_BASE:-http://localhost:8000}"
API_KEY="${API_KEY:-changeme}"
TARGET="${1:-192.168.1.5}"

echo "Creating job for target: $TARGET"

# 1) Create a job (stores target for traceability; Phase 1 will wire this into Masscan targeting)
JOB_IDEMP="host-${TARGET}-$(date +%s)"
JOB_PAYLOAD=$(jq -nc \
  --arg t "$TARGET" \
  --arg id "$JOB_IDEMP" \
  '{type:"masscan-nmap", params:{targets:[$t]}, idempotency_key:$id}')

JOB_RESP=$(curl -sfS \
  -H "x-api-key: $API_KEY" \
  -H "content-type: application/json" \
  -X POST "$API_BASE/jobs" \
  -d "$JOB_PAYLOAD")

echo "Create job response: $JOB_RESP"

JOB_ID="$(echo "$JOB_RESP" | jq -r '.id // empty')"
if [[ -z "$JOB_ID" ]]; then
  echo "ERROR: Failed to get job id. Full response: $JOB_RESP" >&2
  exit 1
fi
echo "Job ID: $JOB_ID"

# 2) Trigger the pipeline for that job
echo "Triggering pipeline..."
TRIGGER_RESP=$(curl -sfS \
  -H "x-api-key: $API_KEY" \
  -X POST "$API_BASE/jobs/nmap-from-masscan?job_id=$JOB_ID")
echo "Trigger response: $TRIGGER_RESP"

# 3) Poll job status until it is finished/failed/canceled
echo "Polling job status..."
while true; do
  STATUS_JSON=$(curl -sfS \
    -H "x-api-key: $API_KEY" \
    "$API_BASE/jobs/$JOB_ID")
  STATUS="$(echo "$STATUS_JSON" | jq -r '.status')"
  echo "Status: $STATUS"
  case "$STATUS" in
    finished|failed|canceled)
      break
      ;;
    *)
      sleep 3
      ;;
  esac
done

echo "Final job status:"
echo "$STATUS_JSON" | jq .

echo "Pipeline task(s):"
curl -sfS \
  -H "x-api-key: $API_KEY" \
  "$API_BASE/jobs/$JOB_ID/tasks" | jq .

