
#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8000}"
API_KEY="${API_KEY:-changeme}"
JOB_ID="${JOB_ID:-}"

if [[ -z "${JOB_ID}" ]]; then
  echo "Usage: JOB_ID=<uuid> ./chkresults.sh [ip-to-filter]"
  echo "You can also set API_BASE and API_KEY via environment variables."
  exit 1
fi

IP_FILTER="${1:-}"

echo "Job:"
curl -s "${API_BASE}/jobs/${JOB_ID}" -H "x-api-key: ${API_KEY}" | jq .

echo "Tasks:"
curl -s "${API_BASE}/jobs/${JOB_ID}/tasks" -H "x-api-key: ${API_KEY}" | jq .

echo "Open ports:"
if [[ -n "${IP_FILTER}" ]]; then
  curl -s "${API_BASE}/ports/open" -H "x-api-key: ${API_KEY}" | jq --arg ip "$IP_FILTER" '.items[] | select(.ip==$ip)'
else
  curl -s "${API_BASE}/ports/open" -H "x-api-key: ${API_KEY}" | jq .
fi

echo "Recent findings:"
curl -s "${API_BASE}/findings?limit=50" -H "x-api-key: ${API_KEY}" | jq .
