#!/usr/bin/env bash
# Delete scan-output files older than RETENTION_DAYS to prevent disk exhaustion.
#
# Usage:
#   ./scripts/cleanup-old-files.sh             # dry run, prints what would be deleted
#   DRY_RUN=0 ./scripts/cleanup-old-files.sh   # actually delete
#   RETENTION_DAYS=30 DRY_RUN=0 ./scripts/cleanup-old-files.sh
#
# Suggested cron (daily 3am):
#   0 3 * * * cd /opt/rag-scan-stack && DRY_RUN=0 ./scripts/cleanup-old-files.sh >> /var/log/rag-cleanup.log 2>&1

set -euo pipefail

RETENTION_DAYS="${RETENTION_DAYS:-120}"
DRY_RUN="${DRY_RUN:-1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

DIRS=(
  "$ROOT/nmap_out"
  "$ROOT/nuclei_reports"
  "$ROOT/web_reports"
  "$ROOT/osint_reports"
  "$ROOT/pd_reports"
  "$ROOT/brutus_reports"
  "$ROOT/playwright_reports"
  "$ROOT/playwright_screenshots"
)

echo "[cleanup] retention=${RETENTION_DAYS}d dry_run=${DRY_RUN}"

for d in "${DIRS[@]}"; do
  [ -d "$d" ] || { echo "[skip] $d (does not exist)"; continue; }
  count=$(find "$d" -type f -mtime +"$RETENTION_DAYS" 2>/dev/null | wc -l)
  echo "[scan] $d → $count file(s) older than ${RETENTION_DAYS}d"
  if [ "$DRY_RUN" = "0" ] && [ "$count" -gt 0 ]; then
    find "$d" -type f -mtime +"$RETENTION_DAYS" -print -delete
    # remove empty subdirectories left behind
    find "$d" -mindepth 1 -type d -empty -delete 2>/dev/null || true
  fi
done

# Clean up stuck scan jobs (older than retention period and still showing as "running")
echo ""
echo "[cleanup] Checking for stuck scan jobs..."

if command -v curl >/dev/null 2>&1; then
  API_KEY="${API_KEY:-changeme}"

  # Get count of running scans older than retention period
  CLEANUP_DATE=$(date -d "$RETENTION_DAYS days ago" --iso-8601=seconds)

  RETENTION_HOURS=$((RETENTION_DAYS * 24))

  if [ "$DRY_RUN" = "0" ]; then
    echo "[scan-cleanup] Cleaning up old scan jobs (> ${RETENTION_DAYS}d / ${RETENTION_HOURS}h)..."
    # API call to cleanup old scan jobs
    curl -sSk -X POST "https://rag-api:8000/cleanup/scans?older_than_hours=${RETENTION_HOURS}&dry_run=false" \
      -H "x-api-key: ${API_KEY}" >/dev/null 2>&1 && echo "[scan-cleanup] ✓ Scan cleanup completed" || echo "[scan-cleanup] ⚠ Scan cleanup failed"
  else
    echo "[scan-cleanup] Would clean up scan jobs older than ${RETENTION_DAYS}d (dry run)"
    curl -sSk -X POST "https://rag-api:8000/cleanup/scans?older_than_hours=${RETENTION_HOURS}&dry_run=true" \
      -H "x-api-key: ${API_KEY}" 2>/dev/null | jq -r '.scans // "unknown"' | sed 's/^/[scan-cleanup] Found /' | sed 's/$/ old scan jobs/'
  fi
  fi
else
  echo "[scan-cleanup] curl not available - skipping scan job cleanup"
fi

echo ""
echo "[cleanup] done"
