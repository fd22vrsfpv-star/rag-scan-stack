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

  # NOTE: a CLEANUP_DATE=$(date -d ...) line lived here, assigned and never
  # used. `date -d` is GNU-only, so on macOS/BSD it aborted the script before
  # any cleanup ran. Retention is expressed in hours below and passed to the
  # API, which does the date arithmetic in SQL.

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
else
  echo "[scan-cleanup] curl not available - skipping scan job cleanup"
fi

# ── Stuck tool executions ─────────────────────────────────────────────────
# A row is set to 'running' before the subprocess starts. If the process dies in
# between — restart, OOM, a wedged tool — nothing reconciled it and the row stays
# 'running' for ever. 41 accumulated before this existed, the oldest three days
# stale, which reads exactly like a hung scan.
#
# The activity view already DISPLAYED such rows as 'lost' via a CASE expression
# without writing it back, so that one view looked correct while every other
# reader, count and export still saw 'running'.
if command -v curl >/dev/null 2>&1; then
  API_KEY="${API_KEY:-changeme}"
  if [ "$DRY_RUN" = "0" ]; then
    echo "[exec-cleanup] Reconciling executions with no completion after 6h..."
    curl -sSk -X POST "https://rag-api:8000/cleanup/tool-executions?stale_after_hours=6&dry_run=false" \
      -H "x-api-key: ${API_KEY}" 2>/dev/null | jq -r '"[exec-cleanup] reconciled \(.reconciled)"' 2>/dev/null \
      || echo "[exec-cleanup] ⚠ reconcile call failed"
  else
    curl -sSk -X POST "https://rag-api:8000/cleanup/tool-executions?stale_after_hours=6&dry_run=true" \
      -H "x-api-key: ${API_KEY}" 2>/dev/null | jq -r '"[exec-cleanup] would reconcile \(.reconcilable)"' 2>/dev/null \
      || echo "[exec-cleanup] ⚠ reconcile check failed"
  fi
fi

# ── Raw artifacts ─────────────────────────────────────────────────────────
# These hold verbatim tool output, so a large share is credential material (see
# Docs/RAW_ARTIFACTS.md). Old artifacts are standing exposure, not just disk.
# Unprocessed and cited artifacts are kept by the endpoint's own defaults.
if command -v curl >/dev/null 2>&1; then
  API_KEY="${API_KEY:-changeme}"
  if [ "$DRY_RUN" = "0" ]; then
    echo "[artifact-cleanup] Pruning raw artifacts older than ${RETENTION_DAYS}d..."
    curl -sSk -X POST "https://rag-api:8000/cleanup/artifacts?older_than_days=${RETENTION_DAYS}&dry_run=false" \
      -H "x-api-key: ${API_KEY}" 2>/dev/null | jq -r '"[artifact-cleanup] deleted \(.artifacts_deleted), kept unprocessed \(.held_back_unprocessed)"' 2>/dev/null \
      || echo "[artifact-cleanup] ⚠ prune call failed"
  else
    curl -sSk -X POST "https://rag-api:8000/cleanup/artifacts?older_than_days=${RETENTION_DAYS}&dry_run=true" \
      -H "x-api-key: ${API_KEY}" 2>/dev/null | jq -r '"[artifact-cleanup] would delete \(.artifacts_matching), kept unprocessed \(.held_back_unprocessed)"' 2>/dev/null \
      || echo "[artifact-cleanup] ⚠ prune check failed"
  fi
fi

echo ""
echo "[cleanup] done"
