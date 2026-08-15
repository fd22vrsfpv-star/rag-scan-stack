#!/usr/bin/env bash
#
# export-knowledge.sh — write the live knowledge base back out as a seed file.
#
# The round-trip partner to import-knowledge.sh. Rules accepted in the UI live
# only in Postgres, so without this a clean install starts with an empty
# service_prompts table and an accepted rule is lost to `docker compose down -v`.
#
# Output is the same format import-knowledge.sh consumes, so the round trip is
# closed: export -> commit -> import on another install.
#
# Usage:
#   ./scripts/export-knowledge.sh
#   ./scripts/export-knowledge.sh --out knowledge/seed/my-rules.yaml
#   ./scripts/export-knowledge.sh --engagement <uuid> --enabled-only
#   ./scripts/export-knowledge.sh --stdout | less
#
# Options:
#   --out PATH        output file (default knowledge/seed/exported-<date>.yaml)
#   --engagement ID   only rules scoped to this engagement
#   --enabled-only    skip rules with enabled = false
#   --stdout          write to stdout instead of a file
#   --api URL         knowledge API base (default https://localhost:8013)
#
# Note: engagement_id is deliberately NOT written to the seed. It is a UUID that
# will not exist on another install, and carrying it over turns a portable seed
# into one that fails its foreign key. Use --engagement to *select* rules; the
# exported file is engagement-neutral.
#
# Prereqs: curl, jq. The stack's scan-recommender must be running.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

API="${KNOWLEDGE_API:-https://localhost:8013}"
OUT=""
ENGAGEMENT=""
ENABLED_ONLY=false
TO_STDOUT=false

usage() { sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out|-o)       OUT="${2:-}"; shift 2 ;;
        --engagement)   ENGAGEMENT="${2:-}"; shift 2 ;;
        --enabled-only) ENABLED_ONLY=true; shift ;;
        --stdout)       TO_STDOUT=true; shift ;;
        --api)          API="${2:-}"; shift 2 ;;
        --help|-h)      usage 0 ;;
        *) echo "Unknown argument: $1" >&2; usage 1 ;;
    esac
done

for cmd in curl jq; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: '$cmd' is required but not installed." >&2; exit 1; }
done

if ! curl -sk --max-time 10 -o /dev/null "${API}/kb/prompts" 2>/dev/null; then
    echo "ERROR: knowledge API not reachable at ${API}" >&2
    echo "  Start it with: docker compose up -d scan-recommender" >&2
    exit 1
fi

query=""
[[ -n "$ENGAGEMENT" ]]        && query="engagement_id=${ENGAGEMENT}"
[[ "$ENABLED_ONLY" == true ]] && query="${query:+${query}&}enabled_only=true"

resp="$(curl -sk --max-time 60 -w '\n%{http_code}' "${API}/kb/prompts/export${query:+?$query}")"
code="$(echo "$resp" | tail -1)"
body="$(echo "$resp" | sed '$d')"

if [[ "$code" != "200" ]]; then
    echo "ERROR: export failed (HTTP $code)" >&2
    echo "$body" | jq -r '.detail // .' 2>/dev/null | head -5 >&2 || echo "$body" | head -5 >&2
    exit 1
fi

count="$(echo "$body" | jq -r '.count')"

if [[ "$TO_STDOUT" == true ]]; then
    echo "$body" | jq -r '.yaml'
    exit 0
fi

if [[ -z "$OUT" ]]; then
    OUT="knowledge/seed/exported-$(date +%Y%m%d).yaml"
fi
mkdir -p "$(dirname "$OUT")"
echo "$body" | jq -r '.yaml' > "$OUT"

echo "Exported ${count} rule(s) -> $OUT"
if [[ "$count" -eq 0 ]]; then
    echo "  (the knowledge base is empty — nothing to seed from)"
    exit 0
fi

cat <<EOF

Next:
  1. Review the file, then commit it so the rules survive a clean rebuild.
  2. Verify it round-trips:
       ./scripts/import-knowledge.sh --file $OUT --dry-run
     Every entry should say "would update" — a "would create" means the export
     lost something that distinguishes the rule.
EOF
