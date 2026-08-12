#!/usr/bin/env bash
#
# walkthrough-to-seed.sh — draft importable knowledge from a pentest walkthrough.
#
# Reads a walkthrough (markdown or plain text), asks the configured LLM to extract
# the technique that generalises to OTHER hosts, and writes a seed file for
# scripts/import-knowledge.sh.
#
# It never writes to the database. Entries that look box-specific — credentials,
# flags, hashes, lab IPs — are written COMMENTED OUT with a !REVIEW reason, so
# they cannot reach live scanning unless you deliberately un-comment them.
#
# Usage:
#   ./scripts/walkthrough-to-seed.sh writeups/lab01.md
#   ./scripts/walkthrough-to-seed.sh writeups/lab01.md --focus "Active Directory only"
#   ./scripts/walkthrough-to-seed.sh writeups/lab01.md --out knowledge/seed/ad.yaml
#   ./scripts/walkthrough-to-seed.sh writeups/lab01.md --no-existing
#
# Options:
#   --focus TEXT     extra steering for this run only
#   --out PATH       output file (default knowledge/seed/<name>.yaml)
#   --no-existing    don't show the model your current rules (it dedupes against them)
#   --api URL        knowledge API base (default https://localhost:8013)
#
# Prereqs: curl, jq. The stack's scan-recommender must be running.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

API="${KNOWLEDGE_API:-https://localhost:8013}"
FILE=""; FOCUS=""; OUT=""; INCLUDE_EXISTING=true

usage() { sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --focus)       FOCUS="${2:-}"; shift 2 ;;
        --out|-o)      OUT="${2:-}"; shift 2 ;;
        --api)         API="${2:-}"; shift 2 ;;
        --no-existing) INCLUDE_EXISTING=false; shift ;;
        --help|-h)     usage 0 ;;
        -*)            echo "Unknown option: $1" >&2; usage 1 ;;
        *)             FILE="$1"; shift ;;
    esac
done

for cmd in curl jq; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: '$cmd' is required." >&2; exit 1; }
done
[[ -n "$FILE" ]] || { echo "ERROR: no walkthrough file given." >&2; usage 1; }
[[ -f "$FILE" ]] || { echo "ERROR: file not found: $FILE" >&2; exit 1; }

if ! curl -sk --max-time 10 -o /dev/null "${API}/kb/prompts" 2>/dev/null; then
    echo "ERROR: knowledge API not reachable at ${API}" >&2
    echo "  Start it with: docker compose up -d scan-recommender" >&2
    exit 1
fi

base="$(basename "$FILE")"; base="${base%.*}"
OUT="${OUT:-knowledge/seed/${base}.yaml}"
mkdir -p "$(dirname "$OUT")"

size="$(wc -c < "$FILE" | tr -d ' ')"
echo "Reading $FILE (${size} bytes)"
echo "Converting — an LLM pass over a full walkthrough usually takes a minute or two..."

# jq builds the JSON so the walkthrough's quotes/newlines/backticks survive intact.
payload="$(jq -n \
    --rawfile content "$FILE" \
    --arg filename "$base" \
    --arg focus "$FOCUS" \
    --argjson include_existing "$INCLUDE_EXISTING" \
    '{content: $content, filename: $filename, include_existing: $include_existing}
     + (if $focus == "" then {} else {focus: $focus} end)')"

resp="$(curl -sk --max-time 900 -w '\n%{http_code}' -X POST "${API}/kb/walkthrough/convert" \
        -H 'Content-Type: application/json' -d "$payload")"
code="$(echo "$resp" | tail -1)"
body="$(echo "$resp" | sed '$d')"

if [[ "$code" != "200" ]]; then
    echo "ERROR: conversion failed (HTTP $code)" >&2
    echo "$body" | jq -r '.detail // .' 2>/dev/null | head -5 >&2 || echo "$body" | head -5 >&2
    exit 1
fi

echo "$body" | jq -r '.yaml' > "$OUT"

n_prompts="$(echo "$body" | jq '.prompts | length')"
n_docs="$(echo "$body"    | jq '.service_docs | length')"
n_flag="$(echo "$body"    | jq '.flagged | length')"
n_rej="$(echo "$body"     | jq '.rejected | length')"
model="$(echo "$body"     | jq -r '.model // "?"')"
n_seen="$(echo "$body"    | jq '.existing_considered | length')"

echo ""
echo "  model: $model"
echo "  drafted: ${n_prompts} rule(s), ${n_docs} training doc(s)"
[[ "$n_seen" -gt 0 ]] && echo "  considered ${n_seen} existing rule(s) to avoid duplicates"
echo "  wrote: $OUT"

if [[ "$n_flag" -gt 0 ]]; then
    echo ""
    echo "  ${n_flag} entr(ies) FLAGGED and commented out — review before un-commenting:"
    echo "$body" | jq -r '.flagged[] | "    ! \(.title // "(untitled)")\n        \(.reasons | join("; "))"'
fi
if [[ "$n_rej" -gt 0 ]]; then
    echo ""
    echo "  ${n_rej} entr(ies) rejected as malformed:"
    echo "$body" | jq -r '.rejected[] | "    x \(.entry)  —  \(.reason)"'
fi

# Show what would actually land, using the importer itself rather than a
# re-implementation — commented entries are invisible to it by construction.
if [[ "$n_prompts" -gt 0 || "$n_docs" -gt 0 ]]; then
    echo ""
    echo "--- dry run (what would be imported) ---"
    "${SCRIPT_DIR}/import-knowledge.sh" --file "$OUT" --dry-run --api "$API" 2>&1 | sed 's/^/  /' || true
fi

cat <<EOF

Next:
  1. Read $OUT — check the guidance is right and nothing box-specific is active.
  2. Apply it:
       ./scripts/import-knowledge.sh --file $OUT
EOF
