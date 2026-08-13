#!/usr/bin/env bash
#
# url-to-guide.sh — turn a published guide into importable knowledge.
#
# Fetches a URL, reduces it to readable markdown, and drafts per-service rules
# from it. Produces two things:
#   knowledge/seed/<slug>.yaml      per-service rules (review-gated)
#   knowledge/playbooks/<slug>.md   cleaned prose for the RAG corpus
#
# Neither is applied automatically. Entries that look box-specific — credentials,
# flags, hashes, lab IPs — are written COMMENTED OUT with a !REVIEW reason.
# Vendor defaults (postgres:postgres, empty MySQL root) legitimately trip that
# check, so read the reason before discarding.
#
# Usage:
#   ./scripts/url-to-guide.sh https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/
#   ./scripts/url-to-guide.sh https://example.test/guide --depth 1 --max-pages 5
#   ./scripts/url-to-guide.sh https://example.test/guide --focus "Active Directory only"
#   ./scripts/url-to-guide.sh http://wiki.internal/notes --allow-internal
#
# Options:
#   --depth N          0 = this page only (default), 1 = follow same-origin links
#   --max-pages N      page cap when depth 1 (default 5, hard cap 20)
#   --focus TEXT       extra steering for this run
#   --allow-internal   permit private/loopback/metadata addresses (off by default)
#   --proxy URL        route the fetch through a proxy
#   --no-playbook      skip the playbook markdown, rules only
#   --api URL          knowledge API base (default https://localhost:8013)
#
# Prereqs: curl, jq. scan-recommender must be running.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

API="${KNOWLEDGE_API:-https://localhost:8013}"
URL=""; DEPTH=0; MAX_PAGES=5; FOCUS=""; ALLOW_INTERNAL=false; PROXY=""; MAKE_PLAYBOOK=true

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --depth)          DEPTH="${2:-0}"; shift 2 ;;
        --max-pages)      MAX_PAGES="${2:-5}"; shift 2 ;;
        --focus)          FOCUS="${2:-}"; shift 2 ;;
        --allow-internal) ALLOW_INTERNAL=true; shift ;;
        --proxy)          PROXY="${2:-}"; shift 2 ;;
        --no-playbook)    MAKE_PLAYBOOK=false; shift ;;
        --api)            API="${2:-}"; shift 2 ;;
        --help|-h)        usage 0 ;;
        -*)               echo "Unknown option: $1" >&2; usage 1 ;;
        *)                URL="$1"; shift ;;
    esac
done

for cmd in curl jq; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: '$cmd' is required." >&2; exit 1; }
done
[[ -n "$URL" ]] || { echo "ERROR: no URL given." >&2; usage 1; }

if ! curl -sk --max-time 10 -o /dev/null "${API}/kb/prompts" 2>/dev/null; then
    echo "ERROR: knowledge API not reachable at ${API}" >&2
    echo "  Start it with: docker compose up -d scan-recommender" >&2
    exit 1
fi

echo "Fetching $URL"
[[ "$DEPTH" -ge 1 ]] && echo "  following same-origin links, up to $MAX_PAGES pages"
[[ "$ALLOW_INTERNAL" == true ]] && echo "  WARNING: --allow-internal is set; internal address checks are relaxed"
echo "  extracting and drafting rules — a full guide usually takes a few minutes..."

payload="$(jq -n \
    --arg url "$URL" --arg focus "$FOCUS" --arg proxy "$PROXY" \
    --argjson depth "$DEPTH" --argjson max_pages "$MAX_PAGES" \
    --argjson allow_internal "$ALLOW_INTERNAL" --argjson make_playbook "$MAKE_PLAYBOOK" \
    '{url:$url, depth:$depth, max_pages:$max_pages, allow_internal:$allow_internal,
      make_playbook:$make_playbook}
     + (if $focus == "" then {} else {focus:$focus} end)
     + (if $proxy == "" then {} else {proxy:$proxy} end)')"

resp="$(curl -sk --max-time 1800 -w '\n%{http_code}' -X POST "${API}/kb/url/convert" \
        -H 'Content-Type: application/json' -d "$payload")"
code="$(echo "$resp" | tail -1)"
body="$(echo "$resp" | sed '$d')"

if [[ "$code" != "200" ]]; then
    echo "ERROR: import failed (HTTP $code)" >&2
    echo "$body" | jq -r '.detail // .' 2>/dev/null | head -6 >&2 || echo "$body" | head -6 >&2
    exit 1
fi

seed_name="$(echo "$body" | jq -r '.seed_filename')"
pb_name="$(echo "$body"   | jq -r '.playbook_filename')"
SEED_OUT="knowledge/seed/${seed_name}"
PB_OUT="knowledge/playbooks/${pb_name}"

mkdir -p knowledge/seed knowledge/playbooks
echo "$body" | jq -r '.yaml' > "$SEED_OUT"

# The API returns the playbook rather than writing it: knowledge/ is mounted
# read-only into the container, deliberately, so the service cannot rewrite its
# own knowledge base.
if [[ "$MAKE_PLAYBOOK" == true ]]; then
    echo "$body" | jq -r '.playbook_markdown' > "$PB_OUT"
fi

echo ""
echo "  model    : $(echo "$body" | jq -r '.model // "?"')"
echo "  pages    : $(echo "$body" | jq '.pages | length')"
echo "$body" | jq -r '.pages[] | "             \(.chars) chars  \(.title // .url)"'
echo "  rules    : $(echo "$body" | jq '.prompts | length')  -> $SEED_OUT"
[[ "$MAKE_PLAYBOOK" == true ]] && \
  echo "  playbook : $(echo "$body" | jq -r '.playbook_markdown | length') chars -> $PB_OUT"

n_flag="$(echo "$body" | jq '.flagged | length')"
if [[ "$n_flag" -gt 0 ]]; then
    echo ""
    echo "  ${n_flag} entr(ies) FLAGGED and commented out — review before un-commenting."
    echo "  Vendor defaults often trip this legitimately; read the reason."
    echo "$body" | jq -r '.flagged[] | "    ! \(.title // "(untitled)")\n        \(.reasons | join("; "))"'
fi
n_rej="$(echo "$body" | jq '.rejected | length')"
if [[ "$n_rej" -gt 0 ]]; then
    echo ""
    echo "  ${n_rej} entr(ies) rejected as malformed:"
    echo "$body" | jq -r '.rejected[] | "    x \(.entry)  —  \(.reason)"'
fi
n_ferr="$(echo "$body" | jq '.fetch_errors | length')"
if [[ "$n_ferr" -gt 0 ]]; then
    echo ""
    echo "  ${n_ferr} sub-page(s) could not be fetched:"
    echo "$body" | jq -r '.fetch_errors[] | "    x \(.url)  —  \(.error)"'
fi

cov_missed="$(echo "$body" | jq -r '.coverage.missed // [] | length')"
if [[ "${cov_missed:-0}" -gt 0 ]]; then
    echo ""
    echo "  COVERAGE: $(echo "$body" | jq -r '.coverage.covered | length')/$(echo "$body" | jq -r '.coverage.mentioned | length') KB-known services became rules ($(echo "$body" | jq -r '.coverage.coverage_pct // 0')%) — $(echo "$body" | jq -r '.coverage.rules_total') rules total"
    outside="$(echo "$body" | jq -r '.coverage.rules_outside_kb_vocabulary // [] | join(", ")')"
    [[ -n "$outside" ]] && echo "  Also covered, outside the KB's vocabulary: $outside"
    echo "  Not covered: $(echo "$body" | jq -r '.coverage.missed | join(", ")')"
    echo "  If those matter, re-run with --focus naming them, or add rules by hand."
fi
if [[ "$(echo "$body" | jq -r '.coverage.skipped // [] | length')" -gt 0 ]]; then
    echo ""
    echo "  Deliberately skipped by the model:"
    echo "$body" | jq -r '.coverage.skipped[] | "    - \(.service // .tech // "?"): \(.reason // "no reason given")"'
fi

# Show what would land, using the importer itself rather than a re-implementation.
if [[ "$(echo "$body" | jq '.prompts | length')" -gt 0 ]]; then
    echo ""
    echo "--- dry run (what would be imported) ---"
    "${SCRIPT_DIR}/import-knowledge.sh" --file "$SEED_OUT" --dry-run --api "$API" 2>&1 | sed 's/^/  /' || true
fi

cat <<EOF

Next:
  1. Read $SEED_OUT — check the guidance is right and nothing box-specific is active.
$( [[ "$MAKE_PLAYBOOK" == true ]] && echo "  2. Skim $PB_OUT — it becomes retrievable context." )
  3. Apply:
       ./scripts/import-knowledge.sh --file $SEED_OUT
$( [[ "$MAKE_PLAYBOOK" == true ]] && echo "       ./scripts/import-knowledge.sh --playbooks" )
EOF
