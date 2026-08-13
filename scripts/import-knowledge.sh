#!/usr/bin/env bash
#
# import-knowledge.sh — bulk-load operator knowledge into the stack.
#
# Seeds three things from one file:
#   1. service_prompts  — per service / port / port+service / technology guidance
#   2. training docs     — markdown indexed into the knowledge base, scoped the same way
#   3. playbooks         — optionally re-ingest the knowledge/playbooks corpus
#
# The API has no bulk endpoint, so this walks the entries and calls the
# single-item routes. Entries are CREATE-OR-UPDATE: an existing rule with the
# same selector is updated in place rather than failing on the unique index,
# which makes the whole run idempotent and safe to re-apply.
#
# Usage:
#   ./scripts/import-knowledge.sh --file knowledge/seed_prompts.example.yaml
#   ./scripts/import-knowledge.sh --file seed.yaml --dry-run
#   ./scripts/import-knowledge.sh --playbooks
#   ./scripts/import-knowledge.sh --file seed.json --api https://localhost:8013
#
# Accepts YAML or JSON. YAML is converted with the PyYAML already present in
# the scan-recommender container, so no host Python dependency is needed.
#
# Prereqs: docker, curl, jq (all already required by scripts/setup.sh).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

# scan-recommender owns service_prompts and the RAG store. Targeted directly by
# default so seeding works even when the dashboard is down; override with --api
# to go through the BFF instead (e.g. https://localhost:3002/api).
API="${KNOWLEDGE_API:-https://localhost:8013}"
FILE=""
DO_PLAYBOOKS=false
DRY_RUN=false

usage() {
    sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --file|-f)    FILE="${2:-}"; shift 2 ;;
        --playbooks)  DO_PLAYBOOKS=true; shift ;;
        --api)        API="${2:-}"; shift 2 ;;
        --dry-run|-n) DRY_RUN=true; shift ;;
        --help|-h)    usage 0 ;;
        *) echo "Unknown argument: $1" >&2; usage 1 ;;
    esac
done

for cmd in curl jq; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: '$cmd' is required but not installed." >&2; exit 1; }
done

if [[ -z "$FILE" && "$DO_PLAYBOOKS" == false ]]; then
    echo "ERROR: nothing to do — pass --file <seed.yaml> and/or --playbooks." >&2
    usage 1
fi

# ── Reachability ─────────────────────────────────────────────────────────────
# Fail fast with a useful message rather than emitting N connection errors.
if ! curl -sk --max-time 10 -o /dev/null "${API}/kb/prompts" 2>/dev/null; then
    echo "ERROR: knowledge API not reachable at ${API}" >&2
    echo "  Is the stack up?   docker compose up -d scan-recommender" >&2
    echo "  Different host?    ./scripts/import-knowledge.sh --api https://host:8013" >&2
    exit 1
fi

created=0; updated=0; failed=0; docs=0; skipped=0

# ── Parse the seed file into JSON ────────────────────────────────────────────
to_json() {
    local f="$1"
    case "$f" in
        *.json)
            jq '.' "$f"
            ;;
        *.yaml|*.yml)
            # PyYAML lives in the scan-recommender image; using it avoids
            # requiring a host Python with yaml installed.
            if ! docker ps --format '{{.Names}}' | grep -q '^scan-recommender$'; then
                echo "ERROR: YAML input needs the scan-recommender container running" >&2
                echo "  (it supplies PyYAML). Convert to JSON, or: docker compose up -d scan-recommender" >&2
                exit 1
            fi
            docker exec -i scan-recommender python3 -c \
                'import sys, json, yaml; json.dump(yaml.safe_load(sys.stdin.read()) or {}, sys.stdout)' < "$f"
            ;;
        *)
            echo "ERROR: unrecognised file type '$f' (expected .yaml, .yml or .json)" >&2
            exit 1
            ;;
    esac
}

if [[ -n "$FILE" ]]; then
    [[ -f "$FILE" ]] || { echo "ERROR: file not found: $FILE" >&2; exit 1; }
    echo "Reading $FILE"
    if ! SEED_JSON="$(to_json "$FILE")"; then
        echo "ERROR: could not parse $FILE" >&2; exit 1
    fi
    if ! echo "$SEED_JSON" | jq -e . >/dev/null 2>&1; then
        echo "ERROR: $FILE did not produce valid JSON — check the syntax." >&2; exit 1
    fi
fi

# Existing rules, so we can decide create vs update per selector.
existing="$(curl -sk --max-time 30 "${API}/kb/prompts" | jq -c '.prompts // []')"

# Match on the selector tuple, which is exactly what the DB's unique index keys on.
find_existing_id() {
    local sel="$1" svc="$2" tech="$3" port="$4"
    echo "$existing" | jq -r --arg sel "$sel" --arg svc "$svc" --arg tech "$tech" --arg port "$port" '
        map(select(
            .selector_type == $sel
            and ((.service // "") | ascii_downcase) == ($svc | ascii_downcase)
            and ((.tech    // "") | ascii_downcase) == ($tech | ascii_downcase)
            and ((.port    // "" ) | tostring)      == $port
        )) | .[0].id // empty'
}

# ── Prompt rules ─────────────────────────────────────────────────────────────
if [[ -n "$FILE" ]]; then
    count="$(echo "$SEED_JSON" | jq '(.prompts // []) | length')"
    echo "Prompt rules: $count"

    for i in $(seq 0 $((count - 1))); do
        [[ "$count" -eq 0 ]] && break
        entry="$(echo "$SEED_JSON" | jq -c ".prompts[$i]")"

        sel="$(echo "$entry"  | jq -r '.selector_type // ""')"
        title="$(echo "$entry"| jq -r '.title // ""')"
        svc="$(echo "$entry"  | jq -r '.service // ""')"
        tech="$(echo "$entry" | jq -r '.tech // ""')"
        port="$(echo "$entry" | jq -r 'if .port == null then "" else (.port|tostring) end')"

        # Validate locally so a typo names the offending entry instead of
        # producing an opaque 400 from the API.
        err=""
        case "$sel" in
            service)      [[ -z "$svc" ]] && err="selector_type 'service' needs a service" ;;
            port)         [[ -z "$port" ]] && err="selector_type 'port' needs a port" ;;
            port_service) { [[ -z "$svc" || -z "$port" ]]; } && err="selector_type 'port_service' needs both service and port" ;;
            tech)         [[ -z "$tech" ]] && err="selector_type 'tech' needs a tech" ;;
            "")           err="missing selector_type" ;;
            *)            err="unknown selector_type '$sel' (use service|port|port_service|tech)" ;;
        esac
        [[ -z "$title" ]] && err="${err:-missing title}"
        if [[ -n "$err" ]]; then
            echo "  ✗ entry $((i + 1)): $err"
            failed=$((failed + 1)); continue
        fi

        # Human-readable selector, e.g. "snmp on 161", "port 161", "tech wordpress"
        case "$sel" in
            port_service) scope="$svc on $port" ;;
            port)         scope="port $port" ;;
            tech)         scope="tech $tech" ;;
            *)            scope="$svc" ;;
        esac
        label="$(printf '%-22s' "$scope") $title"
        id="$(find_existing_id "$sel" "$svc" "$tech" "$port")"

        if [[ "$DRY_RUN" == true ]]; then
            if [[ -n "$id" ]]; then echo "  ~ would update  $label"; else echo "  + would create  $label"; fi
            skipped=$((skipped + 1)); continue
        fi

        if [[ -n "$id" ]]; then
            resp="$(curl -sk --max-time 120 -w '\n%{http_code}' -X PUT "${API}/kb/prompts/${id}" \
                    -H 'Content-Type: application/json' -d "$entry")"
        else
            resp="$(curl -sk --max-time 120 -w '\n%{http_code}' -X POST "${API}/kb/prompts" \
                    -H 'Content-Type: application/json' -d "$entry")"
        fi
        code="$(echo "$resp" | tail -1)"
        body="$(echo "$resp" | sed '$d')"

        if [[ "$code" == "200" ]]; then
            if [[ -n "$id" ]]; then echo "  ~ updated  $label"; updated=$((updated + 1))
            else echo "  + created  $label"; created=$((created + 1)); fi
        else
            echo "  ✗ HTTP $code  $label"
            echo "      $(echo "$body" | jq -r '.detail // .' 2>/dev/null | head -2)"
            failed=$((failed + 1))
        fi
    done

    # ── Standalone training documents ────────────────────────────────────────
    doc_count="$(echo "$SEED_JSON" | jq '(.service_docs // []) | length')"
    if [[ "$doc_count" -gt 0 ]]; then
        echo "Training docs: $doc_count"
        for i in $(seq 0 $((doc_count - 1))); do
            entry="$(echo "$SEED_JSON" | jq -c ".service_docs[$i]")"
            dtitle="$(echo "$entry" | jq -r '.title // ""')"
            if [[ "$DRY_RUN" == true ]]; then
                echo "  + would ingest  $dtitle"; skipped=$((skipped + 1)); continue
            fi
            # Ingest is an atomic replace keyed on (service, port, tech, title),
            # so re-running updates rather than duplicating chunks.
            resp="$(curl -sk --max-time 180 -w '\n%{http_code}' -X POST "${API}/rag/service-docs/ingest" \
                    -H 'Content-Type: application/json' -d "$entry")"
            code="$(echo "$resp" | tail -1)"
            if [[ "$code" == "200" ]]; then
                chunks="$(echo "$resp" | sed '$d' | jq -r '.chunks_inserted // 0')"
                echo "  + ingested  $dtitle ($chunks chunks)"; docs=$((docs + 1))
            else
                echo "  ✗ HTTP $code  $dtitle"
                echo "      $(echo "$resp" | sed '$d' | jq -r '.detail // .' 2>/dev/null | head -2)"
                failed=$((failed + 1))
            fi
        done
    fi
fi

# ── Playbook corpus ──────────────────────────────────────────────────────────
if [[ "$DO_PLAYBOOKS" == true ]]; then
    if [[ "$DRY_RUN" == true ]]; then
        echo "Playbooks: would re-ingest knowledge/playbooks/ ($(ls knowledge/playbooks/*.md 2>/dev/null | wc -l | tr -d ' ') files)"
    else
        echo "Playbooks: ingesting knowledge/playbooks/ (embedding, may take a few minutes)..."
        resp="$(curl -sk --max-time 900 -w '\n%{http_code}' -X POST "${API}/rag/playbooks/ingest" \
                -H 'Content-Type: application/json' -d '{}')"
        code="$(echo "$resp" | tail -1)"
        if [[ "$code" == "200" ]]; then
            echo "  + $(echo "$resp" | sed '$d' | jq -r '"\(.files_processed) files, \(.chunks_inserted) chunks"')"
        else
            echo "  ✗ playbook ingest failed (HTTP $code)"; failed=$((failed + 1))
        fi
    fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=============================="
if [[ "$DRY_RUN" == true ]]; then
    echo "Dry run — nothing was written. $skipped entr(ies) would be applied, $failed invalid."
else
    echo "created=$created  updated=$updated  training_docs=$docs  failed=$failed"
fi
echo "=============================="

if [[ "$failed" -gt 0 ]]; then
    exit 1
fi

if [[ "$DRY_RUN" == false && $((created + updated)) -gt 0 ]]; then
    cat <<EOF

Verify what the AI now receives for a target — this runs the same resolution
the scan recommender uses, so it is the real injected text, not a preview:

  curl -sk "${API}/kb/prompts/resolve?service=snmp&port=161" | jq
  curl -sk "${API}/kb/web-guidance?service=http&tech=wordpress" | jq

Or browse them at  /service-prompts  in the dashboard.
EOF
fi
