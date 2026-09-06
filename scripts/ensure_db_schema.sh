#!/usr/bin/env bash
#
# ensure_db_schema.sh - Ensures all required database tables exist
#
# This script applies the comprehensive schema to the scans database,
# creating any missing tables that are required by the services.
#
# Safe to run multiple times - uses IF NOT EXISTS clauses.
#
# Usage:
#   ./scripts/ensure_db_schema.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== RAG Scan Stack - Database Schema Verification ==="
echo ""

# Check if docker compose is available
if ! command -v docker &> /dev/null; then
    echo "❌ Error: docker is not installed or not in PATH"
    exit 1
fi

# ── Resolve a way to reach the database ─────────────────────────────────────
#
# WHY THIS EXISTS: this script used to require a local `rag-postgres` container
# and `exit 1` without one. In remote / remote_direct DB mode Postgres lives on a
# VPS and no such container exists here, so the schema updater could never run —
# which is exactly how post_review_reports, scan_parameters and
# v_identity_credential_state came to be missing from a long-lived database while
# being present in db_init/ensure_all_tables.sql all along. A clean install was
# correct; only the running deployment drifted, silently, until a query happened
# to touch one of them.
#
# Three backends, most faithful first:
#   local  — `docker exec rag-postgres psql` (unchanged behaviour when present)
#   psql   — any container that ships psql, connected with DB_DSN (kali-listener)
#   python — psycopg2 in a container that has DB_DSN (rag-api / autogen-agents),
#            emulating the psql flags this script actually uses
#
# The DDL is idempotent (CREATE IF NOT EXISTS / CREATE OR REPLACE), so once a
# connection is available this script REPAIRS a drifted database rather than only
# reporting on it.
DB_BACKEND=""
PSQL_CLIENT=""
PY_CLIENT=""
DB_DSN_VALUE=""

_find_dsn() {
    local c
    for c in rag-api autogen-agents kali-listener exploit-runner; do
        docker ps --format '{{.Names}}' | grep -q "^${c}$" || continue
        local d; d=$(docker exec "$c" printenv DB_DSN 2>/dev/null || true)
        [[ -n "$d" ]] && { printf '%s' "$d"; return 0; }
    done
    return 1
}

if docker ps --format '{{.Names}}' | grep -q '^rag-postgres$'; then
    DB_BACKEND="local"
    echo "✓ Docker and rag-postgres container are available"
else
    DB_DSN_VALUE=$(_find_dsn || true)
    if [[ -z "$DB_DSN_VALUE" ]]; then
        echo "❌ Error: no rag-postgres container and no container exposes DB_DSN"
        echo "   Local mode:  docker compose up -d rag-postgres"
        echo "   Remote mode: start rag-api (or autogen-agents) so DB_DSN is available"
        exit 1
    fi
    # Prefer a real psql client: the DDL contains a \connect meta-command and 172
    # dollar-quoted blocks, and psql is the only thing that reproduces psql exactly.
    for c in kali-listener; do
        docker ps --format '{{.Names}}' | grep -q "^${c}$" || continue
        if docker exec "$c" sh -c 'command -v psql' >/dev/null 2>&1; then
            PSQL_CLIENT="$c"; DB_BACKEND="psql"; break
        fi
    done
    if [[ -z "$DB_BACKEND" ]]; then
        for c in rag-api autogen-agents; do
            docker ps --format '{{.Names}}' | grep -q "^${c}$" || continue
            if docker exec "$c" python3 -c 'import psycopg2' >/dev/null 2>&1; then
                PY_CLIENT="$c"; DB_BACKEND="python"; break
            fi
        done
    fi
    if [[ -z "$DB_BACKEND" ]]; then
        echo "❌ Error: DB_DSN found but no container can execute SQL (need psql or psycopg2)"
        exit 1
    fi
    echo "✓ Remote database reachable via ${PSQL_CLIENT:-$PY_CLIENT} (backend: $DB_BACKEND)"
fi

# Forwards psql flags verbatim on the psql backends. The python backend emulates
# the four shapes this script uses: -tAc, -t -c, -c and -f.
_psql() {
    case "$DB_BACKEND" in
      local) docker exec -i rag-postgres psql -U app -d scans "$@" ;;
      psql)  docker exec -i -e PGDSN="$DB_DSN_VALUE" "$PSQL_CLIENT" \
                 sh -c 'exec psql "$PGDSN" "$@"' _ "$@" ;;
      python)
        local sql="" file="" want_tuples=0
        while [[ $# -gt 0 ]]; do
            case "$1" in
              -f) file="$2"; shift 2 ;;
              -c) sql="$2"; shift 2 ;;
              -tAc|-tc) want_tuples=1; sql="$2"; shift 2 ;;
              -t|-A|-q) want_tuples=1; shift ;;
              *) shift ;;
            esac
        done
        if [[ -n "$file" ]]; then
            docker exec -i "$PY_CLIENT" python3 -c '
import os, sys, psycopg2
sql = sys.stdin.read()
# psql meta-commands are not SQL; we are already connected to the right database.
sql = "\n".join(l for l in sql.splitlines() if not l.lstrip().startswith("\\"))
conn = psycopg2.connect(os.environ["DB_DSN"]); conn.autocommit = True
conn.cursor().execute(sql)
print("applied")' < "$file"
        else
            docker exec -i -e SQL="$sql" "$PY_CLIENT" python3 -c '
import os, psycopg2
conn = psycopg2.connect(os.environ["DB_DSN"])
cur = conn.cursor(); cur.execute(os.environ["SQL"])
if cur.description:
    for row in cur.fetchall():
        print("|".join("t" if v is True else "f" if v is False
                       else "" if v is None else str(v) for v in row))'
        fi
        ;;
    esac
}

# Applies a .sql FILE. On the local backend the file already lives inside the
# postgres container; remotely it must be streamed in from this checkout.
_psql_file() {
    local path="$1"
    case "$DB_BACKEND" in
      local) docker exec -i rag-postgres psql -U app -d scans -f "/docker-entrypoint-initdb.d/$(basename "$path")" ;;
      psql)
        # Strip psql meta-commands (the DDL opens with `\connect scans`). We are
        # ALREADY connected to that database; letting psql re-connect would drop
        # the URI's credentials and can block on a password prompt, hanging the
        # whole script with no output.
        grep -v '^[[:space:]]*\\' "$path" \
          | docker exec -i -e PGDSN="$DB_DSN_VALUE" "$PSQL_CLIENT" \
                sh -c 'exec psql "$PGDSN" -v ON_ERROR_STOP=0 -f -' ;;
      python) _psql -f "$path" ;;
    esac
}

# Same as _psql but against a DIFFERENT database on the same server. Two checks
# need this: the `exploits` database (searchsploit/ExploitDB corpus) lives beside
# `scans`, and its existence is probed from `postgres`.
_dsn_for_db() {
    DSN="$DB_DSN_VALUE" DB="$1" python3 -c '
import os
from urllib.parse import urlsplit, urlunsplit
u = urlsplit(os.environ["DSN"])
print(urlunsplit((u.scheme, u.netloc, "/" + os.environ["DB"], u.query, u.fragment)))'
}

_psql_db() {
    local db="$1"; shift
    case "$DB_BACKEND" in
      local) docker exec -i rag-postgres psql -U app -d "$db" "$@" ;;
      psql)  docker exec -i -e PGDSN="$(_dsn_for_db "$db")" "$PSQL_CLIENT" \
                 sh -c 'exec psql "$PGDSN" "$@"' _ "$@" ;;
      python)
        local sql=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
              -c|-tAc|-tc) sql="$2"; shift 2 ;;
              *) shift ;;
            esac
        done
        docker exec -i -e SQL="$sql" -e DSN2="$(_dsn_for_db "$db")" "$PY_CLIENT" python3 -c '
import os, psycopg2
cur = psycopg2.connect(os.environ["DSN2"]).cursor()
cur.execute(os.environ["SQL"])
if cur.description:
    for row in cur.fetchall():
        print("|".join("t" if v is True else "f" if v is False
                       else "" if v is None else str(v) for v in row))'
        ;;
    esac
}

_pg_ready() {
    case "$DB_BACKEND" in
      local) docker exec rag-postgres pg_isready -U app -d scans &>/dev/null ;;
      *)     _psql -tAc "SELECT 1" >/dev/null 2>&1 ;;
    esac
}
echo ""

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
timeout=30
elapsed=0
while ! _pg_ready; do
    if [ $elapsed -ge $timeout ]; then
        echo "❌ Error: PostgreSQL did not become ready within ${timeout}s"
        exit 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
done

echo "✓ PostgreSQL is ready"
echo ""

# Count tables before
BEFORE=$(_psql -t -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public';" | tr -d ' ')
echo "📊 Current table count: ${BEFORE}"
echo ""

# Apply the schema
echo "🔧 Applying comprehensive schema..."
if _psql_file "${PROJECT_ROOT}/db_init/ensure_all_tables.sql" > /tmp/schema_update.log 2>&1; then
    echo "✓ Schema update completed successfully"
else
    echo "⚠️  Schema update completed with warnings (see /tmp/schema_update.log)"
fi
echo ""

# Count tables after
AFTER=$(_psql -t -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public';" | tr -d ' ')
ADDED=$((AFTER - BEFORE))

echo "📊 Updated table count: ${AFTER} (added: ${ADDED})"
echo ""

# List all tables
echo "📋 Current tables in scans database:"
_psql -c "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;"
echo ""

# Verify critical tables exist
echo "🔍 Verifying critical tables..."
CRITICAL_TABLES=(
    "assets"
    "ports"
    "scans"
    "findings"
    "web_findings"
    "vulns"
    "recon_findings"
    "scan_recommendations"
    "credential_findings"
    "discovered_params"
    "port_observation"
    "cve"
    "playwright_scans"
    "playwright_findings"
    "playwright_screenshots"
    "dom_analysis"
    "content_extractions"
    "agent_sessions"
    "agent_messages"
    "agent_tool_calls"
    "session_scan_metrics"
    "llm_request_metrics"
    # LangGraph durable checkpoints (AGENT_ENGINE=langgraph)
    "checkpoints"
    "checkpoint_blobs"
    "checkpoint_writes"
    "checkpoint_migrations"
    "jobs"
    "tasks"
    "pending_exploits"
    "exploit_results"
    "lateral_movement"
    "credential_spray_attempts"
    "credential_spray_approvals"
    "password_policies"
    "platform_control"
    "security_tests"
    "security_test_runs"
    "wstg_manual_reviews"
    "exploit_chunks"
    "scan_tool_feedback"
    "attack_vectors"
    "attack_path_edges"
    "tool_executions"
    "webhooks"
    "webhook_events"
    "webhook_deliveries"
    "engagements"
    "follow_up_items"
    "credential_vault"
    "scheduled_scans"
    "finding_activity"
    "evidence_store"
    "app_settings"
    "software_research_cache"
    "remote_nodes"
    "sync_log"
    "sync_nodes"
    "scope_targets"
    "detection_rule_state"
    "cloud_scan_recommendations"
    "service_prompts"
    "raw_artifacts"
)

MISSING=0
for table in "${CRITICAL_TABLES[@]}"; do
    if _psql -t -c "SELECT to_regclass('public.${table}');" | grep -q "null"; then
        echo "❌ Missing critical table: ${table}"
        MISSING=$((MISSING + 1))
    else
        echo "✓ ${table}"
    fi
done

echo ""

# Verify constraints that application code depends on.
#
# Table existence is not enough here. autogen_agents/scan_tools.py::persist_to_db
# issues ON CONFLICT (session_id, job_id), which RAISES if no matching unique
# index exists. Before this index was added the clause was
# `ON CONFLICT DO NOTHING` with nothing to match, so every persist silently
# re-inserted: 104 rows for 75 distinct jobs, and scans stuck at 'running' that
# could never be corrected once they completed.
echo "🔍 Verifying critical indexes..."
CRITICAL_INDEXES=(
    "uq_session_scan_metrics_session_job"
    # Required by the ON CONFLICT (fingerprint) upserts in the ETL parsers.
    # etl/parse_tool_output.py already depended on this and was failing at
    # runtime with "no unique or exclusion constraint matching the ON CONFLICT
    # specification" because the index had never been created.
    "uq_web_findings_fingerprint"
    "uq_vulns_fingerprint"
    "uq_credential_findings_identity"
    "uq_recon_findings_fingerprint"
    "uq_credential_findings_fingerprint"
    # Required by the ON CONFLICT upsert in /ingest/raw-artifact. Without it
    # every archived tool output raises instead of deduping, and the complete
    # raw output an LLM pass reads from is silently never stored.
    "uq_raw_artifacts_identity"
    # The LLM post-processing queue scans WHERE llm_status='pending'.
    "idx_raw_artifacts_llm_status"
)

# ── Asset identity / port normalization ───────────────────────────────────
#
# A hostname equal to the IP is not a virtual host, it is "hostname unknown"
# written wrongly — and ix_assets_ip_hostname(ip, COALESCE(hostname,'')) counts
# it as a DIFFERENT row from hostname=NULL. Ports hang off asset_id, so each
# such row carries a duplicate copy of that host's ports. This deployment had
# 99 port rows for 59 real (ip, proto, port) tuples before normalization.
if _psql -t -c \
    "SELECT 1 FROM pg_constraint WHERE conname = 'assets_hostname_not_ip';" | grep -q 1; then
    echo "✓ assets_hostname_not_ip (blocks hostname == ip)"
else
    echo "❌ Missing CHECK assets_hostname_not_ip - duplicate assets per IP will recur, each carrying a copy of that host's ports"
    MISSING=$((MISSING + 1))
fi

# One address, two asset rows. ix_assets_ip_hostname is
# UNIQUE(ip, COALESCE(hostname,'')), so (ip, '') and (ip, 'name') are both legal
# and ~20 raw "INSERT INTO assets" sites bypass the helper that now adopts the
# nameless row. ensure_all_tables.sql calls merge_duplicate_assets() on every
# run, so this should be zero; a non-zero count means a merge was refused.
# Addresses with two DIFFERENT hostnames are excluded — those are virtual hosts
# and are meant to stay separate.
# credential_findings.secret_value — the recovered password. Without it the
# bridge writes a NULL credential_value and every follow-on attack has an
# account name and nothing to authenticate with.
HAS_SECRET_VALUE=$(_psql -tAc \
    "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='credential_findings' AND column_name='secret_value');" 2>/dev/null)
if [[ "$HAS_SECRET_VALUE" == "t" ]]; then
    echo "✓ credential_findings.secret_value present"
elif [[ "$HAS_SECRET_VALUE" == "f" ]]; then
    echo "❌ credential_findings.secret_value missing - recovered passwords cannot be stored"
    MISSING=$((MISSING + 1))
else
    echo "⚠  credential_findings.secret_value check skipped (could not query)"
fi

SPLIT_ASSETS=$(_psql -tAc \
    "SELECT count(*) FROM (SELECT ip FROM assets GROUP BY ip HAVING count(*) > 1 AND count(DISTINCT NULLIF(btrim(hostname), '')) <= 1) d;" 2>/dev/null)
if [[ -z "$SPLIT_ASSETS" ]]; then
    echo "⚠  split-asset check skipped (could not query)"
elif [[ "$SPLIT_ASSETS" -le 0 ]]; then
    echo "✓ no address holds a nameless duplicate asset row"
else
    echo "❌ ${SPLIT_ASSETS} address(es) have a nameless duplicate asset row - one host split across two rows, ports on one and findings on the other; re-run ensure_all_tables.sql"
    MISSING=$((MISSING + 1))
fi

HAS_MERGE_FN=$(_psql -tAc \
    "SELECT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'merge_duplicate_assets');" 2>/dev/null)
if [[ "$HAS_MERGE_FN" == "t" ]]; then
    echo "✓ merge_duplicate_assets() present"
elif [[ "$HAS_MERGE_FN" == "f" ]]; then
    echo "❌ merge_duplicate_assets() missing - split asset rows will not self-heal"
    MISSING=$((MISSING + 1))
else
    echo "⚠  merge_duplicate_assets() check skipped (could not query)"
fi

DUP_PORTS=$(_psql -tAc \
    "SELECT (SELECT count(*) FROM ports) - (SELECT count(*) FROM (SELECT DISTINCT a.ip, p.proto, p.port FROM ports p JOIN assets a ON p.asset_id = a.id) d);" 2>/dev/null)
if [[ -z "$DUP_PORTS" ]]; then
    echo "⚠  port duplication check skipped (could not query)"
elif [[ "$DUP_PORTS" -le 0 ]]; then
    echo "✓ ports carry no (ip, proto, port) duplicates"
else
    echo "❌ ports has ${DUP_PORTS} duplicate (ip, proto, port) row(s) - re-run ensure_all_tables.sql to normalize"
    MISSING=$((MISSING + 1))
fi

HOSTNAME_EQ_IP=$(_psql -tAc \
    "SELECT count(*) FROM assets WHERE hostname = host(ip);" 2>/dev/null)
if [[ -n "$HOSTNAME_EQ_IP" && "$HOSTNAME_EQ_IP" -gt 0 ]]; then
    echo "❌ ${HOSTNAME_EQ_IP} asset(s) still store the IP as the hostname"
    MISSING=$((MISSING + 1))
fi

# ── Finding dedup: fingerprints, first/last seen ──────────────────────────
#
# The unique fingerprint indexes are checked above, but a unique index permits
# unlimited NULLs — a NULL fingerprint is an unconstrained row that bypasses
# dedup entirely. The dedup TRIGGERS fill it for the ~19 insert sites that
# supply none, so their absence silently reopens the duplication.
# trg_web_findings_z_infra is named to sort LAST: Postgres fires BEFORE
# triggers alphabetically, and it needs trg_web_findings_port to have
# populated NEW.port first. Renaming it earlier silently keys every group on
# port 0.
for trg in trg_vulns_dedup trg_web_findings_dedup trg_credential_findings_dedup trg_web_findings_z_infra; do
    if _psql -t -c \
        "SELECT 1 FROM pg_trigger WHERE NOT tgisinternal AND tgname = '${trg}';" | grep -q 1; then
        echo "✓ ${trg}"
    else
        echo "❌ Missing dedup trigger ${trg} - inserts without a fingerprint will store NULL and bypass the unique index"
        MISSING=$((MISSING + 1))
    fi
done

for tbl in vulns web_findings recon_findings credential_findings; do
    NULL_FP=$(_psql -tAc \
        "SELECT count(*) FROM public.${tbl} WHERE fingerprint IS NULL;" 2>/dev/null)
    DUP_FP=$(_psql -tAc \
        "SELECT count(*) - count(DISTINCT fingerprint) FROM public.${tbl};" 2>/dev/null)
    if [[ -z "$NULL_FP" || -z "$DUP_FP" ]]; then
        echo "⚠  ${tbl} fingerprint check skipped (could not query)"
    elif [[ "$NULL_FP" -eq 0 && "$DUP_FP" -le 0 ]]; then
        echo "✓ ${tbl}: no NULL and no duplicate fingerprints"
    else
        echo "❌ ${tbl}: ${NULL_FP} NULL fingerprint(s), ${DUP_FP} duplicate(s)"
        MISSING=$((MISSING + 1))
    fi
done

# vulns needs first_seen/last_seen for the delta view. updated_at cannot stand
# in: trg_vulns_updated_at touches it on ANY write, so an operator editing
# tester_notes is indistinguishable from a scan re-observing the finding.
# The credential identity index must be TOTAL and coalesce auth_type. Checking
# only that the NAME exists would pass even after a regression, because the name
# did not change when the expression was fixed: auth_type is nullable, and a NULL
# makes rows non-equal for a unique index, so two runs producing a NULL
# auth_type stored two rows for one account.
CRED_IDX=$(_psql -tAc \
    "SELECT indexdef FROM pg_indexes WHERE indexname='uq_credential_findings_identity';" 2>/dev/null)
if [[ -z "$CRED_IDX" ]]; then
    echo "❌ uq_credential_findings_identity missing - etl/parse_brutus.py ON CONFLICT will fail on every row"
    MISSING=$((MISSING + 1))
elif [[ "$CRED_IDX" == *"COALESCE(auth_type"* && "$CRED_IDX" != *"WHERE"* ]]; then
    echo "✓ uq_credential_findings_identity is total and coalesces auth_type"
else
    echo "❌ uq_credential_findings_identity is partial or does not coalesce auth_type - NULL auth_type rows will duplicate"
    echo "   got: ${CRED_IDX}"
    MISSING=$((MISSING + 1))
fi

# Virtual-host grouping: web_findings.fingerprint contains the hostname, so a
# server-level problem on shared hosting stores one row per vhost. The
# infrastructure_fingerprint groups them without merging.
INFRA_COL=$(_psql -tAc \
    "SELECT count(*) FROM information_schema.columns WHERE table_name='web_findings' AND column_name='infrastructure_fingerprint';" 2>/dev/null)
if [[ "$INFRA_COL" == "1" ]]; then
    echo "✓ web_findings.infrastructure_fingerprint present"
else
    echo "❌ web_findings.infrastructure_fingerprint missing - vhost findings cannot be grouped"
    MISSING=$((MISSING + 1))
fi

# web_findings.record_kind separates crawl INVENTORY (a URL a crawler merely
# discovered — 746 of 779 rows here) from actual findings. Generated, so it
# cannot drift; without it every severity count includes the crawl surface.
RK=$(_psql -tAc \
    "SELECT count(*) FROM information_schema.columns WHERE table_name='web_findings' AND column_name='record_kind';" 2>/dev/null)
if [[ "$RK" == "1" ]]; then
    RK_SPLIT=$(_psql -tAc \
        "SELECT string_agg(record_kind||'='||n, ' ' ORDER BY record_kind) FROM (SELECT record_kind, count(*) n FROM public.web_findings GROUP BY record_kind) x;" 2>/dev/null)
    echo "✓ web_findings.record_kind present (${RK_SPLIT:-empty table})"
else
    echo "❌ web_findings.record_kind missing - crawl inventory will be counted as findings"
    MISSING=$((MISSING + 1))
fi

if _psql -t -c \
    "SELECT 1 FROM pg_views WHERE schemaname='public' AND viewname='v_infrastructure_findings';" | grep -q 1; then
    echo "✓ v_infrastructure_findings view present"
else
    echo "❌ v_infrastructure_findings view missing"
    MISSING=$((MISSING + 1))
fi

VULN_SEEN=$(_psql -tAc \
    "SELECT count(*) FROM information_schema.columns WHERE table_name='vulns' AND column_name IN ('first_seen','last_seen');" 2>/dev/null)
if [[ "$VULN_SEEN" == "2" ]]; then
    echo "✓ vulns.first_seen / vulns.last_seen present"
else
    echo "❌ vulns is missing first_seen/last_seen (delta view cannot distinguish a re-scan from an edit)"
    MISSING=$((MISSING + 1))
fi
for idx in "${CRITICAL_INDEXES[@]}"; do
    if _psql -t -c \
        "SELECT 1 FROM pg_indexes WHERE indexname = '${idx}';" | grep -q 1; then
        echo "✓ ${idx}"
    else
        echo "❌ Missing critical index: ${idx} (ON CONFLICT upserts depending on it will fail at runtime)"
        MISSING=$((MISSING + 1))
    fi
done

echo ""

# ── Dedup trigger ─────────────────────────────────────────────────────────
# web_findings dedup does not live in the application: ~26 insert sites across
# 6 services write to this table and only one computed a fingerprint, so the
# invariant is enforced by a BEFORE INSERT trigger instead. Without it, writers
# that omit a fingerprint insert NULL, NULL never conflicts with the unique
# index, and duplicates silently return (katana previously re-inserted an entire
# crawl every run).
echo "🔍 Verifying dedup trigger..."
for trg in trg_web_findings_dedup trg_vulns_dedup trg_recon_findings_dedup; do
    if _psql -tAc \
         "SELECT 1 FROM pg_trigger WHERE tgname='${trg}' AND NOT tgisinternal;" | grep -q 1; then
        echo "✓ ${trg}"
    else
        echo "❌ Missing ${trg} — findings will duplicate on every re-scan"
        MISSING=$((MISSING + 1))
    fi
done

echo ""

# ── ExploitDB (separate database) ─────────────────────────────────────────
# Not part of the `scans` schema, so the table loop above cannot see it. It was
# absent entirely on a live install: db_init/create_exploits.sh began with
# `docker exec ... rag-postgres psql` while being mounted into the container's
# own /docker-entrypoint-initdb.d, where there is no docker CLI — so it failed
# on every init and exploitdb-etl crash-looped with "password authentication
# failed for user edb_rw", which reads like a bad password rather than a
# database that was never created.
echo "🔍 Verifying exploitdb..."
# This probe needs a connection to a DIFFERENT database (`postgres`) than the one
# this script maintains. A managed/remote server commonly permits only `scans`
# for this role+host, and pg_hba then rejects the probe itself — which is NOT
# evidence that the exploits database is absent. Reporting "Missing exploits
# database" on a failed CONNECTION was a lie: it may well exist and simply not be
# reachable from here. Distinguish the three states.
EDB_PROBE=$(_psql_db postgres -tAc \
     "SELECT 1 FROM pg_database WHERE datname='exploits';" 2>&1 || true)
if printf '%s' "$EDB_PROBE" | grep -q '^1$'; then
    EDB_ROWS=$(_psql_db exploits -tAc \
                 "SELECT count(*) FROM edb.exploits;" 2>/dev/null | tr -d ' ')
    echo "✓ exploits database (edb.exploits rows: ${EDB_ROWS:-unknown})"
    if [ "${EDB_ROWS:-0}" = "0" ]; then
        echo "  ⚠  empty — run: docker compose up -d searchsploit-updater exploitdb-etl"
    fi
elif printf '%s' "$EDB_PROBE" | grep -qiE 'pg_hba|no pg_hba.conf entry|permission denied|password authentication|could not connect|connection to server'; then
    echo "  ⚠  cannot verify the exploits database — this server does not allow"
    echo "     connecting to the 'postgres' database from here:"
    echo "     $(printf '%s' "$EDB_PROBE" | tr '\n' ' ' | cut -c1-140)"
    echo "     Not counted as missing: it may exist and simply be unreachable."
else
    echo "❌ Missing exploits database — CVE/exploit matching has no data"
    echo "   Create it with:"
    echo "     docker exec -e EDB_RW_PASSWORD=\"\$EDB_RW_PASSWORD\" -e POSTGRES_USER=app \\"
    echo "       rag-postgres bash /docker-entrypoint-initdb.d/create_exploits.sh"
    MISSING=$((MISSING + 1))
fi

echo ""

# Verify critical views exist
echo "🔍 Verifying critical views..."
CRITICAL_VIEWS=(
    "detected_software"
)

for view in "${CRITICAL_VIEWS[@]}"; do
    if _psql -t -c "SELECT 1 FROM pg_views WHERE viewname = '${view}';" | grep -q "1"; then
        echo "✓ ${view} (view)"
    else
        echo "❌ Missing critical view: ${view}"
        MISSING=$((MISSING + 1))
    fi
done

echo ""

# ── Required columns on pre-existing tables ───────────────────────────────
# Tables that gained columns via a later migration. A missing column here means
# ensure_all_tables.sql ran against an older schema and the ALTERs didn't apply,
# which surfaces at runtime as a confusing "column does not exist" query error.
echo "🔍 Verifying required columns..."
REQUIRED_COLUMNS=(
    "exploit_chunks:service"     # TIER 24 — per-service RAG training scoping
    "exploit_chunks:port"        # TIER 24
    "exploit_chunks:doc_kind"    # TIER 24
    "exploit_chunks:tech"        # TIER 24 — per-technology web-scan training
    "service_prompts:tech"       # TIER 24 — 'tech' prompt selector
)

for entry in "${REQUIRED_COLUMNS[@]}"; do
    tbl="${entry%%:*}"
    col="${entry##*:}"
    if _psql -tAc \
        "SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='${tbl}' AND column_name='${col}';" \
        | grep -q "1"; then
        echo "✓ ${tbl}.${col}"
    else
        echo "❌ Missing required column: ${tbl}.${col}"
        MISSING=$((MISSING + 1))
    fi
done

echo ""

# ── scope_targets schema fix verification ─────────────────────────────────
# The legacy UNIQUE(name, target) constraint blocked adding the same target
# value across different engagements' scopes. ensure_all_tables.sql migration
# drops it and creates the engagement-scoped unique index.
echo "🔍 Verifying pending_exploits.source allows 'webshell' (WSTG-CONF-06 webshell upload)..."
SRC_OK=$(_psql -tAc \
  "SELECT pg_get_constraintdef(oid) LIKE '%webshell%' FROM pg_constraint WHERE conname='pending_exploits_source_check'" 2>/dev/null)
if [ "$SRC_OK" != "t" ]; then
    echo "  ⚠  pending_exploits_source_check missing 'webshell' — migrating"
    _psql -c \
      "ALTER TABLE pending_exploits DROP CONSTRAINT IF EXISTS pending_exploits_source_check; \
       ALTER TABLE pending_exploits ADD CONSTRAINT pending_exploits_source_check \
       CHECK (source = ANY (ARRAY['exploitdb','metasploit','webshell']))" >/dev/null 2>&1
fi
SRC_OK=$(_psql -tAc \
  "SELECT pg_get_constraintdef(oid) LIKE '%webshell%' FROM pg_constraint WHERE conname='pending_exploits_source_check'" 2>/dev/null)
if [ "$SRC_OK" = "t" ]; then
    echo "  ✓ pending_exploits.source permits 'webshell'"
else
    echo "  ❌ pending_exploits.source still rejects 'webshell'"
    MISSING=$((MISSING + 1))
fi

echo "🔍 Verifying scope_targets schema migration..."
LEGACY=$(_psql -tAc \
  "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.scope_targets'::regclass AND conname='scope_targets_name_target_key')" 2>/dev/null)
if [ "$LEGACY" = "t" ]; then
    echo "  ⚠  Legacy UNIQUE(name,target) constraint still present — dropping now"
    _psql -c \
      "ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS scope_targets_name_target_key" >/dev/null 2>&1
fi
_psql -c \
  "CREATE UNIQUE INDEX IF NOT EXISTS ux_scope_targets_eng_name_target ON scope_targets(engagement_id, name, target)" >/dev/null 2>&1
HAS_INDEX=$(_psql -tAc \
  "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename='scope_targets' AND indexname='ux_scope_targets_eng_name_target')" 2>/dev/null)
if [ "$HAS_INDEX" = "t" ]; then
    echo "  ✓ scope_targets engagement-scoped unique index present"
else
    echo "  ❌ Failed to create ux_scope_targets_eng_name_target index"
    MISSING=$((MISSING + 1))
fi

echo ""

if [ $MISSING -eq 0 ]; then
    echo "✅ All critical tables, views, and constraints are present!"
    echo ""
    echo "Database schema is ready for use."
    exit 0
else
    echo "❌ ${MISSING} critical issue(s) found!"
    echo ""
    echo "Please check the error log at /tmp/schema_update.log"
    exit 1
fi
