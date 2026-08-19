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

# Check if rag-postgres container is running
if ! docker ps --format '{{.Names}}' | grep -q '^rag-postgres$'; then
    echo "❌ Error: rag-postgres container is not running"
    echo "   Start it with: docker compose up -d rag-postgres"
    exit 1
fi

echo "✓ Docker and rag-postgres container are available"
echo ""

# Wait for PostgreSQL to be ready
echo "⏳ Waiting for PostgreSQL to be ready..."
timeout=30
elapsed=0
while ! docker exec rag-postgres pg_isready -U app -d scans &>/dev/null; do
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
BEFORE=$(docker exec rag-postgres psql -U app -d scans -t -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public';" | tr -d ' ')
echo "📊 Current table count: ${BEFORE}"
echo ""

# Apply the schema
echo "🔧 Applying comprehensive schema..."
if docker exec rag-postgres psql -U app -d scans -f /docker-entrypoint-initdb.d/ensure_all_tables.sql > /tmp/schema_update.log 2>&1; then
    echo "✓ Schema update completed successfully"
else
    echo "⚠️  Schema update completed with warnings (see /tmp/schema_update.log)"
fi
echo ""

# Count tables after
AFTER=$(docker exec rag-postgres psql -U app -d scans -t -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public';" | tr -d ' ')
ADDED=$((AFTER - BEFORE))

echo "📊 Updated table count: ${AFTER} (added: ${ADDED})"
echo ""

# List all tables
echo "📋 Current tables in scans database:"
docker exec rag-postgres psql -U app -d scans -c "SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;"
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
    "jobs"
    "tasks"
    "pending_exploits"
    "exploit_results"
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
    if docker exec rag-postgres psql -U app -d scans -t -c "SELECT to_regclass('public.${table}');" | grep -q "null"; then
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
    # Required by the ON CONFLICT upsert in /ingest/raw-artifact. Without it
    # every archived tool output raises instead of deduping, and the complete
    # raw output an LLM pass reads from is silently never stored.
    "uq_raw_artifacts_identity"
    # The LLM post-processing queue scans WHERE llm_status='pending'.
    "idx_raw_artifacts_llm_status"
)
for idx in "${CRITICAL_INDEXES[@]}"; do
    if docker exec rag-postgres psql -U app -d scans -t -c \
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
    if docker exec rag-postgres psql -U app -d scans -tAc \
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
if docker exec rag-postgres psql -U app -d postgres -tAc \
     "SELECT 1 FROM pg_database WHERE datname='exploits';" | grep -q 1; then
    EDB_ROWS=$(docker exec rag-postgres psql -U app -d exploits -tAc \
                 "SELECT count(*) FROM edb.exploits;" 2>/dev/null | tr -d ' ')
    echo "✓ exploits database (edb.exploits rows: ${EDB_ROWS:-unknown})"
    if [ "${EDB_ROWS:-0}" = "0" ]; then
        echo "  ⚠  empty — run: docker compose up -d searchsploit-updater exploitdb-etl"
    fi
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
    if docker exec rag-postgres psql -U app -d scans -t -c "SELECT 1 FROM pg_views WHERE viewname = '${view}';" | grep -q "1"; then
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
    if docker exec rag-postgres psql -U app -d scans -tAc \
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
echo "🔍 Verifying scope_targets schema migration..."
LEGACY=$(docker exec rag-postgres psql -U app -d scans -tAc \
  "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.scope_targets'::regclass AND conname='scope_targets_name_target_key')" 2>/dev/null)
if [ "$LEGACY" = "t" ]; then
    echo "  ⚠  Legacy UNIQUE(name,target) constraint still present — dropping now"
    docker exec rag-postgres psql -U app -d scans -c \
      "ALTER TABLE scope_targets DROP CONSTRAINT IF EXISTS scope_targets_name_target_key" >/dev/null 2>&1
fi
docker exec rag-postgres psql -U app -d scans -c \
  "CREATE UNIQUE INDEX IF NOT EXISTS ux_scope_targets_eng_name_target ON scope_targets(engagement_id, name, target)" >/dev/null 2>&1
HAS_INDEX=$(docker exec rag-postgres psql -U app -d scans -tAc \
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
