#!/usr/bin/env bash
# Post-install verification: checks all DB tables, Go tool binaries,
# container health, and API endpoints.
# Usage: ./scripts/post-install-check.sh

set -uo pipefail
cd "$(dirname "$0")/.."

# Containers are addressed by (compose project, service), never by
# `container_name` or a published host port — both are global, so a check run
# from a second project would happily verify the FIRST stack and report it as
# this install's result. See scripts/lib/compose-target.sh.
# shellcheck source=lib/compose-target.sh
. "$(pwd)/scripts/lib/compose-target.sh"

PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS] $1"; ((PASS++)); }
fail() { echo "  [FAIL] $1"; ((FAIL++)); }
warn() { echo "  [WARN] $1"; ((WARN++)); }

# ── DB access ───────────────────────────────────────────────────────────────
# Runs one statement and echoes the result the way `psql -tA` would: one row per
# line, columns joined by '|', booleans as t/f, NULL as empty.
#
# WHY THIS SHAPE: the previous version hard-coded `docker exec rag-postgres` at
# seven call sites, and its one fallback printed a LITERAL 't'/'f' instead of the
# value. In this deployment Postgres is REMOTE — there is no rag-postgres
# container — so every table check read empty and reported "table missing" for
# ~25 tables that exist, and `SELECT count(*)` came back as the string "f",
# which made `[[ "$X" -eq 0 ]]` evaluate `f` as an arithmetic variable and abort
# the whole script under `set -u` ("f: unbound variable").
#
# The SQL is passed through the environment, not interpolated into the python
# source, so quotes in a statement cannot break the command.
#
# The caller learns "ran" vs "could not run" from the EXIT STATUS, not a global:
# `x=$(_run_sql ...)` runs the function in a SUBSHELL, so any variable it sets is
# lost. Exit status propagates; a global does not. (Proven: `X=0; f(){ X=1; };
# out=$(f); echo $X` prints 0.) On failure the error text is printed instead of a
# result, so a caller that ignores the status still sees something non-numeric /
# non-"t" rather than a silent empty string.
#
# "could not query" must never be reported as "missing" — that is the same
# skip-vs-fail confusion that kept CI red (see tests/_container.py).
#
# The two routes and their rationale now live in ct_sql (scripts/lib/
# compose-target.sh) so setup.sh's Phase 7 uses the same resolution instead of
# its own `docker exec rag-postgres`. The only behavioural change is that the
# lookup is scoped to THIS compose project: grepping `docker ps` for the NAME
# rag-postgres matched whichever stack owned it, which under a rehearsal is the
# live one — so a fresh-install check would have verified the live database and
# passed.
#
# ct_sql returns 2 for "no database reachable" where this used to return 1;
# every caller here tests `rc != 0`, and _check_object's "could not query"
# branch covers both.
_run_sql() { ct_sql "$1"; }

# Numeric guard. `[[ "$x" -eq 0 ]]` on a non-numeric string sends bash into
# arithmetic evaluation, where a bare word is a VARIABLE NAME — under `set -u`
# that aborts the script instead of failing the comparison.
_is_num() { [[ "${1:-}" =~ ^-?[0-9]+$ ]]; }

_exists_sql() {  # $1 = kind (table|view), $2 = name
  case "$1" in
    table) echo "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema='public' AND table_name='$2')" ;;
    view)  echo "SELECT EXISTS (SELECT FROM pg_views WHERE schemaname='public' AND viewname='$2')" ;;
  esac
}

# Reports missing ONLY when the query actually RAN. $1=kind $2=name $3=label
_check_object() {
  local result rc
  result=$(_run_sql "$(_exists_sql "$1" "$2")"); rc=$?
  if (( rc != 0 )); then
    warn "$3 — could not query the database (${result:0:90})"
  elif [[ "$result" == "t" ]]; then
    pass "$3"
  else
    fail "$3 — $1 missing"
  fi
}

# ── 1. Database Tables ──
echo ""
echo "=== Database Tables ==="

EXPECTED_TABLES=(
  # TIER 0: Foundation
  assets scans
  # TIER 1: Core scanning
  ports findings port_observation raw_output scan_targets finding_evidence cve
  # TIER 2: Tool-specific findings
  web_findings discovered_params vulns scan_recommendations
  credential_findings recon_findings
  # TIER 3: Playwright
  playwright_scans playwright_findings playwright_screenshots
  # TIER 4: Content intelligence
  dom_analysis content_extractions content_intel_patterns
  # TIER 5: ZAP / KB
  zap_sessions kb_service_overrides scan_tool_feedback attack_vectors attack_path_edges
  # TIER 6: Jobs / Tasks
  jobs tasks
  # TIER 7: Agent / LLM
  agent_sessions agent_messages agent_tool_calls
  session_scan_metrics llm_request_metrics prompt_configs
  # LangGraph durable checkpoints (AGENT_ENGINE=langgraph). Library-managed by
  # PostgresSaver.setup(), but declared in db_init so a fresh install has them
  # before the first agent session — assert them like any other table.
  checkpoints checkpoint_blobs checkpoint_writes checkpoint_migrations
  # TIER 8: Exploit management
  pending_exploits exploit_results exploit_chunks
  lateral_movement credential_spray_attempts credential_spray_approvals password_policies platform_control security_tests security_test_runs
  exploit_approval_rules
  msf_modules active_listeners exploit_callbacks tool_executions
  # TIER 9: Webhooks
  webhooks webhook_events webhook_deliveries
  # TIER 10: Infrastructure
  remote_nodes node_scan_jobs ad_attack_results
  # TIER 11: GRPO / ML
  grpo_feedback grpo_training_runs grpo_model_registry
  # TIER 12: Wordlists / Settings / Software
  wordlists app_settings software_research_cache
  # TIER 13: Engagements / Workflow
  engagements finding_activity evidence_store evidence_links
  campaign_events credential_vault scheduled_scans screenshot_metadata
  # TIER 14: Follow-ups / Detection
  follow_up_items osint_agent_feedback detection_rule_state
  # TIER 15: API testing
  api_collections api_endpoints api_test_sessions api_test_results api_param_configs
  # TIER 16: Scan runs / Cloud
  scan_runs scan_run_findings credential_access_map cloud_scan_recommendations
  # TIER 17: Sync
  sync_nodes sync_state sync_log sync_conflicts
  # TIER 18: Scope
  scope_targets scope_classification_rules scope_decisions scope_suggestions
  # Self-adapting extractors + agent-to-agent feedback channel
  extractor_learned agent_flags
  # TIER 18: Scan pipelines
  scan_pipelines scan_pipeline_jobs
  # TIER 19: Recon agent
  recon_agent_state scope_coverage
  # TIER 20: Cloud Tenant Discovery
  cloud_tenants
  # TIER 21: News Intelligence
  # NB: asset matches are stored in the news_items.asset_matches JSONB column,
  # not a separate news_asset_matches table (see news_runner/news_agent.py).
  news_sources news_items news_runs
  # TIER 22: Chat presets
  chat_presets
  # TIER 24: Per-service / per-port prompts + RAG training data
  service_prompts
  # TIER 25: Virtual-host finding groups (one problem, N affected vhosts)
  finding_group_state
  # TIER 26: Post-execution review (app/rag-api/post_review_agent.py)
  post_review_reports
  # TIER 27: Operator-declared scan parameters (app/rag-api/scan_parameters.py)
  scan_parameters
  # TIER 28: WSTG guided manual checklist sign-off (app/rag-api/wstg_coverage.py)
  wstg_manual_reviews
  # TIER 29: findings-level RAG store (app/load_all.py). Declared in the SCANS
  # schema since 2026-09-09 — it used to be created in the `n8n` database while
  # its writer connected to `scans`, so it existed nowhere the code could see.
  rag_documents
)

# Views that reports and the spray list depend on. A missing view fails only when
# a page queries it, which reads as "no results" rather than "not installed".
EXPECTED_VIEWS=(
  v_identity_credential_state
  # Moved out of the n8n database with rag_documents.
  rag_recent_high
)

for table in "${EXPECTED_TABLES[@]}"; do
  _check_object table "$table" "$table"
done

for view in "${EXPECTED_VIEWS[@]}"; do
  _check_object view "$view" "$view (view)"
done

# Knowledge base content, not just schema. The table existing tells you nothing
# about whether setup.sh phase 10 actually seeded it — an empty service_prompts
# silently degrades AI scans to generic prompting, which looks like a model
# quality problem rather than a missing install step.
#
# WARN not FAIL: the stack is usable with no rules, and an operator may have
# deliberately cleared them.
echo ""
echo "  -- Knowledge base content --"
SEED_FILES=$(ls knowledge/seed/*.yaml 2>/dev/null | wc -l | tr -d ' ')
RULE_ROWS=$(_run_sql "SELECT COUNT(*) FROM public.service_prompts")
if ! _is_num "$RULE_ROWS"; then
  warn "service_prompts — could not be queried"
elif [[ "$RULE_ROWS" -gt 0 ]]; then
  pass "service_prompts — $RULE_ROWS rule(s) seeded"
elif [[ "$SEED_FILES" -gt 0 ]]; then
  warn "service_prompts is empty but $SEED_FILES seed file(s) exist — seeding did not run"
  echo "         Fix: ./scripts/import-knowledge.sh --file knowledge/seed/<file>.yaml"
else
  warn "service_prompts is empty and no seed files present — AI scans use generic prompts"
  echo "         Add rules in the UI (Service Prompts), then ./scripts/export-knowledge.sh"
fi

# Check critical views
echo ""
echo "  -- Views --"
EXPECTED_VIEWS=(detected_software v_infrastructure_findings)
for view in "${EXPECTED_VIEWS[@]}"; do
  _check_object view "$view" "$view (view)"
done

# Schema integrity: scope_targets must allow same target across engagements
# Works for both local (rag-postgres container) and remote DB (via rag-api shell).
echo ""
echo "  -- scope_targets schema --"
HAS_LEGACY=$(_run_sql "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.scope_targets'::regclass AND conname='scope_targets_name_target_key')")
if [[ "$HAS_LEGACY" == "f" ]]; then
  pass "scope_targets: legacy UNIQUE(name,target) constraint absent"
elif [[ "$HAS_LEGACY" == "t" ]]; then
  fail "scope_targets: legacy UNIQUE(name,target) STILL PRESENT — run ./scripts/ensure_db_schema.sh"
else
  warn "scope_targets: schema check skipped (no local rag-postgres or rag-api)"
fi
HAS_NEW=$(_run_sql "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename='scope_targets' AND indexname='ux_scope_targets_eng_name_target')")
if [[ "$HAS_NEW" == "t" ]]; then
  pass "scope_targets: ux_scope_targets_eng_name_target index present"
elif [[ "$HAS_NEW" == "f" ]]; then
  fail "scope_targets: missing ux_scope_targets_eng_name_target — run ./scripts/ensure_db_schema.sh"
else
  warn "scope_targets: index check skipped (no DB connection helper available)"
fi

# scan_recommendations.target_kind — dispatch refuses non-'service' kinds rather
# than firing a file/range/resource recommendation at an IP as a network scan.
# Missing column means every rec reads as 'service' and that guard cannot work.
HAS_TK=$(_run_sql "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='scan_recommendations' AND column_name='target_kind')")
if [[ "$HAS_TK" == "t" ]]; then
  pass "scan_recommendations.target_kind column present"
elif [[ "$HAS_TK" == "f" ]]; then
  fail "scan_recommendations.target_kind missing — run ./scripts/ensure_db_schema.sh (dispatch cannot distinguish file/range/resource recs)"
else
  warn "scan_recommendations.target_kind check skipped (no DB connection helper available)"
fi

# Asset identity: a hostname equal to the IP is not a virtual host, it is
# "hostname unknown" written wrongly — and ix_assets_ip_hostname(ip,
# COALESCE(hostname,'')) counts it as a DIFFERENT row from hostname=NULL. Ports
# hang off asset_id, so each such row carries a duplicate copy of that host's
# ports, inflating every port count an agent or report reads.
HAS_HN_CHECK=$(_run_sql "SELECT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='assets_hostname_not_ip')")
if [[ "$HAS_HN_CHECK" == "t" ]]; then
  pass "assets_hostname_not_ip CHECK present"
elif [[ "$HAS_HN_CHECK" == "f" ]]; then
  fail "assets_hostname_not_ip missing — run ./scripts/ensure_db_schema.sh (duplicate assets per IP will recur, each carrying a copy of that host's ports)"
else
  warn "assets_hostname_not_ip check skipped (no DB connection helper available)"
fi

DUP_PORT_ROWS=$(_run_sql "SELECT (SELECT count(*) FROM ports) - (SELECT count(*) FROM (SELECT DISTINCT a.ip, p.proto, p.port FROM ports p JOIN assets a ON p.asset_id = a.id) d);")
if ! _is_num "$DUP_PORT_ROWS"; then
  warn "ports duplication check skipped (could not query)"
elif [[ "$DUP_PORT_ROWS" -le 0 ]]; then
  pass "ports carry no (ip, proto, port) duplicates"
else
  fail "ports has $DUP_PORT_ROWS duplicate (ip, proto, port) row(s) — run ./scripts/ensure_db_schema.sh"
fi

# Verified credentials must reach the vault, or the Users page badge stays dark.
# The bridge runs automatically after a brutus ingest, so a non-zero count here
# means an upgrade landed on a database that already had credential findings.
UNBRIDGED=$(_run_sql "SELECT count(*) FROM (
    SELECT DISTINCT host(cf.ip) AS h, lower(cf.username) AS u
      FROM credential_findings cf WHERE cf.valid_cred IS TRUE) f
   WHERE NOT EXISTS (SELECT 1 FROM credential_vault cv
                      WHERE lower(cv.username) = f.u AND cv.domain = f.h)")
if ! _is_num "$UNBRIDGED"; then
  warn "credential bridge check skipped (could not query)"
elif [[ "$UNBRIDGED" -eq 0 ]]; then
  pass "every verified credential is present in credential_vault"
else
  warn "$UNBRIDGED verified credential account(s) are not in credential_vault — the Users page 'cred' badge will be dark for them; POST /vault/bridge-credential-findings {\"dry_run\": false}"
fi

# assets.provider column + GIN index — required for cloud-hosting filter
HAS_PROVIDER=$(_run_sql "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='assets' AND column_name='provider')")
if [[ "$HAS_PROVIDER" == "t" ]]; then
  pass "assets.provider column present"
elif [[ "$HAS_PROVIDER" == "f" ]]; then
  fail "assets.provider missing — run ./scripts/ensure_db_schema.sh"
else
  warn "assets.provider check skipped (no DB connection helper available)"
fi

# scan_recommendations.priority — written by the recommender (G1/G2 ranking)
HAS_PRIO=$(_run_sql "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='scan_recommendations' AND column_name='priority')")
if [[ "$HAS_PRIO" == "t" ]]; then
  pass "scan_recommendations.priority column present"
elif [[ "$HAS_PRIO" == "f" ]]; then
  fail "scan_recommendations.priority missing — run ./scripts/ensure_db_schema.sh"
else
  warn "scan_recommendations.priority check skipped (no DB connection helper available)"
fi

# raw_artifacts.note / item_count — upload label + per-file item count (Scan Results)
HAS_ARTIFACT_COLS=$(_run_sql "SELECT (count(*) = 2)::text FROM information_schema.columns WHERE table_name='raw_artifacts' AND column_name IN ('note','item_count')")
if [[ "$HAS_ARTIFACT_COLS" == "true" ]]; then
  pass "raw_artifacts.note + item_count columns present"
elif [[ "$HAS_ARTIFACT_COLS" == "false" ]]; then
  fail "raw_artifacts.note/item_count missing — run ./scripts/ensure_db_schema.sh"
else
  warn "raw_artifacts.note/item_count check skipped (no DB connection helper available)"
fi

# RAG_API_URL must be https:// wherever it is set. rag-api is TLS-only, so an
# http:// value returns an empty reply — and the fire-and-forget webhook
# emitters swallow that, so the only symptom is "no webhook events ever".
# Found 2026-09-10: .env had http://, and every news webhook silently vanished.
for _svc in news-runner kali-listener; do
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$_svc"; then
    _url=$(docker exec "$_svc" sh -c 'echo $RAG_API_URL' 2>/dev/null | tr -d '\r')
    case "$_url" in
      https://*) pass "$_svc RAG_API_URL is https ($_url)" ;;
      http://*)  fail "$_svc RAG_API_URL is $_url — rag-api is TLS-only; webhook emits will fail SILENTLY. Set RAG_API_URL=https://rag-api:8000 in .env and recreate." ;;
      "")        warn "$_svc RAG_API_URL is unset (falls back to the code default)" ;;
      *)         warn "$_svc RAG_API_URL has an unexpected form: $_url" ;;
    esac
  else
    warn "$_svc not running — RAG_API_URL scheme not checked"
  fi
done

# Per-task LLM routing: the endpoint must respond AND llm_query must be able to
# import the resolver. The import is soft in the code (a broken one degrades to
# the global model silently), so it needs asserting here or per-task selection
# stops working with no visible symptom.
# Addressed by (project, service) via compose-target.sh — never `localhost:3002`
# or `docker exec llm_query`. Both are GLOBAL: under a second compose project a
# literal host port or container name reaches the LIVE stack and reports IT
# healthy. Enforced by tests/test_rehearsal_isolation.py.
for _ep in /api/settings/llm/routes /api/settings/llm/providers; do
  _code=$(ct_http_code pentest-dashboard 443 "$_ep" 2>/dev/null || echo "000")
  if [[ "$_code" =~ ^(200|401|403)$ ]]; then
    pass "$_ep responding (HTTP $_code)"
  elif [[ "$_code" != "000" ]]; then
    fail "$_ep returned HTTP $_code — per-task model selection unavailable"
  else
    warn "$_ep not checked (dashboard unreachable)"
  fi
done

# llm_query must be able to IMPORT the resolver. That import is soft in the
# code (a failure degrades to the global model silently), so without this the
# whole routing feature can stop working with no visible symptom.
if ct_cid llm_query >/dev/null 2>&1; then
  if ct_exec llm_query python -c "import sys; sys.path.insert(0,'/app'); from common.llm_settings import get_route; get_route('news')" >/dev/null 2>&1; then
    pass "llm_query can resolve per-task LLM routes"
  else
    fail "llm_query cannot import common.llm_settings.get_route — per-task routing silently falls back to the global model. Check the ./common bind-mount."
  fi
else
  warn "llm_query not running — per-task route resolution not checked"
fi

# news_items.published_at — the ARTICLE's publication date, distinct from
# first_seen/last_seen (which are ingest times). Added 2026-09-10. Without it
# GET /news/items returns published_at:null for every row and sort=published
# raises "column does not exist".
HAS_NEWS_PUB=$(_run_sql "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='news_items' AND column_name='published_at')")
if [[ "$HAS_NEWS_PUB" == "t" ]]; then
  pass "news_items.published_at column present"
elif [[ "$HAS_NEWS_PUB" == "f" ]]; then
  fail "news_items.published_at missing — run ./scripts/ensure_db_schema.sh"
else
  warn "news_items.published_at check skipped (no DB connection helper available)"
fi

HAS_NEWS_PUB_IDX=$(_run_sql "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename='news_items' AND indexname='idx_news_items_published_at')")
if [[ "$HAS_NEWS_PUB_IDX" == "t" ]]; then
  pass "idx_news_items_published_at present"
elif [[ "$HAS_NEWS_PUB_IDX" == "f" ]]; then
  fail "idx_news_items_published_at missing — run ./scripts/ensure_db_schema.sh"
else
  warn "idx_news_items_published_at check skipped (no DB connection helper available)"
fi

# idx_assets_engagement_ip — G3 discovery scan-loop hot lookup
HAS_ENG_IDX=$(_run_sql "SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename='assets' AND indexname='idx_assets_engagement_ip')")
if [[ "$HAS_ENG_IDX" == "t" ]]; then
  pass "assets: idx_assets_engagement_ip present"
elif [[ "$HAS_ENG_IDX" == "f" ]]; then
  fail "assets: idx_assets_engagement_ip missing — run ./scripts/ensure_db_schema.sh"
else
  warn "idx_assets_engagement_ip check skipped (no DB connection helper available)"
fi

# recon_findings engagement-propagation trigger (G3)
HAS_RF_TRG=$(_run_sql "SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='trg_recon_findings_engagement')")
if [[ "$HAS_RF_TRG" == "t" ]]; then
  pass "recon_findings: trg_recon_findings_engagement present"
elif [[ "$HAS_RF_TRG" == "f" ]]; then
  fail "recon_findings: trg_recon_findings_engagement missing — run ./scripts/ensure_db_schema.sh"
else
  warn "trg_recon_findings_engagement check skipped (no DB connection helper available)"
fi

# Tool registry (node_manager) reachable + Kali allowlist reconciled
echo ""
echo "  -- tool registry / Kali allowlist --"
if ct_cid rag-api >/dev/null 2>&1; then
  REG_COUNT=$(ct_exec rag-api sh -c 'curl -sk -H "x-api-key: $API_KEY" https://node-manager:8027/tools/registry 2>/dev/null' \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)
  if [[ "${REG_COUNT:-0}" -gt 0 ]]; then
    pass "node_manager /tools/registry reachable ($REG_COUNT tools)"
  else
    warn "node_manager /tools/registry not reachable (capability checks degraded)"
  fi
  KALI_COUNT=$(ct_exec rag-api sh -c 'curl -sk -H "x-api-key: $API_KEY" https://kali-listener:8019/tools/allowed 2>/dev/null' \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('total',0))" 2>/dev/null || echo 0)
  if [[ "${KALI_COUNT:-0}" -gt 0 ]]; then
    # Reconciled if Kali allowlist is at least as large as the fallback (23).
    if [[ "${KALI_COUNT}" -ge 23 ]]; then
      pass "kali-listener allowlist reconciled ($KALI_COUNT tools, Metasploit excluded)"
    else
      warn "kali-listener allowlist small ($KALI_COUNT) — registry may be unreachable from kali"
    fi
  else
    warn "kali-listener /tools/allowed not reachable"
  fi
else
  warn "tool registry/allowlist check skipped (rag-api not running)"
fi

# ── 2. Go Tool Binaries ──
echo ""
echo "=== Go Tool Binaries ==="

# Tool presence, per service.
#
# $1 service  $2 label  $3 missing severity (fail|warn)  $4 hint  $5.. tools
#
# The five loops this replaces each ran `docker exec <name> which X` and
# reported ANY failure as "binary missing" — so a runner that was not up, or
# not part of this project at all, produced a screenful of false FAILs about
# binaries that are present in the image. Resolve the container once: no
# container is a SKIP, and only a resolved container can fail a tool.
_check_tools() {
  local service="$1" label="$2" sev="$3" hint="$4"; shift 4
  if ! ct_cid "$service" >/dev/null 2>&1; then
    warn "${label}: no container in project '$(ct_project)' — tool check skipped"
    return
  fi
  local tool
  for tool in "$@"; do
    if ct_exec "$service" which "$tool" >/dev/null 2>&1; then
      pass "${label}: $tool"
    elif [[ "$sev" == "warn" ]]; then
      warn "${label}: $tool — ${hint}"
    else
      fail "${label}: $tool — ${hint}"
    fi
  done
}

GO_HINT="binary missing (run scripts/build-go-tools.sh)"

echo "  -- pd-runner --"
_check_tools pd-runner "pd-runner" fail "$GO_HINT" httpx naabu katana tlsx ffuf

echo "  -- osint-runner --"
_check_tools osint-runner "osint-runner" fail "$GO_HINT" \
  subfinder dnsx httpx tlsx asnmap uncover cloudlist alterx mapcidr chaos \
  shuffledns amass gau waybackurls gowitness massdns trufflehog

echo "  -- nmap-scanner --"
_check_tools nmap_scanner "nmap-scanner" fail "binary missing" masscan nmap

echo "  -- web-scanner --"
_check_tools web-scanner "web-scanner" fail "binary missing" gobuster nikto

echo "  -- brutus-runner --"
_check_tools brutus-runner "brutus-runner" warn "not installed (optional)" hydra medusa ncrack

# ── 3. Container Health ──
echo ""
echo "=== Container Health ==="

CONTAINERS=(
  rag-api pentest-dashboard
  playwright-scanner web-scanner nmap_scanner
  pd-runner osint-runner nuclei-runner brutus-runner
  scan-recommender container-logs node-manager
)

# rag-postgres is NOT in the list above. In remote / remote_direct mode the
# database lives on a VPS and no such container exists here, so requiring it
# reported a hard FAIL on a correctly-configured stack. What actually matters is
# that the database is REACHABLE, which is what gets checked instead.
# (It also produced the confusing bare "[FAIL] rag-postgres: " — `docker inspect`
# on a missing object prints an empty line to stdout AND exits 1, so the
# `|| echo not_found` appended to an empty line and matched no branch.)
DB_MODE=$(python3 -c "
import json
try:
    d = json.load(open('db-config.json'))
except Exception:
    d = {}
print(d.get('mode') or (d.get('config') or {}).get('mode') or 'local')" 2>/dev/null || echo local)
if ct_cid rag-postgres >/dev/null 2>&1; then
  pgstatus=$(docker inspect --format='{{.State.Health.Status}}' rag-postgres 2>/dev/null)
  if [[ "$pgstatus" == "healthy" || -z "$pgstatus" ]]; then
    pass "rag-postgres: present (db mode: $DB_MODE)"
  else
    fail "rag-postgres: $pgstatus"
  fi
elif [[ "$DB_MODE" == "local" ]]; then
  fail "rag-postgres: not running, but db mode is 'local'"
else
  if _run_sql "SELECT 1" >/dev/null 2>&1; then
    pass "database reachable (db mode: $DB_MODE, no local rag-postgres — expected)"
  else
    fail "database unreachable (db mode: $DB_MODE) — $(_run_sql 'SELECT 1' 2>&1 | head -c 120)"
  fi
fi

for cname in "${CONTAINERS[@]}"; do
  status=$(docker inspect --format='{{.State.Health.Status}}' "$cname" 2>/dev/null) || status="not_found"
  [[ -z "$status" ]] && status="not_found"
  if [[ "$status" == "healthy" ]]; then
    pass "$cname: healthy"
  elif [[ "$status" == "starting" ]]; then
    warn "$cname: still starting"
  elif [[ "$status" == "not_found" ]]; then
    # Check if container exists but has no healthcheck
    running=$(docker inspect --format='{{.State.Running}}' "$cname" 2>/dev/null || echo "false")
    if [[ "$running" == "true" ]]; then
      pass "$cname: running (no healthcheck)"
    else
      fail "$cname: not running"
    fi
  else
    fail "$cname: $status"
  fi
done

# Optional containers
for cname in embedder zap autogen-agents; do
  status=$(docker inspect --format='{{.State.Running}}' "$cname" 2>/dev/null || echo "false")
  if [[ "$status" == "true" ]]; then
    pass "$cname: running (optional)"
  else
    warn "$cname: not running (optional)"
  fi
done

# ── 4. API Endpoints ──
echo ""
echo "=== API Endpoints ==="

# Prefer an explicit env override, else read the generated key from .env so the
# authenticated RAG API endpoints return 200 instead of 401.
if [ -z "${API_KEY:-}" ] && [ -f ".env" ]; then
  API_KEY=$(grep '^API_KEY=' .env | head -1 | cut -d= -f2-)
fi
API_KEY="${API_KEY:-changeme}"

# Paths, not URLs: each is probed inside this project's rag-api on its
# CONTAINER port. `https://localhost:8000` belongs to the host — under a second
# stack, or after an operator remaps the port, every one of these would have
# swept the OTHER stack's API and passed.
endpoints=(
  "/health|RAG API health"
  "/assets?limit=1|Assets endpoint"
  "/software|Software inventory"
  "/content-extractions?limit=1|Content extractions"
  "/content-intel/patterns|Content patterns"
  "/wordlists|Wordlists"
  "/opsec/timeline?hours=1|OpSec timeline"
  "/follow-ups?limit=1|Follow-ups"
  "/health/database|Health DB schema"
  "/software/cve-prompt|CVE prompt config"
  "/software/vendor-pages|Vendor pages config"
  "/software/ddg-jobs|AI check jobs"
)

if ! ct_cid rag-api >/dev/null 2>&1; then
  warn "RAG API endpoint sweep skipped — no rag-api container in project '$(ct_project)'"
else
  for entry in "${endpoints[@]}"; do
    IFS='|' read -r path label <<< "$entry"
    code=$(ct_http_code rag-api 8000 "$path" -H "x-api-key: $API_KEY")
    if [[ "$code" == "200" ]]; then
      pass "$label ($code)"
    else
      fail "$label — HTTP $code"
    fi
  done
fi

# BFF endpoints
# The dashboard serves HTTPS on container port 443 and 301-redirects plain HTTP
# to it. Probing inside the container removes the published-port guesswork this
# block used to carry (`docker port` for 443, then 80, then a hardcoded 3002
# fallback that was simply wrong on a stack publishing neither) — and, like the
# sweep above, keeps it from reaching another project's dashboard.
bff_endpoints=(
  "/api/health|BFF health"
  "/api/content-extractions?limit=1|BFF content extractions"
  "/api/content-intel/patterns|BFF content patterns"
  "/api/software|BFF software inventory"
  "/api/follow-ups?limit=1|BFF follow-ups"
)

if ! ct_cid pentest-dashboard >/dev/null 2>&1; then
  warn "BFF endpoint sweep skipped — no pentest-dashboard container in project '$(ct_project)'"
else
  for entry in "${bff_endpoints[@]}"; do
    IFS='|' read -r path label <<< "$entry"
    code=$(ct_http_code pentest-dashboard 443 "$path")
    if [[ "$code" == "200" ]]; then
      pass "$label ($code)"
    else
      fail "$label — HTTP $code"
    fi
  done
fi

# ── 5. Webhook Registration ──
echo ""
echo "=== Webhooks ==="

webhooks=$(_run_sql "SELECT name FROM webhooks ORDER BY name")
for wh in event-log dashboard-bff; do
  if echo "$webhooks" | grep -q "$wh"; then
    pass "Webhook: $wh registered"
  else
    fail "Webhook: $wh not registered"
  fi
done

# ── 6. Local Binary Files ──
echo ""
echo "=== Local Binary Files ==="

echo "  -- pd_runner/bin/ --"
for tool in httpx naabu katana tlsx ffuf; do
  if [[ -f "pd_runner/bin/$tool" ]]; then
    size=$(ls -lh "pd_runner/bin/$tool" | awk '{print $5}')
    pass "pd_runner/bin/$tool ($size)"
  else
    fail "pd_runner/bin/$tool — missing (run scripts/build-go-tools.sh)"
  fi
done

echo "  -- osint_runner/bin/ --"
for tool in subfinder dnsx httpx tlsx amass gau waybackurls gowitness massdns trufflehog; do
  if [[ -f "osint_runner/bin/$tool" ]]; then
    pass "osint_runner/bin/$tool"
  else
    fail "osint_runner/bin/$tool — missing"
  fi
done

# ── 7. New utility scripts + Vault layout ──
echo ""
echo "=== Utility scripts ==="
for s in cleanup-old-files.sh vault-seed.sh ensure_db_schema.sh build-go-tools.sh; do
  if [[ -x "scripts/$s" ]]; then
    pass "scripts/$s executable"
  elif [[ -f "scripts/$s" ]]; then
    warn "scripts/$s exists but not executable (chmod +x scripts/$s)"
  else
    fail "scripts/$s missing"
  fi
done

echo ""
echo "=== Runtime config files ==="
# db-config.json MUST be a file. docker-compose bind-mounts it into
# container-logs + pentest-dashboard; if it's missing at first `up`, Docker
# auto-creates it as a *directory*, which breaks every DB mode switch
# (_write_db_config -> IsADirectoryError). setup.sh seeds it as a file.
if [[ -f "db-config.json" ]]; then
  pass "db-config.json is a file"
elif [[ -d "db-config.json" ]]; then
  fail "db-config.json is a DIRECTORY (Docker auto-created it) — rmdir it and seed: echo '{\"mode\":\"local\"}' > db-config.json, then recreate container-logs + pentest-dashboard"
else
  warn "db-config.json missing — run ./scripts/setup.sh or seed: echo '{\"mode\":\"local\"}' > db-config.json"
fi

# Exactly one container may answer to `rag-postgres`.
#
# In remote / remote_direct mode the `rag-db-tunnel` sidecar takes that NETWORK
# ALIAS and forwards to the remote database. The local postgres claims the same
# alias, and if both run, Docker's DNS hands out both addresses: roughly half
# of all new connections land on the local server, which has no SSL, and fail
# with "server does not support SSL, but SSL was required" — a message that
# reads like a TLS misconfiguration and is actually two containers wearing one
# name.
#
# This is easy to cause by accident: `.env` sets COMPOSE_PROFILES=local-db, so
# ANY `docker compose up` in this project — even `up -d --no-deps <one service>`
# — starts rag-postgres as part of reconciling the active profile. Applying an
# env change to a single service is enough to do it.
ALIAS_OWNERS=""
for _cid in $(docker ps -q 2>/dev/null); do
  if docker inspect "$_cid" \
       --format '{{range .NetworkSettings.Networks}}{{.Aliases}}{{end}}' 2>/dev/null \
     | grep -q 'rag-postgres'; then
    ALIAS_OWNERS="${ALIAS_OWNERS} $(docker inspect "$_cid" --format '{{.Name}}' 2>/dev/null | tr -d '/')"
  fi
done
ALIAS_N=$(echo $ALIAS_OWNERS | wc -w)
if ! command -v docker >/dev/null 2>&1; then
  warn "rag-postgres alias check skipped (no docker CLI)"
elif [[ "$ALIAS_N" -eq 1 ]]; then
  pass "rag-postgres alias claimed by exactly one container ($(echo $ALIAS_OWNERS))"
elif [[ "$ALIAS_N" -eq 0 ]]; then
  warn "nothing claims the rag-postgres alias — the database is unreachable by name"
else
  fail "rag-postgres alias claimed by ${ALIAS_N} containers ($(echo $ALIAS_OWNERS)) — about half of all DB connections will fail with a misleading \"server does not support SSL\". Stop the one that should not be running: docker compose stop rag-postgres"
fi

echo ""
echo "=== Vault layout (only required if using --profile vault) ==="
for d in vault/config vault/data vault/init vault/logs; do
  if [[ -d "$d" ]]; then
    pass "$d/ exists"
  else
    warn "$d/ missing — run ./scripts/setup.sh or mkdir -p $d (only needed for vault profile)"
  fi
done
if [[ -f "vault/config/vault.hcl" ]]; then
  pass "vault/config/vault.hcl present"
else
  warn "vault/config/vault.hcl missing (only needed for vault profile)"
fi
if [[ -f "vault/init-unseal.sh" ]]; then
  pass "vault/init-unseal.sh present"
else
  warn "vault/init-unseal.sh missing (only needed for vault profile)"
fi

# ── 8. New BFF endpoints (sanity) ──
echo ""
echo "=== New API endpoints ==="
# The container ID of THIS project's dashboard, not whatever owns the name.
DASH=$(ct_cid pentest-dashboard || true)
if [[ -n "$DASH" ]]; then
  for ep in /api/settings/scan-timeouts /api/scans/limits /api/port-profiles /api/kb/prompts \
            /api/web-profiles /api/import/web-scan/formats /api/rag/service-docs \
            /api/kb/walkthrough-prompt; do
    code=$(docker exec "$DASH" curl -sk -o /dev/null -w "%{http_code}" "https://127.0.0.1${ep}" 2>/dev/null || echo "000")
    if [[ "$code" =~ ^(200|401|403)$ ]]; then
      pass "$ep responding (HTTP $code)"
    else
      fail "$ep unreachable (HTTP $code)"
    fi
  done

  # Port profiles must resolve from the mounted knowledge/ volume. `degraded`
  # means port_profiles.yaml was unreadable — the API still answers, but
  # top-1000 is unavailable, so a plain HTTP 200 check above would miss it.
  DEGRADED=$(docker exec "$DASH" curl -sk "https://127.0.0.1/api/port-profiles" 2>/dev/null \
    | grep -o '"degraded":[[:space:]]*true' || true)
  if [[ -n "$DEGRADED" ]]; then
    fail "port profiles degraded — check ./knowledge:/knowledge:ro mount on pentest-dashboard"
  else
    pass "port profiles loaded from knowledge/port_profiles.yaml"
  fi

  # Follow-on action rules also come from the knowledge/ mount. A missing or
  # malformed file does not break any endpoint — it just means NO follow-up is
  # ever suggested, which looks identical to "this output had nothing to act
  # on". Assert both that rules loaded and that none failed to parse.
  # Recommender capacity + LLM backend. Both fail SILENTLY: /next_scan returns
  # 200 from deterministic rules whether or not the LLM is usable, so a missing
  # container or an uninstalled model shows up as "fewer recommendations" rather
  # than as an error. Reported as a warning, not a failure — deterministic-only
  # is a valid way to run this.
  # ONE probe, direct. The old primary leg went through the dashboard at
  # /api/scan-recommendations/capacity -- a route NO service declares. It
  # returned {"detail":"Not Found"}, which is not empty, so the `-z` test below
  # never fired and the working fallback was unreachable. The check then warned
  # "scan-recommender may be down" about a service answering 200 with
  # engagement_scan_limit and reachable:true. A dead leg that MASKS a live one is
  # worse than a missing check: it trains the operator to ignore the output.
  #
  # CLAUDE.md: "A fallback leg is an endpoint. Verify every leg or delete it."
  # Deleted, because nothing else in the repo ever called that path.
  CAP_JSON=$(ct_exec scan-recommender curl -sk --max-time 15 \
      "https://127.0.0.1:8013/next_scan/capacity" 2>/dev/null || true)
  if ! echo "$CAP_JSON" | grep -q '"engagement_scan_limit"'; then
    # Retry over plain HTTP once: TLS on this port is the norm, but a dev
    # container may serve http and a wrong-scheme miss should not read as down.
    CAP_JSON=$(ct_exec scan-recommender curl -s --max-time 15 \
        "http://127.0.0.1:8013/next_scan/capacity" 2>/dev/null || true)
  fi
  if echo "$CAP_JSON" | grep -q '"engagement_scan_limit"'; then
    LIMIT=$(echo "$CAP_JSON" | grep -o '"engagement_scan_limit":[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
    pass "recommender bounded by engagement scan limit (${LIMIT})"
    if echo "$CAP_JSON" | grep -q '"reachable":[[:space:]]*false'; then
      warn "LLM backend unreachable — recommendations are deterministic-only: $(echo "$CAP_JSON" | grep -o '"note":[[:space:]]*"[^"]*"' | head -1)"
    elif echo "$CAP_JSON" | grep -q '"model_present":[[:space:]]*false'; then
      warn "configured LLM model is not installed — LLM recommendations fall back to rules"
    fi
  else
    warn "could not read recommender capacity (scan-recommender may be down)"
  fi

  RULES_JSON=$(docker exec "$DASH" curl -sk "https://127.0.0.1/api/artifacts/auto-queue" 2>/dev/null || true)
  RULES_N=$(echo "$RULES_JSON" | grep -o '"rules_loaded":[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
  if ! _is_num "$RULES_N" || [[ "$RULES_N" -eq 0 ]]; then
    fail "no artifact follow-on rules loaded — check knowledge/artifact_rules/builtin.yaml and the ./knowledge:/knowledge:ro mount"
  elif echo "$RULES_JSON" | grep -q '"rule_errors":[[:space:]]*\[[^]]'; then
    fail "artifact rule file has errors (those rules are not running): $(echo "$RULES_JSON" | grep -o '"rule_errors":.*')"
  else
    pass "artifact follow-on rules loaded (${RULES_N} rules)"
  fi

  WEB_DEGRADED=$(docker exec "$DASH" curl -sk "https://127.0.0.1/api/web-profiles" 2>/dev/null \
    | grep -o '"degraded":[[:space:]]*true' || true)
  if [[ -n "$WEB_DEGRADED" ]]; then
    fail "web profiles degraded — check ./knowledge:/knowledge:ro mount on pentest-dashboard"
  else
    pass "web profiles loaded from knowledge/web_profiles.yaml"
  fi

  # The merged CA bundle is what lets internal HTTPS verify instead of every
  # caller passing verify=False. If it is missing, REQUESTS_CA_BUNDLE points at a
  # nonexistent path and EVERY verifying TLS call in that container fails — a far
  # louder failure than the one it replaced, so check it explicitly.
  if [[ -f certs/ca-bundle.crt ]]; then
    bundle_n=$(grep -c "BEGIN CERTIFICATE" certs/ca-bundle.crt || echo 0)
    if [[ "$bundle_n" -gt 100 ]] && grep -q "RagScanStack internal" certs/ca-bundle.crt; then
      pass "CA bundle present (${bundle_n} certs, includes the internal cert)"
    else
      fail "certs/ca-bundle.crt looks wrong (${bundle_n} certs, internal cert marker missing) — rerun scripts/generate-ca-bundle.sh"
    fi
    if ct_cid rag-api >/dev/null 2>&1; then
      if ct_exec rag-api test -r /certs/ca-bundle.crt 2>/dev/null; then
        pass "rag-api can read /certs/ca-bundle.crt"
      else
        fail "rag-api cannot read /certs/ca-bundle.crt — REQUESTS_CA_BUNDLE points at a missing file; every verifying HTTPS call in it will fail"
      fi
    fi
  else
    fail "certs/ca-bundle.crt missing — run scripts/generate-ca-bundle.sh (services set REQUESTS_CA_BUNDLE to it)"
  fi

  # nmap_scanner resolves the SAME profile for its own empty-ports fallback, so
  # it needs the knowledge/ mount too. Without it the fallback degrades to the
  # sequential 1-1000 range — which still returns HTTP 200 and still produces
  # results, just results that miss mysql/postgresql/vnc/tomcat. Nothing else in
  # this script would catch that.
  if ct_cid nmap_scanner >/dev/null 2>&1; then
    if ct_exec nmap_scanner test -r /knowledge/port_profiles.yaml 2>/dev/null; then
      pass "nmap_scanner can read knowledge/port_profiles.yaml"
    else
      fail "nmap_scanner cannot read /knowledge/port_profiles.yaml — add ./knowledge:/knowledge:ro to the nmap_scanner volumes; its default quick scan will silently fall back to the sequential 1-1000 range"
    fi

    # The deep sweep must cover the full range. 1001-65535 was correct only while
    # the quick pass was sequential 1-1000; against the frequency-ranked top-1000
    # it leaves the low ports outside that list unscanned by either phase.
    DEEP=$(ct_exec nmap_scanner printenv DEEP_SCAN_PORTS 2>/dev/null || echo "")
    if [[ "$DEEP" == "1001-65535" ]]; then
      fail "nmap_scanner DEEP_SCAN_PORTS=1001-65535 — stale value; set DEEP_SCAN_PORTS=1-65535 in .env and recreate the container"
    else
      pass "nmap_scanner deep sweep scope = ${DEEP:-1-65535 (default)}"
    fi
  fi
fi

# ── Summary ──
echo ""
echo "=============================="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  WARN: $WARN"
echo "=============================="

if [[ $FAIL -gt 0 ]]; then
  echo ""
  echo "Some checks failed. Review the output above and fix issues."
  exit 1
else
  echo ""
  echo "All critical checks passed."
  exit 0
fi

# ── Running code vs working tree ──────────────────────────────────────────
# Most services bake their source into the image, so `docker compose restart`
# re-runs OLD code with no error. A scope fix once sat committed and believed
# live for hours while the container kept ingesting out-of-scope hosts.
echo ""
echo "🔍 Verifying containers run the current code..."
# Shared modules copied per Docker build context must stay identical. A weaker
# sanitizer in one service is a real hole, and drift here is silent: each
# service works fine in isolation.
if python3 "$(dirname "${BASH_SOURCE[0]}")/check_shared_code.py" >/dev/null 2>&1; then
  pass "shared modules consistent across services"
else
  fail "shared module drift — run: python3 scripts/check_shared_code.py --list"
fi

# Every SQL column reference must exist on the table it reads or writes.
#
# The one defect class no other guard here can catch: it passes ast.parse,
# imports fine, reports a healthy container, and 500s only when that code path
# runs. Postgres also reports only the FIRST bad column, so one fix can reveal
# the next. Its first run found 20 — including seven in one function whose
# caller logged the failure as a warning, so agents silently lost the "what we
# already know about this target" context and re-scanned covered ground.
if python3 "$(dirname "${BASH_SOURCE[0]}")/../tests/test_sql_columns.py" >/tmp/sqlcols.log 2>&1; then
  pass "SQL columns — $(grep -oE 'Checked [0-9]+' /tmp/sqlcols.log | head -1 | awk '{print $2}') reference(s) resolve against the schema"
else
  fail "SQL reference(s) name a column their table does not have:"
  grep -E '^  ✗' /tmp/sqlcols.log 2>/dev/null | head -10 || true
fi

# Every BFF proxy call must name a path some service actually declares.
#
# Static, so it runs before anything is up. 68% of BFF routes are thin proxies
# whose only real failure mode is naming a dead upstream path — and a fallback
# or a bare `except` hides that from the live sweep. Its first run found four,
# including a Burp import that reported success while storing nothing.
if python3 "$(dirname "${BASH_SOURCE[0]}")/../tests/test_proxy_contracts.py" >/tmp/proxy.log 2>&1; then
  pass "proxy contracts — $(grep -oE 'Checked [0-9]+' /tmp/proxy.log | head -1 | awk '{print $2}') call(s) resolve upstream"
else
  fail "proxy call(s) name an upstream path no service declares:"
  grep -E '^  ✗' /tmp/proxy.log 2>/dev/null | head -10 || true
fi

# Call every GET endpoint — bare and parameterised — and fail on any 5xx.
#
# ~1,150 endpoints exist and about 11% are mentioned by any test, so this sweep
# is the only thing that touches most of them. Its first run found four broken
# endpoints in two minutes — a query on a non-existent column and a set of
# routes made unreachable by declaration order. Extending it to parameterised
# GETs (ids resolved live from list endpoints) immediately found a fifth:
# /scope/{name}/analysis selected two columns that do not exist.
if python3 "$(dirname "${BASH_SOURCE[0]}")/smoke_endpoints.py" >/tmp/smoke.log 2>&1; then
  pass "endpoint smoke sweep — no 5xx ($(grep -c '200' /tmp/smoke.log 2>/dev/null || echo '?') checked)"
else
  fail "endpoint smoke sweep found failing endpoint(s):"
  grep -E '^  ✗' /tmp/smoke.log 2>/dev/null | head -10 || true
fi

if python3 "$(dirname "${BASH_SOURCE[0]}")/check_image_freshness.py"; then
    :
else
    echo "   ^ rebuild the services listed above; a restart will not help"
fi
