#!/usr/bin/env bash
# Post-install verification: checks all DB tables, Go tool binaries,
# container health, and API endpoints.
# Usage: ./scripts/post-install-check.sh

set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS] $1"; ((PASS++)); }
fail() { echo "  [FAIL] $1"; ((FAIL++)); }
warn() { echo "  [WARN] $1"; ((WARN++)); }

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
  # TIER 8: Exploit management
  pending_exploits exploit_results exploit_chunks
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
)

for table in "${EXPECTED_TABLES[@]}"; do
  result=$(docker exec rag-postgres psql -U app -d scans -tAc "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_schema='public' AND table_name='$table')" 2>/dev/null)
  if [[ "$result" == "t" ]]; then
    pass "$table"
  else
    fail "$table — table missing"
  fi
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
RULE_ROWS=$(docker exec rag-postgres psql -U app -d scans -tAc \
  "SELECT COUNT(*) FROM public.service_prompts" 2>/dev/null || echo "")
if [[ -z "$RULE_ROWS" ]]; then
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
EXPECTED_VIEWS=(detected_software)
for view in "${EXPECTED_VIEWS[@]}"; do
  result=$(docker exec rag-postgres psql -U app -d scans -tAc "SELECT EXISTS (SELECT FROM pg_views WHERE schemaname='public' AND viewname='$view')" 2>/dev/null)
  if [[ "$result" == "t" ]]; then
    pass "$view (view)"
  else
    fail "$view — view missing"
  fi
done

# Schema integrity: scope_targets must allow same target across engagements
# Works for both local (rag-postgres container) and remote DB (via rag-api shell).
echo ""
echo "  -- scope_targets schema --"
_run_sql() {
  # Tries local rag-postgres first, falls back to rag-api which has DB_DSN env.
  local sql="$1"
  if docker ps --format '{{.Names}}' | grep -q '^rag-postgres$'; then
    docker exec rag-postgres psql -U app -d scans -tAc "$sql" 2>/dev/null
  elif docker ps --format '{{.Names}}' | grep -q '^rag-api$'; then
    docker exec rag-api python3 -c "
import os, psycopg2
c = psycopg2.connect(os.environ['DB_DSN'])
cur = c.cursor(); cur.execute(\"\"\"$sql\"\"\")
r = cur.fetchone()
print('t' if (r and r[0]) else 'f')
" 2>/dev/null
  else
    echo ""
  fi
}
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
if docker ps --format '{{.Names}}' | grep -q '^rag-api$'; then
  REG_COUNT=$(docker exec rag-api sh -c 'curl -sk -H "x-api-key: $API_KEY" https://node-manager:8027/tools/registry 2>/dev/null' \
    | python3 -c "import sys,json;print(json.load(sys.stdin).get('count',0))" 2>/dev/null || echo 0)
  if [[ "${REG_COUNT:-0}" -gt 0 ]]; then
    pass "node_manager /tools/registry reachable ($REG_COUNT tools)"
  else
    warn "node_manager /tools/registry not reachable (capability checks degraded)"
  fi
  KALI_COUNT=$(docker exec rag-api sh -c 'curl -sk -H "x-api-key: $API_KEY" https://kali-listener:8019/tools/allowed 2>/dev/null' \
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

echo "  -- pd-runner --"
PD_TOOLS=(httpx naabu katana tlsx ffuf)
for tool in "${PD_TOOLS[@]}"; do
  if docker exec pd-runner which "$tool" >/dev/null 2>&1; then
    pass "pd-runner: $tool"
  else
    fail "pd-runner: $tool — binary missing (run scripts/build-go-tools.sh)"
  fi
done

echo "  -- osint-runner --"
OSINT_TOOLS=(subfinder dnsx httpx tlsx asnmap uncover cloudlist alterx mapcidr chaos shuffledns amass gau waybackurls gowitness massdns trufflehog)
for tool in "${OSINT_TOOLS[@]}"; do
  if docker exec osint-runner which "$tool" >/dev/null 2>&1; then
    pass "osint-runner: $tool"
  else
    fail "osint-runner: $tool — binary missing (run scripts/build-go-tools.sh)"
  fi
done

echo "  -- nmap-scanner --"
for tool in masscan nmap; do
  if docker exec nmap_scanner which "$tool" >/dev/null 2>&1; then
    pass "nmap-scanner: $tool"
  else
    fail "nmap-scanner: $tool — binary missing"
  fi
done

echo "  -- web-scanner --"
for tool in gobuster nikto; do
  if docker exec web-scanner which "$tool" >/dev/null 2>&1; then
    pass "web-scanner: $tool"
  else
    fail "web-scanner: $tool — binary missing"
  fi
done

echo "  -- brutus-runner --"
for tool in hydra medusa ncrack; do
  if docker exec brutus-runner which "$tool" >/dev/null 2>&1; then
    pass "brutus-runner: $tool"
  else
    warn "brutus-runner: $tool — not installed (optional)"
  fi
done

# ── 3. Container Health ──
echo ""
echo "=== Container Health ==="

CONTAINERS=(
  rag-postgres rag-api pentest-dashboard
  playwright-scanner web-scanner nmap_scanner
  pd-runner osint-runner nuclei-runner brutus-runner
  scan-recommender container-logs node-manager
)

for cname in "${CONTAINERS[@]}"; do
  status=$(docker inspect --format='{{.State.Health.Status}}' "$cname" 2>/dev/null || echo "not_found")
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

endpoints=(
  "GET|https://localhost:8000/health|RAG API health"
  "GET|https://localhost:8000/assets?limit=1|Assets endpoint"
  "GET|https://localhost:8000/software|Software inventory"
  "GET|https://localhost:8000/content-extractions?limit=1|Content extractions"
  "GET|https://localhost:8000/content-intel/patterns|Content patterns"
  "GET|https://localhost:8000/wordlists|Wordlists"
  "GET|https://localhost:8000/opsec/timeline?hours=1|OpSec timeline"
  "GET|https://localhost:8000/follow-ups?limit=1|Follow-ups"
  "GET|https://localhost:8000/health/database|Health DB schema"
  "GET|https://localhost:8000/software/cve-prompt|CVE prompt config"
  "GET|https://localhost:8000/software/vendor-pages|Vendor pages config"
  "GET|https://localhost:8000/software/ddg-jobs|AI check jobs"
)

for entry in "${endpoints[@]}"; do
  IFS='|' read -r method url label <<< "$entry"
  code=$(curl -sk -o /dev/null -w '%{http_code}' -H "x-api-key: $API_KEY" "$url" 2>/dev/null)
  if [[ "$code" == "200" ]]; then
    pass "$label ($code)"
  else
    fail "$label — HTTP $code"
  fi
done

# BFF endpoints
# The dashboard serves over HTTPS (container port 443) and 301-redirects plain
# HTTP to HTTPS, so hit the HTTPS-mapped port directly with -k. Fall back to the
# HTTP port only if no 443 mapping is published.
BFF_PORT=$(docker port pentest-dashboard 443 2>/dev/null | head -1 | sed 's/.*://')
BFF_SCHEME="https"
if [ -z "$BFF_PORT" ]; then
  BFF_PORT=$(docker port pentest-dashboard 80 2>/dev/null | head -1 | sed 's/.*://')
  BFF_SCHEME="http"
fi
BFF_PORT="${BFF_PORT:-3002}"

bff_endpoints=(
  "GET|${BFF_SCHEME}://localhost:${BFF_PORT}/api/health|BFF health"
  "GET|${BFF_SCHEME}://localhost:${BFF_PORT}/api/content-extractions?limit=1|BFF content extractions"
  "GET|${BFF_SCHEME}://localhost:${BFF_PORT}/api/content-intel/patterns|BFF content patterns"
  "GET|${BFF_SCHEME}://localhost:${BFF_PORT}/api/software|BFF software inventory"
  "GET|${BFF_SCHEME}://localhost:${BFF_PORT}/api/follow-ups?limit=1|BFF follow-ups"
)

for entry in "${bff_endpoints[@]}"; do
  IFS='|' read -r method url label <<< "$entry"
  code=$(curl -sk -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)
  if [[ "$code" == "200" ]]; then
    pass "$label ($code)"
  else
    fail "$label — HTTP $code"
  fi
done

# ── 5. Webhook Registration ──
echo ""
echo "=== Webhooks ==="

webhooks=$(docker exec rag-postgres psql -U app -d scans -tAc "SELECT name FROM webhooks ORDER BY name" 2>/dev/null)
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
DASH=$(docker ps --filter "name=^pentest-dashboard$" --format '{{.Names}}')
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
  CAP_JSON=$(docker exec "$DASH" curl -sk "https://127.0.0.1/api/scan-recommendations/capacity" 2>/dev/null || true)
  if [[ -z "$CAP_JSON" ]]; then
    CAP_JSON=$(docker exec scan-recommender curl -sk "https://127.0.0.1:8013/next_scan/capacity" 2>/dev/null || true)
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
  if [[ -z "$RULES_N" || "$RULES_N" -eq 0 ]]; then
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
    if docker ps --format '{{.Names}}' | grep -q '^rag-api$'; then
      if docker exec rag-api test -r /certs/ca-bundle.crt 2>/dev/null; then
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
  if docker ps --format '{{.Names}}' | grep -q '^nmap_scanner$'; then
    if docker exec nmap_scanner test -r /knowledge/port_profiles.yaml 2>/dev/null; then
      pass "nmap_scanner can read knowledge/port_profiles.yaml"
    else
      fail "nmap_scanner cannot read /knowledge/port_profiles.yaml — add ./knowledge:/knowledge:ro to the nmap_scanner volumes; its default quick scan will silently fall back to the sequential 1-1000 range"
    fi

    # The deep sweep must cover the full range. 1001-65535 was correct only while
    # the quick pass was sequential 1-1000; against the frequency-ranked top-1000
    # it leaves the low ports outside that list unscanned by either phase.
    DEEP=$(docker exec nmap_scanner printenv DEEP_SCAN_PORTS 2>/dev/null || echo "")
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

if python3 "$(dirname "${BASH_SOURCE[0]}")/check_image_freshness.py"; then
    :
else
    echo "   ^ rebuild the services listed above; a restart will not help"
fi
