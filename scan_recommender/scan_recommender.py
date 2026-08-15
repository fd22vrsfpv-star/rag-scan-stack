# scan_recommender.py (unified + Ollama query & health endpoints)
import os
import json
import logging
import re
import threading
from contextlib import contextmanager
from typing import Any, List, Optional, Dict, Tuple

import requests
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from fastapi import FastAPI, APIRouter, Query, HTTPException, Body, Header
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from exploits_rag import rag_router
from tool_kb import get_tool_kb, get_high_value_port_info
from tool_catalog import filter_recommendations
from log_manager import get_log_handler, setup_log_capture, LOGS_UI_HTML

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("scan-recommender")

# ---- Env ----
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://ollama:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "mistral:latest")

LLM_BACKEND = os.environ.get("LLM_BACKEND", "ollama").lower()
AZURE_ENDPOINT = os.environ.get("AZURE_ENDPOINT", "")
AZURE_API_KEY = os.environ.get("AZURE_API_KEY", "")
AZURE_MODEL = os.environ.get("AZURE_MODEL", "")
AZURE_API_VERSION = os.environ.get("AZURE_API_VERSION", "2024-08-01-preview")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
OPENAI_API_BASE = os.environ.get("OPENAI_API_BASE", "https://api.openai.com")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

DB_HOST = os.environ.get("DB_HOST", "rag-postgres")
DB_PORT = os.environ.get("DB_PORT", "5432")
DB_NAME = os.environ.get("DB_NAME", "scans")


# ---- Helpers ----
def resolve_ollama_generate_endpoint(base_url: str) -> str:
    """
    Resolve the OLLAMA generate endpoint.
    """
    u = base_url.rstrip("/")
    if u.endswith(":11434") or u in {"http://ollama:11434", "http://localhost:11434"}:
        return u + "/api/generate"
    if u.endswith("/api"):
        return u + "/generate"
    return u

def resolve_ollama_health_endpoint(base_url: str) -> str:
    """
    Resolve the OLLAMA health endpoint.
    """
    u = base_url.rstrip("/")
    if u.endswith(":11434") or u in {"http://ollama:11434", "http://localhost:11434"}:
        return u + "/api"
    if u.endswith("/api"):
        return u
    return u

DB_USER = os.environ.get("DB_USER", "app")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "app")

PERSIST_RECS = os.environ.get("PERSIST_RECS", "1").lower() in ("1", "true", "yes")

# When /next_scan finds port rows it answers from the deterministic tool_kb rules,
# which never consult service_prompts. This adds a second, LLM pass carrying the
# operator's authored guidance — but only for services that actually have a rule,
# so an install with an empty knowledge base behaves exactly as before and pays
# nothing. Set to 0 to keep recommendations purely deterministic.
HYBRID_KB_RECS = os.environ.get("HYBRID_KB_RECS", "1").lower() in ("1", "true", "yes")


# ---- DB helper ----
@contextmanager
def get_db():
    conn = psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD
    )
    try:
        yield conn
    finally:
        conn.close()


# ---- Models ----
class ScanRecommendation(BaseModel):
    scanner: str
    action: Optional[str] = None
    script: Optional[str] = None
    template: Optional[str] = None
    # Source-row context.  Stamped by generate_recommendations() so the
    # persistence path can label each rec with its OWN service/port/banner
    # instead of the batch's first-row values.  Optional in the API
    # response (callers can ignore), but lets operators see at a glance
    # which discovered port a rec was generated for.
    service: Optional[str] = None
    port: Optional[int] = None
    banner: Optional[str] = None
    # Overlap group (from the KB). Tools sharing a group return the same data;
    # the recommender keeps only one per group (an "OR").
    purpose_group: Optional[str] = None


class ScanRecommendationsResponse(BaseModel):
    recommendations: List[ScanRecommendation]


class OllamaQueryRequest(BaseModel):
    prompt: str
    model: Optional[str] = None
    stream: bool = False  # if true, we still return the full accumulated text


class OllamaQueryResponse(BaseModel):
    model: str
    response: str


class OllamaHealthResponse(BaseModel):
    ok: bool
    endpoint: str
    models: List[Dict] = []
    running: List[Dict] = []
    detail: Optional[str] = None


# ---- Safe tools constant (auto-executable, NOT MSF modules) ----
SAFE_TOOLS = {
    "nmap", "nuclei", "whatweb", "ssh-audit", "enum4linux", "showmount",
    "rpcinfo", "smbclient", "smbmap", "snmpwalk", "dig", "dnsrecon",
    "curl", "ldapsearch", "redis-cli", "snmp-check", "sslscan",
    "testssl", "sslyze", "subfinder", "dnsx", "vulnx",
}

# ---- Auto-execute config ----
KALI_LISTENER_URL = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")
AUTO_EXECUTE = os.environ.get("AUTO_EXECUTE_SAFE", "1").lower() in ("1", "true", "yes")

# ---- Webhook emit (cross-container HTTP) ----
# scan-recommender is its own container/image with no access to rag-api's
# `webhooks` package, so it emits over HTTP to rag-api's /webhooks/emit
# (same pattern as web_scanner/scan_pipeline.py).  Fire-and-forget: a
# webhook failure must never break recommendation generation.
API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "1").lower() in ("1", "true", "yes")


def _emit_webhook(event_type: str, data: Dict, severity: Optional[str] = None):
    """POST a webhook event to rag-api so external tools can subscribe."""
    if not WEBHOOK_ENABLED:
        return
    try:
        payload = {"event_type": event_type, "source": "scan_recommender",
                   "data": data or {}}
        if severity:
            payload["severity"] = severity
        requests.post(
            f"{API_BASE}/webhooks/emit", json=payload,
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=5, verify=False,
        )
    except Exception as e:
        logger.debug("webhook emit failed (%s): %s", event_type, e)


def _build_overlap_maps():
    """Build overlap-group lookups from the KB's tool_metadata.overlap_groups.

    Returns (tool_to_group, msf_globs) where tool_to_group maps a tool name to
    its group and msf_globs is a list of (group, glob) for matching metasploit
    modules (members written as "metasploit:<glob>"). Falls back to the legacy
    hardcoded groups if the KB declares none."""
    groups = get_tool_kb().get_overlap_groups()
    tool_to_group: Dict[str, str] = {}
    msf_globs: List = []  # (group, glob)
    if groups:
        for group, spec in groups.items():
            for member in (spec or {}).get("members", []) or []:
                ml = str(member).lower()
                if ml.startswith("metasploit:"):
                    msf_globs.append((group, ml.split(":", 1)[1]))
                else:
                    tool_to_group[ml] = group
    else:
        legacy = {
            "content_discovery": ["gobuster", "feroxbuster", "dirsearch", "wfuzz", "ffuf"],
            "web_vuln_scan": ["nikto", "nuclei"],
            "tech_fingerprint": ["whatweb", "wappalyzer"],
            "sql_injection": ["sqlmap"],
        }
        for group, tools in legacy.items():
            for t in tools:
                tool_to_group[t] = group
    return tool_to_group, msf_globs


def _msf_module_group(module: str, msf_globs) -> Optional[str]:
    """Match a metasploit module path against the overlap-group globs."""
    import fnmatch
    m = (module or "").lower()
    for group, glob in msf_globs:
        if fnmatch.fnmatch(m, glob):
            return group
    return None


def _kb_result_to_recommendations(kb_result: Dict) -> List[Dict]:
    """Convert ToolKnowledgeBase result into List[Dict] recommendation format.

    - Skips tools the KB classifies as non-scanners (e.g. vulnx = CVE lookup);
      those are handled by the assets software flow, not run against ports.
    - Tags each rec with its overlap purpose_group (from the KB) so overlapping
      tools (nmap -sV / ssh-audit / msf *_version, etc.) are treated as an OR."""
    tool_to_group, msf_globs = _build_overlap_maps()
    non_scanners = get_tool_kb().get_non_scanner_tools()

    recs: List[Dict] = []

    for tool in kb_result.get("tools", []):
        name = tool.get("name", "unknown").lower()
        if name in non_scanners:
            # e.g. vulnx — CVE lookup for already-detected software, not a scan.
            continue
        recs.append({
            "scanner": tool.get("name", "unknown"),
            "action": tool.get("purpose"),
            "script": tool.get("command"),
            "template": None,
            "purpose_group": tool_to_group.get(name),
        })

    # nuclei_tags → one recommendation
    tags = kb_result.get("nuclei_tags", [])
    if tags:
        recs.append({
            "scanner": "nuclei",
            "action": "template scan",
            "script": None,
            "template": ",".join(tags),
            "purpose_group": tool_to_group.get("nuclei"),
        })

    # Each metasploit[] entry
    for msf in kb_result.get("metasploit", []):
        module = msf.get("module")
        recs.append({
            "scanner": "metasploit",
            "action": msf.get("purpose"),
            "script": module,
            "template": None,
            "purpose_group": _msf_module_group(module, msf_globs),
        })

    return recs


def _get_kb_overrides(service_name: str) -> Optional[Dict]:
    """Fetch DB overlay for a service (returns None if no override)."""
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT data FROM public.kb_service_overrides WHERE service_name = %s",
                (service_name.lower(),),
            )
            row = cur.fetchone()
            return dict(row["data"]) if row else None
    except Exception:
        return None



def _get_discovered_software(ip: Optional[str] = None, limit: int = 50) -> List[Dict]:
    """Query detected_software view to get all discovered software with versions."""
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            if ip:
                # Get software for specific IP
                cur.execute("""
                    SELECT DISTINCT asset_id, ip, hostname, port, protocol,
                           product, version, source, detection_type, first_seen, last_seen
                    FROM public.detected_software
                    WHERE ip = %s AND product IS NOT NULL
                    ORDER BY first_seen DESC
                    LIMIT %s
                """, (ip, limit))
            else:
                # Get all discovered software
                cur.execute("""
                    SELECT DISTINCT asset_id, ip, hostname, port, protocol,
                           product, version, source, detection_type, first_seen, last_seen
                    FROM public.detected_software
                    WHERE product IS NOT NULL
                    ORDER BY first_seen DESC
                    LIMIT %s
                """, (limit,))
            return [dict(row) for row in cur.fetchall()]
    except Exception as e:
        logger.warning(f"Failed to query detected_software: {e}")
        return []


def _generate_vulnx_recommendations_for_software(software_list: List[Dict]) -> List[Dict]:
    """Generate vulnx recommendations for a list of discovered software."""
    recs = []
    seen_products = set()  # Deduplicate by product+version

    for software in software_list:
        product = (software.get("product") or "").strip()
        version = (software.get("version") or "").strip()
        ip = software.get("ip", "")
        source = software.get("source", "")

        if not product:
            continue

        # Create dedup key
        dedup_key = f"{product.lower()}:{version.lower()}"
        if dedup_key in seen_products:
            continue
        seen_products.add(dedup_key)

        # Build descriptive action text
        action_parts = [f"CVE research for {product}"]
        if version:
            action_parts.append(f"v{version}")
        if ip:
            action_parts.append(f"on {ip}")
        if source:
            action_parts.append(f"(detected by {source})")

        recs.append({
            "scanner": "vulnx",
            "action": " ".join(action_parts),
            "script": None,
            "template": None,
            "purpose_group": "vulnerability_research",
            "software_context": {
                "product": product,
                "version": version,
                "ip": ip,
                "source": source,
                "port": software.get("port"),
                "protocol": software.get("protocol")
            }
        })

    return recs


def _get_detected_tech(ip: Optional[str], port: Optional[int] = None) -> tuple:
    """Return (tech_tokens, source) for an IP[:port] (G1).

    Reads the tech-stack httpx/whatweb already detected and persisted to
    `recon_findings.data` (`->'tech'` array + `->>'webserver'`).  Used to
    pick CMS/framework-targeted nuclei templates.  Defensive: returns
    ([], "") on any error so recommendation generation never breaks.
    """
    if not ip:
        return [], ""
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT rf.data, rf.source
                FROM public.recon_findings rf
                JOIN public.assets a ON a.id = rf.asset_id
                WHERE host(a.ip) = %s
                  AND rf.source IN ('httpx', 'whatweb')
                  AND (%s IS NULL OR rf.data->>'port' = %s)
                ORDER BY rf.created_at DESC
                LIMIT 10
                """,
                (ip, port, str(port) if port is not None else None),
            )
            rows = cur.fetchall()
    except Exception as e:
        logger.debug(f"tech lookup skipped for {ip}: {e}")
        return [], ""

    tokens: List[str] = []
    source = ""
    for r in rows:
        data = r.get("data") or {}
        if isinstance(data, dict):
            tech = data.get("tech") or []
            if isinstance(tech, list):
                tokens.extend(str(t) for t in tech if t)
            ws = data.get("webserver")
            if ws:
                tokens.append(str(ws))
        source = source or (r.get("source") or "")
    return tokens, source


def _append_tech_targeted_recs(recs: List[Dict], ip: Optional[str],
                               port: Optional[int] = None) -> List[Dict]:
    """G1: add nuclei recs targeting the detected CMS/framework.

    Returns the list of matched tech signatures (for webhook reporting).
    Uses a tech-distinct `action` string so the rec's fingerprint differs
    from the generic service-based nuclei rec (the unique fingerprint
    excludes priority/extra, so distinct action is what avoids collision).
    """
    tokens, source = _get_detected_tech(ip, port)
    if not tokens:
        return []
    matches = get_tool_kb().match_tech_to_tags(tokens)
    for m in matches:
        tags = m.get("nuclei_tags") or []
        if not tags:
            continue
        recs.append({
            "scanner": "nuclei",
            "action": f"tech-targeted scan ({m['name']})",
            "script": None,
            "template": ",".join(tags),
            "priority": 15,
            "tech_context": {"matched": m["name"], "source": source},
        })
    return matches


def _append_high_value_port_recs(recs: List[Dict], port: Optional[int]) -> Optional[Dict]:
    """G2: prioritize + enqueue curated module for a high-value port.

    When `port` is in the curated HIGH_VALUE_PORTS intel, bump the priority
    of every rec already generated for it (lower int = runs first) and, if
    the port has a curated Metasploit module, enqueue it as its own rec.
    Returns the port info dict (for webhook reporting) or None.
    """
    if port is None:
        return None
    info = get_high_value_port_info(port)
    if not info:
        return None
    msf = info.get("msf")
    base_priority = 5 if msf else 10
    hv_ctx = {"vulns": info.get("vulns", []), "note": info.get("note", ""),
              "service": info.get("service", ""), "port": port}
    for r in recs:
        cur = r.get("priority")
        if cur is None or cur > base_priority:
            r["priority"] = base_priority
        r.setdefault("high_value", hv_ctx)
    if msf:
        recs.append({
            "scanner": "metasploit",
            "action": f"high-value port {port}: {info.get('note', '')}",
            "script": msf,
            "template": None,
            "priority": 5,
            "high_value": hv_ctx,
        })
    return info


def _enrich_and_finalize(recs: List[Dict], row: Dict, port: Optional[int],
                         ip: Optional[str]) -> List[Dict]:
    """Shared recommendation enrichment tail used by every branch of
    generate_recommendations() so G1/G2 fire consistently.

    Order matters: high-value-port handling runs LAST so it can bump the
    priority of everything already appended (tech-targeted, vulnx, etc.).
    """
    # NOTE: vulnx is a CVE-lookup for detected *software*, not a port probe.
    # It is no longer emitted as a per-port scan recommendation (that produced
    # dozens of duplicate / raw-banner "CVE lookup" recs that looked like tools
    # to run against ports). Software CVE lookups are handled by the assets
    # software flow (/software-assets + bulk-check), which keys off the
    # detected_software product/version rather than raw banners.
    _append_common_web_fallback(recs, port)
    if ip:
        _append_tech_targeted_recs(recs, ip, port)      # G1
    _append_high_value_port_recs(recs, port)            # G2 (last)
    svc = row.get("service") if isinstance(row, dict) else None
    recs = _apply_tool_feedback(recs, svc)
    return _stamp_source_context(_dedupe_overlapping(recs), row, port)


# Durable tool-selection feedback (scan_tool_feedback table). Cached briefly so
# rec generation doesn't hit the DB on every call.
_TOOL_FEEDBACK_CACHE: Dict[str, Any] = {"ts": 0.0, "rows": []}
_TOOL_FEEDBACK_TTL = 20.0  # seconds


def _invalidate_tool_feedback_cache():
    _TOOL_FEEDBACK_CACHE["ts"] = 0.0


def _get_tool_feedback() -> List[Dict]:
    """Active rows from scan_tool_feedback (cached for _TOOL_FEEDBACK_TTL)."""
    import time
    now = time.monotonic()
    if _TOOL_FEEDBACK_CACHE["rows"] and (now - _TOOL_FEEDBACK_CACHE["ts"]) < _TOOL_FEEDBACK_TTL:
        return _TOOL_FEEDBACK_CACHE["rows"]
    rows: List[Dict] = []
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT service, scanner, selector, verdict, payload "
                "FROM public.scan_tool_feedback WHERE active = true"
            )
            rows = [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.debug("tool feedback load failed: %s", e)
    _TOOL_FEEDBACK_CACHE["ts"] = now
    _TOOL_FEEDBACK_CACHE["rows"] = rows
    return rows


# ── Per-service / per-port operator prompts ────────────────────────────────
# Rows from public.service_prompts, injected into the LLM's tool-selection
# prompt whenever a matching service/port is seen.  Cached like the tool
# feedback above: this is read on every /next_scan LLM call, and the table is
# small and changes rarely.
_SERVICE_PROMPT_CACHE: Dict[str, Any] = {"ts": 0.0, "rows": []}
_SERVICE_PROMPT_TTL = 60.0  # seconds


def _invalidate_service_prompt_cache():
    _SERVICE_PROMPT_CACHE["ts"] = 0.0


def _get_all_service_prompts() -> List[Dict]:
    """All enabled service_prompts rows (cached for _SERVICE_PROMPT_TTL)."""
    import time
    now = time.monotonic()
    if _SERVICE_PROMPT_CACHE["rows"] and (now - _SERVICE_PROMPT_CACHE["ts"]) < _SERVICE_PROMPT_TTL:
        return _SERVICE_PROMPT_CACHE["rows"]
    rows: List[Dict] = []
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                # `tags` is selected because /kb/web-guidance turns operator
                # tags into suggested nuclei templates.
                "SELECT id::text, selector_type, service, tech, port, title, prompt, "
                "       tags, priority, engagement_id::text "
                "  FROM public.service_prompts "
                # A rule is useful if it carries prompt text OR tags: a
                # tags-only rule contributes nuclei templates via
                # /kb/web-guidance without adding anything to the LLM prompt.
                " WHERE enabled = true "
                "   AND (prompt <> '' OR coalesce(array_length(tags, 1), 0) > 0)"
            )
            rows = [dict(r) for r in cur.fetchall()]
    except Exception as e:
        # Table missing (pre-migration) or DB down — degrade to no guidance
        # rather than breaking recommendation generation.
        logger.debug("service prompt load failed: %s", e)
    _SERVICE_PROMPT_CACHE["ts"] = now
    _SERVICE_PROMPT_CACHE["rows"] = rows
    return rows


# Specificity ranking — lower sorts first, so the most specific rule leads.
# `tech` sits between port_service and port: knowing the target runs WordPress
# is more actionable than knowing the port number, but less specific than an
# exact (service, port) match the operator wrote for this engagement.
_SELECTOR_RANK = {"port_service": 0, "tech": 1, "port": 2, "service": 3}


def _canonical_service(name: Optional[str]) -> Optional[str]:
    """Fold a service name to its canonical form, or None.

    Rules drafted from a walkthrough carry the vocabulary of the document —
    "Samba", "Postgres" — while scanners report what they fingerprint:
    `netbios-ssn`, `microsoft-ds`. Matching those raw strings meant an ingested
    rule could never fire on a real scan: a `samba` rule sat unused while every
    SMB port on the target was reported as `netbios-ssn`.

    tool_kb already maintains the alias table for exactly this
    (`microsoft-ds` -> `smb`, `netbios-ssn` -> `smb`, `samba` -> `smb`); it was
    simply never applied here. Folding BOTH sides means a rule and a scan result
    meet on canonical ground regardless of which vocabulary each came from.

    Falls back to the lowercased name when tool_kb is unavailable, which keeps
    exact matching working rather than dropping guidance entirely.
    """
    s = (name or "").strip().lower()
    if not s:
        return None
    try:
        # Module-level helper, not a method on the KB object — importing it
        # lazily keeps this usable even if the KB YAML fails to load.
        from tool_kb import _normalize_service_name
        return _normalize_service_name(s) or s
    except Exception:
        return s


def _get_service_prompts(
    service: Optional[str],
    port: Optional[int],
    engagement_id: Optional[str] = None,
    tech: Optional[List[str]] = None,
) -> List[Dict]:
    """Prompts matching (service, port, tech), most specific first.

    Precedence: port_service → tech → port → service.  Within a tier,
    engagement-scoped rows precede global ones, then lower `priority` wins.
    All matches are returned (not just the best) so a broad "all http" rule and
    a narrow "http on 8080" rule compose rather than one silently shadowing the
    other.

    `tech` is the list of technologies detected on the target (wordpress,
    tomcat, …) — see _get_detected_tech.  This is what lets operator training
    data steer WEB scans, where the useful signal is what's running, not which
    port it's on.
    """
    svc = _canonical_service(service)
    tech_set = {t.strip().lower() for t in (tech or []) if t and t.strip()}
    matches: List[Dict] = []
    for row in _get_all_service_prompts():
        # Engagement-scoped rows apply only to their engagement.
        row_eid = row.get("engagement_id")
        if row_eid and row_eid != engagement_id:
            continue
        sel = row.get("selector_type")
        row_svc = _canonical_service(row.get("service"))
        row_tech = (row.get("tech") or "").strip().lower() or None
        row_port = row.get("port")
        if sel == "port_service":
            if svc and row_svc == svc and port and row_port == port:
                matches.append(row)
        elif sel == "tech":
            if row_tech and row_tech in tech_set:
                matches.append(row)
        elif sel == "port":
            if port and row_port == port:
                matches.append(row)
        elif sel == "service":
            if svc and row_svc == svc:
                matches.append(row)
    matches.sort(key=lambda r: (
        _SELECTOR_RANK.get(r.get("selector_type"), 9),
        0 if r.get("engagement_id") else 1,   # engagement-specific first
        r.get("priority") if r.get("priority") is not None else 100,
        r.get("title") or "",
    ))
    return matches


def _build_guidance_block(
    service: Optional[str],
    port: Optional[int],
    engagement_id: Optional[str] = None,
    tech: Optional[List[str]] = None,
) -> str:
    """Operator guidance for this (service, port, tech), or '' when none applies.

    Returning '' when there are no rows keeps the LLM prompt byte-identical to
    its pre-feature form, so existing behaviour is unchanged until an operator
    actually authors a rule.
    """
    rows = [r for r in _get_service_prompts(service, port, engagement_id, tech)
            if (r.get("prompt") or "").strip()]
    if not rows:
        return ""
    lines = [
        "",
        "SERVICE-SPECIFIC GUIDANCE (operator-authored — this OVERRIDES the general rules above):",
    ]
    for r in rows:
        scope = {
            "port_service": f"{r.get('service')} on port {r.get('port')}",
            "tech": f"technology {r.get('tech')}",
            "port": f"port {r.get('port')}",
            "service": f"service {r.get('service')}",
        }.get(r.get("selector_type"), "match")
        lines.append(f"- [{scope}] {r.get('title')}: {(r.get('prompt') or '').strip()}")
    return "\n".join(lines)


def _get_training_context(service: Optional[str], port: Optional[int], top_k: int = 3,
                          tech: Optional[List[str]] = None) -> str:
    """Retrieved per-service/port/tech training documents, or '' when unavailable.

    Uses the scoped retrieval added to exploits_rag._retrieve. Best-effort: the
    embedder being down must not break recommendation generation.
    """
    tech_list = [t for t in (tech or []) if t]
    if not service and not port and not tech_list:
        return ""
    try:
        from exploits_rag import _embed, _retrieve, TRAINING_SOURCE_REPO
        query = " ".join(filter(None, [
            service or "", f"port {port}" if port else "",
            " ".join(tech_list), "penetration testing methodology",
        ])).strip()
        hits = _retrieve(
            _embed(query), top_k,
            service=service, port=port, tech=tech_list or None,
            source_repos=[TRAINING_SOURCE_REPO],
        )
    except Exception as e:
        logger.debug("training context retrieval failed: %s", e)
        return ""
    if not hits:
        return ""
    lines = ["", "TRAINING CONTEXT (operator-provided knowledge for this service/port):"]
    for h in hits:
        header = h.get("section_header") or h.get("title") or "note"
        lines.append(f"- [{header}] {(h.get('chunk') or '')[:600].strip()}")
    return "\n".join(lines)


def _apply_tool_feedback(recs: List[Dict], service: Optional[str]) -> List[Dict]:
    """Apply suppress / add_overlap / add_tool policies to a service's recs.

    Two sources, combined: the KB's stable suppress rules (tool_metadata.suppress
    in service_tools.yaml — ships in git, reloads) and the DB feedback loop
    (scan_tool_feedback — per-install/ad-hoc). Rows with service=None apply to
    every service. (KB overlap_groups are handled separately in _build_overlap_maps.)
    """
    import fnmatch
    # KB suppress rules → same shape as feedback rows (verdict='suppress').
    kb_suppress = [
        {"verdict": "suppress", "scanner": r.get("scanner"),
         "service": r.get("service"), "selector": r.get("selector")}
        for r in get_tool_kb().get_suppress_rules()
    ]
    fb = kb_suppress + _get_tool_feedback()
    if not fb:
        return recs
    svc = (service or "").lower()

    def _scope_ok(f) -> bool:
        return not f.get("service") or f["service"].lower() == svc

    def _matches(f, rec) -> bool:
        sc = (f.get("scanner") or "").lower()
        if sc and (rec.get("scanner") or "").lower() != sc:
            return False
        sel = f.get("selector")
        if sel and not fnmatch.fnmatch((rec.get("script") or "").lower(), sel.lower()):
            return False
        return True

    # add_overlap: retag matching recs into a group (so dedup collapses them).
    for f in fb:
        if f["verdict"] != "add_overlap" or not _scope_ok(f):
            continue
        group = (f.get("payload") or {}).get("group")
        if group:
            for r in recs:
                if _matches(f, r):
                    r["purpose_group"] = group

    # suppress: drop matching recs.
    recs = [
        r for r in recs
        if not any(f["verdict"] == "suppress" and _scope_ok(f) and _matches(f, r) for f in fb)
    ]

    # add_tool: inject a tool rec for this service (deduped by name+command).
    have = {((r.get("scanner") or "").lower(), r.get("script") or "") for r in recs}
    for f in fb:
        if f["verdict"] != "add_tool" or not _scope_ok(f):
            continue
        p = f.get("payload") or {}
        name = p.get("name")
        if not name:
            continue
        key = (name.lower(), p.get("command") or "")
        if key in have:
            continue
        recs.append({
            "scanner": name,
            "action": p.get("action"),
            "script": p.get("command"),
            "template": None,
            "purpose_group": p.get("purpose_group"),
        })
        have.add(key)

    return recs


def _dedupe_overlapping(recs: List[Dict]) -> List[Dict]:
    """Collapse overlapping recommendations to one per purpose_group (an "OR").

    Tools/modules tagged with the same purpose_group (e.g. nmap -sV and the
    metasploit *_version modules) return the same data, so only the first
    (highest-priority) one is kept. Untagged recs are always kept."""
    seen_groups = set()
    out: List[Dict] = []
    for rec in recs:
        group = rec.get("purpose_group")
        if group:
            if group in seen_groups:
                continue
            seen_groups.add(group)
        out.append(rec)
    return out


# ---- Rules ----
# Ports that look like HTTP even when nmap can't fingerprint the service.
# When the port row has service=null/unknown AND port is in this set, the
# generator appends an httpx rec so the recon agent's KB-drain phase probes
# the port.  httpx confirms whether it's HTTP, fills banner+title, and on
# the NEXT ingest the KB lookup picks up the full web toolchain.  Without
# this fallback an `nmap tcpwrapped`/`unknown` finding on 8443 would emit
# only a generic nmap banner rec and the agent would never reach the port
# with web tooling.
COMMON_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8008, 8888, 3000, 5000, 9000, 9090, 4443, 9443}
COMMON_HTTPS_PORTS = {443, 8443, 4443, 9443}


def _append_common_web_fallback(recs: List[Dict], port: Optional[int]):
    """Append an httpx rec for HTTP-likely ports when no httpx rec exists.

    Idempotent: if a KB lookup already emitted httpx (e.g. service was
    fingerprinted as http/https), do nothing.  Otherwise append a
    minimal httpx command that does fingerprint + tech detect + status
    code, so the recon agent's KB-drain phase has something to dispatch
    against unfingerprinted web ports.
    """
    if port is None or port not in COMMON_WEB_PORTS:
        return
    if any((r.get("scanner") or "").lower() == "httpx" for r in recs):
        return
    scheme = "https" if port in COMMON_HTTPS_PORTS else "http"
    recs.append({
        "scanner": "httpx",
        "action": "fingerprint + tech detect (port-based fallback)",
        "script": (
            f"httpx -u {scheme}://{{target}}:{{port}} -title -tech-detect "
            "-status-code -web-server -follow-redirects"
            + (" -tls-probe" if scheme == "https" else "")
        ),
        "template": None,
    })


def _stamp_source_context(recs: List[Dict], row: Dict, port: Optional[int]) -> List[Dict]:
    """Stamp each generated rec with its source row's service/port/banner.

    Without this, the /next_scan handler's batch persist call assigns
    `rows[0].service` to every persisted rec -- a port-53 lookup and a
    port-80 lookup in the same call both end up labeled with whichever
    came first.  `setdefault` ensures we don't overwrite if a helper
    (e.g. _append_common_web_fallback) deliberately set its own context.
    """
    row_service = row.get("service")
    row_banner = row.get("banner")
    for r in recs:
        r.setdefault("service", row_service)
        r.setdefault("port", port)
        r.setdefault("banner", row_banner)
    return recs


def generate_recommendations(row: Dict, port: Optional[int] = None, ip: Optional[str] = None) -> List[Dict]:
    service = (row.get("service") or "").lower()
    kb = get_tool_kb()

    # Try DB override first
    override = _get_kb_overrides(service) if service else None
    if override:
        # Build a KB-style result from the override data
        kb_result = {
            "tools": override.get("tools", []),
            "nuclei_tags": override.get("nuclei_tags", []),
            "metasploit": override.get("metasploit", []),
        }
        recs = _kb_result_to_recommendations(kb_result)
        if recs:
            return _enrich_and_finalize(recs, row, port, ip)

    # Try YAML KB
    kb_result = kb.get_tools_for_service(service=service, port=port)
    if not kb_result.get("error"):
        recs = _kb_result_to_recommendations(kb_result)
        if recs:
            return _enrich_and_finalize(recs, row, port, ip)

    # Fallback to old 3-rule logic
    recs: List[Dict] = []
    if service == "http":
        recs.append({"scanner": "nmap", "action": None, "script": "http-title", "template": None})
        recs.append({"scanner": "nuclei", "action": None, "script": None, "template": "cves/2023/*"})
    elif service == "ssh":
        recs.append({"scanner": "nmap", "action": None, "script": "ssh2-enum-algos", "template": None})
    else:
        recs.append({"scanner": "nmap", "action": None, "script": "banner", "template": None})

    return _enrich_and_finalize(recs, row, port, ip)


def _dispatch_auto_execute(ip: str, service: str, port: int):
    """Fire-and-forget call to kali-listener's /tools/execute-recommended."""
    try:
        resp = requests.post(
            f"{KALI_LISTENER_URL}/tools/execute-recommended",
            params={"target": ip, "service": service, "port": str(port)},
            timeout=10,
            verify=False,
        )
        logger.info(f"Auto-execute dispatch for {ip}:{port}/{service} → {resp.status_code}")
    except Exception as e:
        logger.warning(f"Auto-execute dispatch failed for {ip}:{port}/{service}: {e}")


# ---- Persistence ----
def persist_recommendations(
    ip: str,
    recs: List[Dict[str, Optional[str]]],
    *,
    asset_id: Optional[int] = None,
    service: Optional[str] = None,
    banner: Optional[str] = None,
    source: str = "ollama",
    model: Optional[str] = None,
    extra: Optional[Dict] = None,
    engagement_id: Optional[str] = None,
) -> int:
    """Insert scan_recommendations rows for the given IP.

    `asset_id` resolution: callers historically passed `asset_id=None`
    (the /next_scan handler is a notable example -- it has the IP but
    not the asset PK).  That left every persisted rec with a NULL FK,
    which breaks any downstream consumer that joins through assets
    (e.g. the recon agent's Phase 4 engagement scoping).  When
    asset_id is None and ip is provided, look it up from assets so
    the FK is populated.  Picks the most-recently-updated row to be
    deterministic when multiple assets share an IP across engagements.
    """
    if not recs:
        return 0

    inserted = 0
    with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Resolve asset_id from IP if the caller didn't have it.  Cheap
        # one-shot lookup; persisting recs without the FK link silently
        # breaks the recon agent's KB-drain queue scoping.  Wrapped in a
        # SAVEPOINT so a lookup error (missing column, type mismatch)
        # doesn't poison the surrounding transaction and abort the
        # subsequent INSERTs.
        if asset_id is None and ip:
            cur.execute("SAVEPOINT asset_lookup")
            try:
                cur.execute(
                    "SELECT id, engagement_id FROM public.assets WHERE host(ip)=%s "
                    "ORDER BY last_seen DESC NULLS LAST, first_seen DESC NULLS LAST "
                    "LIMIT 1",
                    (ip,),
                )
                row = cur.fetchone()
                if row:
                    asset_id = row["id"]
                    # Derive engagement scope from the asset when the caller
                    # didn't pass one, so the rec is engagement-filterable.
                    if engagement_id is None:
                        engagement_id = row.get("engagement_id")
                cur.execute("RELEASE SAVEPOINT asset_lookup")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT asset_lookup")
                logger.debug(f"asset_id resolution skipped for {ip}: {e}")
        elif asset_id is not None and engagement_id is None:
            # Caller gave us the asset PK but not the engagement; look it up so
            # the persisted rec carries its engagement scope.
            cur.execute("SAVEPOINT eng_lookup")
            try:
                cur.execute(
                    "SELECT engagement_id FROM public.assets WHERE id=%s", (asset_id,)
                )
                row = cur.fetchone()
                if row:
                    engagement_id = row.get("engagement_id")
                cur.execute("RELEASE SAVEPOINT eng_lookup")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT eng_lookup")
                logger.debug(f"engagement_id resolution skipped for asset {asset_id}: {e}")

        for rec in recs:
            # Per-rec service/banner/port (stamped by
            # _stamp_source_context in generate_recommendations) take
            # priority over the batch-level fallbacks.  Without this,
            # every rec in a multi-port /next_scan call gets the first
            # row's service value -- a port-53 dig finding and a port-80
            # httpx finding both end up labeled "domain".  Port goes
            # into `extra.port` since the table has no port column.
            rec_service = rec.get("service") or service
            rec_banner = rec.get("banner") or banner
            rec_port = rec.get("port")
            rec_extra = dict(extra or {})
            if rec_port is not None:
                rec_extra.setdefault("port", rec_port)
            # Carry G1/G2 context through into extra so it survives even
            # though the unique `fingerprint` excludes priority/extra.
            if rec.get("tech_context"):
                rec_extra["tech_context"] = rec["tech_context"]
            if rec.get("high_value"):
                rec_extra["high_value"] = rec["high_value"]
            if rec.get("software_context"):
                rec_extra.setdefault("software_context", rec["software_context"])
            # priority: NULL → DB default (50) via COALESCE.  Lower runs first.
            rec_priority = rec.get("priority")

            cur.execute(
                """
                INSERT INTO public.scan_recommendations
                  (asset_id, ip, service, banner, scanner, action, script, template, source, model, extra, priority, engagement_id)
                VALUES
                  (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s, 50), %s)
                ON CONFLICT (fingerprint) DO NOTHING
                RETURNING id;
                """,
                (
                    asset_id, ip, rec_service, rec_banner,
                    rec.get("scanner"), rec.get("action"),
                    rec.get("script"), rec.get("template"),
                    source, model,
                    Json(rec_extra) if rec_extra else None,
                    rec_priority,
                    engagement_id,
                ),
            )
            if cur.rowcount > 0:
                inserted += 1
        conn.commit()
    return inserted


# ---- Ollama primitives ----
def _ollama_streamed_generate(prompt: str, model: str, endpoint: str,
                              timeout: Optional[int] = None,
                              options: Optional[Dict] = None) -> str:
    def _stream(use_format_json: bool) -> str:
        payload = {"model": model, "prompt": prompt, "stream": True}
        if use_format_json:
            payload["format"] = "json"
        if options:
            payload["options"] = options
        out = ""
        with requests.post(endpoint, json=payload, stream=True, timeout=(timeout or 120)) as r:
            r.raise_for_status()
            for line in r.iter_lines():
                if not line:
                    continue
                chunk = json.loads(line.decode("utf-8"))
                # Ollama streams {"response": "..."} lines; could also have "done": true
                if "response" in chunk:
                    out += chunk["response"]
                if chunk.get("done"):
                    break
        return out

    full = _stream(True)
    if full.strip():
        return full

    # Reasoning models (the qwen3 family) stream their chain of thought in a
    # separate "thinking" field, and combining that with format=json makes Ollama
    # emit an EMPTY response — 8 chunks, no content, done_reason=stop. The caller
    # then sees "returned non-JSON payload" and the whole recommendation is lost.
    # Measured: qwen3.6 produced 0 recommendations across 6 services this way,
    # while the same model without format=json returned clean, valid JSON.
    #
    # Retrying unconstrained costs one extra call only for models that fail the
    # first form. Dropping the constraint means the model MAY wrap its JSON in
    # prose, so callers parse with _extract_json_object rather than json.loads.
    logger.warning(
        "Model %r returned an empty response with format=json (typical of "
        "reasoning models) — retrying without the format constraint", model,
    )
    return _stream(False)


def _ollama_nonstream_generate(prompt: str, model: str, endpoint: str,
                               timeout: Optional[int] = None,
                               options: Optional[Dict] = None) -> str:
    payload = {"model": model, "prompt": prompt, "format": "json", "stream": False}
    if options:
        payload["options"] = options
    with requests.post(endpoint, json=payload, timeout=(timeout or 120)) as r:
        r.raise_for_status()
        data = r.json()
        # Non-stream returns an object with "response"
        return data.get("response", "")


def _azure_chat_url(endpoint: str, model: str, api_version: str) -> str:
    """Build Azure chat completions URL based on endpoint pattern."""
    base = endpoint.rstrip("/")
    if ".models.ai.azure.com" in base:
        # AI Foundry serverless — OpenAI-compatible
        return f"{base}/v1/chat/completions"
    # Azure OpenAI
    return f"{base}/openai/deployments/{model}/chat/completions?api-version={api_version}"


def _azure_headers() -> Dict[str, str]:
    return {"api-key": AZURE_API_KEY, "Content-Type": "application/json"}


def _azure_generate(prompt: str, json_mode: bool = False,
                    timeout: Optional[int] = None) -> str:
    """Call Azure chat completions and return the assistant message content."""
    url = _azure_chat_url(AZURE_ENDPOINT, AZURE_MODEL, AZURE_API_VERSION)
    payload: Dict[str, Any] = {
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 2048,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    r = requests.post(url, json=payload, headers=_azure_headers(), timeout=(timeout or 120))
    r.raise_for_status()
    data = r.json()
    return data["choices"][0]["message"]["content"]


def _openai_headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}


def _openai_generate(prompt: str, json_mode: bool = False,
                     timeout: Optional[int] = None) -> str:
    """Call OpenAI chat completions and return the assistant message content."""
    url = f"{OPENAI_API_BASE.rstrip('/')}/v1/chat/completions"
    payload: Dict[str, Any] = {
        "model": OPENAI_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 2048,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    r = requests.post(url, json=payload, headers=_openai_headers(), timeout=(timeout or 120))
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _anthropic_headers() -> Dict[str, str]:
    return {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }


def _anthropic_generate(prompt: str, timeout: Optional[int] = None) -> str:
    """Call Anthropic messages API and return the text content."""
    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    }
    r = requests.post("https://api.anthropic.com/v1/messages",
                      json=payload, headers=_anthropic_headers(), timeout=(timeout or 120))
    r.raise_for_status()
    data = r.json()
    for block in data.get("content", []):
        if block.get("type") == "text":
            return block["text"]
    return ""


def _extract_json_object(text: str) -> Optional[Dict]:
    """The first JSON object in `text`, or None.

    Needed because the format=json constraint has to be dropped for reasoning
    models (see _ollama_streamed_generate), and an unconstrained model may wrap
    its JSON in prose or a ```json fence. Strict json.loads then fails on output
    that is perfectly usable.

    Scans for a balanced {...} rather than regex-matching, so a nested object
    does not truncate at the first closing brace.
    """
    if not text:
        return None
    s = text.strip()
    # Strip a markdown fence if present — common when the constraint is dropped.
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    start = s.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(s)):
            c = s[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(s[start:i + 1])
                    except json.JSONDecodeError:
                        break          # malformed; try the next candidate
        start = s.find("{", start + 1)
    return None


def _safe_json_parse(text: str) -> Dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Return as plain text wrapped in JSON if not valid JSON
        return {"response": text}


def ollama_query(prompt: str, model: Optional[str] = None, stream: bool = False,
                 timeout: Optional[int] = None, options: Optional[Dict] = None) -> Dict:
    """Query the configured LLM backend.

    `options` is Ollama-specific (num_ctx / num_predict). Ollama's defaults
    silently truncate BOTH a long prompt and a long structured response, which
    is why the walkthrough converter passes generous values — without them a
    20KB guide produced zero rules with no error. Ignored by the hosted
    backends, which manage their own limits.
    """
    if LLM_BACKEND == "azure":
        mdl = AZURE_MODEL or "gpt-4o"
        try:
            text = _azure_generate(prompt, timeout=timeout)
        except requests.RequestException as e:
            logger.error(f"Azure query failed: {e}")
            raise
        data = _safe_json_parse(text)
        if "recommendations" in data:
            return {"model": mdl, "response": json.dumps(data)}
        return {"model": mdl, "response": data.get("response", text)}

    if LLM_BACKEND == "openai":
        mdl = OPENAI_MODEL
        try:
            text = _openai_generate(prompt, timeout=timeout)
        except requests.RequestException as e:
            logger.error(f"OpenAI query failed: {e}")
            raise
        data = _safe_json_parse(text)
        if "recommendations" in data:
            return {"model": mdl, "response": json.dumps(data)}
        return {"model": mdl, "response": data.get("response", text)}

    if LLM_BACKEND == "anthropic":
        mdl = ANTHROPIC_MODEL
        try:
            text = _anthropic_generate(prompt, timeout=timeout)
        except requests.RequestException as e:
            logger.error(f"Anthropic query failed: {e}")
            raise
        data = _safe_json_parse(text)
        if "recommendations" in data:
            return {"model": mdl, "response": json.dumps(data)}
        return {"model": mdl, "response": data.get("response", text)}

    mdl = model or OLLAMA_MODEL
    endpoint = resolve_ollama_generate_endpoint(OLLAMA_BASE_URL)

    try:
        text = (_ollama_streamed_generate(prompt, mdl, endpoint, timeout=timeout, options=options)
                if stream else
                _ollama_nonstream_generate(prompt, mdl, endpoint, timeout=timeout, options=options))
    except requests.HTTPError as e:
        # Retry once with normalized endpoint if 405
        if e.response is not None and e.response.status_code == 405:
            endpoint = resolve_ollama_generate_endpoint(OLLAMA_BASE_URL)
            text = (_ollama_streamed_generate(prompt, mdl, endpoint, timeout=timeout) if stream
                else _ollama_nonstream_generate(prompt, mdl, endpoint, timeout=timeout))
        else:
            logger.error(f"HTTP error while querying Ollama: {e.response.status_code} - {e.response.reason}")
            raise
    except requests.RequestException as e:
        logger.error(f"Request failed while querying Ollama: {e}")
        raise

    # Try to parse as JSON (since we asked model to return JSON); if not, fallback to raw text
    data = _safe_json_parse(text)
    # If the model produced {"recommendations": ...}, return as-is; otherwise unify to {"response": "..."}
    if "recommendations" in data:
        return {"model": mdl, "response": json.dumps(data)}  # return the JSON object as string
    return {"model": mdl, "response": data.get("response", text)}


def _merge_kb_recs(rule_recs: List[Dict], llm_recs: List[Dict],
                   seen_keys: set) -> List[Dict]:
    """LLM recommendations that genuinely add to the rule-based ones.

    Two kinds of duplicate have to go:

    1. Exact repeats, caught by the same (scanner, action, script, template) key
       the rules path already uses — `seen_keys` is mutated so the caller's set
       stays authoritative.
    2. *Bare* recommendations — a scanner named with no action, script or
       template — when the rules already produced that scanner WITH specifics.
       "snmpwalk" adds nothing next to "snmpwalk -v2c -c public", but the
       exact-match key misses it because null != the populated script. This was
       observed on the first real run: the model returned bare `snmpwalk` and
       `onesixtyone` alongside the rules' fully-formed versions.

    A bare rec for a scanner the rules did NOT suggest is kept — that is the LLM
    contributing a tool the static KB does not know about, which is the point.
    """
    rule_scanners = {r.get("scanner") for r in rule_recs if r.get("scanner")}
    kept: List[Dict] = []
    for rec in llm_recs:
        bare = not any(rec.get(f) for f in ("action", "script", "template"))
        if bare and rec.get("scanner") in rule_scanners:
            continue
        key = (rec.get("scanner"), rec.get("action"),
               rec.get("script"), rec.get("template"), "", "")
        if key in seen_keys:
            continue
        seen_keys.add(key)
        kept.append(rec)
    return kept


def fetch_ollama_recommendations(
    ip: str, service: Optional[str], banner: Optional[str], model: str = OLLAMA_MODEL,
    port: Optional[int] = None, engagement_id: Optional[str] = None,
) -> List[Dict[str, str]]:
    # Operator-authored guidance and training documents for this target. Tech is
    # read from what httpx/whatweb already detected, so a "wordpress" rule fires
    # on a WordPress host without the operator naming the port. All return "" when
    # nothing matches, leaving the prompt byte-identical to its pre-feature form.
    tech_tokens, _tech_src = _get_detected_tech(ip, port)
    guidance = _build_guidance_block(service, port, engagement_id, tech_tokens)
    training = _get_training_context(service, port, tech=tech_tokens)

    prompt = f"""
Return ONLY a compact JSON object with this exact shape:

{{
  "recommendations": [
    {{"scanner":"nmap","action":null,"script":"ssh2-enum-algos","template":null}}
  ]
}}

Rules:
- No prose. No markdown. Only the JSON object.
- Use null for missing fields.
- Base suggestions on:
  ip: {ip!r}
  service: {service!r}
  port: {port!r}
  banner: {banner!r}
- Prefer practical web and service probes (nmap scripts, nuclei templates, ZAP actions).
- Do NOT recommend vulnx (or any CVE-lookup tool). vulnx is NOT a scanner — it
  only looks up CVEs for an already-detected product+version and runs via the
  assets software flow, never as a port/service probe.
- Tools that return the same data are redundant; recommend only ONE per group:
  version detection (nmap -sV / ssh-audit / metasploit *_version),
  content discovery (gobuster / feroxbuster / dirsearch / ffuf / wfuzz),
  web vuln scan (nikto / nuclei), tech fingerprint (whatweb / wappalyzer),
  login brute force (hydra / medusa / ncrack / metasploit *_login).
{guidance}
{training}
"""
    if guidance or training:
        logger.info(
            "LLM prompt augmented for %s:%s — guidance=%dch, training=%dch",
            service, port, len(guidance), len(training),
        )
    if LLM_BACKEND == "azure":
        try:
            text = _azure_generate(prompt.strip(), json_mode=True)
        except requests.RequestException as e:
            logger.error(f"Azure recommendation query failed: {e}")
            raise HTTPException(status_code=502, detail=f"Azure LLM service unavailable: {e}")
    elif LLM_BACKEND == "openai":
        try:
            text = _openai_generate(prompt.strip(), json_mode=True)
        except requests.RequestException as e:
            logger.error(f"OpenAI recommendation query failed: {e}")
            raise HTTPException(status_code=502, detail=f"OpenAI LLM service unavailable: {e}")
    elif LLM_BACKEND == "anthropic":
        try:
            text = _anthropic_generate(prompt.strip())
        except requests.RequestException as e:
            logger.error(f"Anthropic recommendation query failed: {e}")
            raise HTTPException(status_code=502, detail=f"Anthropic LLM service unavailable: {e}")
    else:
        endpoint = resolve_ollama_generate_endpoint(OLLAMA_BASE_URL)
        try:
            # stream to assemble the full JSON emitted by the model
            text = _ollama_streamed_generate(prompt.strip(), model, endpoint)
        except requests.HTTPError as e:
            logger.error(f"HTTP error while querying Ollama: {e.response.status_code} - {e.response.reason}")
            raise HTTPException(status_code=502, detail=f"Ollama service unavailable: {e}")
        except requests.RequestException as e:
            logger.error(f"Request failed while querying Ollama: {e}")
            raise HTTPException(status_code=502, detail=f"Ollama service unavailable: {e}")

    try:
        data = _extract_json_object(text)
        if data is None:
            raise json.JSONDecodeError("no JSON object found", text or "", 0)
        recs = data.get("recommendations", [])
        return [{
            "scanner": rec.get("scanner"),
            "action": rec.get("action"),
            "script": rec.get("script"),
            "template": rec.get("template"),
        } for rec in recs]
    except json.JSONDecodeError:
        logger.error(f"Ollama returned non-JSON payload: {text[:400]}...")
        raise HTTPException(status_code=502, detail="Ollama returned invalid JSON")


# ---- FastAPI ----
app = FastAPI(title="Scan Recommender")
router = APIRouter()
# added to include the python for searchsploit
app.include_router(rag_router)


@app.on_event("startup")
async def startup_event():
    """
    Initialize RAG schema and log capture on startup.
    Creates exploit_chunks table if it doesn't exist.
    """
    # Initialize log capture for exploitdb operations
    setup_log_capture()
    logger.info("Scan recommender service starting up...")

    try:
        with get_db() as conn, conn.cursor() as cur:
            # Ensure vector extension
            cur.execute("CREATE EXTENSION IF NOT EXISTS vector")

            # Check if table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_name = 'exploit_chunks'
                )
            """)
            table_exists = cur.fetchone()[0]

            if not table_exists:
                logger.info("Creating exploit_chunks table...")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS exploit_chunks (
                        id BIGSERIAL PRIMARY KEY,
                        edb_id INTEGER,
                        title TEXT,
                        path TEXT,
                        platform TEXT,
                        type TEXT,
                        source_repo TEXT,
                        published DATE,
                        chunk_id INTEGER,
                        chunk TEXT,
                        embedding vector(768),
                        sha256 TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                        UNIQUE (edb_id, chunk_id)
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS exploit_chunks_edb_idx ON exploit_chunks(edb_id)")
                conn.commit()
                logger.info("exploit_chunks table created successfully")
            else:
                logger.info("exploit_chunks table already exists")
    except Exception as e:
        logger.warning(f"Could not initialize RAG schema: {e}")


@router.get("/healthz")
def healthz():
    return {"ok": True, "version": os.environ.get("BUILD_VERSION", "dev")}

@router.get("/health")
def health():
    return {"ok": True, "version": os.environ.get("BUILD_VERSION", "dev")}

@router.get("/ollama/health", response_model=OllamaHealthResponse)
def ollama_health():
    if LLM_BACKEND == "azure":
        url = _azure_chat_url(AZURE_ENDPOINT, AZURE_MODEL, AZURE_API_VERSION)
        try:
            r = requests.post(
                url, json={"messages": [{"role": "user", "content": "ping"}], "max_tokens": 1},
                headers=_azure_headers(), timeout=10,
            )
            r.raise_for_status()
            return OllamaHealthResponse(
                ok=True, endpoint=AZURE_ENDPOINT,
                models=[{"name": AZURE_MODEL, "backend": "azure"}],
                running=[{"name": AZURE_MODEL}],
            )
        except Exception as e:
            logger.error(f"Azure health check failed: {e}")
            return OllamaHealthResponse(
                ok=False, endpoint=AZURE_ENDPOINT, models=[], running=[], detail=str(e),
            )

    if LLM_BACKEND == "openai":
        try:
            r = requests.post(
                f"{OPENAI_API_BASE.rstrip('/')}/v1/chat/completions",
                json={"model": OPENAI_MODEL, "messages": [{"role": "user", "content": "ping"}], "max_tokens": 1},
                headers=_openai_headers(), timeout=10,
            )
            r.raise_for_status()
            return OllamaHealthResponse(
                ok=True, endpoint=OPENAI_API_BASE,
                models=[{"name": OPENAI_MODEL, "backend": "openai"}],
                running=[{"name": OPENAI_MODEL}],
            )
        except Exception as e:
            logger.error(f"OpenAI health check failed: {e}")
            return OllamaHealthResponse(ok=False, endpoint=OPENAI_API_BASE, models=[], running=[], detail=str(e))

    if LLM_BACKEND == "anthropic":
        try:
            r = requests.post(
                "https://api.anthropic.com/v1/messages",
                json={"model": ANTHROPIC_MODEL, "max_tokens": 1, "messages": [{"role": "user", "content": "ping"}]},
                headers=_anthropic_headers(), timeout=10,
            )
            r.raise_for_status()
            return OllamaHealthResponse(
                ok=True, endpoint="https://api.anthropic.com",
                models=[{"name": ANTHROPIC_MODEL, "backend": "anthropic"}],
                running=[{"name": ANTHROPIC_MODEL}],
            )
        except Exception as e:
            logger.error(f"Anthropic health check failed: {e}")
            return OllamaHealthResponse(ok=False, endpoint="https://api.anthropic.com", models=[], running=[], detail=str(e))

    base_url = OLLAMA_BASE_URL.rstrip("/")
    endpoint = resolve_ollama_health_endpoint(base_url)
    try:
        # List models
        tags = requests.get(f"{endpoint}/tags", timeout=10)
        tags.raise_for_status()
        models = tags.json().get("models", []) if isinstance(tags.json(), dict) else tags.json()

        # List running (ps)
        ps = requests.get(f"{endpoint}/ps", timeout=10)
        ps.raise_for_status()
        running = ps.json().get("models", []) if isinstance(ps.json(), dict) else ps.json()

        return OllamaHealthResponse(ok=True, endpoint=endpoint, models=models, running=running)
    except requests.HTTPError as e:
        logger.error(f"HTTP error while checking Ollama health: {e.response.status_code} - {e.response.reason}")
        return OllamaHealthResponse(ok=False, endpoint=endpoint, models=[], running=[], detail=str(e))
    except Exception as e:
        logger.error(f"Error while checking Ollama health: {e}")
        return OllamaHealthResponse(ok=False, endpoint=endpoint, models=[], running=[], detail=str(e))

@router.post("/ollama/query", response_model=OllamaQueryResponse)
def ollama_query_route(req: OllamaQueryRequest):
    """
    Generic Ollama query: send a prompt, get back a response string.
    If your prompt asks for JSON, you'll receive it in the 'response' string.
    """
    try:
        result = ollama_query(prompt=req.prompt, model=req.model, stream=req.stream)
        return OllamaQueryResponse(model=result["model"], response=result["response"])
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=f"Ollama service unavailable: {e}")

@router.get("/next_scan", response_model=ScanRecommendationsResponse)
def get_next_scan_recommendations(
    ip: str = Query(..., description="IP address of the asset"),
    service: Optional[str] = Query(None, description="Service type (e.g., http, ssh)"),
    banner: Optional[str] = Query(None, description="Banner information"),
    port: Optional[int] = Query(None, description="Port number"),
    use_ollama: bool = Query(False, description="Force fetching from Ollama even if DB has rows"),
    persist: bool = Query(True, description="Persist results to DB if schema exists"),
):
    recommendations: List[ScanRecommendation] = []
    effective_service = service
    effective_port = port
    try:
        # Build filtered query — narrow to specific service/port when provided
        query = "SELECT p.service, p.banner, p.port FROM public.ports p JOIN public.assets a ON p.asset_id = a.id WHERE host(a.ip)=%s"
        params_list: list = [ip]
        if service:
            query += " AND lower(p.service) = lower(%s)"
            params_list.append(service)
        if port:
            query += " AND p.port = %s"
            params_list.append(port)
        query += " ORDER BY p.id DESC"

        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, tuple(params_list))
            rows = cur.fetchall()
            logger.info(f"DB rows found for {ip} (service={service}, port={port}): {len(rows)}")
        if not rows or use_ollama:
            # `port` is passed so per-port and per-(port,service) operator
            # prompts resolve — previously the LLM path discarded it entirely.
            ollama_recs = fetch_ollama_recommendations(ip, service, banner, port=port)
            # Same catalog gate as the hybrid path below — this branch is the one
            # that runs when no port rows exist yet, so it must not be the hole
            # through which unrunnable invocations reach the queue.
            ollama_recs, rejected_llm = filter_recommendations(ollama_recs)
            for bad in rejected_llm:
                logger.warning("Rejected unrunnable recommendation for %s:%s — %s (%s)",
                               ip, port, bad.get("_rejection"),
                               bad.get("script") or bad.get("template") or bad.get("action"))
            if rejected_llm:
                _emit_webhook("scan_recommender_invalid_recs_rejected", {
                    "ip": ip, "port": port, "service": service,
                    "rejected_count": len(rejected_llm),
                    "reasons": [b.get("_rejection") for b in rejected_llm],
                })
            recommendations.extend(ScanRecommendation(**rec) for rec in ollama_recs)
            if persist and PERSIST_RECS:
                dict_recs = [r.dict() for r in recommendations]
                try:
                    inserted = persist_recommendations(
                        ip=ip, recs=dict_recs, asset_id=None,
                        service=service, banner=banner,
                        source="ollama", model=OLLAMA_MODEL,
                        extra={"generator": "scan_recommender.py/next_scan"},
                    )
                    logger.info(f"Persisted {inserted} new recommendations for {ip}")
                except Exception as pe:
                    logger.warning(f"Persistence skipped/failed: {pe}")
        else:
            seen_keys: set = set()
            # Keep the RAW rec dicts (not the ScanRecommendation round-trip)
            # for persistence: the model drops extra keys (priority,
            # tech_context, high_value), so persisting r.dict() would lose
            # the G1/G2 enrichment.  raw_recs preserves them.
            raw_recs: List[Dict] = []
            tech_matched: List[str] = []
            high_value_hits: List[Dict] = []
            for row in rows:
                row_port = port or row.get("port")
                for rec in generate_recommendations(row, port=row_port, ip=ip):
                    # Deduplicate by (scanner, action, script, template, software_context)
                    # Include software_context in dedup key to avoid losing vulnx recs for different software
                    software_ctx = rec.get("software_context", {})
                    key = (rec.get("scanner"), rec.get("action"), rec.get("script"), rec.get("template"),
                           software_ctx.get("product", ""), software_ctx.get("version", ""))
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    recommendations.append(ScanRecommendation(**rec))
                    raw_recs.append(rec)
                    # Collect G1/G2 signal for the webhooks below.
                    if rec.get("tech_context", {}).get("matched"):
                        tech_matched.append(rec["tech_context"]["matched"])
                    if rec.get("high_value") and rec.get("scanner") == "metasploit":
                        high_value_hits.append(rec["high_value"])
                # Track for auto-execute
                if not effective_service:
                    effective_service = row.get("service")
                if not effective_port:
                    effective_port = row.get("port")
            # ── Hybrid pass: operator knowledge on top of the deterministic rules ──
            #
            # The rules above come from tool_kb YAML and never consult
            # service_prompts, so before this the seeded operator rules had no
            # effect on automated recon: _dispatch_recommender_for_ports does not
            # pass use_ollama, and `rows` is always non-empty when dispatching per
            # discovered port, so the LLM branch that *does* inject guidance was
            # never taken. Every stored recommendation was source='rules'.
            #
            # Gated on guidance actually existing: with no authored rule for this
            # service/port the LLM would only re-derive what tool_kb already gave
            # us, so the call is skipped. Cost therefore scales with the size of
            # the knowledge base, not with the number of open ports.
            kb_recs: List[Dict] = []
            if HYBRID_KB_RECS and raw_recs:
                probe_service = service or (rows[0].get("service") if rows else None)
                probe_port = effective_port or port
                try:
                    tech_tokens, _src = _get_detected_tech(ip, probe_port)
                    if _build_guidance_block(probe_service, probe_port, None, tech_tokens):
                        merged = _merge_kb_recs(
                            raw_recs,
                            fetch_ollama_recommendations(
                                ip, probe_service, banner, port=probe_port),
                            seen_keys,
                        )
                        # The LLM is not constrained to real tool names. Measured
                        # on a live run: 2 of 8 suggestions were unrunnable —
                        # `smb Vuln-MS17-010` (malformed) and `smb-enum-links`
                        # (no such nmap script). Both would have failed at the
                        # scanner after costing a dispatch.
                        merged, rejected_recs = filter_recommendations(merged)
                        for bad in rejected_recs:
                            logger.warning(
                                "Rejected unrunnable recommendation for %s:%s — %s (%s)",
                                ip, probe_port, bad.get("_rejection"),
                                bad.get("script") or bad.get("template") or bad.get("action"),
                            )
                        if rejected_recs:
                            _emit_webhook("scan_recommender_invalid_recs_rejected", {
                                "ip": ip, "port": probe_port, "service": probe_service,
                                "rejected_count": len(rejected_recs),
                                "reasons": [b.get("_rejection") for b in rejected_recs],
                            })
                        for rec in merged:
                            recommendations.append(ScanRecommendation(**rec))
                            kb_recs.append(rec)
                        logger.info(
                            "KB-guided pass added %d rec(s) for %s:%s on top of %d rule-based",
                            len(kb_recs), ip, probe_port, len(raw_recs),
                        )
                except HTTPException as he:
                    # A model that returns junk must not cost us the rule-based
                    # recommendations we already have — they are the reliable half.
                    logger.warning(
                        "KB-guided pass failed for %s:%s (%s) — keeping %d rule-based rec(s)",
                        ip, probe_port, he.detail, len(raw_recs),
                    )
                except Exception as e:
                    logger.warning(
                        "KB-guided pass errored for %s:%s (%s) — keeping rule-based only",
                        ip, probe_port, e,
                    )

            if persist and PERSIST_RECS:
                try:
                    inserted = persist_recommendations(
                        ip=ip, recs=raw_recs, asset_id=None,
                        service=service or (rows[0].get("service") if rows else None),
                        banner=banner or (rows[0].get("banner") if rows else None),
                        source="rules", model=None,
                        extra={"generator": "scan_recommender.py/next_scan"},
                    )
                    logger.info(f"Persisted {inserted} rule-based recommendations for {ip}")
                except Exception as pe:
                    logger.warning(f"Persistence skipped/failed: {pe}")
                # Persisted separately so provenance survives: querying
                # source='ollama' tells you what the operator's knowledge added
                # that the static KB did not.
                if kb_recs:
                    try:
                        inserted_kb = persist_recommendations(
                            ip=ip, recs=kb_recs, asset_id=None,
                            service=service or (rows[0].get("service") if rows else None),
                            banner=banner or (rows[0].get("banner") if rows else None),
                            source="ollama", model=OLLAMA_MODEL,
                            extra={"generator": "scan_recommender.py/next_scan:kb_guided"},
                        )
                        logger.info(f"Persisted {inserted_kb} KB-guided recommendations for {ip}")
                    except Exception as pe:
                        logger.warning(f"KB-guided persistence skipped/failed: {pe}")

            if kb_recs:
                _emit_webhook("scan_recommender_kb_guided_recs_added", {
                    "ip": ip, "port": effective_port, "service": effective_service,
                    "kb_guided_count": len(kb_recs), "rule_based_count": len(raw_recs),
                })

            # Webhooks for the new enrichment actions (per CLAUDE.md).
            if tech_matched:
                _emit_webhook("scan_recommender_tech_targeted_recs_added", {
                    "ip": ip, "port": effective_port,
                    "matched_tech": sorted(set(tech_matched)),
                })
            for hv in high_value_hits:
                _emit_webhook("scan_recommender_high_value_port_detected", {
                    "ip": ip, "port": hv.get("port"), "service": hv.get("service"),
                    "vulns": hv.get("vulns", []), "note": hv.get("note"),
                }, severity="high")

        # Auto-execute safe tools via kali-listener
        if AUTO_EXECUTE and effective_port and effective_service:
            threading.Thread(
                target=_dispatch_auto_execute,
                args=(ip, effective_service, effective_port),
                daemon=True,
            ).start()

        return ScanRecommendationsResponse(recommendations=recommendations)
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unhandled error in /next_scan")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")

@router.get("/recommendations")
def list_all_recommendations(
    status: str = Query("pending"),
    ip: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    engagement_id: Optional[str] = Query(None),
    x_engagement_id: Optional[str] = Header(None, alias="X-Engagement-Id"),
):
    """List all scan recommendations from the database.

    Engagement isolation: when an engagement is active it arrives either as the
    explicit ``engagement_id`` query param or (as the BFF forwards it) the
    ``X-Engagement-Id`` header. Recommendations are scoped to it. Because
    legacy rows persisted before engagement stamping have a NULL
    ``engagement_id``, we also include rows whose linked asset belongs to the
    engagement, so historical recommendations remain visible under their host.
    """
    eid = engagement_id or x_engagement_id
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            conditions = []
            params = []
            if status and status != "all":
                conditions.append("status = %s")
                params.append(status)
            if ip:
                conditions.append("ip = %s::inet")
                params.append(ip)
            if eid:
                conditions.append(
                    "(engagement_id = %s::uuid OR (engagement_id IS NULL "
                    "AND asset_id IN (SELECT id FROM public.assets "
                    "WHERE engagement_id = %s::uuid)))"
                )
                params.extend([eid, eid])
            where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            cur.execute(
                f"""
                SELECT DISTINCT ON (ip, scanner, COALESCE(action,''), COALESCE(template,''))
                       id, ip::text, service, banner, scanner, action, script, template,
                       source, model, confidence, priority, status, executed_at,
                       created_at, updated_at
                FROM scan_recommendations
                {where}
                ORDER BY ip, scanner, COALESCE(action,''), COALESCE(template,''),
                         priority ASC, created_at DESC
                LIMIT %s
                """,
                params + [limit]
            )
            rows = cur.fetchall()
            cur.close()
        return {"recommendations": [dict(r) for r in rows], "total": len(rows)}
    except Exception as e:
        logger.error(f"Failed to list recommendations: {e}")
        return {"recommendations": [], "total": 0, "error": str(e)}


@router.get("/software-assets", response_model=Dict)
def get_software_asset_recommendations(
    ip: Optional[str] = Query(None, description="IP address to filter by"),
    auto_execute: bool = Query(False, description="Automatically execute safe vulnx scans"),
    persist: bool = Query(True, description="Persist vulnx recommendations to DB"),
    limit: int = Query(50, ge=1, le=200, description="Max software products to analyze"),
):
    """
    Generate vulnx recommendations for all discovered software assets.
    This implements the software asset discovery → vulnerability research workflow.
    """
    try:
        # Get discovered software
        discovered_software = _get_discovered_software(ip=ip, limit=limit)

        if not discovered_software:
            return {
                "software_count": 0,
                "recommendations": [],
                "message": f"No software discovered for {'IP ' + ip if ip else 'any assets'}"
            }

        # Generate vulnx recommendations
        vulnx_recs = _generate_vulnx_recommendations_for_software(discovered_software)

        # Convert to ScanRecommendation format
        recommendations = [ScanRecommendation(**rec) for rec in vulnx_recs]

        # Persist recommendations if requested
        if persist and PERSIST_RECS and vulnx_recs:
            try:
                inserted = persist_recommendations(
                    ip=ip or "global",
                    recs=vulnx_recs,
                    asset_id=None,
                    service="software_asset_discovery",
                    banner=None,
                    source="software_asset_workflow",
                    model=None,
                    extra={
                        "generator": "scan_recommender.py/software-assets",
                        "discovered_software_count": len(discovered_software),
                        "workflow": "asset_discovery_to_vuln_research"
                    }
                )
                logger.info(f"Persisted {inserted} software asset vulnx recommendations")
            except Exception as pe:
                logger.warning(f"Failed to persist software asset recommendations: {pe}")

        # Auto-execute if requested and safe
        executed_count = 0
        if auto_execute and "vulnx" in SAFE_TOOLS:
            for rec in vulnx_recs[:10]:  # Limit auto-execution to prevent overwhelming
                software_ctx = rec.get("software_context", {})
                target_ip = software_ctx.get("ip")
                product = software_ctx.get("product", "")

                if target_ip and product:
                    # Dispatch vulnx execution via kali-listener
                    threading.Thread(
                        target=_dispatch_vulnx_execution,
                        args=(target_ip, product, software_ctx.get("version", "")),
                        daemon=True,
                    ).start()
                    executed_count += 1

        return {
            "software_count": len(discovered_software),
            "recommendations": [rec.dict() for rec in recommendations],
            "vulnx_recommendations": len(vulnx_recs),
            "executed_count": executed_count if auto_execute else 0,
            "discovered_software": [
                {
                    "product": s.get("product"),
                    "version": s.get("version"),
                    "ip": s.get("ip"),
                    "port": s.get("port"),
                    "source": s.get("source"),
                    "first_seen": s.get("first_seen")
                } for s in discovered_software[:20]  # Limit response size
            ],
            "message": f"Generated {len(vulnx_recs)} vulnx recommendations from {len(discovered_software)} discovered software products"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Unhandled error in /software-assets")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")


def _dispatch_vulnx_execution(ip: str, product: str, version: str):
    """Fire-and-forget call to execute vulnx scan for discovered software."""
    try:
        target_query = f"{product} {version}".strip()
        resp = requests.post(
            f"{KALI_LISTENER_URL}/tools/vulnx",
            json={"query": target_query, "target_context": f"Discovered on {ip}"},
            timeout=10,
            verify=False,
        )
        logger.info(f"Auto-executed vulnx for {product} {version} on {ip} → {resp.status_code}")
    except Exception as e:
        logger.warning(f"Auto-execute vulnx failed for {product} on {ip}: {e}")


app.include_router(router)


# ---- KB CRUD Endpoints ----
kb_router = APIRouter(prefix="/kb", tags=["Knowledge Base"])


@kb_router.get("/services")
def list_kb_services():
    """List all KB services (YAML merged with DB overrides)."""
    kb = get_tool_kb()
    yaml_services = kb._data.get("services", {})

    # Fetch all DB overrides
    overrides: Dict[str, Dict] = {}
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT service_name, data, updated_at FROM public.kb_service_overrides")
            for row in cur.fetchall():
                overrides[row["service_name"]] = {
                    "data": row["data"],
                    "updated_at": row["updated_at"].isoformat() if row["updated_at"] else None,
                }
    except Exception as e:
        logger.warning(f"Could not fetch KB overrides: {e}")

    result = []
    seen = set()
    for name, svc_data in yaml_services.items():
        seen.add(name)
        source = "yaml"
        merged = dict(svc_data)
        if name in overrides:
            source = "both"
            # Overlay DB data onto YAML
            merged.update(overrides[name]["data"])
        result.append({
            "name": name,
            "source": source,
            "ports": merged.get("ports", []),
            "description": merged.get("description", ""),
            "tool_count": len(merged.get("tools", [])),
            "msf_count": len(merged.get("metasploit", [])),
            "nuclei_tags": merged.get("nuclei_tags", []),
            "common_vulns": merged.get("common_vulns", []),
        })

    # DB-only entries (new services added by user)
    for name, ov in overrides.items():
        if name not in seen:
            data = ov["data"]
            result.append({
                "name": name,
                "source": "override",
                "ports": data.get("ports", []),
                "description": data.get("description", ""),
                "tool_count": len(data.get("tools", [])),
                "msf_count": len(data.get("metasploit", [])),
                "nuclei_tags": data.get("nuclei_tags", []),
                "common_vulns": data.get("common_vulns", []),
            })

    result.sort(key=lambda s: s["name"])
    return {"services": result, "count": len(result)}


@kb_router.get("/services/{name}")
def get_kb_service(name: str):
    """Get one KB service (YAML merged with DB override)."""
    kb = get_tool_kb()
    svc_name = name.lower()
    yaml_data = kb.get_service_info(svc_name)

    override = _get_kb_overrides(svc_name)

    if not yaml_data and not override:
        raise HTTPException(404, f"Service '{name}' not found")

    merged = dict(yaml_data) if yaml_data else {}
    source = "yaml" if yaml_data else "override"
    if override:
        source = "both" if yaml_data else "override"
        merged.update(override)

    return {
        "name": svc_name,
        "source": source,
        "data": merged,
    }


@kb_router.put("/services/{name}")
def upsert_kb_service(name: str, body: Dict = Body(...)):
    """Create or update a DB override for a service."""
    svc_name = name.lower()
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public.kb_service_overrides (service_name, data)
                VALUES (%s, %s)
                ON CONFLICT (service_name) DO UPDATE
                  SET data = EXCLUDED.data, updated_at = now()
                RETURNING id;
                """,
                (svc_name, Json(body)),
            )
            conn.commit()
            row = cur.fetchone()
            return {"ok": True, "service_name": svc_name, "id": str(row[0])}
    except Exception as e:
        logger.error(f"Failed to upsert KB service {svc_name}: {e}")
        raise HTTPException(500, f"Failed to save: {e}")


@kb_router.delete("/services/{name}")
def delete_kb_service_override(name: str):
    """Delete DB override (reverts to YAML-only)."""
    svc_name = name.lower()
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM public.kb_service_overrides WHERE service_name = %s RETURNING id",
                (svc_name,),
            )
            conn.commit()
            if cur.rowcount == 0:
                raise HTTPException(404, f"No override found for '{name}'")
            return {"ok": True, "deleted": svc_name}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete KB override {svc_name}: {e}")
        raise HTTPException(500, f"Failed to delete: {e}")


class ToolFeedbackBody(BaseModel):
    verdict: str                       # 'suppress' | 'add_tool' | 'add_overlap'
    service: Optional[str] = None      # e.g. 'http'; None = all services
    scanner: Optional[str] = None      # e.g. 'metasploit', 'vulnx'
    selector: Optional[str] = None     # glob vs rec script/module
    payload: Optional[Dict[str, Any]] = None   # add_tool: {name,action,command}; add_overlap: {group}
    reason: Optional[str] = None
    created_by: Optional[str] = None


@kb_router.get("/feedback")
def list_tool_feedback():
    """List recorded tool-selection feedback (the durable policy rows)."""
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT id, service, scanner, selector, verdict, payload, reason, "
                "created_by, active, created_at FROM public.scan_tool_feedback "
                "ORDER BY created_at DESC"
            )
            return {"feedback": [dict(r) for r in cur.fetchall()]}
    except Exception as e:
        raise HTTPException(500, f"Failed to list feedback: {e}")


@kb_router.post("/feedback")
def add_tool_feedback(body: ToolFeedbackBody):
    """Record a tool-selection feedback policy that steers future recs.

    verdict 'suppress'    → stop recommending scanner [+ selector] (service or global)
    verdict 'add_tool'    → inject a tool rec (payload {name, action, command}) for a service
    verdict 'add_overlap' → tag matching recs into an overlap group (payload {group})
    """
    if body.verdict not in ("suppress", "add_tool", "add_overlap"):
        raise HTTPException(400, "verdict must be suppress | add_tool | add_overlap")
    if body.verdict == "add_tool" and not (body.payload or {}).get("name"):
        raise HTTPException(400, "add_tool requires payload.name")
    if body.verdict == "add_overlap" and not (body.payload or {}).get("group"):
        raise HTTPException(400, "add_overlap requires payload.group")
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO public.scan_tool_feedback
                    (service, scanner, selector, verdict, payload, reason, created_by)
                VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s)
                RETURNING id, created_at
                """,
                (body.service, body.scanner, body.selector, body.verdict,
                 Json(body.payload or {}), body.reason, body.created_by or "operator"),
            )
            row = cur.fetchone()
            conn.commit()
    except Exception as e:
        raise HTTPException(500, f"Failed to record feedback: {e}")

    _invalidate_tool_feedback_cache()  # apply immediately to subsequent recs
    _emit_webhook("scan_recommender_tool_feedback_recorded", {
        "verdict": body.verdict, "service": body.service, "scanner": body.scanner,
        "selector": body.selector, "reason": body.reason,
    })
    return {"ok": True, "id": str(row["id"]), "created_at": str(row["created_at"])}


@kb_router.delete("/feedback/{feedback_id}")
def deactivate_tool_feedback(feedback_id: str):
    """Deactivate a feedback policy (soft-delete; stops affecting recs)."""
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE public.scan_tool_feedback SET active = false, updated_at = now() "
                "WHERE id = %s RETURNING id",
                (feedback_id,),
            )
            conn.commit()
            if cur.rowcount == 0:
                raise HTTPException(404, "feedback not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Failed to deactivate: {e}")
    _invalidate_tool_feedback_cache()
    return {"ok": True, "deactivated": feedback_id}


# ---- KB: per-service / per-port operator prompts ----
class ServicePromptBody(BaseModel):
    """A per-service / per-port prompt rule.

    `selector_type` decides which selector fields are required:
      service      → service only
      port         → port only
      port_service → service + port
      tech         → detected technology only (wordpress, tomcat, ...)
    The DB enforces the same shape (service_prompts_selector_shape), so a row
    can never end up unreachable by the resolver.
    """
    selector_type: str
    title: str
    prompt: str = ""
    service: Optional[str] = None
    tech: Optional[str] = None
    port: Optional[int] = None
    training_notes: Optional[str] = None
    tags: Optional[List[str]] = None
    priority: int = 100
    enabled: bool = True
    engagement_id: Optional[str] = None


# ── Walkthrough → knowledge conversion ──────────────────────────────────────
#
# Drafts service_prompts entries from a pentest walkthrough. The converter NEVER
# writes to the database: it returns proposals, and the operator applies them via
# scripts/import-knowledge.sh or the UI. Walkthroughs are dense with box-specific
# artifacts and an LLM will happily promote "the password was summer2023" into
# permanent guidance, so a review gate is the whole point.

WALKTHROUGH_PROMPT_PATH = os.environ.get(
    "WALKTHROUGH_PROMPT_PATH", "/knowledge/prompts/walkthrough_to_seed.md")
WALKTHROUGH_PROMPT_SETTING = "walkthrough_import.system_prompt"

# Long input + long structured output; the module's other LLM calls use 120s,
# which a full walkthrough conversion routinely exceeds.
WALKTHROUGH_LLM_TIMEOUT = int(os.environ.get("WALKTHROUGH_LLM_TIMEOUT", "600"))

# Ollama defaults (num_ctx 2048) silently truncate a long guide's prompt AND
# its structured response — the failure mode is zero rules with no error, not a
# crash. Sized for a full documentation page plus a large YAML payload.
WALKTHROUGH_NUM_CTX = int(os.environ.get("WALKTHROUGH_NUM_CTX", "16384"))
WALKTHROUGH_NUM_PREDICT = int(os.environ.get("WALKTHROUGH_NUM_PREDICT", "8192"))

_APP_SETTING_CACHE: Dict[str, Any] = {}
_APP_SETTING_TTL = 300.0  # seconds


def _get_app_setting(key: str, default: str = "") -> str:
    """Read a config value from app_settings, cached.

    scan_recommender has no app_settings reader of its own (rag-api's
    `_get_setting` lives in a different container), so this mirrors that shape:
    category='config', 5-minute cache, falls back to `default` on any error so a
    DB blip degrades to the shipped prompt rather than breaking conversion.
    """
    import time as _t
    now = _t.monotonic()
    hit = _APP_SETTING_CACHE.get(key)
    if hit and (now - hit["ts"]) < _APP_SETTING_TTL:
        return hit["val"]
    val = default
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT value FROM app_settings WHERE key = %s AND category = 'config'",
                (key,),
            )
            row = cur.fetchone()
            if row and row[0]:
                val = row[0]
    except Exception as e:
        logger.debug("app_setting %s read failed: %s", key, e)
    _APP_SETTING_CACHE[key] = {"val": val, "ts": now}
    return val


def _invalidate_app_setting(key: str) -> None:
    _APP_SETTING_CACHE.pop(key, None)


def _read_default_walkthrough_prompt() -> str:
    """The shipped guiding prompt from the read-only knowledge mount."""
    try:
        with open(WALKTHROUGH_PROMPT_PATH, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as e:
        logger.error(
            "Default walkthrough prompt unreadable at %s (%s) — is "
            "./knowledge:/knowledge:ro mounted?", WALKTHROUGH_PROMPT_PATH, e)
        return ""


def resolve_walkthrough_prompt(focus: Optional[str] = None) -> str:
    """Guiding prompt, most specific layer last.

    file default -> app_settings override -> per-run focus.  An empty override
    means "use the file", matching the cve_analysis prompt convention where
    saving a blank value reverts to the shipped default.
    """
    base = _get_app_setting(WALKTHROUGH_PROMPT_SETTING, "") or _read_default_walkthrough_prompt()
    if (focus or "").strip():
        base += (
            "\n\n# Additional focus for this run\n"
            "The operator asked you to focus on the following. It narrows what to "
            "extract; it does not relax any rule above.\n\n"
            + focus.strip()
        )
    return base


# Patterns that suggest an entry carried box-specific data out of the walkthrough.
# These FLAG rather than drop, because every family overlaps with legitimate
# content: SNMP guidance genuinely names the community strings public/private,
# and a vendor default-credential table is exactly the knowledge worth keeping.
_SCRUB_PATTERNS = (
    ("capture-the-flag flag value",
     re.compile(r"\b(?:HTB|THM|FLAG|CTF)\{[^}]{2,}\}", re.I)),
    ("credential pair",
     re.compile(r"\b[A-Za-z0-9._-]{3,}:[^\s:'\"]{6,}\b")),
    ("stated password",
     re.compile(r"\b(?:password|passwd|creds?|credentials)\s*(?:was|were|is|are|=|:)\s*\S{4,}", re.I)),
    ("password hash",
     re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})(?![0-9a-fA-F])")),
    ("lab IP address",
     re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")),
)


def scrub_entry(entry: Dict) -> List[str]:
    """Reasons this entry looks box-specific. Empty list means clean.

    Only operator-visible text is scanned — the selector fields are structural.
    """
    haystack = "\n".join(str(entry.get(f) or "") for f in
                         ("title", "prompt", "training_notes", "content"))
    reasons = []
    for reason, rx in _SCRUB_PATTERNS:
        m = rx.search(haystack)
        if m:
            snippet = m.group(0)
            reasons.append(f"{reason}: {snippet[:60]}")
    return reasons


def _yaml_block(entry: Dict, commented: bool, reasons: List[str]) -> str:
    """Render one entry as a YAML list item, commented out when flagged.

    Flagged entries stay in the file so the operator can see what was proposed
    and un-comment anything that is a false positive — but being comments, they
    are invisible to the importer and cannot reach live scanning by accident.
    """
    import yaml as _yaml
    body = _yaml.safe_dump([entry], sort_keys=False, allow_unicode=True,
                           default_flow_style=False, width=88)
    if not commented:
        return body
    out = [f"# !REVIEW  {r}" for r in reasons]
    out += ["# " + line if line.strip() else "#" for line in body.splitlines()]
    return "\n".join(out) + "\n"


def render_seed_yaml(prompts: List[Dict], docs: List[Dict],
                     flagged_prompt_idx: Dict[int, List[str]],
                     flagged_doc_idx: Dict[int, List[str]],
                     source: str,
                     header: Optional[List[str]] = None) -> str:
    """Assemble the seed file that scripts/import-knowledge.sh consumes.

    `header` overrides the comment block only. Exports are already-reviewed rules
    rather than drafts, so the default "review before importing" preamble would be
    wrong on them; the body format stays identical either way, which is what makes
    an export re-importable.
    """
    lines = header if header is not None else [
        f"# Drafted from walkthrough: {source}",
        "#",
        "# Review before importing. Entries commented out below were flagged as",
        "# possibly box-specific — un-comment only what is genuinely reusable.",
        "#",
        "#   ./scripts/import-knowledge.sh --file <this file> --dry-run",
        "#   ./scripts/import-knowledge.sh --file <this file>",
        "",
    ]
    if prompts:
        lines.append("prompts:")
        for i, e in enumerate(prompts):
            reasons = flagged_prompt_idx.get(i) or []
            block = _yaml_block(e, bool(reasons), reasons)
            # safe_dump emits a top-level list; strip its indentation offset by
            # re-indenting nothing — the dumped "- key:" form is already correct.
            lines.append(block.rstrip("\n"))
        lines.append("")
    if docs:
        lines.append("service_docs:")
        for i, e in enumerate(docs):
            reasons = flagged_doc_idx.get(i) or []
            lines.append(_yaml_block(e, bool(reasons), reasons).rstrip("\n"))
        lines.append("")
    if not prompts and not docs:
        lines.append("prompts: []")
        lines.append("")
    return "\n".join(lines)


# Selector values name a service or a technology, so they look like identifiers.
# Models occasionally emit fragments scraped out of a URL or heading ("//s",
# "http://x"), which would otherwise be stored as an unmatchable rule.
_SELECTOR_VALUE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._+-]{1,39}$")


def repair_entry(entry: Dict) -> Dict:
    """Fix the field/selector mismatches models routinely produce.

    Returns a shallow-copied, corrected entry. Purely a normalisation step —
    it never invents a selector, so an entry that is genuinely unusable still
    fails validation afterwards with a reason.

    The common failure is naming the right thing in the wrong field, e.g.
    `selector_type: tech` with the technology in `service`. Rejecting those
    throws away correct knowledge over a field name.
    """
    e = dict(entry)
    sel = str(e.get("selector_type") or "").strip().lower()
    service = str(e.get("service") or "").strip()
    tech = str(e.get("tech") or "").strip()
    port = e.get("port")

    # Value sanity: drop anything that isn't identifier-shaped.
    if service and not _SELECTOR_VALUE_RE.match(service):
        service = ""
        e.pop("service", None)
    if tech and not _SELECTOR_VALUE_RE.match(tech):
        tech = ""
        e.pop("tech", None)

    # Right value, wrong field.
    if sel == "tech" and not tech and service:
        e["tech"], service = service, ""
        e.pop("service", None)
        tech = e["tech"]
    elif sel in ("service", "port_service") and not service and tech:
        e["service"], tech = tech, ""
        e.pop("tech", None)
        service = e["service"]

    # Missing selector_type but the fields make the intent obvious.
    if not sel:
        if service and port:
            e["selector_type"] = "port_service"
        elif tech:
            e["selector_type"] = "tech"
        elif service:
            e["selector_type"] = "service"
        elif port:
            e["selector_type"] = "port"

    # A declared port_service missing one half degrades to whichever half it
    # actually has, rather than being thrown away.
    if str(e.get("selector_type") or "") == "port_service":
        if not port and service:
            e["selector_type"] = "service"
        elif not service and port:
            e["selector_type"] = "port"
    return e


def normalize_selector(selector_type, service, tech, port, title) -> tuple:
    """Normalize + validate selector fields without raising.

    Returns ``(service, tech, port, error)`` where `error` is None on success and
    a human-readable string otherwise.  Pure and exception-free so both the CRUD
    endpoint (which turns `error` into a 400) and the walkthrough converter
    (which collects errors per proposed entry) enforce exactly one rule table —
    a second copy would drift and let the converter emit entries the API then
    rejects.

    Fields irrelevant to the chosen selector_type are forced to None rather than
    passed through, so a stray value can't trip the DB's shape CHECK and produce
    a confusing 500.
    """
    sel = (selector_type or "").strip().lower()
    if sel not in ("service", "port", "port_service", "tech"):
        return None, None, None, (
            "selector_type must be one of: service, port, port_service, tech")

    service = (service or "").strip().lower() or None
    tech = (tech or "").strip().lower() or None

    # Accept a stringified port — LLM output and YAML both produce these.
    if isinstance(port, str):
        port = port.strip()
        port = int(port) if port.isdigit() else None

    if sel in ("service", "port_service") and not service:
        return None, None, None, f"selector_type '{sel}' requires a service"
    if sel in ("port", "port_service") and not port:
        return None, None, None, f"selector_type '{sel}' requires a port"
    if sel == "tech" and not tech:
        return None, None, None, "selector_type 'tech' requires a tech"

    if sel == "service":
        port, tech = None, None
    elif sel == "port":
        service, tech = None, None
    elif sel == "port_service":
        tech = None
    elif sel == "tech":
        service, port = None, None

    if port is not None and not (0 < port <= 65535):
        return None, None, None, "port must be between 1 and 65535"
    if not (title or "").strip():
        return None, None, None, "title is required"
    return service, tech, port, None


def _validate_prompt_selector(body: "ServicePromptBody") -> tuple:
    """Normalize + validate selector fields for the CRUD path. Returns (service, tech, port)."""
    service, tech, port, error = normalize_selector(
        body.selector_type, body.service, body.tech, body.port, body.title,
    )
    if error:
        raise HTTPException(400, error)
    return service, tech, port


def _ingest_training_notes(row_id: str, service: Optional[str], port: Optional[int],
                           title: str, notes: Optional[str],
                           tech: Optional[str] = None) -> None:
    """Push a rule's training_notes into the RAG store, best-effort.

    Called after save. A RAG/embedder outage must not fail the save — the notes
    are already persisted in service_prompts and `rag_ingested_at` stays NULL,
    which is how the UI shows "not yet indexed".
    """
    if not (notes or "").strip():
        return
    try:
        from exploits_rag import ingest_service_doc, ServiceDocIngest
        ingest_service_doc(ServiceDocIngest(
            title=title, content=notes, service=service, port=port, tech=tech,
            doc_kind="training",
        ))
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                "UPDATE public.service_prompts SET rag_ingested_at = now() WHERE id = %s::uuid",
                (row_id,),
            )
            conn.commit()
    except Exception as e:
        logger.warning("training notes ingest failed for %s: %s", title, e)


@kb_router.get("/prompts")
def list_service_prompts(
    service: Optional[str] = Query(None),
    port: Optional[int] = Query(None),
    engagement_id: Optional[str] = Query(None),
    enabled_only: bool = Query(False),
):
    """List prompt rules, optionally filtered."""
    where, params = [], []
    if service:
        where.append("lower(service) = lower(%s)")
        params.append(service)
    if port:
        where.append("port = %s")
        params.append(port)
    if engagement_id:
        where.append("engagement_id = %s::uuid")
        params.append(engagement_id)
    if enabled_only:
        where.append("enabled = true")
    sql = (
        "SELECT id::text, selector_type, service, tech, port, title, prompt, "
        "       training_notes, tags, priority, enabled, engagement_id::text, "
        "       rag_ingested_at, created_at, updated_at "
        "  FROM public.service_prompts "
        + (" WHERE " + " AND ".join(where) if where else "")
        + " ORDER BY selector_type, priority, title"
    )
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, tuple(params))
            return {"prompts": [dict(r) for r in cur.fetchall()]}
    except Exception as e:
        logger.error("Failed to list service prompts: %s", e)
        raise HTTPException(500, f"Failed to list prompts: {e}")


# Columns that describe a row's life in this database rather than the knowledge
# itself. They must not reach a seed file: `id` and the timestamps are
# regenerated on import, and `engagement_id` is a UUID that will not exist on any
# other install — carrying it over turns a portable seed into one that fails its
# foreign key.
_EXPORT_DROP = ("id", "created_at", "updated_at", "rag_ingested_at", "engagement_id")


def _export_row(row: Dict) -> Dict:
    """Reduce a DB row to the fields the importer accepts."""
    out = {}
    for k, v in row.items():
        if k in _EXPORT_DROP:
            continue
        # Drop nulls to keep the file readable, but never drop a false/0 — omitting
        # `enabled: false` would silently re-import the rule as enabled.
        if v is None:
            continue
        if k == "tags":
            v = list(v)
            if not v:
                continue
        out[k] = v
    return out


@kb_router.get("/tool-catalog")
def get_tool_catalog_info():
    """What the recommendation validator knows, and how old that knowledge is.

    Surfaces the snapshot's age because the catalog cannot detect its own
    staleness: it is generated by an explicit refresh so that validation never
    depends on live containers, which means a tool installed after the last run
    is invisible to it.
    """
    from tool_catalog import catalog_info
    info = catalog_info()
    # Nodes execute scans with their own toolsets; a validator that only knows
    # this host's containers would reject work those nodes could run.
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT name, status, "
                "       jsonb_array_length(COALESCE(capabilities,'[]'::jsonb)) AS tools "
                "  FROM public.remote_nodes ORDER BY name")
            info["nodes"] = [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.debug("tool-catalog: node capabilities unavailable (%s)", e)
        info["nodes"] = []
    return info


@kb_router.get("/prompts/export")
def export_service_prompts(
    engagement_id: Optional[str] = Query(None),
    enabled_only: bool = Query(False),
):
    """Export prompt rules as a seed file, re-importable by import-knowledge.sh.

    The round-trip partner to the importer: rules accepted in the UI live only in
    Postgres until this writes them back out, so a clean install starts empty and
    an accepted rule is lost on `docker compose down -v`.

    Nothing is flagged or commented out here — these rules already passed review
    when they were accepted, unlike converter drafts.
    """
    where, params = [], []
    if engagement_id:
        where.append("engagement_id = %s::uuid")
        params.append(engagement_id)
    if enabled_only:
        where.append("enabled = true")
    sql = (
        "SELECT id::text, selector_type, service, tech, port, title, prompt, "
        "       training_notes, tags, priority, enabled, engagement_id::text, "
        "       rag_ingested_at, created_at, updated_at "
        "  FROM public.service_prompts "
        + (" WHERE " + " AND ".join(where) if where else "")
        # Stable ordering keeps successive exports diffable — an export that
        # reshuffles rows produces noise in git for no change in content.
        + " ORDER BY selector_type, COALESCE(service, tech, ''), COALESCE(port, -1), title"
    )
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, tuple(params))
            rows = [dict(r) for r in cur.fetchall()]
    except Exception as e:
        logger.error("Failed to export service prompts: %s", e)
        raise HTTPException(500, f"Failed to export prompts: {e}")

    entries = [_export_row(r) for r in rows]
    scope = f"engagement {engagement_id}" if engagement_id else "all engagements"
    header = [
        f"# Exported from the live knowledge base — {len(entries)} rule(s), {scope}.",
        "#" + (" Enabled rules only." if enabled_only else ""),
        "# These were already reviewed when accepted, so nothing here is commented out.",
        "#",
        "#   ./scripts/import-knowledge.sh --file <this file> --dry-run",
        "#   ./scripts/import-knowledge.sh --file <this file>",
        "",
    ]
    yaml_text = render_seed_yaml(entries, [], {}, {}, scope, header=header)
    return {"ok": True, "count": len(entries), "yaml": yaml_text}


@kb_router.get("/prompts/resolve")
def resolve_service_prompts(
    service: Optional[str] = Query(None),
    port: Optional[int] = Query(None),
    tech: Optional[str] = Query(None, description="Comma-separated technologies"),
    engagement_id: Optional[str] = Query(None),
):
    """Preview exactly what would be injected for a (service, port, tech).

    This is the same resolution the LLM path uses, so the UI's test panel shows
    the real thing rather than an approximation.
    """
    tech_list = [t.strip() for t in (tech or "").split(",") if t.strip()]
    matches = _get_service_prompts(service, port, engagement_id, tech_list)
    return {
        "service": service,
        "port": port,
        "tech": tech_list,
        "matched": matches,
        "guidance_block": _build_guidance_block(service, port, engagement_id, tech_list),
        "training_context": _get_training_context(service, port, tech=tech_list),
    }


@kb_router.get("/web-guidance")
def web_scan_guidance(
    ip: Optional[str] = Query(None, description="Target IP — detected tech is looked up from it"),
    service: Optional[str] = Query("http"),
    port: Optional[int] = Query(None),
    tech: Optional[str] = Query(None, description="Comma-separated tech; overrides detection"),
    engagement_id: Optional[str] = Query(None),
):
    """What operator training says about scanning THIS web target.

    Returns the guidance text, retrieved training context, and — the part a
    scanner can act on directly — `suggested_nuclei_tags`, merged from:
      1. tags on matching service_prompts rows (operator-authored), and
      2. the KB's tech_signatures for whatever is running on the target.

    Intended as a REFINEMENT on top of a web profile: the profile decides how
    deep to dig, this decides what to look for once you know it's WordPress.
    Deliberately additive — it never removes stages or widens scope.
    """
    if tech:
        tech_list = [t.strip().lower() for t in tech.split(",") if t.strip()]
        tech_source = "explicit"
    else:
        tech_list, tech_source = _get_detected_tech(ip, port)
        tech_list = [t.lower() for t in (tech_list or [])]

    matches = _get_service_prompts(service, port, engagement_id, tech_list)

    # 1. Tags the operator attached to matching rules.
    suggested: List[str] = []
    for row in matches:
        for t in (row.get("tags") or []):
            t = (t or "").strip().lower()
            if t and t not in suggested:
                suggested.append(t)

    # 2. Tags the KB already associates with the detected technology.
    if tech_list:
        try:
            for m in get_tool_kb().match_tech_to_tags(tech_list):
                for t in (m.get("nuclei_tags") or []):
                    t = (t or "").strip().lower()
                    if t and t not in suggested:
                        suggested.append(t)
        except Exception as e:
            logger.debug("tech->tags lookup failed: %s", e)

    return {
        "ip": ip,
        "service": service,
        "port": port,
        "tech": tech_list,
        "tech_source": tech_source,
        "matched": matches,
        "guidance_block": _build_guidance_block(service, port, engagement_id, tech_list),
        "training_context": _get_training_context(service, port, tech=tech_list),
        "suggested_nuclei_tags": suggested,
    }


@kb_router.post("/prompts")
def create_service_prompt(body: ServicePromptBody):
    """Create a prompt rule (and index its training notes into RAG)."""
    service, tech, port = _validate_prompt_selector(body)
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public.service_prompts
                    (selector_type, service, tech, port, title, prompt, training_notes,
                     tags, priority, enabled, engagement_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id::text
                """,
                (body.selector_type.strip().lower(), service, tech, port,
                 body.title.strip(), body.prompt or "", body.training_notes,
                 body.tags or [], body.priority, body.enabled,
                 body.engagement_id or None),
            )
            row = cur.fetchone()
            conn.commit()
    except HTTPException:
        raise
    except Exception as e:
        # The unique index gives a clear duplicate message rather than a 500.
        if "idx_service_prompts_selector" in str(e):
            raise HTTPException(409, "A rule already exists for this selector")
        logger.error("Failed to create service prompt: %s", e)
        raise HTTPException(500, f"Failed to create prompt: {e}")

    prompt_id = row[0]
    _invalidate_service_prompt_cache()
    _ingest_training_notes(prompt_id, service, port, body.title.strip(),
                           body.training_notes, tech)
    _emit_webhook("service_prompt_saved", {
        "id": prompt_id, "action": "created", "selector_type": body.selector_type,
        "service": service, "tech": tech, "port": port, "title": body.title,
        "has_training_notes": bool((body.training_notes or "").strip()),
    })
    return {"ok": True, "id": prompt_id}


@kb_router.put("/prompts/{prompt_id}")
def update_service_prompt(prompt_id: str, body: ServicePromptBody):
    """Replace a prompt rule (and re-index its training notes)."""
    service, tech, port = _validate_prompt_selector(body)
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE public.service_prompts
                   SET selector_type = %s, service = %s, tech = %s, port = %s, title = %s,
                       prompt = %s, training_notes = %s, tags = %s,
                       priority = %s, enabled = %s, engagement_id = %s
                 WHERE id = %s::uuid
                RETURNING id::text
                """,
                (body.selector_type.strip().lower(), service, tech, port,
                 body.title.strip(), body.prompt or "", body.training_notes,
                 body.tags or [], body.priority, body.enabled,
                 body.engagement_id or None, prompt_id),
            )
            row = cur.fetchone()
            conn.commit()
            if not row:
                raise HTTPException(404, f"No prompt with id {prompt_id}")
    except HTTPException:
        raise
    except Exception as e:
        if "idx_service_prompts_selector" in str(e):
            raise HTTPException(409, "A rule already exists for this selector")
        logger.error("Failed to update service prompt: %s", e)
        raise HTTPException(500, f"Failed to update prompt: {e}")

    _invalidate_service_prompt_cache()
    _ingest_training_notes(prompt_id, service, port, body.title.strip(),
                           body.training_notes, tech)
    _emit_webhook("service_prompt_saved", {
        "id": prompt_id, "action": "updated", "selector_type": body.selector_type,
        "service": service, "tech": tech, "port": port, "title": body.title,
        "has_training_notes": bool((body.training_notes or "").strip()),
    })
    return {"ok": True, "id": prompt_id}


@kb_router.delete("/prompts/{prompt_id}")
def delete_service_prompt(prompt_id: str):
    """Delete a prompt rule and any training document it indexed."""
    try:
        with get_db() as conn, conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "DELETE FROM public.service_prompts WHERE id = %s::uuid "
                "RETURNING title, service, tech, port, training_notes",
                (prompt_id,),
            )
            row = cur.fetchone()
            conn.commit()
            if not row:
                raise HTTPException(404, f"No prompt with id {prompt_id}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to delete service prompt: %s", e)
        raise HTTPException(500, f"Failed to delete prompt: {e}")

    # Remove the matching RAG document so deleted guidance stops being
    # retrieved. Keyed identically to ingest, so it targets the same rows.
    if (row.get("training_notes") or "").strip():
        try:
            from exploits_rag import _stable_training_id, delete_service_doc
            delete_service_doc(_stable_training_id(
                (row.get("service") or "").lower() or None, row.get("port"),
                row["title"], (row.get("tech") or "").lower() or None,
            ))
        except Exception as e:
            logger.debug("training doc cleanup skipped for %s: %s", prompt_id, e)

    _invalidate_service_prompt_cache()
    _emit_webhook("service_prompt_deleted", {
        "id": prompt_id, "title": row.get("title"),
        "service": row.get("service"), "port": row.get("port"),
    })
    return {"ok": True, "deleted": prompt_id}


# ---- KB: draft rules from a pentest walkthrough ----
class WalkthroughConvertBody(BaseModel):
    content: str
    filename: Optional[str] = None
    focus: Optional[str] = None
    include_existing: bool = True
    gap_pass: bool = True          # re-ask for services coverage flagged as missed


class WalkthroughPromptBody(BaseModel):
    """Empty string reverts to the shipped default (cve_analysis convention)."""
    prompt: str = ""


def _existing_rules_for(text: str, limit: int = 20) -> List[Dict]:
    """Existing rules whose service or tech is named in the walkthrough.

    Fed back to the model so it extends what is already there instead of
    proposing near-duplicates — which matters because import-knowledge.sh is
    create-or-update, so a duplicate silently overwrites the original.
    """
    low = (text or "").lower()
    out = []
    for row in _get_all_service_prompts():
        key = (row.get("service") or row.get("tech") or "").lower()
        if key and key in low:
            out.append({
                "selector_type": row.get("selector_type"),
                "service": row.get("service"), "tech": row.get("tech"),
                "port": row.get("port"), "title": row.get("title"),
                "prompt": (row.get("prompt") or "")[:400],
            })
        if len(out) >= limit:
            break
    return out


@kb_router.get("/walkthrough-prompt")
def get_walkthrough_prompt():
    """Current guiding prompt, the shipped default, and whether one is overridden."""
    default = _read_default_walkthrough_prompt()
    override = _get_app_setting(WALKTHROUGH_PROMPT_SETTING, "")
    return {
        "prompt": override or default,
        "default": default,
        "using_custom": bool(override),
        "default_path": WALKTHROUGH_PROMPT_PATH,
        "default_available": bool(default),
    }


@kb_router.put("/walkthrough-prompt")
def set_walkthrough_prompt(body: WalkthroughPromptBody):
    """Override the guiding prompt; an empty string deletes the override."""
    val = (body.prompt or "").strip()
    try:
        with get_db() as conn, conn.cursor() as cur:
            if val:
                cur.execute(
                    "INSERT INTO app_settings (key, value, category) "
                    "VALUES (%s, %s, 'config') "
                    "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
                    (WALKTHROUGH_PROMPT_SETTING, val),
                )
            else:
                cur.execute(
                    "DELETE FROM app_settings WHERE key = %s AND category = 'config'",
                    (WALKTHROUGH_PROMPT_SETTING,),
                )
            conn.commit()
    except Exception as e:
        logger.error("Failed to save walkthrough prompt: %s", e)
        raise HTTPException(500, f"Failed to save prompt: {e}")
    _invalidate_app_setting(WALKTHROUGH_PROMPT_SETTING)
    _emit_webhook("walkthrough_prompt_updated", {"using_custom": bool(val)})
    return {"ok": True, "using_custom": bool(val)}


@kb_router.post("/walkthrough/convert")
def convert_walkthrough(body: WalkthroughConvertBody):
    """Draft importable rules from a walkthrough. Never writes to the database.

    Returns proposals plus the reasons anything was flagged or rejected, so the
    operator reviews before any of it reaches live scanning.
    """
    return convert_text_to_knowledge(
        content=body.content, source=(body.filename or "pasted"),
        focus=body.focus, include_existing=body.include_existing,
        gap_pass=body.gap_pass,
    )


# A whole documentation page in one LLM call is unreliable: the model spends its
# output budget narrating and the JSON gets truncated mid-structure, which
# surfaces as "0 rules drafted" or a parse error. Converting section by section
# keeps every request small enough to finish, and improves quality because the
# model considers one service at a time.
WALKTHROUGH_CHUNK_CHARS = int(os.environ.get("WALKTHROUGH_CHUNK_CHARS", "6000"))
WALKTHROUGH_MAX_CHUNKS = int(os.environ.get("WALKTHROUGH_MAX_CHUNKS", "12"))


def _split_for_conversion(text: str, max_chars: int = None) -> List[str]:
    """Split on markdown headings, packing sections up to `max_chars`.

    Splitting on headings rather than a fixed window keeps each request coherent
    — a section about one service stays intact instead of being cut mid-command.
    """
    max_chars = max_chars or WALKTHROUGH_CHUNK_CHARS
    if len(text) <= max_chars:
        return [text]

    # Keep the heading with the body that follows it.
    parts = re.split(r"\n(?=#{1,3} )", text)
    chunks, buf = [], ""
    for part in parts:
        if buf and len(buf) + len(part) > max_chars:
            chunks.append(buf.strip())
            buf = part
        else:
            buf = f"{buf}\n{part}" if buf else part
    if buf.strip():
        chunks.append(buf.strip())

    # A single section larger than the budget still has to be broken up.
    out = []
    for c in chunks:
        while len(c) > max_chars * 2:
            out.append(c[:max_chars])
            c = c[max_chars:]
        out.append(c)
    return [c for c in out if c.strip()][:WALKTHROUGH_MAX_CHUNKS]


def _llm_extract(chunk: str, guide: str, existing: List[Dict]) -> Tuple[List, List, List, str]:
    """One LLM call over one chunk. Returns (prompts, service_docs, skipped, model).

    Never raises on a bad response — a chunk that fails to parse is skipped so
    one awkward section doesn't lose the whole document.
    """
    parts = [guide]
    if existing:
        parts.append(
            "\n# Existing rules that already cover services here\n"
            "Extend or sharpen these rather than restating them:\n"
            + json.dumps(existing, indent=2)
        )
    parts.append("\n# Walkthrough\n\n" + chunk)

    try:
        result = ollama_query(
            prompt="\n".join(parts), timeout=WALKTHROUGH_LLM_TIMEOUT,
            options={"num_ctx": WALKTHROUGH_NUM_CTX, "num_predict": WALKTHROUGH_NUM_PREDICT},
        )
    except requests.RequestException as e:
        logger.warning("[walkthrough] LLM call failed for a chunk: %s", e)
        return [], [], [], ""

    raw = result.get("response", "")
    model = result.get("model", "")
    text = re.sub(r"^\s*```(?:ya?ml|json)?\s*|\s*```\s*$", "", (raw or "").strip())
    try:
        import yaml as _yaml
        parsed = _yaml.safe_load(text) or {}
    except Exception as e:
        logger.warning("[walkthrough] unparsable chunk response (%s) — skipping", e)
        return [], [], [], model
    if not isinstance(parsed, dict):
        return [], [], [], model

    # Reasoning models wrap the payload, e.g. {"thought": ..., "prompts": [...]}.
    if "prompts" not in parsed and "service_docs" not in parsed:
        for value in parsed.values():
            if isinstance(value, dict) and ("prompts" in value or "service_docs" in value):
                parsed = value
                break

    return (parsed.get("prompts") or [], parsed.get("service_docs") or [],
            parsed.get("skipped") or [], model)


def coverage_report(text: str, prompts: List[Dict], skipped: List[Dict] = None) -> Dict:
    """Which services the document mentions vs which became rules.

    A thin conversion is otherwise indistinguishable from a thin document: the
    Rapid7 Metasploitable guide covers ~20 services and produced 7 rules, and
    nothing in the output said so. This names the gap explicitly.

    Detection reuses the KB's own vocabulary (97 services + 17 tech signatures)
    rather than a hand-kept list, so it stays current as the KB grows.
    """
    low = (text or "").lower()
    try:
        kb = get_tool_kb()
        # alias -> canonical, so a document saying "Samba" or "microsoft-ds" is
        # credited against the KB's canonical "smb". Reporting the CANONICAL name
        # matters: that is the value a rule must use for it to actually fire.
        import tool_kb as _tool_kb
        vocab = {n: n for n in (kb.get_all_services() or [])}
        vocab.update({k: v for k, v in (getattr(_tool_kb, "_SERVICE_ALIASES", {}) or {}).items()
                      if v in vocab})
        vocab.update({t: t for t in (kb._data.get("tech_signatures") or {})})
    except Exception as e:
        logger.debug("coverage: KB unavailable (%s)", e)
        return {}

    # Word-boundary match so short names don't fire inside unrelated words.
    mentioned = {canonical for term, canonical in vocab.items()
                 if len(term) > 2 and re.search(r"\b" + re.escape(term) + r"\b", low)}

    covered = set()
    for p in prompts:
        for field in ("service", "tech"):
            v = (p.get(field) or "").strip().lower()
            if v:
                covered.add(v)

    skipped_names = {(s.get("service") or s.get("tech") or "").strip().lower()
                     for s in (skipped or [])}
    skipped_names.discard("")

    missed = sorted(mentioned - covered - skipped_names)
    return {
        "mentioned": sorted(mentioned),
        "covered": sorted(covered & mentioned),
        "missed": missed,
        "skipped": [s for s in (skipped or []) if isinstance(s, dict)],
        "coverage_pct": (
            round(100 * len(covered & mentioned) / len(mentioned)) if mentioned else None
        ),
        "rules_total": len(prompts),
        # Rules for things the KB has no vocabulary for (mutillidae, distcc,
        # unrealircd) are real output but cannot be counted against `mentioned`,
        # so the percentage understates. Surfaced to keep it from reading as a
        # failure when the rule count is healthy.
        "rules_outside_kb_vocabulary": sorted(covered - mentioned),
    }


# Cap on the gap pass. Bounded so a document naming fifty services can't turn
# one import into fifty LLM calls.
WALKTHROUGH_GAP_MAX = int(os.environ.get("WALKTHROUGH_GAP_MAX", "15"))
# How much surrounding text to hand the focused call. Small on purpose: naming
# one service and showing only where it appears is a task a local model does
# reliably, unlike "find everything in this document".
WALKTHROUGH_GAP_WINDOW = int(os.environ.get("WALKTHROUGH_GAP_WINDOW", "2500"))


def _slices_mentioning(text: str, term: str, window: int = None,
                       max_slices: int = 3) -> str:
    """Text around each mention of `term`, joined.

    The focused pass only needs the parts of the document that actually discuss
    the service; sending the whole thing reintroduces the problem the gap pass
    exists to solve.
    """
    window = window or WALKTHROUGH_GAP_WINDOW
    low, out, start = text.lower(), [], 0
    rx = re.compile(r"\b" + re.escape(term.lower()) + r"\b")
    for m in rx.finditer(low):
        if len(out) >= max_slices:
            break
        a = max(0, m.start() - window // 3)
        b = min(len(text), m.end() + window)
        if out and a < start:      # overlapping window; skip
            continue
        out.append(text[a:b])
        start = b
    return "\n...\n".join(out)


def _extract_for_service(text: str, term: str, guide: str) -> List[Dict]:
    """One focused call: extract rules for a single named service.

    Returns [] rather than raising — a failed gap call must not lose the rules
    the first pass already found.
    """
    excerpt = _slices_mentioning(text, term)
    if len(excerpt.strip()) < 120:
        return []          # only a passing mention; nothing to extract

    prompt = (
        guide
        + f"\n\n# This run is narrowed to ONE service: {term}\n"
        + f"Extract rules for **{term}** only, from the excerpt below. Ignore every\n"
        + "other service. If the excerpt gives real technique for it, emit one or two\n"
        + f"rules. If it only mentions {term} in passing with no technique, return\n"
        + "`prompts: []` — do not invent anything to fill the gap.\n"
        + f"\n# Excerpt\n\n{excerpt}"
    )
    try:
        result = ollama_query(
            prompt=prompt, timeout=WALKTHROUGH_LLM_TIMEOUT,
            options={"num_ctx": WALKTHROUGH_NUM_CTX, "num_predict": 2048},
        )
    except requests.RequestException as e:
        logger.warning("[walkthrough] gap call failed for %s: %s", term, e)
        return []

    raw = re.sub(r"^\s*```(?:ya?ml|json)?\s*|\s*```\s*$", "",
                 (result.get("response") or "").strip())
    try:
        import yaml as _yaml
        parsed = _yaml.safe_load(raw) or {}
    except Exception:
        return []
    if not isinstance(parsed, dict):
        return []
    if "prompts" not in parsed:
        for v in parsed.values():
            if isinstance(v, dict) and "prompts" in v:
                parsed = v
                break
    return [e for e in (parsed.get("prompts") or []) if isinstance(e, dict)]


def convert_text_to_knowledge(content: str, source: str, focus: Optional[str] = None,
                              include_existing: bool = True,
                              gap_pass: bool = True) -> Dict:
    """Shared conversion pipeline: text -> drafted rules + seed YAML.

    Called by both the walkthrough endpoint and the URL endpoint so the guiding
    prompt, scrubber, validator and renderer have exactly one implementation —
    a second copy would drift and let one path emit entries the other refuses.
    """
    content = (content or "").strip()
    if not content:
        raise HTTPException(400, "content is required")
    if len(content) > 400_000:
        raise HTTPException(413, "walkthrough too large (limit 400KB)")

    source = (source or "pasted").strip()
    guide = resolve_walkthrough_prompt(focus)
    if not guide:
        raise HTTPException(
            500,
            f"No guiding prompt available: {WALKTHROUGH_PROMPT_PATH} is unreadable and "
            "no override is set. Check that ./knowledge:/knowledge:ro is mounted.",
        )

    existing = _existing_rules_for(content) if include_existing else []

    # Convert section by section and merge. Each request stays small enough to
    # complete, so a long guide no longer silently yields nothing.
    chunks = _split_for_conversion(content)
    logger.info("[walkthrough] %s: %d char(s) in %d chunk(s)", source, len(content), len(chunks))

    prompts_in, docs_in, model = [], [], ""
    skipped_in: List[Dict] = []
    seen_keys = set()
    for i, chunk in enumerate(chunks, 1):
        c_prompts, c_docs, c_skipped, c_model = _llm_extract(chunk, guide, existing)
        skipped_in.extend(x for x in c_skipped if isinstance(x, dict))
        model = model or c_model
        for e in c_prompts:
            if not isinstance(e, dict):
                continue
            # Sections often repeat a service; keep the first, drop re-statements.
            key = (str(e.get("selector_type")), str(e.get("service") or ""),
                   str(e.get("tech") or ""), str(e.get("port") or ""),
                   str(e.get("title") or "").strip().lower())
            if key in seen_keys:
                continue
            seen_keys.add(key)
            prompts_in.append(e)
        docs_in.extend(d for d in c_docs if isinstance(d, dict))
        logger.info("[walkthrough]   chunk %d/%d → %d rule(s)", i, len(chunks), len(c_prompts))

    # ── Gap pass ────────────────────────────────────────────────────────────
    # The chunk pass asks "find everything", which a local model does poorly on a
    # long catalogue. Coverage already knows exactly what it missed, so re-ask
    # for those services one at a time — a focused prompt naming one service is
    # a task a small model handles reliably. Cost scales with the gap, not the
    # document.
    gap_stats = {"attempted": [], "recovered": 0, "skipped_cap": 0}
    if gap_pass and prompts_in:
        provisional = coverage_report(content, [
            {"service": e.get("service"), "tech": e.get("tech")} for e in prompts_in
        ], skipped_in)
        missed = provisional.get("missed") or []
        if len(missed) > WALKTHROUGH_GAP_MAX:
            gap_stats["skipped_cap"] = len(missed) - WALKTHROUGH_GAP_MAX
            missed = missed[:WALKTHROUGH_GAP_MAX]
        for term in missed:
            gap_stats["attempted"].append(term)
            found = _extract_for_service(content, term, guide)
            for e in found:
                key = (str(e.get("selector_type")), str(e.get("service") or ""),
                       str(e.get("tech") or ""), str(e.get("port") or ""),
                       str(e.get("title") or "").strip().lower())
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                prompts_in.append(e)
                gap_stats["recovered"] += 1
        if gap_stats["attempted"]:
            logger.info("[walkthrough] gap pass: %d service(s) re-asked, %d rule(s) recovered%s",
                        len(gap_stats["attempted"]), gap_stats["recovered"],
                        f", {gap_stats['skipped_cap']} beyond cap" if gap_stats["skipped_cap"] else "")

    if not prompts_in and not docs_in:
        raise HTTPException(
            422,
            "The model returned nothing usable from any section. It may be too small for "
            "structured extraction at this length — try a narrower focus, or a hosted "
            "LLM_BACKEND.",
        )
    tag = f"source:walkthrough:{source}"

    prompts, rejected = [], []
    flagged_p: Dict[int, List[str]] = {}
    for entry in prompts_in:
        if not isinstance(entry, dict):
            rejected.append({"entry": str(entry)[:120], "reason": "not a mapping"})
            continue
        entry = repair_entry(entry)      # fix wrong-field / missing-selector cases first
        service, tech, port, error = normalize_selector(
            entry.get("selector_type"), entry.get("service"),
            entry.get("tech"), entry.get("port"), entry.get("title"),
        )
        if error:
            rejected.append({"entry": str(entry.get("title") or entry)[:120], "reason": error})
            continue
        clean = {
            "selector_type": (entry.get("selector_type") or "").strip().lower(),
            "title": (entry.get("title") or "").strip(),
            "prompt": (entry.get("prompt") or "").strip(),
        }
        if service: clean["service"] = service
        if tech:    clean["tech"] = tech
        if port:    clean["port"] = port
        if entry.get("training_notes"):
            clean["training_notes"] = entry["training_notes"]
        tags = [str(t) for t in (entry.get("tags") or []) if t]
        clean["tags"] = tags + [tag]          # attribution: bulk-removable later
        if entry.get("priority") is not None:
            try: clean["priority"] = int(entry["priority"])
            except (TypeError, ValueError): pass
        reasons = scrub_entry(clean)
        if reasons:
            flagged_p[len(prompts)] = reasons
        prompts.append(clean)

    docs = []
    flagged_d: Dict[int, List[str]] = {}
    for entry in docs_in:
        if not isinstance(entry, dict):
            rejected.append({"entry": str(entry)[:120], "reason": "not a mapping"})
            continue
        if not (entry.get("title") or "").strip() or not (entry.get("content") or "").strip():
            rejected.append({"entry": str(entry.get("title") or entry)[:120],
                             "reason": "training doc needs a title and content"})
            continue
        if not any(entry.get(k) for k in ("service", "port", "tech")):
            rejected.append({"entry": (entry.get("title") or "")[:120],
                             "reason": "training doc needs at least one of service, port, tech"})
            continue
        clean = {k: entry[k] for k in ("title", "service", "port", "tech", "content")
                 if entry.get(k) not in (None, "")}
        reasons = scrub_entry(clean)
        if reasons:
            flagged_d[len(docs)] = reasons
        docs.append(clean)

    yaml_text = render_seed_yaml(prompts, docs, flagged_p, flagged_d, source)

    # Each chunk reports skips from ITS OWN view of the document. A service the
    # port-list chunk dismissed as "no technique given" may be covered in depth
    # by a later chunk, so a skip that contradicts an actual rule is dropped —
    # otherwise the report claims FTP was untouched while an FTP rule sits in
    # the output.
    covered_names = {(p.get("service") or p.get("tech") or "").strip().lower()
                     for p in prompts}
    covered_names.discard("")
    skipped_in = [x for x in skipped_in
                  if (x.get("service") or x.get("tech") or "").strip().lower()
                  not in covered_names]

    coverage = coverage_report(content, prompts, skipped_in)
    if coverage.get("missed"):
        logger.info("[walkthrough] %s: %d/%d services covered, missed: %s",
                    source, len(coverage["covered"]), len(coverage["mentioned"]),
                    ", ".join(coverage["missed"][:12]))

    logger.info(
        "[walkthrough] %s → %d rules (%d flagged), %d docs (%d flagged), %d rejected",
        source, len(prompts), len(flagged_p), len(docs), len(flagged_d), len(rejected),
    )
    _emit_webhook("walkthrough_converted", {
        "source": source, "model": model,
        "prompts": len(prompts), "flagged": len(flagged_p) + len(flagged_d),
        "docs": len(docs), "rejected": len(rejected),
    })

    return {
        "ok": True, "source": source, "model": model,
        "prompts": prompts, "service_docs": docs,
        "flagged": (
            [{"kind": "prompt", "index": i, "title": prompts[i].get("title"), "reasons": r}
             for i, r in flagged_p.items()]
            + [{"kind": "service_doc", "index": i, "title": docs[i].get("title"), "reasons": r}
               for i, r in flagged_d.items()]
        ),
        "rejected": rejected,
        "existing_considered": existing,
        "coverage": coverage,
        "gap_pass": gap_stats,
        "yaml": yaml_text,
    }


class UrlConvertBody(BaseModel):
    url: str
    depth: int = 0                    # 0 = just this page; 1 = same-origin links too
    max_pages: int = 1
    allow_internal: bool = False      # opt-in for deliberate internal sources
    proxy: Optional[str] = None
    focus: Optional[str] = None
    make_playbook: bool = True
    include_existing: bool = True
    gap_pass: bool = True


@kb_router.post("/url/convert")
def convert_url(body: UrlConvertBody):
    """Fetch a published guide and draft knowledge from it. Never writes.

    Returns both outputs: a seed YAML of per-service rules (review-gated, same
    as the walkthrough path) and a cleaned playbook markdown. A broad guide is
    usually both — per-service technique AND methodology worth retrieving whole.

    The playbook is RETURNED rather than written: knowledge/ is mounted
    read-only, deliberately, so the service cannot rewrite its own knowledge
    base. The CLI/UI writes it.
    """
    from url_fetch import UrlFetchError, fetch_guide, slugify

    try:
        fetched = fetch_guide(
            body.url, depth=body.depth, max_pages=body.max_pages,
            allow_internal=body.allow_internal, proxy=body.proxy,
        )
    except UrlFetchError as e:
        # Refusals are operator-fixable (wrong scheme, internal address, too
        # big), so surface them as 400 with the reason intact.
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.exception("URL fetch failed for %s", body.url)
        raise HTTPException(502, f"Could not fetch {body.url}: {e}")

    text = fetched["markdown"]
    if len(text.strip()) < 200:
        raise HTTPException(
            422,
            f"Fetched {body.url} but extracted only {len(text.strip())} characters of text. "
            "The page may be JavaScript-rendered or behind a login.",
        )

    pages = fetched["pages"]
    title = pages[0]["title"] if pages else ""
    slug = slugify(body.url, title)

    result = convert_text_to_knowledge(
        content=text, source=slug, focus=body.focus,
        include_existing=body.include_existing, gap_pass=body.gap_pass,
    )

    playbook = ""
    if body.make_playbook:
        header = [f"# {title or slug}", ""]
        header.append(f"Imported from {body.url}" if len(pages) == 1
                      else f"Imported from {body.url} ({len(pages)} pages)")
        header.append("")
        playbook = "\n".join(header) + text

    logger.info("[url_convert] %s → %d page(s), %d rule(s), playbook=%dch",
                body.url, len(pages), len(result.get("prompts") or []), len(playbook))
    _emit_webhook("url_guide_imported", {
        "url": body.url, "pages": len(pages), "slug": slug,
        "prompts": len(result.get("prompts") or []),
        "flagged": len(result.get("flagged") or []),
        "playbook_chars": len(playbook),
    })

    result.update({
        "url": body.url,
        "pages": [{"url": p["url"], "title": p["title"], "chars": p["chars"]} for p in pages],
        "fetch_errors": fetched["errors"],
        "playbook_markdown": playbook,
        "playbook_filename": f"{slug}.md",
        "seed_filename": f"{slug}.yaml",
    })
    return result


app.include_router(kb_router)


# ---- Logs UI Endpoints ----
@app.get("/logs/ui", response_class=HTMLResponse)
async def logs_ui():
    """Serve the logs web UI"""
    return HTMLResponse(content=LOGS_UI_HTML)


@app.get("/logs")
async def get_logs(
    level: Optional[str] = Query(None, description="Filter by log level"),
    limit: int = Query(100, ge=1, le=1000, description="Max logs to return"),
    search: Optional[str] = Query(None, description="Search in log messages"),
    request_id: Optional[str] = Query(None, description="Filter by request ID")
):
    """Get logs with optional filtering"""
    handler = get_log_handler()
    logs = await handler.async_get_logs(level=level, limit=limit, search=search, request_id=request_id)
    return {"logs": logs}


@app.get("/logs/stats")
async def get_log_stats():
    """Get logging statistics"""
    handler = get_log_handler()
    stats = await handler.async_get_stats()
    return {"ok": True, "stats": stats}


@app.get("/logs/export")
async def export_logs():
    """Export all logs as JSON file"""
    handler = get_log_handler()
    json_data = await handler.async_export_json()
    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=exploitdb_logs.json"}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("scan_recommender:app", host=os.environ.get("HOST", "0.0.0.0", ssl_certfile=os.environ.get("SSL_CERTFILE"), ssl_keyfile=os.environ.get("SSL_KEYFILE")), port=int(os.environ.get("PORT", "8013")))
