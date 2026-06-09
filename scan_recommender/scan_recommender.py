# scan_recommender.py (unified + Ollama query & health endpoints)
import os
import json
import logging
import threading
from contextlib import contextmanager
from typing import Any, List, Optional, Dict

import requests
import psycopg2
from psycopg2.extras import RealDictCursor, Json
from fastapi import FastAPI, APIRouter, Query, HTTPException, Body
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from exploits_rag import rag_router
from tool_kb import get_tool_kb, get_high_value_port_info
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


def _kb_result_to_recommendations(kb_result: Dict) -> List[Dict]:
    """Convert ToolKnowledgeBase result into List[Dict] recommendation format.
    Tags tools with their purpose_group so the UI can group overlapping tools."""

    # Tools that serve the same purpose — tagged so UI can group them
    PURPOSE_GROUPS = {
        "content_discovery": ["gobuster", "feroxbuster", "dirsearch", "wfuzz", "ffuf"],
        "web_vuln_scan": ["nikto", "nuclei"],
        "tech_fingerprint": ["whatweb", "wappalyzer"],
        "sql_injection": ["sqlmap"],
    }
    _tool_to_group = {}
    for group, tools in PURPOSE_GROUPS.items():
        for t in tools:
            _tool_to_group[t] = group

    recs: List[Dict] = []

    for tool in kb_result.get("tools", []):
        name = tool.get("name", "unknown").lower()
        recs.append({
            "scanner": tool.get("name", "unknown"),
            "action": tool.get("purpose"),
            "script": tool.get("command"),
            "template": None,
            "purpose_group": _tool_to_group.get(name),
        })

    # nuclei_tags → one recommendation
    tags = kb_result.get("nuclei_tags", [])
    if tags:
        recs.append({
            "scanner": "nuclei",
            "action": "template scan",
            "script": None,
            "template": ",".join(tags),
        })

    # Each metasploit[] entry
    for msf in kb_result.get("metasploit", []):
        recs.append({
            "scanner": "metasploit",
            "action": msf.get("purpose"),
            "script": msf.get("module"),
            "template": None,
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


def _append_vulnx_rec(recs: List[Dict], row: Dict):
    """Append a vulnx CVE lookup recommendation when product/banner info is available."""
    product = (row.get("product") or "").strip()
    version = (row.get("version") or "").strip()
    banner_text = (row.get("banner") or "").strip()
    if product or banner_text:
        query_parts = [product, version] if product else [banner_text]
        recs.append({
            "scanner": "vulnx",
            "action": f"CVE lookup for {' '.join(filter(None, query_parts))}",
            "script": None,
            "template": None,
        })


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


def _append_proactive_vulnx_recs(recs: List[Dict], ip: str):
    """Append proactive vulnx recommendations based on all discovered software for the IP."""
    discovered = _get_discovered_software(ip=ip, limit=20)  # Limit to prevent overwhelming recommendations

    if not discovered:
        return

    vulnx_recs = _generate_vulnx_recommendations_for_software(discovered)

    # Add up to 5 most relevant vulnx recommendations to avoid overwhelming the user
    for i, rec in enumerate(vulnx_recs[:5]):
        # Add priority based on version availability (versioned software gets higher priority)
        software_ctx = rec.get("software_context", {})
        # Priority scale (lower = runs first): high-value-port MSF=5,
        # high-value-port=10, tech-targeted=15, then proactive vulnx.
        if software_ctx.get("version"):
            rec["priority"] = 20  # versioned software (more actionable)
        else:
            rec["priority"] = 30  # unversioned software

        recs.append(rec)

    logger.info(f"Added {len(vulnx_recs[:5])} proactive vulnx recommendations for {ip} (from {len(discovered)} discovered software products)")


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
    _append_vulnx_rec(recs, row)
    _append_common_web_fallback(recs, port)
    if ip:
        _append_tech_targeted_recs(recs, ip, port)      # G1
        _append_proactive_vulnx_recs(recs, ip)
    _append_high_value_port_recs(recs, port)            # G2 (last)
    return _stamp_source_context(recs, row, port)


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
                    "SELECT id FROM public.assets WHERE host(ip)=%s "
                    "ORDER BY last_seen DESC NULLS LAST, first_seen DESC NULLS LAST "
                    "LIMIT 1",
                    (ip,),
                )
                row = cur.fetchone()
                if row:
                    asset_id = row["id"]
                cur.execute("RELEASE SAVEPOINT asset_lookup")
            except Exception as e:
                cur.execute("ROLLBACK TO SAVEPOINT asset_lookup")
                logger.debug(f"asset_id resolution skipped for {ip}: {e}")

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
                  (asset_id, ip, service, banner, scanner, action, script, template, source, model, extra, priority)
                VALUES
                  (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s, 50))
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
                ),
            )
            if cur.rowcount > 0:
                inserted += 1
        conn.commit()
    return inserted


# ---- Ollama primitives ----
def _ollama_streamed_generate(prompt: str, model: str, endpoint: str) -> str:
    payload = {"model": model, "prompt": prompt, "format": "json", "stream": True}
    full = ""
    with requests.post(endpoint, json=payload, stream=True, timeout=120) as r:
        r.raise_for_status()
        for line in r.iter_lines():
            if not line:
                continue
            chunk = json.loads(line.decode("utf-8"))
            # Ollama streams {"response": "..."} lines; could also have "done": true
            if "response" in chunk:
                full += chunk["response"]
            if chunk.get("done"):
                break
    return full


def _ollama_nonstream_generate(prompt: str, model: str, endpoint: str) -> str:
    payload = {"model": model, "prompt": prompt, "format": "json", "stream": False}
    with requests.post(endpoint, json=payload, timeout=120) as r:
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


def _azure_generate(prompt: str, json_mode: bool = False) -> str:
    """Call Azure chat completions and return the assistant message content."""
    url = _azure_chat_url(AZURE_ENDPOINT, AZURE_MODEL, AZURE_API_VERSION)
    payload: Dict[str, Any] = {
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 2048,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    r = requests.post(url, json=payload, headers=_azure_headers(), timeout=120)
    r.raise_for_status()
    data = r.json()
    return data["choices"][0]["message"]["content"]


def _openai_headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {OPENAI_API_KEY}", "Content-Type": "application/json"}


def _openai_generate(prompt: str, json_mode: bool = False) -> str:
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
    r = requests.post(url, json=payload, headers=_openai_headers(), timeout=120)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"]


def _anthropic_headers() -> Dict[str, str]:
    return {
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }


def _anthropic_generate(prompt: str) -> str:
    """Call Anthropic messages API and return the text content."""
    payload = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": prompt}],
    }
    r = requests.post("https://api.anthropic.com/v1/messages",
                      json=payload, headers=_anthropic_headers(), timeout=120)
    r.raise_for_status()
    data = r.json()
    for block in data.get("content", []):
        if block.get("type") == "text":
            return block["text"]
    return ""


def _safe_json_parse(text: str) -> Dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Return as plain text wrapped in JSON if not valid JSON
        return {"response": text}


def ollama_query(prompt: str, model: Optional[str] = None, stream: bool = False) -> Dict:
    if LLM_BACKEND == "azure":
        mdl = AZURE_MODEL or "gpt-4o"
        try:
            text = _azure_generate(prompt)
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
            text = _openai_generate(prompt)
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
            text = _anthropic_generate(prompt)
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
        text = _ollama_streamed_generate(prompt, mdl, endpoint) if stream else _ollama_nonstream_generate(prompt, mdl, endpoint)
    except requests.HTTPError as e:
        # Retry once with normalized endpoint if 405
        if e.response is not None and e.response.status_code == 405:
            endpoint = resolve_ollama_generate_endpoint(OLLAMA_BASE_URL)
            text = _ollama_streamed_generate(prompt, mdl, endpoint) if stream else _ollama_nonstream_generate(prompt, mdl, endpoint)
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


def fetch_ollama_recommendations(
    ip: str, service: Optional[str], banner: Optional[str], model: str = OLLAMA_MODEL
) -> List[Dict[str, str]]:
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
  banner: {banner!r}
- Prefer practical web and service probes (nmap scripts, nuclei templates, ZAP actions).
"""
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
        data = json.loads(text)
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
            ollama_recs = fetch_ollama_recommendations(ip, service, banner)
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
):
    """List all scan recommendations from the database."""
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
