"""
BFF router for remote node management.

Proxies requests to the node-manager service and handles
dispatching scans through remote node SOCKS proxies.
"""

import asyncio
import logging
from typing import Optional
from utils import safe_json

import httpx
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Request, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from config import get_settings
from polling import register_job, active_jobs, pending_queue
from routers.scans import MAX_CONCURRENT_SCANS, _count_active_scans

log = logging.getLogger("nodes")
router = APIRouter()


# ---------------------------------------------------------------------------
# Proxy helpers
# ---------------------------------------------------------------------------
async def _nm_get(path: str, retries: int = 3, backoff: float = 2.0) -> dict:
    """GET from node-manager with retry + exponential backoff."""
    s = get_settings()
    url = f"{s.tunnel_manager_url}{path}"
    last_error = None
    for attempt in range(retries):
        try:
            async with httpx.AsyncClient(verify=False, timeout=30) as c:
                resp = await c.get(url)
            if resp.status_code < 400:
                return safe_json(resp)
            last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
            # 404 on proxy lookup = node may still be connecting — retry
            if resp.status_code == 404 and attempt < retries - 1:
                wait = backoff * (2 ** attempt)
                log.warning("node-manager %s returned 404 (attempt %d/%d), retrying in %.1fs — %s",
                            path, attempt + 1, retries, wait, last_error)
                await asyncio.sleep(wait)
                continue
            # Other 4xx/5xx — don't retry
            raise HTTPException(resp.status_code, resp.text)
        except HTTPException:
            raise
        except Exception as e:
            last_error = str(e)
            if attempt < retries - 1:
                wait = backoff * (2 ** attempt)
                log.warning("node-manager %s failed (attempt %d/%d), retrying in %.1fs — %s",
                            path, attempt + 1, retries, wait, e)
                await asyncio.sleep(wait)
            else:
                log.error("node-manager %s failed after %d attempts: %s", path, retries, e)
                raise HTTPException(502, f"Node manager unreachable after {retries} attempts: {last_error}")
    raise HTTPException(502, f"Node manager failed after {retries} attempts: {last_error}")


async def _nm_post(path: str, payload: dict = None, retries: int = 2, backoff: float = 2.0) -> dict:
    """POST to node-manager with retry + exponential backoff."""
    s = get_settings()
    url = f"{s.tunnel_manager_url}{path}"
    last_error = None
    for attempt in range(retries):
        try:
            async with httpx.AsyncClient(verify=False, timeout=60) as c:
                resp = await c.post(url, json=payload or {})
            if resp.status_code < 400:
                return safe_json(resp)
            last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
            if resp.status_code in (502, 503) and attempt < retries - 1:
                wait = backoff * (2 ** attempt)
                log.warning("node-manager POST %s returned %d (attempt %d/%d), retrying in %.1fs",
                            path, resp.status_code, attempt + 1, retries, wait)
                await asyncio.sleep(wait)
                continue
            raise HTTPException(resp.status_code, resp.text)
        except HTTPException:
            raise
        except Exception as e:
            last_error = str(e)
            if attempt < retries - 1:
                wait = backoff * (2 ** attempt)
                log.warning("node-manager POST %s failed (attempt %d/%d), retrying in %.1fs — %s",
                            path, attempt + 1, retries, wait, e)
                await asyncio.sleep(wait)
            else:
                log.error("node-manager POST %s failed after %d attempts: %s", path, retries, e)
                raise HTTPException(502, f"Node manager unreachable after {retries} attempts: {last_error}")
    raise HTTPException(502, f"Node manager failed after {retries} attempts: {last_error}")


async def _nm_delete(path: str) -> dict:
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.delete(f"{s.tunnel_manager_url}{path}")
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


# ---------------------------------------------------------------------------
# Node CRUD
# ---------------------------------------------------------------------------
@router.get("/api/nodes")
async def list_nodes():
    return await _nm_get("/nodes")


@router.get("/api/nodes/{node_id}")
async def get_node(node_id: str):
    return await _nm_get(f"/nodes/{node_id}")


@router.post("/api/nodes/register")
async def register_node(payload: dict):
    return await _nm_post("/nodes/register", payload)


@router.delete("/api/nodes/{node_id}")
async def decommission_node(node_id: str):
    return await _nm_delete(f"/nodes/{node_id}")


# ---------------------------------------------------------------------------
# Proxy info
# ---------------------------------------------------------------------------
@router.get("/api/nodes/{node_id}/proxy")
async def get_proxy(node_id: str):
    return await _nm_get(f"/nodes/{node_id}/proxy")


# ---------------------------------------------------------------------------
# SOCKS management
# ---------------------------------------------------------------------------
@router.post("/api/nodes/{node_id}/socks/start")
async def start_socks(node_id: str, payload: dict = {}):
    return await _nm_post(f"/nodes/{node_id}/socks/start", payload)


@router.post("/api/nodes/{node_id}/socks/stop")
async def stop_socks(node_id: str):
    return await _nm_post(f"/nodes/{node_id}/socks/stop")


# ---------------------------------------------------------------------------
# Scan through node — routes scan to scanner with SOCKS proxy
# ---------------------------------------------------------------------------
class NodeScanRequest(BaseModel):
    model_config = {"extra": "allow"}  # Pass through scan-specific params (content-recon toggles, etc.)
    scan_type: str
    target: Optional[str] = None
    targets: Optional[list[str]] = None
    target_url: Optional[str] = None
    target_urls: Optional[list[str]] = None
    ports: Optional[str] = None
    rate: Optional[int] = None
    severity: Optional[str] = None
    limit: Optional[int] = None
    depth: Optional[int] = None
    aggression: Optional[int] = None
    query: Optional[str] = None
    engine: Optional[str] = None
    skip_phases: Optional[list[str]] = None
    scope_name: Optional[str] = None
    engagement_id: Optional[str] = None


SCAN_ROUTE_MAP = {
    # Network scanning
    "nmap": ("nmap_scanner_url", "/jobs/masscan-then-nmap"),
    "nmap-tcp": ("nmap_scanner_url", "/jobs/masscan-then-nmap"),  # standalone nmap -sT (proxy-aware)
    "full": ("nmap_scanner_url", "/jobs/full-scan"),
    "masscan": ("nmap_scanner_url", "/jobs/masscan-only"),
    "udp": ("nmap_scanner_url", "/jobs/nmap-udp"),
    # Web scanning
    "nuclei": ("nuclei_url", "/jobs/nuclei-scan"),
    "web": ("web_scanner_url", "/jobs/web-scan"),
    "pipeline": ("web_scanner_url", "/jobs/pipeline-scan"),
    "nikto": ("web_scanner_url", "/jobs/nikto-scan"),
    # Active recon (pd-runner)
    "httpx": ("pd_runner_url", "/jobs/httpx"),
    "naabu": ("pd_runner_url", "/jobs/naabu"),
    "katana": ("pd_runner_url", "/jobs/katana"),
    "tlsx": ("pd_runner_url", "/jobs/tlsx"),
    "whatweb": ("pd_runner_url", "/jobs/whatweb"),
    # Passive recon (osint-runner)
    "subfinder": ("osint_runner_url", "/jobs/subfinder"),
    "dnsx": ("osint_runner_url", "/jobs/dnsx"),
    "uncover": ("osint_runner_url", "/jobs/uncover"),
    "chaos": ("osint_runner_url", "/jobs/chaos"),
    "shuffledns": ("osint_runner_url", "/jobs/shuffledns"),
    "crtsh": ("osint_runner_url", "/jobs/crtsh"),
    "recon-pipeline": ("osint_runner_url", "/jobs/recon-pipeline"),
    "passive-recon": ("osint_runner_url", "/jobs/passive-recon"),
    "wafw00f": ("osint_runner_url", "/jobs/wafw00f"),
    "amass": ("osint_runner_url", "/jobs/amass"),
    "gau": ("osint_runner_url", "/jobs/gau"),
    "waybackurls": ("osint_runner_url", "/jobs/waybackurls"),
    "gowitness": ("osint_runner_url", "/jobs/gowitness"),
    "greyhatwarfare": ("osint_runner_url", "/jobs/greyhatwarfare"),
    "trufflehog": ("osint_runner_url", "/jobs/trufflehog"),
    "censys": ("osint_runner_url", "/jobs/censys"),
    "ffuf": ("pd_runner_url", "/jobs/ffuf"),
    # Subdomain takeover + JS endpoints
    "subzy": ("osint_runner_url", "/jobs/subzy"),
    "golinkfinder": ("osint_runner_url", "/jobs/golinkfinder"),
    # WHOIS
    "whois": ("osint_runner_url", "/jobs/whois"),
    # Service enumeration
    "email-enum": ("osint_runner_url", "/jobs/email-enum"),
    "dns-enum": ("osint_runner_url", "/jobs/dns-enum"),
    "service-enum": ("osint_runner_url", "/jobs/service-enum"),
    # Web content / recon pipelines
    "gobuster": ("web_scanner_url", "/jobs/gobuster"),
    "content-recon": ("web_scanner_url", "/jobs/content-recon"),
    # Tools that don't support SOCKS proxy — added so they appear in route map
    # but get redirected to remote exec on SSH nodes
    "playwright": ("playwright_scanner_url", "/scan"),
    "brutus": ("brutus_runner_url", "/jobs/brutus"),
}


# Scan types that use raw sockets and CANNOT work through a SOCKS proxy.
# These must be routed as SSH remote commands when the node is SSH type.
# NOTE: "nmap" and "full" are NOT here because the nmap-api handles proxy mode
# internally (skips masscan, runs nmap -sT --proxies).
_RAW_SOCKET_SCANS = {"masscan", "udp"}

# Scan types that don't accept a proxy parameter at all.
# On SSH nodes these are pushed to the remote end for direct execution.
_NO_PROXY_SCANS = {"playwright", "brutus", "email-enum", "dns-enum", "service-enum", "whois"}

# Mapping from scan_type to remote-scan template name
_REMOTE_SCAN_MAP = {
    "masscan": "masscan",
    "udp": "nmap",      # UDP uses nmap
    "brutus": "hydra",   # hydra on remote node replaces brutus
    "playwright": "playwright",
    "email-enum": "email-enum",
    "dns-enum": "dns-enum",
    "service-enum": "service-enum",
    "whois": "whois",
}


@router.post("/api/nodes/{node_id}/scan")
async def scan_through_node(node_id: str, req: NodeScanRequest):
    """Dispatch a scan routed through a remote node's SOCKS proxy.

    Raw-socket scans (masscan, nmap, full, udp) cannot traverse SOCKS proxies.
    When the node is SSH type, these are automatically routed as remote commands
    executed directly on the SSH host via node-manager's remote-scan endpoint.
    """
    if req.scan_type not in SCAN_ROUTE_MAP:
        raise HTTPException(400, f"Unsupported proxied scan type: {req.scan_type}")

    # Get proxy address and node type from node-manager (with retry for nodes still connecting)
    log.info("Scan through node %s: type=%s, targets=%s", node_id[:12], req.scan_type,
             req.target or req.targets)
    proxy_info = await _nm_get(f"/nodes/{node_id}/proxy", retries=4, backoff=3.0)
    proxy_url = proxy_info.get("proxy")  # e.g. "socks5://sliver-server:10001"
    node_type = proxy_info.get("node_type", "")
    log.info("Node %s proxy: %s (type=%s)", node_id[:12], proxy_url, node_type)
    if not proxy_url:
        log.error("Node %s has no proxy URL — proxy_info: %s", node_id[:12], proxy_info)
        raise HTTPException(400, "No proxy available for this node")

    # Normalize targets
    raw = req.targets or ([req.target] if req.target else [])
    targets = []
    for item in raw:
        targets.extend(t.strip() for t in str(item).split(",") if t.strip())

    # Raw-socket scans or no-proxy scans on SSH nodes → route as remote command execution
    if (req.scan_type in _RAW_SOCKET_SCANS or req.scan_type in _NO_PROXY_SCANS) and node_type == "ssh":
        remote_type = _REMOTE_SCAN_MAP.get(req.scan_type)
        if not remote_type:
            raise HTTPException(400, f"{req.scan_type} cannot use SOCKS proxy and has no remote exec template")
        remote_payload = {
            "scan_type": remote_type,
            "targets": targets,
            "ports": req.ports or "1-1000",
            "rate": str(req.rate or 1000),
        }
        # Pass extra context for non-standard tools
        if req.scan_type == "brutus":
            extra = []
            # Build hydra-compatible extra_args from brutus params
            if hasattr(req, 'protocols') and req.protocols:
                extra.extend(["-s", req.protocols])
            remote_payload["extra_args"] = extra
        s = get_settings()
        async with httpx.AsyncClient(verify=False, timeout=660) as c:
            resp = await c.post(
                f"{s.tunnel_manager_url}/ssh/{node_id}/remote-scan",
                json=remote_payload,
            )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        data = resp.json()
        remote_job_id = data.get("job_id") or data.get("id")
        if remote_job_id:
            remote_target = req.target or (targets[0] if targets else None) or "unknown"
            register_job(remote_job_id, f"{s.tunnel_manager_url}", req.scan_type, proxy=proxy_url,
                         engagement_id=req.engagement_id,
                         scope_name=req.scope_name,
                         target=remote_target)
        reason = "uses raw sockets" if req.scan_type in _RAW_SOCKET_SCANS else "does not support SOCKS proxy"
        data["proxied_through"] = {
            "node_id": node_id,
            "proxy": proxy_url,
            "mode": "remote_exec",
            "note": f"{req.scan_type} {reason} — executed directly on SSH host",
        }
        return data

    # No-proxy scans on non-SSH nodes → cannot be proxied at all
    if req.scan_type in _NO_PROXY_SCANS and node_type != "ssh":
        raise HTTPException(400,
            f"{req.scan_type} does not support SOCKS proxy. "
            f"Use an SSH node to push execution to the remote end.")

    # Build scanner payload with SOCKS proxy for tools that support it
    attr, path = SCAN_ROUTE_MAP[req.scan_type]
    s = get_settings()
    service_url = getattr(s, attr)

    payload = {k: v for k, v in req.model_dump(exclude_none=True).items() if k != "scan_type"}
    payload["proxy"] = proxy_url

    if req.scan_type in ("nmap", "nmap-tcp", "full", "masscan", "udp", "httpx", "naabu",
                          "katana", "tlsx", "whatweb", "recon-pipeline"):
        payload["targets"] = targets
        payload.pop("target", None)
        # Inject katana API extraction defaults if not explicitly set
        if req.scan_type == "katana":
            payload.setdefault("xhr_extraction", True)
            payload.setdefault("form_extraction", True)
            payload.setdefault("known_files", "all")
            payload.setdefault("js_crawl", True)
    elif req.scan_type in ("subfinder", "dnsx", "shuffledns", "amass"):
        payload["domains"] = targets
        payload.pop("targets", None)
        payload.pop("target", None)
    elif req.scan_type in ("gau", "waybackurls"):
        payload["domains"] = targets
        payload.pop("targets", None)
        payload.pop("target", None)
    elif req.scan_type in ("chaos", "crtsh"):
        payload["domain"] = req.target or (targets[0] if targets else "")
        payload.pop("targets", None)
        payload.pop("target", None)
    elif req.scan_type == "uncover":
        payload["query"] = req.query or req.target or ""
        payload.pop("targets", None)
        payload.pop("target", None)
    elif req.scan_type == "greyhatwarfare":
        payload["search_query"] = req.query or req.target or ""
        payload.pop("targets", None)
        payload.pop("target", None)
    elif req.scan_type == "trufflehog":
        payload["target"] = req.target or (targets[0] if targets else "")
        payload.pop("targets", None)
    elif req.scan_type == "censys":
        payload["query"] = req.query or req.target or ""
        payload.pop("targets", None)
        payload.pop("target", None)
    elif req.scan_type in ("nuclei",):
        payload["target"] = req.target or (targets[0] if targets else "")
        payload.pop("targets", None)
    elif req.scan_type in ("web", "pipeline", "nikto", "gobuster"):
        payload["target_url"] = req.target_url or req.target or (targets[0] if targets else "")
        payload.pop("targets", None)
        payload.pop("target", None)
    elif req.scan_type == "content-recon":
        # Extract all URLs for batching
        all_urls = []
        raw_urls = payload.get("target_urls")
        if raw_urls:
            if isinstance(raw_urls, list):
                all_urls = [u.strip() for u in raw_urls if u.strip()]
            elif isinstance(raw_urls, str):
                all_urls = [u.strip() for u in raw_urls.split("\n") if u.strip()]
        elif payload.get("target_url"):
            all_urls = [str(payload["target_url"]).strip()]
        elif req.target_url:
            all_urls = [req.target_url]
        elif targets:
            all_urls = targets

        # Ensure https:// prefix
        all_urls = [u if u.startswith(("http://", "https://")) else f"https://{u}" for u in all_urls if u]

        # Convert run_gobuster (UI) to skip_gobuster (backend) — inverted logic
        if "run_gobuster" in payload:
            payload["skip_gobuster"] = not payload.pop("run_gobuster")
        elif "skip_gobuster" not in payload:
            payload["skip_gobuster"] = True

        # Clean payload for content-recon
        payload.pop("target_urls", None)
        payload.pop("targets", None)
        payload.pop("target", None)
        payload.pop("scope_name", None)
        payload.pop("engagement_id", None)
        payload.pop("scan_type", None)

        # Batch: launch one job per URL (respecting concurrency limit, queue the rest)
        if len(all_urls) > 1:
            job_ids = []
            queued_count = 0
            # Build payload template without target_url
            payload_template = dict(payload)
            payload_template.pop("target_url", None)

            async with httpx.AsyncClient(verify=False, timeout=30) as c:
                for url in all_urls:
                    if _count_active_scans() >= MAX_CONCURRENT_SCANS:
                        pending_queue.append({
                            "url": url,
                            "service_url": service_url,
                            "path": path,
                            "payload_template": payload_template,
                            "proxy": proxy_url,
                            "engagement_id": req.engagement_id,
                            "scope_name": req.scope_name,
                            "scan_type": req.scan_type,
                            "api_key": s.api_key if hasattr(s, 'api_key') else get_settings().api_key,
                        })
                        queued_count += 1
                        continue
                    single = dict(payload)
                    single["target_url"] = url
                    try:
                        resp = await c.post(f"{service_url}{path}", json=single)
                        if resp.status_code < 400:
                            jdata = resp.json()
                            jid = jdata.get("job_id")
                            if jid:
                                job_ids.append(jid)
                                register_job(jid, service_url, req.scan_type, proxy=proxy_url,
                                             engagement_id=req.engagement_id,
                                             scope_name=req.scope_name,
                                             target=url)
                    except Exception:
                        pass
            return {
                "ok": True, "batch": True, "job_ids": job_ids,
                "total_urls": len(all_urls), "jobs_launched": len(job_ids),
                "queued_for_later": queued_count, "pending_queue_size": len(pending_queue),
                "max_concurrent": MAX_CONCURRENT_SCANS,
                "type": req.scan_type, "status": "queued",
                "proxied_through": {"node_id": node_id, "proxy": proxy_url, "mode": "socks_proxy"},
            }

        # Single URL — check concurrency
        payload["target_url"] = all_urls[0] if all_urls else "unknown"

    # Concurrency check for single launches
    active = _count_active_scans()
    if active >= MAX_CONCURRENT_SCANS:
        raise HTTPException(429, f"Scan limit reached: {active}/{MAX_CONCURRENT_SCANS} active. "
                                 f"Wait for running scans to complete.")

    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.post(f"{service_url}{path}", json=payload)

    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)

    data = resp.json()
    job_id = data.get("job_id") or data.get("id") or data.get("scan_id")
    scan_target = req.target_url or req.target or (targets[0] if targets else None) or "unknown"
    if job_id:
        register_job(job_id, service_url, req.scan_type, proxy=proxy_url,
                     engagement_id=req.engagement_id,
                     scope_name=req.scope_name,
                     target=scan_target)
    data["proxied_through"] = {
        "node_id": node_id,
        "proxy": proxy_url,
        "mode": "socks_proxy",
    }
    return data


# ---------------------------------------------------------------------------
# Node Update
# ---------------------------------------------------------------------------
@router.patch("/api/nodes/{node_id}")
async def patch_node(node_id: str, payload: dict):
    """Update node metadata (e.g. os_type)."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.patch(f"{s.tunnel_manager_url}/nodes/{node_id}", json=payload)
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


# ---------------------------------------------------------------------------
# Node Provisioning
# ---------------------------------------------------------------------------
@router.post("/api/nodes/{node_id}/provision")
async def provision_node(node_id: str, payload: dict = {}):
    """Install scan tools on a remote SSH node. Streams SSE events per tool."""
    from starlette.responses import StreamingResponse as SR
    s = get_settings()

    async def _proxy():
        async with httpx.AsyncClient(verify=False, timeout=600) as c:
            async with c.stream("POST", f"{s.tunnel_manager_url}/ssh/{node_id}/provision",
                                json=payload) as resp:
                async for line in resp.aiter_lines():
                    yield line + "\n"

    return SR(_proxy(), media_type="text/event-stream")


@router.post("/api/nodes/{node_id}/provision-background")
async def provision_background(node_id: str, payload: dict):
    """Start background installation that persists across GUI sessions."""
    return await _nm_post(f"/ssh/{node_id}/provision-background", payload)

@router.get("/api/nodes/{node_id}/installation-tasks")
async def get_installation_tasks(node_id: str):
    """Get all installation tasks for a node."""
    return await _nm_get(f"/ssh/{node_id}/installation-tasks")

@router.get("/api/nodes/{node_id}/installation-tasks/{task_id}")
async def get_installation_task(node_id: str, task_id: str):
    """Get specific installation task status."""
    return await _nm_get(f"/ssh/{node_id}/installation-tasks/{task_id}")

@router.delete("/api/nodes/{node_id}/installation-tasks/{task_id}")
async def cancel_installation_task(node_id: str, task_id: str):
    """Cancel a background installation task."""
    return await _nm_delete(f"/ssh/{node_id}/installation-tasks/{task_id}")

@router.get("/api/nodes/{node_id}/provision-status")
async def provision_status(node_id: str, live: bool = False):
    """Check which tools are installed on a remote SSH node."""
    if not live:
        return await _nm_get(f"/ssh/{node_id}/provision-status?live=false")

    from starlette.responses import StreamingResponse as SR
    s = get_settings()

    async def _proxy():
        async with httpx.AsyncClient(verify=False, timeout=120) as c:
            async with c.stream("GET", f"{s.tunnel_manager_url}/ssh/{node_id}/provision-status?live=true") as resp:
                async for line in resp.aiter_lines():
                    yield line + "\n"

    return SR(_proxy(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Implants
# ---------------------------------------------------------------------------
@router.post("/api/nodes/implants/generate")
async def generate_implant(payload: dict):
    return await _nm_post("/implants/generate", payload)


@router.get("/api/nodes/implants")
async def list_implants():
    return await _nm_get("/implants/list")


# ---------------------------------------------------------------------------
# Sliver sessions
# ---------------------------------------------------------------------------
@router.get("/api/nodes/sessions")
async def list_sessions():
    return await _nm_get("/sessions")


# ---------------------------------------------------------------------------
# AD Attacks
# ---------------------------------------------------------------------------
@router.get("/api/nodes/ad/attacks")
async def list_ad_attacks():
    return await _nm_get("/ad/attacks")


@router.post("/api/nodes/{node_id}/ad/{attack_type}")
async def execute_ad_attack(node_id: str, attack_type: str, payload: dict = {}):
    return await _nm_post(f"/nodes/{node_id}/ad/{attack_type}", payload)


@router.get("/api/nodes/{node_id}/ad/results")
async def get_ad_results(node_id: str):
    return await _nm_get(f"/nodes/{node_id}/ad/results")


# ---------------------------------------------------------------------------
# Remote Kali MCP
# ---------------------------------------------------------------------------

@router.post("/api/nodes/{node_id}/start-mcp")
async def start_node_mcp(node_id: str):
    """Start Kali MCP server on remote node with SSH port forwarding."""
    result = await _nm_post(f"/ssh/{node_id}/start-mcp", {})
    # Auto-reload MCP tool cache so new tools appear in chat immediately
    try:
        from services.tool_definitions import reload_mcp_tools
        reloaded = reload_mcp_tools()
        result["tools_reloaded"] = len(reloaded)
    except Exception:
        pass
    return result


@router.post("/api/nodes/{node_id}/stop-mcp")
async def stop_node_mcp(node_id: str):
    """Stop MCP port forwarding for a node."""
    return await _nm_post(f"/ssh/{node_id}/stop-mcp", {})


@router.get("/api/nodes/{node_id}/mcp-status")
async def node_mcp_status(node_id: str):
    """Check if MCP is active for a node."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            resp = await c.get(f"{s.tunnel_manager_url}/ssh/{node_id}/mcp-status")
            return safe_json(resp)
    except Exception as e:
        return {"active": False, "error": str(e)}


@router.post("/api/nodes/{node_id}/mcp-proxy")
async def node_mcp_proxy(node_id: str, request: Request):
    """Proxy MCP requests to remote Kali MCP."""
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.post(
            f"{s.tunnel_manager_url}/ssh/{node_id}/mcp-proxy",
            json=body,
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.post("/api/mcp-tools/reload")
async def reload_mcp_tools_endpoint():
    """Force rediscovery of all MCP tools (after starting/stopping remote MCP)."""
    from services.tool_definitions import reload_mcp_tools
    tools = reload_mcp_tools()
    kali_count = sum(1 for t in tools if 'kali' in t.get('_mcp_server', '').lower())
    return {"ok": True, "total_tools": len(tools), "kali_tools": kali_count}


@router.get("/api/mcp-nodes")
async def list_mcp_nodes():
    """List all nodes with active MCP."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            resp = await c.get(f"{s.tunnel_manager_url}/mcp-nodes")
            return safe_json(resp)
    except Exception as e:
        return {"nodes": [], "error": str(e)}


# ---------------------------------------------------------------------------
# Chisel config
# ---------------------------------------------------------------------------
@router.post("/api/nodes/chisel/config")
async def chisel_config(payload: dict):
    return await _nm_post("/chisel/config", payload)


# ---------------------------------------------------------------------------
# SSH Tunnel Management
# ---------------------------------------------------------------------------
@router.get("/api/nodes/ssh/keys")
async def list_ssh_keys():
    return await _nm_get("/ssh/keys")


@router.get("/api/nodes/ssh/public-keys")
async def list_ssh_public_keys():
    return await _nm_get("/ssh/public-keys")


@router.post("/api/nodes/ssh/connect")
async def ssh_connect(payload: dict):
    return await _nm_post("/ssh/connect", payload)


@router.post("/api/nodes/{node_id}/ssh/disconnect")
async def ssh_disconnect(node_id: str):
    return await _nm_post(f"/ssh/{node_id}/disconnect")


@router.post("/api/nodes/{node_id}/ssh/reconnect")
async def ssh_reconnect(node_id: str):
    return await _nm_post(f"/ssh/{node_id}/reconnect")


@router.post("/api/nodes/{node_id}/ssh/exec")
async def ssh_exec(node_id: str, payload: dict):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.post(f"{s.tunnel_manager_url}/ssh/{node_id}/exec", json=payload)
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.post("/api/nodes/{node_id}/ssh/upload")
async def ssh_upload(node_id: str, file: UploadFile = File(...), remote_path: str = Form(...)):
    s = get_settings()
    file_bytes = await file.read()
    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.post(
            f"{s.tunnel_manager_url}/ssh/{node_id}/upload",
            params={"remote_path": remote_path},
            content=file_bytes,
        )
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.post("/api/nodes/{node_id}/ssh/remote-scan")
async def remote_scan(node_id: str, payload: dict):
    """Run a scan tool directly on a remote SSH host."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=660) as c:
        resp = await c.post(f"{s.tunnel_manager_url}/ssh/{node_id}/remote-scan", json=payload)
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return safe_json(resp)


@router.post("/api/nodes/{node_id}/ssh/download")
async def ssh_download(node_id: str, payload: dict):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=120) as c:
        resp = await c.post(
            f"{s.tunnel_manager_url}/ssh/{node_id}/download",
            json=payload,
        )
    if resp.status_code >= 400:
        raise HTTPException(resp.status_code, resp.text)
    return StreamingResponse(
        iter([resp.content]),
        media_type=resp.headers.get("content-type", "application/octet-stream"),
        headers={
            "Content-Disposition": resp.headers.get("content-disposition", "attachment"),
        },
    )


# ── DigitalOcean Cloud Provisioning ──────────────────────────────────────────

@router.get("/api/cloud/do/options")
async def do_options():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.tunnel_manager_url}/cloud/do/options")
        return safe_json(resp)


@router.get("/api/cloud/do/status/{droplet_id}")
async def do_status(droplet_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.tunnel_manager_url}/cloud/do/status/{droplet_id}")
        return safe_json(resp)


@router.get("/api/cloud/do/droplets")
async def list_do_droplets():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(f"{s.tunnel_manager_url}/cloud/do/droplets")
        return safe_json(resp)


@router.post("/api/cloud/do/create")
async def create_do_droplet(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=180) as c:
        resp = await c.post(f"{s.tunnel_manager_url}/cloud/do/create", json=body)
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/cloud/do/droplet-by-id/{droplet_id}")
async def destroy_do_droplet_by_id(droplet_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.request("DELETE", f"{s.tunnel_manager_url}/cloud/do/droplet-by-id/{droplet_id}")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/cloud/do/droplet/{node_id}")
async def destroy_do_droplet(node_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.request("DELETE", f"{s.tunnel_manager_url}/cloud/do/droplet/{node_id}")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ---------------------------------------------------------------------------
# AWS EC2
# ---------------------------------------------------------------------------

@router.get("/api/cloud/aws/options")
async def aws_options():
    return await _nm_get("/cloud/aws/options")


@router.post("/api/cloud/aws/create")
async def create_aws_instance(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=180) as c:
        resp = await c.post(f"{s.tunnel_manager_url}/cloud/aws/create", json=body, timeout=60)
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.get("/api/cloud/aws/status/{instance_id}")
async def aws_provision_status(instance_id: str):
    return await _nm_get(f"/cloud/aws/status/{instance_id}")


@router.get("/api/cloud/aws/instances")
async def list_aws_instances(region: str = Query("us-east-1")):
    return await _nm_get(f"/cloud/aws/instances?region={region}")


@router.delete("/api/cloud/aws/instance-by-id/{instance_id}")
async def destroy_aws_instance_by_id(instance_id: str, region: str = Query("us-east-1")):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.request("DELETE", f"{s.tunnel_manager_url}/cloud/aws/instance-by-id/{instance_id}?region={region}")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


@router.delete("/api/cloud/aws/instance/{node_id}")
async def destroy_aws_instance(node_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.request("DELETE", f"{s.tunnel_manager_url}/cloud/aws/instance/{node_id}")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return safe_json(resp)


# ── IP Rotation ─────────────────────────────────────────────────────────────

@router.post("/api/cloud/do/rotate-ip/{node_id}")
async def rotate_do_ip(node_id: str, strategy: str = Query("reserved_ip",
        description="reserved_ip (fast, keeps droplet) or destroy_recreate (slow, new droplet)")):
    """Rotate the IP address on a DigitalOcean droplet."""
    return await _nm_post(f"/cloud/do/rotate-ip/{node_id}?strategy={strategy}")


@router.get("/api/cloud/do/rotate-status/{node_id}")
async def do_rotate_status(node_id: str):
    """Poll DO IP rotation progress."""
    return await _nm_get(f"/cloud/do/rotate-status/{node_id}")


# ── IP History ──────────────────────────────────────────────────────────────

@router.get("/api/cloud/ip-history")
async def get_ip_history(node_id: Optional[str] = Query(None), limit: int = Query(100)):
    """Get IP assignment history, optionally filtered by node."""
    params = f"?limit={limit}"
    if node_id:
        params += f"&node_id={node_id}"
    return await _nm_get(f"/cloud/ip-history{params}")


@router.get("/api/tunnel-events")
async def tunnel_events(node_id: Optional[str] = None, limit: int = 50):
    """Get tunnel lifecycle events for the Nodes SSH tab."""
    s = get_settings()
    params = {"limit": limit}
    if node_id:
        params["node_id"] = node_id
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            resp = await c.get(f"{s.tunnel_manager_url}/tunnel-events", params=params)
            if resp.status_code == 200:
                return safe_json(resp)
            return {"events": []}
    except Exception:
        return {"events": []}


@router.post("/api/wordlist-check")
async def wordlist_check(payload: dict):
    """Check if configured wordlist files exist on all online SSH nodes."""
    s = get_settings()
    paths = payload.get("paths", {})
    results: dict[str, list] = {k: [] for k in paths}

    # Get online nodes
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            resp = await c.get(f"{s.tunnel_manager_url}/nodes")
            if resp.status_code != 200:
                return {"results": results}
            nodes = [n for n in resp.json().get("nodes", [])
                     if n.get("node_type") == "ssh" and n.get("status") == "online"]
    except Exception:
        return {"results": results}

    # Check each file on each node
    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        for node in nodes:
            nid = node["id"]
            nname = node.get("name", nid[:8])
            for key, path in paths.items():
                if not path:
                    continue
                try:
                    resp = await c.post(
                        f"{s.tunnel_manager_url}/ssh/{nid}/exec",
                        json={"command": f"test -f '{path}' && echo EXISTS || echo MISSING", "timeout": 5},
                    )
                    if resp.status_code == 200:
                        stdout = resp.json().get("stdout", "")
                        results[key].append({"node": nname, "exists": "EXISTS" in stdout})
                    else:
                        results[key].append({"node": nname, "exists": False})
                except Exception:
                    results[key].append({"node": nname, "exists": False})
    return {"results": results}


# ---------------------------------------------------------------------------
# WireGuard Management
# ---------------------------------------------------------------------------

@router.get("/api/wg/peers")
async def list_wg_peers():
    """List WireGuard peers."""
    return await _nm_get("/api/wg/peers")


@router.post("/api/wg/peers")
async def create_wg_peer(request: Request):
    """Create a new WireGuard peer."""
    s = get_settings()
    body = await request.json()

    async with httpx.AsyncClient(verify=False, timeout=300) as c:
        resp = await c.post(
            f"{s.tunnel_manager_url}/api/wg/peers",
            json=body
        )
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()


@router.delete("/api/wg/peers/{peer_id}")
async def delete_wg_peer(peer_id: str):
    """Delete a WireGuard peer."""
    s = get_settings()

    async with httpx.AsyncClient(verify=False, timeout=30) as c:
        resp = await c.delete(f"{s.tunnel_manager_url}/api/wg/peers/{peer_id}")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()


@router.get("/api/wg/peers/{peer_id}/config")
async def get_wg_peer_config(peer_id: str):
    """Get WireGuard peer configuration."""
    return await _nm_get(f"/api/wg/peers/{peer_id}/config")


@router.post("/api/wg/peers/{peer_id}/client/status")
async def get_wg_client_status(peer_id: str):
    """Check WireGuard client status on remote node."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.post(f"{s.tunnel_manager_url}/api/wg/peers/{peer_id}/client/status")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()


@router.post("/api/wg/peers/{peer_id}/client/start")
async def start_wg_client(peer_id: str):
    """Start WireGuard client on remote node."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.post(f"{s.tunnel_manager_url}/api/wg/peers/{peer_id}/client/start")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()


@router.post("/api/wg/peers/{peer_id}/client/stop")
async def stop_wg_client(peer_id: str):
    """Stop WireGuard client on remote node."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.post(f"{s.tunnel_manager_url}/api/wg/peers/{peer_id}/client/stop")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()


@router.post("/api/wg/peers/{peer_id}/client/restart")
async def restart_wg_client(peer_id: str):
    """Restart WireGuard client on remote node."""
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=60) as c:
        resp = await c.post(f"{s.tunnel_manager_url}/api/wg/peers/{peer_id}/client/restart")
        if resp.status_code >= 400:
            raise HTTPException(resp.status_code, resp.text)
        return resp.json()
