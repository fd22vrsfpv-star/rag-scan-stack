"""Execute tool calls against backend services."""

import logging
import os
import httpx
from config import get_settings
from polling import register_job

log = logging.getLogger("tool_executor")


def _s():
    return get_settings()


def _split_targets(target_str: str) -> list[str]:
    """Split a comma-separated target string into a list of individual targets."""
    return [t.strip() for t in target_str.split(",") if t.strip()]


# Tool name → (method, url_builder, payload_builder)
# url_builder: callable(settings, args) → str
# payload_builder: callable(args) → dict | None (None = no body, use GET params)
TOOL_ROUTES: dict[str, tuple[str, callable, callable]] = {
    "search_findings": (
        "GET",
        lambda s, a: f"{s.rag_api_url}/findings/search",
        lambda a: {k: v for k, v in {
            "severity": a.get("severity"), "source": a.get("source"),
            "ip": a.get("ip"), "cve": a.get("cve"), "search": a.get("search"),
            "port": a.get("port"), "limit": a.get("limit", 50),
        }.items() if v is not None},
    ),
    "get_assets": (
        "GET",
        lambda s, a: f"{s.rag_api_url}/assets",
        lambda a: {k: v for k, v in {
            "provider": a.get("provider") or a.get("cloud") or a.get("host_provider"),
            "search": a.get("search") or a.get("query"),  # accept "query" too — small models hallucinate it
            "limit": min(int(a.get("limit") or 100), 5000),
            "offset": a.get("offset", 0),
        }.items() if v is not None},
    ),
    "get_open_ports": (
        "GET",
        lambda s, a: f"{s.rag_api_url}/ports/open",
        lambda a: {k: v for k, v in {
            "ip": a.get("ip"), "service": a.get("service"),
            "limit": a.get("limit", 200),
        }.items() if v is not None},
    ),
    "get_vulns": (
        "GET",
        lambda s, a: f"{s.rag_api_url}/vulns",
        lambda a: {k: v for k, v in {
            "ip": a.get("ip"), "limit": a.get("limit", 200),
        }.items() if v is not None},
    ),
    "search_identities": (
        "GET",
        lambda s, a: f"{s.rag_api_url}/identities",
        lambda a: {k: v for k, v in {
            "provider": a.get("provider"),
            "principal_type": a.get("principal_type"),
            "search": a.get("search"),
            "is_admin": a.get("is_admin"),
            "is_guest": a.get("is_guest"),
            "is_dirsync": a.get("is_dirsync"),
            "has_credential": a.get("has_credential"),
            "member_of": a.get("member_of"),
            "limit": min(a.get("limit", 100), 2000),
        }.items() if v is not None},
    ),
    "start_masscan": (
        "POST",
        lambda s, a: f"{s.nmap_scanner_url}/jobs/masscan-only",
        lambda a: {"targets": _split_targets(a["target"]), "ports": a.get("ports", "1-1000"), "rate": a.get("rate", 1000)},
    ),
    "start_nmap_scan": (
        "POST",
        lambda s, a: f"{s.nmap_scanner_url}/jobs/masscan-then-nmap",
        lambda a: {"targets": _split_targets(a["target"]), "ports": a.get("ports", "1-1000"), "rate": 1000},
    ),
    "start_full_port_scan": (
        "POST",
        lambda s, a: f"{s.nmap_scanner_url}/jobs/full-scan",
        lambda a: {"targets": _split_targets(a["target"]), "rate": a.get("rate", 1000)},
    ),
    "start_nuclei_scan": (
        "POST",
        lambda s, a: f"{s.nuclei_url}/jobs/nuclei-scan",
        lambda a: {k: v for k, v in {
            "target": a.get("target"), "severity": a.get("severity", "medium,high,critical"),
            "limit": 25,
        }.items() if v is not None},
    ),
    "start_web_scan": (
        "POST",
        lambda s, a: f"{s.web_scanner_url}/jobs/web-scan",
        lambda a: {k: v for k, v in {
            "target_url": a.get("target_url"), "do_gobuster": True, "do_zap": True, "limit": 25,
        }.items() if v is not None},
    ),
    "start_web_pipeline": (
        "POST",
        lambda s, a: f"{s.web_scanner_url}/jobs/pipeline-scan",
        lambda a: {"target_url": a["target_url"], "max_paths_to_visit": a.get("max_paths", 50)},
    ),
    "start_httpx_probe": (
        "POST",
        lambda s, a: f"{s.pd_runner_url}/jobs/httpx",
        lambda a: {k: v for k, v in {
            "targets": a.get("targets"), "ports": a.get("ports"), "tech_detect": True,
        }.items() if v is not None},
    ),
    "start_katana": (
        "POST",
        lambda s, a: f"{s.pd_runner_url}/jobs/katana",
        lambda a: {k: v for k, v in {
            "targets": a.get("targets"), "depth": a.get("depth", 3), "js_crawl": True,
        }.items() if v is not None},
    ),
    "start_naabu": (
        "POST",
        lambda s, a: f"{s.pd_runner_url}/jobs/naabu",
        lambda a: {"targets": a["targets"], "ports": a.get("ports", "1-1000"), "rate": a.get("rate", 1000)},
    ),
    "start_udp_scan": (
        "POST",
        lambda s, a: f"{s.nmap_scanner_url}/jobs/nmap-udp",
        lambda a: {"targets": _split_targets(a["target"]), "ports": a.get("ports", "53,67,68,69,111,123,135,137,161,445,500,514,1434,1900,5353")},
    ),
    "start_tlsx": (
        "POST",
        lambda s, a: f"{s.pd_runner_url}/jobs/tlsx",
        lambda a: {k: v for k, v in {
            "targets": a.get("targets"), "ports": a.get("ports"),
        }.items() if v is not None},
    ),
    "start_subfinder": (
        "POST",
        lambda s, a: f"{s.osint_runner_url}/jobs/subfinder",
        lambda a: {"domains": a["targets"]},
    ),
    "start_dnsx": (
        "POST",
        lambda s, a: f"{s.osint_runner_url}/jobs/dnsx",
        lambda a: {"domains": a["targets"]},
    ),
    "search_recon": (
        "GET",
        lambda s, a: f"{s.rag_api_url}/recon/search",
        lambda a: {k: v for k, v in {
            "source": a.get("source"), "finding_type": a.get("finding_type"),
            "target": a.get("target"), "severity": a.get("severity"),
            "search": a.get("search"), "limit": a.get("limit", 100),
        }.items() if v is not None},
    ),
    "search_sitemap": (
        "GET",
        lambda s, a: f"{s.rag_api_url}/content-intel/sitemap",
        lambda a: {k: v for k, v in {
            "domain": a.get("domain"), "asset_id": a.get("asset_id"),
        }.items() if v is not None},
    ),
    "search_params": (
        "GET",
        lambda s, a: f"{s.rag_api_url}/params",
        lambda a: {k: v for k, v in {
            "url_pattern": a.get("url_pattern"), "param_name": a.get("param_name"),
            "param_type": a.get("param_type"), "limit": a.get("limit", 100),
        }.items() if v is not None},
    ),
    "get_content_intel": (
        "GET",
        lambda s, a: f"{s.rag_api_url}/content-extractions/summary",
        lambda a: {k: v for k, v in {
            "asset_id": a.get("asset_id"),
        }.items() if v is not None},
    ),
    "start_crtsh": (
        "POST",
        lambda s, a: f"{s.osint_runner_url}/jobs/crtsh",
        lambda a: {"domain": a["domain"]},
    ),
    "start_uncover": (
        "POST",
        lambda s, a: f"{s.osint_runner_url}/jobs/uncover",
        lambda a: {"query": a["query"], "engine": a.get("engine", "shodan"), "limit": a.get("limit", 100)},
    ),
    "start_chaos": (
        "POST",
        lambda s, a: f"{s.osint_runner_url}/jobs/chaos",
        lambda a: {"domain": a["target"]},
    ),
    "start_shuffledns": (
        "POST",
        lambda s, a: f"{s.osint_runner_url}/jobs/shuffledns",
        lambda a: {"domains": a["targets"]},
    ),
    "start_cvemap": (
        "POST",
        lambda s, a: f"{s.osint_runner_url}/jobs/cvemap",
        lambda a: {k: v for k, v in {"cve_ids": a.get("cve_ids"), "keyword": a.get("keyword"), "severity": a.get("severity"), "product": a.get("product"), "limit": a.get("limit", 100)}.items() if v is not None},
    ),
    "get_job_status": (
        "MULTI_GET",
        None,
        None,
    ),
    "get_recommendations": (
        "GET",
        lambda s, a: f"{s.scan_recommender_url}/get_next_recommendations",
        lambda a: {},
    ),
    "search_exploits": (
        "GET",
        lambda s, a: f"{s.rag_api_url}/rag/search/enhanced",
        lambda a: {k: v for k, v in {
            "cve": a.get("cve"), "service": a.get("service"),
            "version": a.get("version"), "query": a.get("query"), "top_k": 10,
        }.items() if v is not None},
    ),
    "get_pending_exploits": (
        "GET",
        lambda s, a: f"{s.exploit_runner_url}/exploits/pending",
        lambda a: {},
    ),
    "get_all_exploits": (
        "GET",
        lambda s, a: f"{s.exploit_runner_url}/exploits/all",
        lambda a: {k: v for k, v in {
            "status": a.get("status"),
        }.items() if v is not None},
    ),
    "get_exploit_results": (
        "GET",
        lambda s, a: f"{s.exploit_runner_url}/results/all",
        lambda a: {},
    ),
    "get_msf_sessions": (
        "GET",
        lambda s, a: f"{s.exploit_runner_url}/msf/sessions",
        lambda a: {},
    ),
    "get_all_active_jobs": (
        "MULTI_JOBS",
        None,
        None,
    ),
    "start_nikto_scan": (
        "POST",
        lambda s, a: f"{s.web_scanner_url}/jobs/nikto-scan",
        lambda a: {k: v for k, v in {
            "target_url": a["target_url"], "tuning": a.get("tuning"),
            "timeout_sec": a.get("timeout_sec"),
        }.items() if v is not None},
    ),
    "start_playwright_scan": (
        "POST",
        lambda s, a: f"{s.playwright_scanner_url}/scan",
        lambda a: {"url": a["target_url"]},
    ),
    "cleanup_findings": (
        "POST",
        lambda s, a: f"{s.rag_api_url}/cleanup/findings",
        lambda a: {k: v for k, v in {
            "sources": a.get("sources"), "older_than_hours": a.get("older_than_hours"),
            "dry_run": a.get("dry_run", True),
        }.items() if v is not None},
    ),
}

# Scan tools that return job IDs and should be registered for polling
SCAN_TOOLS = {
    "start_masscan": ("nmap_scanner_url", "masscan"),
    "start_nmap_scan": ("nmap_scanner_url", "nmap"),
    "start_full_port_scan": ("nmap_scanner_url", "full"),
    "start_nuclei_scan": ("nuclei_url", "nuclei"),
    "start_web_scan": ("web_scanner_url", "web"),
    "start_web_pipeline": ("web_scanner_url", "pipeline"),
    "start_httpx_probe": ("pd_runner_url", "httpx"),
    "start_katana": ("pd_runner_url", "katana"),
    "start_naabu": ("pd_runner_url", "naabu"),
    "start_udp_scan": ("nmap_scanner_url", "udp"),
    "start_tlsx": ("pd_runner_url", "tlsx"),
    "start_subfinder": ("osint_runner_url", "subfinder"),
    "start_dnsx": ("osint_runner_url", "dnsx"),
    "start_uncover": ("osint_runner_url", "uncover"),
    "start_chaos": ("osint_runner_url", "chaos"),
    "start_crtsh": ("osint_runner_url", "crtsh"),
    "start_shuffledns": ("osint_runner_url", "shuffledns"),
    "start_cvemap": ("osint_runner_url", "cvemap"),
    "start_playwright_scan": ("playwright_scanner_url", "playwright"),
    "start_nikto_scan": ("web_scanner_url", "nikto"),
}


# RFC-2606 reserved + community-standard placeholders that small models
# substitute when they don't have a real target. Calling tools with these
# wastes rounds — pre-empt by refusing the call with a structured error
# the model can read and adapt to.
_HALLUCINATION_PLACEHOLDERS = {
    "example.com", "example.org", "example.net",
    "test.com", "test.local", "target.invalid", "foo.com", "foo.bar",
    "yoursite.com", "yourdomain.com", "site.com", "domain.com",
    "<root_domain>", "<target>", "<domain>", "<tenant_or_domain>",
}


def _check_placeholder_args(arguments: dict) -> str | None:
    """Return a string describing the placeholder hit, or None.

    Walks single-level scalar values in `arguments`. Doesn't recurse into
    nested objects — the placeholders we care about are always top-level
    target/domain/host args.
    """
    if not isinstance(arguments, dict):
        return None
    for k, v in arguments.items():
        if not isinstance(v, str):
            continue
        s = v.strip().lower()
        if s in _HALLUCINATION_PLACEHOLDERS:
            return f"{k}={v!r}"
    return None


async def execute_tool(name: str, arguments: dict, allowed_tools: list[str] | None = None) -> dict:
    """Execute a tool call and return the result.

    `allowed_tools` (when set) is a tool-name allowlist. Calls to tools not
    in the list are refused with a structured error. Used by saved-query
    presets to enforce layer-3 hardening of the LLM-tool stack.
    """
    settings = _s()
    headers = {"x-api-key": settings.api_key}

    # Defensive name normalization — small local LLMs sometimes hallucinate
    # tool naming conventions like "query:get_assets", "tools.get_assets",
    # "functions.get_assets", or wrap the name with quotes/whitespace.
    # Strip these so the operator's intended tool still resolves.
    if isinstance(name, str):
        name = name.strip().strip('"').strip("'")
        for prefix in ("query:", "functions.", "tools.", "tool:", "function:"):
            if name.startswith(prefix):
                name = name[len(prefix):]

    # Layer-3 hardening: per-request allowlist. Refuse anything outside it
    # — including unknown tool names that would otherwise fall through to
    # MCP dispatch. The model gets a structured error it can read and adapt.
    if allowed_tools and name not in allowed_tools:
        return {
            "error": "tool_not_allowed",
            "tool": name,
            "message": (
                f"REFUSED: '{name}' is not allowed in this saved query. "
                f"You may only call these tools: {', '.join(sorted(allowed_tools))}. "
                f"Pick the matching read-only equivalent and try again. "
                f"Do NOT call any tool whose name starts with 'start_'."
            ),
            "allowed_tools": sorted(allowed_tools),
        }

    # Layer-4 hardening: refuse calls that pass a placeholder string in any
    # argument. Models loop forever calling get_recon_overview(target=
    # "example.com") because the empty result tells them nothing went wrong.
    # Returning a structured error gives them something concrete to react to.
    placeholder_hit = _check_placeholder_args(arguments)
    if placeholder_hit:
        return {
            "error": "placeholder_target",
            "rejected_arg": placeholder_hit,
            "message": (
                f"REJECTED: argument {placeholder_hit} is a placeholder, "
                "not a real target. You must use a hostname / domain that "
                "appeared in a PREVIOUS tool result. If you have no real "
                "domain to query, write 'STEP N: 0 results' and proceed to "
                "the next step instead of inventing one."
            ),
            "examples_of_forbidden": sorted(_HALLUCINATION_PLACEHOLDERS),
        }

    # Special case: read_uploaded_file fetches a binary blob from evidence_store
    if name == "read_uploaded_file":
        return await _read_uploaded_file(arguments, settings, headers)

    # Special case: scan pipeline tools go through BFF /api/pipelines
    if name == "start_scan_pipeline":
        return await _start_pipeline(arguments, settings, headers)
    if name == "get_pipeline_status":
        return await _get_pipeline_status(arguments, settings, headers)
    if name == "stop_pipeline":
        return await _stop_pipeline(arguments, settings, headers)

    if name not in TOOL_ROUTES:
        # Try MCP tool execution
        return await _execute_mcp_tool(name, arguments)

    method, url_fn, payload_fn = TOOL_ROUTES[name]

    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            # Special: get_job_status tries multiple services
            if method == "MULTI_GET":
                return await _get_job_status(client, arguments, settings, headers)

            # Special: get_all_active_jobs polls all services
            if method == "MULTI_JOBS":
                return await _get_all_jobs(client, settings, headers)

            url = url_fn(settings, arguments)
            payload = payload_fn(arguments)

            if method == "GET":
                resp = await client.get(url, params=payload, headers=headers)
            else:
                resp = await client.post(url, json=payload, headers=headers)

            result = resp.json() if resp.status_code < 500 else {"error": resp.text}

            # Register scan jobs for polling
            if name in SCAN_TOOLS and resp.status_code < 400:
                job_id = result.get("job_id") or result.get("id") or result.get("scan_id")
                if job_id:
                    attr, scan_type = SCAN_TOOLS[name]
                    register_job(job_id, getattr(settings, attr), scan_type)

            return result

    except Exception as e:
        log.exception("Tool execution failed: %s", name)
        return {"error": str(e)}


_DEFAULT_READ_CHUNK = 262144  # 256 KB per call (was 64 KB; LLM was stopping too early)


_BFF_BASE = f"https://127.0.0.1:{os.environ.get('BFF_PORT', '443')}"


async def _start_pipeline(args: dict, settings, headers) -> dict:
    try:
        body = {
            "engagement_id": args.get("engagement_id", ""),
            "profile": args.get("profile", "pentest"),
            "scope_name": args.get("scope_name"),
            "config": {"use_tunnels": args.get("use_tunnels", False)},
        }
        async with httpx.AsyncClient(verify=False, timeout=30) as c:
            resp = await c.post(f"{_BFF_BASE}/api/pipelines", json=body,
                                headers={**headers, "Content-Type": "application/json"})
            return resp.json() if resp.status_code < 500 else {"error": resp.text[:300]}
    except Exception as e:
        return {"error": str(e)}


async def _get_pipeline_status(args: dict, settings, headers) -> dict:
    pid = args.get("pipeline_id", "")
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            resp = await c.get(f"{settings.rag_api_url}/pipelines/{pid}", headers=headers)
            if resp.status_code >= 400:
                return {"error": f"HTTP {resp.status_code}: {resp.text[:200]}"}
            data = resp.json()
            # Summarize host_states for concise LLM output
            hs = data.get("host_states") or {}
            stage_counts: dict[str, int] = {}
            for h in hs.values():
                sn = h.get("stage_name", "unknown")
                stage_counts[sn] = stage_counts.get(sn, 0) + 1
            data["stage_summary"] = stage_counts
            return data
    except Exception as e:
        return {"error": str(e)}


async def _stop_pipeline(args: dict, settings, headers) -> dict:
    pid = args.get("pipeline_id", "")
    try:
        async with httpx.AsyncClient(verify=False, timeout=15) as c:
            resp = await c.post(f"{_BFF_BASE}/api/pipelines/{pid}/stop",
                                headers=headers)
            return resp.json() if resp.status_code < 500 else {"error": resp.text[:300]}
    except Exception as e:
        return {"error": str(e)}


async def _read_uploaded_file(args: dict, settings, headers) -> dict:
    """Fetch an uploaded file from evidence_store and return text/base64 chunk.

    Args:
        file_id (str): evidence_store row id (uuid)
        start (int, optional): byte offset (default 0)
        end (int, optional): exclusive byte offset (default start + 256KB)
        as_text (bool, optional): try utf-8 decode (default True). On failure, falls back to base64.
    """
    file_id = str(args.get("file_id", "")).strip()
    if not file_id:
        return {"error": "file_id is required"}
    try:
        start = max(0, int(args.get("start", 0)))
    except (TypeError, ValueError):
        start = 0
    try:
        end_val = args.get("end")
        end = int(end_val) if end_val is not None else (start + _DEFAULT_READ_CHUNK)
    except (TypeError, ValueError):
        end = start + _DEFAULT_READ_CHUNK
    if end <= start:
        end = start + _DEFAULT_READ_CHUNK
    as_text = args.get("as_text", True)

    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as c:
            # First fetch metadata to know content_type + total size
            meta_resp = await c.get(f"{settings.rag_api_url}/evidence/{file_id}",
                                    headers=headers)
            if meta_resp.status_code != 200:
                return {"error": f"evidence lookup failed: HTTP {meta_resp.status_code}",
                        "detail": meta_resp.text[:300]}
            meta = meta_resp.json() or {}
            total_size = int(meta.get("file_size") or 0)
            content_type = meta.get("content_type") or "application/octet-stream"
            title = meta.get("title") or ""
            # Clamp end to total size if known
            if total_size > 0 and end > total_size:
                end = total_size
            length = max(0, end - start)

            content_resp = await c.get(
                f"{settings.rag_api_url}/evidence/{file_id}/content",
                headers={**headers, "Range": f"bytes={start}-{end - 1}"} if length > 0 else headers,
            )
            if content_resp.status_code not in (200, 206):
                return {"error": f"content fetch failed: HTTP {content_resp.status_code}",
                        "detail": content_resp.text[:300]}
            raw = content_resp.content
            # If the upstream ignored Range and returned everything, slice client-side
            if content_resp.status_code == 200 and (start > 0 or len(raw) > length):
                raw = raw[start:end]

        chunk_end = start + len(raw)
        eof = (total_size > 0 and chunk_end >= total_size) or len(raw) == 0
        next_start = chunk_end if not eof else None
        # Construct a hint that's directly visible to the LLM in the tool result.
        if eof:
            hint = "EOF reached. You have read the full file."
        else:
            remaining = max(0, total_size - chunk_end) if total_size else None
            hint = (
                f"More data remains ({remaining} bytes left). "
                f"Call read_uploaded_file again with file_id='{file_id}', start={next_start} "
                f"to continue. Keep paging until eof=true."
            )
        result: dict = {
            "file_id": file_id, "title": title, "content_type": content_type,
            "total_size": total_size, "start": start, "end": chunk_end,
            "bytes_returned": len(raw),
            "eof": eof,
            "next_start": next_start,
            "hint": hint,
        }
        if as_text:
            try:
                result["text"] = raw.decode("utf-8")
                return result
            except UnicodeDecodeError:
                pass
        # Binary fallback
        import base64 as _b64
        result["base64"] = _b64.b64encode(raw).decode("ascii")
        return result
    except Exception as e:
        log.exception("read_uploaded_file failed")
        return {"error": f"{type(e).__name__}: {e}"}


async def _get_job_status(client, args, settings, headers):
    job_id = args.get("job_id", "")
    for attr in ["nmap_scanner_url", "web_scanner_url", "nuclei_url", "pd_runner_url", "osint_runner_url", "brutus_runner_url"]:
        try:
            url = getattr(settings, attr)
            resp = await client.get(f"{url}/jobs/{job_id}", headers=headers)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            continue
    return {"error": f"Job {job_id} not found on any service"}


async def _get_all_jobs(client, settings, headers):
    all_jobs = {}
    services = {
        "nmap": settings.nmap_scanner_url,
        "web": settings.web_scanner_url,
        "nuclei": settings.nuclei_url,
        "pd": settings.pd_runner_url,
        "osint": settings.osint_runner_url,
        "brutus": settings.brutus_runner_url,
    }
    for name, url in services.items():
        try:
            resp = await client.get(f"{url}/jobs", headers=headers)
            if resp.status_code == 200:
                all_jobs[name] = resp.json()
        except Exception:
            all_jobs[name] = {"error": "unreachable"}
    return all_jobs


async def _execute_mcp_tool(name: str, arguments: dict) -> dict:
    """Execute a tool via MCP protocol (for dynamically discovered tools)."""
    import json
    import os
    from services.tool_definitions import get_mcp_tool_info

    info = get_mcp_tool_info(name)
    if not info:
        return {"error": f"Unknown tool: {name}"}

    # Check if this is a remote Kali MCP tool (has node_id)
    node_id = info.get("node_id")
    if node_id:
        return await _execute_remote_mcp_tool(name, arguments, node_id)

    # SSE-transport servers open a fresh session per call
    if info.get("transport") == "sse" and info.get("url"):
        return await _execute_sse_mcp_tool(name, arguments, info)

    mcp_host = os.environ.get("MCP_STREAMABLE_HOST", "mcp-streamable")
    mcp_scheme = os.environ.get("MCP_STREAMABLE_SCHEME", "http")
    port = info["port"]
    base_url = info.get("url") or f"{mcp_scheme}://{mcp_host}:{port}/mcp"

    try:
        async with httpx.AsyncClient(verify=False, timeout=120) as client:
            resp = await client.post(
                base_url,
                json={
                    "jsonrpc": "2.0", "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
                headers={"Accept": "application/json, text/event-stream"},
            )
            if resp.status_code != 200:
                return {"error": f"MCP call failed: HTTP {resp.status_code}"}

            # Parse SSE or JSON response
            ct = resp.headers.get("content-type", "")
            if "text/event-stream" in ct:
                for line in resp.text.split("\n"):
                    line = line.strip()
                    if line.startswith("data: "):
                        try:
                            data = json.loads(line[6:])
                            result = data.get("result", data)
                            content = result.get("content", [])
                            if isinstance(content, list):
                                texts = [c.get("text", "") for c in content if c.get("type") == "text"]
                                if texts:
                                    return {"result": "\n".join(texts)}
                            return result
                        except json.JSONDecodeError:
                            continue
                return {"error": "No valid response from MCP server"}
            else:
                data = resp.json()
                if "error" in data:
                    return {"error": data["error"]}
                result = data.get("result", data)
                content = result.get("content", [])
                if isinstance(content, list):
                    texts = [c.get("text", "") for c in content if c.get("type") == "text"]
                    if texts:
                        return {"result": "\n".join(texts)}
                return result

    except httpx.TimeoutException:
        return {"error": f"MCP tool {name} timed out"}
    except Exception as e:
        log.exception("MCP tool execution failed: %s", name)
        return {"error": str(e)}


async def _execute_sse_mcp_tool(name: str, arguments: dict, info: dict) -> dict:
    """Execute a tool on an SSE-transport MCP server (e.g. Burp Suite).

    Opens a fresh SSE session, sends initialize + tool call, reads the
    response from the SSE event stream.
    """
    import json
    import threading
    import queue

    sse_url = info["url"]

    try:
        from httpx_sse import connect_sse
        from urllib.parse import urljoin

        response_queue = queue.Queue()
        stop_event = threading.Event()

        def sse_listener():
            try:
                with httpx.Client(verify=False, timeout=180) as sse_client:
                    with connect_sse(sse_client, "GET", sse_url) as event_source:
                        for event in event_source.iter_sse():
                            if stop_event.is_set():
                                break
                            if event.event == "endpoint":
                                endpoint = event.data.strip()
                                base = sse_url.rsplit("/", 1)[0] + "/"
                                response_queue.put(("endpoint", urljoin(base, endpoint)))
                            elif event.event == "message":
                                try:
                                    response_queue.put(("message", json.loads(event.data)))
                                except json.JSONDecodeError:
                                    pass
            except Exception as e:
                response_queue.put(("error", str(e)))

        listener = threading.Thread(target=sse_listener, daemon=True)
        listener.start()

        # Wait for endpoint
        try:
            event_type, data = response_queue.get(timeout=10)
        except queue.Empty:
            return {"error": "SSE server timeout waiting for endpoint"}
        if event_type != "endpoint":
            return {"error": f"SSE unexpected event: {event_type}"}

        message_url = data

        with httpx.Client(verify=False, timeout=120) as client:
            # Initialize
            client.post(message_url, json={
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                           "clientInfo": {"name": "chat-bridge", "version": "1.0"}},
            })
            try:
                response_queue.get(timeout=5)
            except queue.Empty:
                pass

            client.post(message_url, json={
                "jsonrpc": "2.0", "method": "notifications/initialized",
            })

            # Call tool
            client.post(message_url, json={
                "jsonrpc": "2.0", "id": 2,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            })

            # Wait for tool response
            try:
                event_type, data = response_queue.get(timeout=120)
            except queue.Empty:
                stop_event.set()
                return {"error": f"SSE MCP tool {name} timed out waiting for response"}

        stop_event.set()

        if event_type == "error":
            return {"error": data}
        if event_type != "message":
            return {"error": f"Unexpected SSE event: {event_type}"}

        result = data.get("result", data)
        if "error" in data:
            return {"error": data["error"]}
        content = result.get("content", [])
        if isinstance(content, list):
            texts = [c.get("text", "") for c in content if c.get("type") == "text"]
            if texts:
                return {"result": "\n".join(texts)}
        return result

    except Exception as e:
        log.exception("SSE MCP tool execution failed: %s", name)
        return {"error": str(e)}


async def _execute_remote_mcp_tool(name: str, arguments: dict, node_id: str) -> dict:
    """Execute a tool on a remote Kali MCP server via node-manager proxy."""
    import os
    tunnel_manager_url = os.environ.get("TUNNEL_MANAGER_URL", "http://host.docker.internal:8027")
    try:
        async with httpx.AsyncClient(verify=False, timeout=120) as client:
            resp = await client.post(
                f"{tunnel_manager_url}/ssh/{node_id}/mcp-proxy",
                json={
                    "jsonrpc": "2.0", "id": 1,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
            )
            if resp.status_code != 200:
                return {"error": f"Remote MCP call failed: HTTP {resp.status_code} {resp.text[:200]}"}
            data = resp.json()
            if "error" in data:
                return {"error": data["error"]}
            result = data.get("result", data)
            content = result.get("content", [])
            if isinstance(content, list):
                texts = [c.get("text", "") for c in content if c.get("type") == "text"]
                if texts:
                    return {"result": "\n".join(texts)}
            return result
    except httpx.TimeoutException:
        return {"error": f"Remote MCP tool {name} timed out (120s)"}
    except Exception as e:
        log.exception("Remote MCP tool execution failed: %s on node %s", name, node_id)
        return {"error": str(e)}
