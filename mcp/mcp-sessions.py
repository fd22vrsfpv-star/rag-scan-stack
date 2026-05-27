#!/usr/bin/env python3
"""MCP Server: Pentest Sessions + Data Queries + Utilities (17 tools) — Port 9016"""

import json, os, logging
from datetime import datetime, timezone
from typing import Annotated, Optional
import httpx
from pydantic import Field
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

API_URL = os.environ.get("API_URL", "https://autogen-agents:8015")
RAG_API_URL = os.environ.get("RAG_API_URL", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
TIMEOUT = float(os.environ.get("MCP_TIMEOUT_SCAN", "300"))

mcp = FastMCP("pentest-sessions", host="0.0.0.0", port=9016, stateless_http=True, streamable_http_path="/mcp")


@mcp.tool()
async def start_pentest_session(session_name: Annotated[str, Field(description="Human-readable session name, e.g. 'webapp-audit-feb18'")], target_description: Annotated[str, Field(description="Target IP or description, e.g. '192.168.1.150'")], initial_task: Annotated[str, Field(description="What the AI should do first")] = "Perform comprehensive reconnaissance and vulnerability assessment", max_rounds: Annotated[int, Field(description="Max conversation rounds")] = 200) -> str:
    """Start an autonomous AI-powered penetration testing session.

    Args:
        session_name: Human-readable session name (e.g., 'webapp-audit-feb18')
        target_description: Target IP or description (e.g., '192.168.1.150')
        initial_task: What the AI should do first
        max_rounds: Max conversation rounds (default: 200)
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(f"{API_URL}/pentest", json={"session_name": session_name, "target_description": target_description, "initial_task": initial_task, "max_rounds": max_rounds})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_session_status(session_id: Annotated[str, Field(description="Session UUID")] ) -> str:
    """Get status of a pentest session.

    Args:
        session_id: Session UUID
    """
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(f"{API_URL}/pentest/{session_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_session_scans(session_id: Annotated[str, Field(description="Session UUID")]) -> str:
    """Get all scan results for a pentest session.

    Args:
        session_id: Session UUID
    """
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(f"{API_URL}/pentest/{session_id}/scans")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def list_sessions(status: Annotated[Optional[str], Field(description="Filter by status: active, completed, failed, stopped")] = None) -> str:
    """List all pentest sessions.

    Args:
        status: Filter by status (active, completed, failed, stopped)
    """
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        params = {"limit": 50}
        if status:
            params["status"] = status
        resp = await client.get(f"{API_URL}/pentest/sessions", params=params)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def stop_session(session_id: Annotated[str, Field(description="Session UUID")]) -> str:
    """Stop a running pentest session.

    Args:
        session_id: Session UUID
    """
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.post(f"{API_URL}/pentest/{session_id}/stop")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def resume_pentest_session(session_id: Annotated[str, Field(description="UUID of the session to resume")], additional_instructions: Annotated[str, Field(description="Extra instructions for the resumed session")] = "", max_rounds: Annotated[int, Field(description="Max conversation rounds")] = 200) -> str:
    """Resume a failed/stalled/stopped pentest session.

    Args:
        session_id: UUID of the session to resume
        additional_instructions: Extra instructions for the resumed session
        max_rounds: Max conversation rounds (default: 200)
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(f"{API_URL}/pentest/{session_id}/resume", json={"max_rounds": max_rounds, "additional_instructions": additional_instructions or None})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_session_report(session_id: Annotated[str, Field(description="Session UUID")]) -> str:
    """Get full penetration testing report for a session.

    Args:
        session_id: Session UUID
    """
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.get(f"{API_URL}/reports/full", params={"session_id": session_id})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


_API_PAGE_SIZE = 5000          # rag-api hard cap on a single /assets|/ports/open|/vulns request
_DEFAULT_MAX_TOTAL = 20000     # fan-out cap so a runaway query can't blow the LLM context


async def _paginate(client: httpx.AsyncClient, path: str, base_params: dict,
                    list_key: str, max_total: int = _DEFAULT_MAX_TOTAL) -> dict:
    """Walk every page of a rag-api list endpoint until exhausted or
    `max_total` rows are collected. Works for any endpoint that:
      - accepts `limit` and `offset`
      - returns a `total` field plus an array under `list_key`
    Returns a flattened {total, returned, truncated, results} envelope."""
    collected: list = []
    total = 0
    offset = 0
    while len(collected) < max_total:
        params = dict(base_params)
        params["limit"] = _API_PAGE_SIZE
        params["offset"] = offset
        resp = await client.get(f"{RAG_API_URL}{path}", params=params,
                                headers={"x-api-key": API_KEY})
        if resp.status_code != 200:
            return {"error": resp.text}
        data = resp.json()
        total = int(data.get("total", 0)) or len(data.get(list_key, []) or [])
        page = data.get(list_key, []) or []
        collected.extend(page)
        if len(page) < _API_PAGE_SIZE:
            break
        offset += _API_PAGE_SIZE
    truncated = total > len(collected)
    if truncated:
        collected = collected[:max_total]
    return {"total": total, "returned": len(collected),
            "truncated": truncated, "results": collected}


@mcp.tool()
async def query_assets(
    ip_filter: Annotated[Optional[str], Field(description="Substring filter on IP (case-insensitive)")] = None,
    search: Annotated[Optional[str], Field(description="Substring filter on hostname or IP (case-insensitive). Use this for 'find host containing X' lookups so the filter runs server-side.")] = None,
    provider: Annotated[Optional[str], Field(description="Cloud-hosting provider tag — aws, azure, cloudflare. Comma-separated for OR-match (e.g. 'aws,azure'). PREFERRED for 'find AWS-hosted assets' since it catches vanity domains (cdn.example.com → CloudFront) that hostname-substring would miss. Each row returns provider + provider_evidence inherited from assets.provider.")] = None,
    max_total: Annotated[int, Field(description="Hard cap on rows returned across all pages (default 20000)")] = _DEFAULT_MAX_TOTAL,
) -> str:
    """Query discovered assets (hosts) from the database.

    Auto-paginates internally — returns up to `max_total` rows in a single
    flat list. The response carries `{total, returned, truncated, results}`
    so the caller can tell when more matched than were returned.

    Filtering by `provider` is the right tool for cloud-hosting questions —
    "find every AWS-hosted asset in scope" is one call. Each returned row
    carries `provider` (string array, e.g. ['aws','azure'] when a CDN
    fronts a different-provider origin) and `provider_evidence` (per-tag
    list of why we tagged it: cname:cloudfront, http:aws-header, etc.).
    """
    base: dict = {}
    if ip_filter:
        base["search"] = ip_filter
    if search:
        # Both ip_filter and search supported; if both passed, search wins.
        base["search"] = search
    if provider:
        base["provider"] = provider
    async with httpx.AsyncClient(verify=False, timeout=120) as client:
        out = await _paginate(client, "/assets", base, list_key="assets",
                              max_total=max_total)
        return json.dumps(out, indent=2)


@mcp.tool()
async def query_open_ports(
    ip: Annotated[Optional[str], Field(description="Filter by exact IP address")] = None,
    service: Annotated[Optional[str], Field(description="Filter by service name (e.g. ssh, http) — case-insensitive")] = None,
    search: Annotated[Optional[str], Field(description="Substring match on service / product / banner (case-insensitive). Use for 'find ports with banner containing X'.")] = None,
    max_total: Annotated[int, Field(description="Hard cap on rows returned across all pages (default 20000)")] = _DEFAULT_MAX_TOTAL,
) -> str:
    """Query discovered open ports and services.

    Auto-paginates internally — returns up to `max_total` rows in a single
    flat list. The response carries `{total, returned, truncated, results}`.
    """
    base: dict = {}
    if ip:
        base["ip"] = ip
    if service:
        base["service"] = service
    if search:
        base["search"] = search
    async with httpx.AsyncClient(verify=False, timeout=120) as client:
        out = await _paginate(client, "/ports/open", base, list_key="items",
                              max_total=max_total)
        return json.dumps(out, indent=2)


@mcp.tool()
async def query_findings(
    severity: Annotated[Optional[str], Field(description="Filter: info, low, medium, high, critical")] = None,
    ip: Annotated[Optional[str], Field(description="Filter by exact IP address")] = None,
    script_type: Annotated[Optional[str], Field(description="Filter by Nmap script type")] = None,
    search: Annotated[Optional[str], Field(description="Substring match on script / output / banner (case-insensitive). Use for 'find vulns mentioning X'.")] = None,
    max_total: Annotated[int, Field(description="Hard cap on rows returned across all pages (default 20000)")] = _DEFAULT_MAX_TOTAL,
) -> str:
    """Query vulnerability findings from all scanners.

    Auto-paginates internally — returns up to `max_total` rows in a single
    flat list. The response carries `{total, returned, truncated, results}`.
    """
    base: dict = {}
    if severity:
        base["severity"] = severity
    if ip:
        base["ip"] = ip
    if script_type:
        base["script_type"] = script_type
    if search:
        base["search"] = search
    async with httpx.AsyncClient(verify=False, timeout=120) as client:
        out = await _paginate(client, "/vulns", base, list_key="vulns",
                              max_total=max_total)
        return json.dumps(out, indent=2)


@mcp.tool()
async def get_session_messages(session_id: Annotated[str, Field(description="Session UUID")]) -> str:
    """Get conversation history/messages for a pentest session.

    Args:
        session_id: Session UUID
    """
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.get(f"{API_URL}/pentest/{session_id}/messages")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def cleanup_findings(sources: Annotated[Optional[list[str]], Field(description="Filter by source, e.g. ['nuclei', 'nmap', 'zap']. Deletes all if omitted")] = None, older_than_hours: Annotated[Optional[int], Field(description="Only delete findings older than N hours")] = None, dry_run: Annotated[bool, Field(description="If true, only show what would be deleted")] = True) -> str:
    """Delete vulnerability findings from the database.

    Args:
        sources: Filter by source (e.g., ['nuclei', 'nmap', 'zap']). Deletes all if omitted.
        older_than_hours: Only delete findings older than N hours
        dry_run: If true, only show what would be deleted without deleting (default: true)
    """
    payload = {"dry_run": dry_run}
    if sources:
        payload["sources"] = sources
    if older_than_hours:
        payload["older_than_hours"] = older_than_hours
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(f"{RAG_API_URL}/cleanup/findings", json=payload, headers={"x-api-key": API_KEY})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def cleanup_old_sessions(older_than_hours: Annotated[int, Field(description="Delete sessions older than N hours")] = 72) -> str:
    """Delete old pentest sessions from the database.

    Args:
        older_than_hours: Delete sessions older than N hours (default: 72)
    """
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(f"{API_URL}/pentest/cleanup", json={"older_than_hours": older_than_hours})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def echo(message: Annotated[str, Field(description="Message to echo back")]) -> str:
    """Echo a message back. Use this to test that tool calling is working.

    Args:
        message: Message to echo back
    """
    return json.dumps({"echo": message, "status": "tool_calling_works"})


@mcp.tool()
async def get_time() -> str:
    """Get the current server time."""
    now = datetime.now(timezone.utc)
    return json.dumps({"utc": now.isoformat(), "unix": int(now.timestamp())})


@mcp.tool()
async def add(a: Annotated[float, Field(description="First number")], b: Annotated[float, Field(description="Second number")]) -> str:
    """Add two numbers. Use this to test tool calling with parameters.

    Args:
        a: First number
        b: Second number
    """
    return json.dumps({"a": a, "b": b, "result": a + b})


@mcp.tool()
async def check_health() -> str:
    """Check health status of all backend services."""
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(f"{API_URL}/health/system")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


if __name__ == "__main__":
    logger.info("Starting MCP Sessions Server on 0.0.0.0:9016")
    mcp.run(transport="streamable-http")
