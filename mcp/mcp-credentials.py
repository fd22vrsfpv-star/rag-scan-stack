#!/usr/bin/env python3
"""MCP Server: Credential Testing + Identity Queries (6 tools) — Port 9020
Brutus tools require explicit enablement; identity/group readout is always-on."""

import json, os, logging
from typing import Annotated, Optional
import httpx
from pydantic import Field
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BRUTUS_URL = os.environ.get("BRUTUS_URL", "https://brutus-runner:8025")
RAG_API_URL = os.environ.get("RAG_API_URL", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
TIMEOUT = float(os.environ.get("MCP_TIMEOUT_SCAN", "300"))

mcp = FastMCP("pentest-credentials", host="0.0.0.0", port=9020, stateless_http=True, streamable_http_path="/mcp")


@mcp.tool()
async def start_brutus(targets: Annotated[list[str], Field(description="List of target IPs or host:port pairs")], protocols: Annotated[list[str], Field(description="Protocols to test: ssh, ftp, http-basic, smb, mysql, rdp, etc.")], usernames: Annotated[Optional[list[str]], Field(description="Custom username list; uses built-in defaults if not provided")] = None, passwords: Annotated[Optional[list[str]], Field(description="Custom password list; uses built-in defaults if not provided")] = None) -> str:
    """Start credential testing against target services using Brutus.

    Args:
        targets: List of target IPs or host:port pairs
        protocols: Protocols to test (e.g., ['ssh', 'ftp', 'http-basic', 'smb', 'mysql', 'rdp'])
        usernames: Custom username list (uses defaults if not provided)
        passwords: Custom password list (uses defaults if not provided)
    """
    payload = {"targets": targets, "protocols": protocols}
    if usernames:
        payload["usernames"] = usernames
    if passwords:
        payload["passwords"] = passwords
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(f"{BRUTUS_URL}/jobs/brutus", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_brutus_job_status(job_id: Annotated[str, Field(description="Job UUID returned by start_brutus")]) -> str:
    """Get status of a Brutus credential testing job.

    Args:
        job_id: Job UUID from start_brutus
    """
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(f"{BRUTUS_URL}/jobs/{job_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


_API_PAGE_SIZE = 2000          # rag-api hard cap on a single /identities request
_DEFAULT_MAX_TOTAL = 20000     # fan-out cap so a runaway query can't blow the LLM context


async def _paginate_identities(client: httpx.AsyncClient, base_params: dict,
                               max_total: int = _DEFAULT_MAX_TOTAL) -> dict:
    """Loop over /identities pages until the source is exhausted or max_total
    rows are collected. Returns a flattened {total, results, truncated}
    envelope so the LLM sees ALL matching rows (or knows when more exist)."""
    collected: list = []
    total = 0
    offset = 0
    while len(collected) < max_total:
        params = dict(base_params)
        params["limit"] = _API_PAGE_SIZE
        params["offset"] = offset
        resp = await client.get(f"{RAG_API_URL}/identities", params=params,
                                headers={"x-api-key": API_KEY})
        if resp.status_code != 200:
            return {"error": resp.text}
        data = resp.json()
        total = int(data.get("total", 0))
        page = data.get("results", []) or []
        collected.extend(page)
        if len(page) < _API_PAGE_SIZE:
            break  # last page, done
        offset += _API_PAGE_SIZE
    truncated = total > len(collected)
    if truncated:
        collected = collected[:max_total]
    return {"total": total, "returned": len(collected),
            "truncated": truncated, "results": collected}


@mcp.tool()
async def list_users(
    provider: Annotated[Optional[str], Field(description="Filter by provider: azure, on_prem_ad, aws, gcp")] = None,
    principal_type: Annotated[Optional[str], Field(description="Filter by type: user, guest, service_principal, group, computer")] = None,
    member_of: Annotated[Optional[str], Field(description="Filter to members of this group (matches member_of:<group> tag, e.g. 'Domain Admins')")] = None,
    search: Annotated[Optional[str], Field(description="Substring match on UPN or display name")] = None,
    is_admin: Annotated[Optional[bool], Field(description="True to return only admins")] = None,
    is_guest: Annotated[Optional[bool], Field(description="True to return only guest accounts")] = None,
    has_credential: Annotated[Optional[bool], Field(description="True to return only identities with a matching credential_vault row")] = None,
    max_total: Annotated[int, Field(description="Hard cap on rows returned across all pages (default 20000)")] = _DEFAULT_MAX_TOTAL,
) -> str:
    """List identities (users / guests / service principals) ingested from
    MicroBurst, AzureHound, etc. Combine with member_of=<group> to get a
    group's membership; pair with brutus to spray surfaced accounts.

    Auto-paginates internally — returns up to `max_total` rows in a single
    flat list. The response carries `{total, returned, truncated, results}`
    so the caller can tell when more matched than were returned.
    """
    base: dict = {}
    for k, v in (("provider", provider), ("principal_type", principal_type),
                 ("member_of", member_of), ("search", search),
                 ("is_admin", is_admin), ("is_guest", is_guest),
                 ("has_credential", has_credential)):
        if v is not None:
            base[k] = v
    async with httpx.AsyncClient(verify=False, timeout=120) as client:
        out = await _paginate_identities(client, base, max_total=max_total)
        return json.dumps(out, indent=2)


@mcp.tool()
async def get_user(
    identity_id: Annotated[str, Field(description="Identity UUID returned by list_users")],
) -> str:
    """Full identity detail: every member_of:* group tag, linked credentials,
    recon findings that surfaced this identifier, and provider/tenant context.
    """
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.get(f"{RAG_API_URL}/identities/{identity_id}", headers={"x-api-key": API_KEY})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def list_groups(
    search: Annotated[Optional[str], Field(description="Substring filter on group name (case-insensitive). Use this to narrow large group catalogs (14k+ groups) instead of returning everything.")] = None,
    min_members: Annotated[int, Field(description="Drop groups smaller than this. Useful for hiding 1-member trash groups.")] = 1,
    limit: Annotated[int, Field(description="Max rows to return per call (1-20000). Default 500 keeps responses well under chat/LLM context caps.")] = 500,
    offset: Annotated[int, Field(description="Pagination offset for retrieving > limit groups")] = 0,
) -> str:
    """Groups discovered via MicroBurst <GroupName>_Users.csv ingestion + group
    tags from other Azure AD/Entra ingestors, with member counts.

    The full catalog can run to 14k+ groups (>1 MB JSON), which exceeds chat
    display caps and LLM context limits. ALWAYS pass `search` for "find groups
    matching X" lookups — server-side ILIKE filter keeps the response small.
    Returns `{total, count, limit, offset, results}` so the caller can tell
    when more matched than were returned. Pass a group name to
    get_group_members to expand its membership.
    """
    params: dict = {"limit": limit, "offset": offset, "min_members": min_members}
    if search:
        params["search"] = search
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.get(f"{RAG_API_URL}/identities/groups", params=params,
                                headers={"x-api-key": API_KEY})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_group_members(
    group_name: Annotated[str, Field(description="Group name as returned by list_groups (e.g. 'Domain Admins')")],
    active_only: Annotated[bool, Field(description="Drop disabled accounts (recommended for spray lists)")] = True,
    search: Annotated[Optional[str], Field(description="OPTIONAL — server-side substring filter on UPN / display name (case-insensitive). Use this when looking for a specific person inside a large group instead of returning the whole membership.")] = None,
    max_total: Annotated[int, Field(description="Hard cap on members returned across all pages (default 20000)")] = _DEFAULT_MAX_TOTAL,
) -> str:
    """Every member of one group. Auto-paginates internally — returns the
    full membership in one flat `results` array (up to `max_total`). The
    response includes `{total, returned, truncated}` so the caller knows
    when more existed than were returned. Flatten `results[*].identifier`
    for a spray list.

    For "find <name> in <group>" lookups, pass the `search` parameter so
    the filter runs server-side and the response stays small — much faster
    and cheaper than pulling all 7000+ members into context to grep.
    """
    base = {"member_of": group_name}
    if search:
        base["search"] = search
    async with httpx.AsyncClient(verify=False, timeout=120) as client:
        out = await _paginate_identities(client, base, max_total=max_total)
        if "error" in out:
            return json.dumps(out, indent=2)
        if active_only:
            before = len(out["results"])
            out["results"] = [r for r in out["results"] if r.get("status") != "disabled"]
            out["dropped_disabled"] = before - len(out["results"])
            out["returned"] = len(out["results"])
        return json.dumps(out, indent=2)


if __name__ == "__main__":
    logger.info("Starting MCP Credentials Server on 0.0.0.0:9020")
    mcp.run(transport="streamable-http")
