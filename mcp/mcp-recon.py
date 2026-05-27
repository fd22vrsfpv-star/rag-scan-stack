#!/usr/bin/env python3
"""MCP Server: OSINT Recon Tools (9 tools) — Port 9018"""

import json, os, logging
from typing import Annotated, Optional
import httpx
from pydantic import Field
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

OSINT_URL = os.environ.get("OSINT_URL", "https://osint-runner:8024")
RAG_API_URL = os.environ.get("RAG_API_URL", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
SCAN_RECOMMENDER_URL = os.environ.get("SCAN_RECOMMENDER_URL", "https://scan-recommender:8013")
TIMEOUT = float(os.environ.get("MCP_TIMEOUT_SCAN", "300"))

mcp = FastMCP("pentest-recon", host="0.0.0.0", port=9018, stateless_http=True, streamable_http_path="/mcp")


@mcp.tool()
async def start_subfinder(domains: Annotated[list[str], Field(description="List of target domains, e.g. ['example.com', 'target.org']")], sources: Annotated[Optional[str], Field(description="Comma-separated sources, e.g. 'virustotal,shodan,censys'")] = None) -> str:
    """Passive subdomain enumeration to discover subdomains.

    Args:
        domains: List of target domains (e.g., ['example.com', 'target.org'])
        sources: Comma-separated sources (e.g., 'virustotal,shodan,censys')
    """
    payload = {"domains": domains}
    if sources:
        payload["sources"] = sources
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/subfinder", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_dnsx(domains: Annotated[list[str], Field(description="List of domains or subdomains to resolve")], record_types: Annotated[str, Field(description="DNS record types, e.g. 'a,aaaa,cname,mx,ns,txt'")] = "a,aaaa,cname,mx") -> str:
    """DNS resolution and enumeration for domains.

    Args:
        domains: List of domains/subdomains to resolve
        record_types: DNS record types (e.g., 'a,aaaa,cname,mx,ns,txt')
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/dnsx", json={"domains": domains, "record_types": record_types})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_asnmap(targets: Annotated[list[str], Field(description="List of ASN numbers, IPs, or domains to map")]) -> str:
    """Map ASN numbers to CIDR ranges for network discovery.

    Args:
        targets: List of ASN numbers, IPs, or domains
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/asnmap", json={"targets": targets})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_next_scan_recommendation(target_ip: Annotated[Optional[str], Field(description="Target IP to get recommendations for")] = None) -> str:
    """AI-powered recommendation for what to scan next based on current findings.

    Args:
        target_ip: Target IP to get recommendations for
    """
    params = {}
    if target_ip:
        params["target"] = target_ip
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(f"{SCAN_RECOMMENDER_URL}/next_scan", params=params)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_uncover(query: Annotated[str, Field(description="Search query, e.g. 'org:\"Target Corp\"' or 'ssl:\"target.com\"'")], engine: Annotated[str, Field(description="Search engine to use: shodan, censys, or fofa")] = "shodan", limit: Annotated[int, Field(description="Maximum number of results to return")] = 100) -> str:
    """Search engine reconnaissance using Shodan, Censys, or Fofa for passive intel on targets.

    Args:
        query: Search query (e.g., 'org:\"Target Corp\"', 'ssl:\"target.com\"')
        engine: Search engine to use (shodan, censys, fofa)
        limit: Maximum results
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/uncover", json={"query": query, "engine": engine, "limit": limit})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_cloudlist(provider: Annotated[str, Field(description="Cloud provider: aws, gcp, azure, digitalocean, etc.")] = "aws") -> str:
    """Enumerate cloud provider IP ranges and assets.

    Args:
        provider: Cloud provider (aws, gcp, azure, digitalocean, etc.)
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/cloudlist", json={"provider": provider})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_alterx(domains: Annotated[list[str], Field(description="List of domains to generate permutations for")], patterns: Annotated[Optional[list[str]], Field(description="Custom permutation patterns; uses defaults if not provided")] = None) -> str:
    """Generate subdomain wordlists using pattern-based permutation.

    Args:
        domains: List of domains to generate permutations for
        patterns: Custom patterns (uses defaults if not provided)
    """
    payload = {"domains": domains}
    if patterns:
        payload["patterns"] = patterns
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/alterx", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_mapcidr(cidrs: Annotated[list[str], Field(description="List of CIDR ranges, e.g. ['192.168.1.0/24', '10.0.0.0/16']")], operation: Annotated[str, Field(description="Operation to perform: expand, aggregate, or count")] = "expand") -> str:
    """CIDR range utility for aggregation, expansion, or host counting.

    Args:
        cidrs: List of CIDR ranges (e.g., ['192.168.1.0/24', '10.0.0.0/16'])
        operation: Operation to perform (expand, aggregate, count)
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/mapcidr", json={"cidrs": cidrs, "operation": operation})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_passive_recon(
    targets: Annotated[list[str], Field(description="List of target domains, e.g. ['example.com', 'target.org']")],
    scope_name: Annotated[Optional[str], Field(description="Scope name for auto-adding discovered domains")] = None,
    include_spider: Annotated[bool, Field(description="Enable katana web crawling")] = False,
    spider_depth: Annotated[int, Field(description="Katana crawl depth (1-5)")] = 2,
    include_cert_chain: Annotated[bool, Field(description="Enable cert serial chaining via crt.sh")] = True,
    cert_chain_max_iterations: Annotated[int, Field(description="Max cert chain iterations (1-3)")] = 2,
    plan_only: Annotated[bool, Field(description="Return plan without executing")] = False,
    proxy: Annotated[Optional[str], Field(description="SOCKS proxy URL, e.g. socks5://127.0.0.1:10120")] = None,
) -> str:
    """Passive-only recon pipeline: subfinder→dnsx→crtsh→httpx→tlsx→cert-chain→gau→katana→gowitness→whatweb.
    No port scanning, no DNS brute force, no vulnerability scanning.

    Args:
        targets: List of target domains
        scope_name: Scope name for auto-adding discovered domains
        include_spider: Enable katana web crawling (default False)
        spider_depth: Katana crawl depth 1-5 (default 2)
        include_cert_chain: Enable cert serial chaining (default True)
        cert_chain_max_iterations: Max iterations 1-3 (default 2)
        plan_only: Return plan without executing (default False)
        proxy: SOCKS proxy URL (optional)
    """
    payload = {
        "targets": targets,
        "include_spider": include_spider,
        "spider_depth": spider_depth,
        "include_cert_chain": include_cert_chain,
        "cert_chain_max_iterations": cert_chain_max_iterations,
        "plan_only": plan_only,
    }
    if scope_name:
        payload["scope_name"] = scope_name
    if proxy:
        payload["proxy"] = proxy
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/passive-recon", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_osint_job_status(job_id: Annotated[str, Field(description="Job UUID returned by any OSINT tool")]) -> str:
    """Get status of an OSINT job (subfinder, dnsx, asnmap, uncover, cloudlist, alterx, mapcidr).

    Args:
        job_id: Job UUID from any OSINT tool
    """
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(f"{OSINT_URL}/jobs/{job_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def list_scopes() -> str:
    """List all scope names with target counts. Shows how targets are organized into scopes like 'unknown_scope', 'customer_or_third_party', etc."""
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(f"{RAG_API_URL}/scope/names", headers={"x-api-key": API_KEY})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def list_scope_targets(
    scope_name: Annotated[str, Field(description="Scope name, e.g. 'unknown_scope' or 'customer_apps'")],
) -> str:
    """List all targets in a specific scope.

    Args:
        scope_name: Name of the scope to list targets from
    """
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(f"{RAG_API_URL}/scope", params={"name": scope_name}, headers={"x-api-key": API_KEY})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def move_to_scope(
    targets: Annotated[list[str], Field(description="List of hostnames, domains, or IPs to move")],
    from_scope: Annotated[str, Field(description="Source scope name to remove from, e.g. 'unknown_scope'")],
    to_scope: Annotated[str, Field(description="Destination scope name to add to, e.g. 'customer_apps'. Creates if new.")],
) -> str:
    """Move targets from one scope to another. Removes from source, adds to destination.
    Use this to triage assets from 'unknown_scope' into proper scopes.

    Args:
        targets: List of hostnames/domains/IPs (e.g., ['blog.example.com', 'app.example.com'])
        from_scope: Source scope name to remove targets from
        to_scope: Destination scope name to move targets to (created if doesn't exist)
    """
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.post(
            f"{RAG_API_URL}/scope/move",
            json={"from_scope": from_scope, "to_scope": to_scope, "targets": targets},
            headers={"x-api-key": API_KEY},
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def add_to_scope(
    targets: Annotated[list[str], Field(description="List of hostnames, domains, or IPs to add")],
    scope_name: Annotated[str, Field(description="Scope name to add targets to, e.g. 'customer_apps'")] = "default",
) -> str:
    """Add targets to a scope without removing from any other scope.

    Args:
        targets: List of hostnames/domains/IPs to add
        scope_name: Scope name to add to (created if doesn't exist)
    """
    target_items = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        target_type = "ip" if t.replace(".", "").isdigit() or ":" in t else "domain"
        target_items.append({"target": t, "target_type": target_type, "source": "mcp"})
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.post(
            f"{RAG_API_URL}/scope/add",
            json={"name": scope_name, "targets": target_items},
            headers={"x-api-key": API_KEY},
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def auto_assign_unknown_scope() -> str:
    """Scan all assets and recon findings, assign any that aren't in a scope to 'unknown_scope'.
    Run this after new scans to triage unscoped discoveries."""
    async with httpx.AsyncClient(verify=False, timeout=120) as client:
        resp = await client.post(f"{RAG_API_URL}/scope/auto-assign-unknown", headers={"x-api-key": API_KEY})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_domain_overview(
    domain: Annotated[str, Field(description="Domain or subdomain to get overview for, e.g. 'blog.example.com'")],
) -> str:
    """Get full recon overview for a domain or subdomain: subdomains, DNS, HTTP services, TLS, web findings, parameters.

    Args:
        domain: Domain or subdomain name
    """
    async with httpx.AsyncClient(verify=False, timeout=30) as client:
        resp = await client.get(
            f"{RAG_API_URL}/recon/domains/{domain}/overview",
            headers={"x-api-key": API_KEY},
        )
        if resp.status_code == 200:
            data = resp.json()
            # Summarize to keep response manageable
            stats = data.get("stats", {})
            summary = {
                "domain": data.get("domain"),
                "total_findings": stats.get("total_findings", 0),
                "subdomains_count": len(data.get("subdomains", [])),
                "http_services_count": len(data.get("http_services", [])),
                "dns_records_count": sum(len(v) for v in data.get("dns_records", {}).values()),
                "tls_certs_count": len(data.get("tls_certs", [])),
                "web_findings_count": stats.get("web_findings_count", 0),
                "params_count": len(data.get("discovered_params", [])),
                "by_source": stats.get("by_source", {}),
                "first_seen": stats.get("first_seen"),
                "last_seen": stats.get("last_seen"),
                "subdomains": [s["name"] for s in data.get("subdomains", [])[:50]],
                "params": [{"name": p["name"], "count": p["count"]} for p in data.get("discovered_params", [])[:20]],
            }
            return json.dumps(summary, indent=2)
        return json.dumps({"error": resp.text}, indent=2)


if __name__ == "__main__":
    logger.info("Starting MCP Recon Server on 0.0.0.0:9018")
    mcp.run(transport="streamable-http")
