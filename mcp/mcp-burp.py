#!/usr/bin/env python3
"""MCP Server: Burp Suite Integration (10 tools) — Port 9022"""

import json, os, logging, io
from typing import Annotated, Optional
import httpx
from pydantic import Field
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RAG_API_URL = os.environ.get("RAG_API_URL", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
TIMEOUT = float(os.environ.get("MCP_TIMEOUT_BURP", "120"))

mcp = FastMCP("burp-integration", host="0.0.0.0", port=9022,
              stateless_http=True, streamable_http_path="/mcp")


def _headers():
    return {"x-api-key": API_KEY}


# ── Ingest tools (Burp → Platform) ──────────────────────────────────────────

@mcp.tool()
async def import_burp_xml(
    xml_content: Annotated[str, Field(description="Raw Burp XML export content (scanner issues or sitemap)")]
) -> str:
    """Import a Burp Suite XML export (scanner issues or sitemap) into the platform.

    Accepts the full XML content from a Burp export. Supports both:
    - Scanner issues (<issues> root) — vulnerability findings with severity, confidence, detail
    - Sitemap export (<items> root) — captured requests/responses with URLs, methods, status codes

    Findings are deduplicated by fingerprint so re-importing the same file is safe.
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        files = {"file": ("burp_export.xml", xml_content.encode("utf-8"), "application/xml")}
        resp = await client.post(
            f"{RAG_API_URL}/ingest/burp",
            headers=_headers(),
            files=files
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def import_burp_sitemap(
    xml_content: Annotated[str, Field(description="Burp sitemap XML export (<items> root)")]
) -> str:
    """Import a Burp sitemap export and extract URLs for content intelligence.

    Parses the sitemap XML into web_findings and also triggers URL extraction
    for the content intelligence module (discovered parameters, login forms, etc.).
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        # First, ingest the XML
        files = {"file": ("burp_sitemap.xml", xml_content.encode("utf-8"), "application/xml")}
        resp = await client.post(
            f"{RAG_API_URL}/ingest/burp",
            headers=_headers(),
            files=files
        )
        result = resp.json() if resp.status_code == 200 else {"error": resp.text}

        # Extract URLs from the XML for content intel enrichment
        urls_found = []
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_content)
            for item in root.findall(".//item"):
                url = item.findtext("url")
                if url:
                    urls_found.append(url)
        except Exception as e:
            result["url_extraction_error"] = str(e)

        result["urls_extracted"] = len(urls_found)
        return json.dumps(result, indent=2)


@mcp.tool()
async def import_burp_requests(
    requests_json: Annotated[str, Field(description="JSON array of objects with fields: url, method, request, response, status_code, comment")]
) -> str:
    """Import request/response pairs from Burp into the platform as findings.

    Accepts a JSON array of request/response objects (useful for Burp extensions
    that export selected items as JSON). Each object should have:
    - url (required): The full URL
    - method: HTTP method (default: GET)
    - request: Raw request text
    - response: Raw response text
    - status_code: HTTP status code
    - comment: Burp comment/annotation

    Synthesizes a Burp sitemap XML and imports it through the standard pipeline.
    """
    try:
        items = json.loads(requests_json)
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid JSON: {e}"})

    if not isinstance(items, list):
        return json.dumps({"error": "Expected a JSON array of request/response objects"})

    # Synthesize Burp sitemap XML
    import base64
    lines = ['<?xml version="1.0"?>', '<items burpVersion="synthesized" exportTime="now">']
    for item in items:
        url = item.get("url", "")
        method = item.get("method", "GET")
        request_text = item.get("request", "")
        response_text = item.get("response", "")
        status = item.get("status_code", "200")
        comment = item.get("comment", "")

        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
            protocol = parsed.scheme or "http"
            path = parsed.path or "/"
        except Exception:
            host, port, protocol, path = "", "80", "http", "/"

        req_b64 = base64.b64encode(request_text.encode("utf-8")).decode("ascii") if request_text else ""
        resp_b64 = base64.b64encode(response_text.encode("utf-8")).decode("ascii") if response_text else ""

        lines.append("  <item>")
        lines.append(f"    <url><![CDATA[{url}]]></url>")
        lines.append(f"    <host ip=''>{host}</host>")
        lines.append(f"    <port>{port}</port>")
        lines.append(f"    <protocol>{protocol}</protocol>")
        lines.append(f"    <method><![CDATA[{method}]]></method>")
        lines.append(f"    <path><![CDATA[{path}]]></path>")
        lines.append(f"    <status>{status}</status>")
        lines.append(f"    <comment><![CDATA[{comment}]]></comment>")
        lines.append(f"    <request base64='true'><![CDATA[{req_b64}]]></request>")
        lines.append(f"    <response base64='true'><![CDATA[{resp_b64}]]></response>")
        lines.append("  </item>")
    lines.append("</items>")

    xml_content = "\n".join(lines)

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        files = {"file": ("burp_requests.xml", xml_content.encode("utf-8"), "application/xml")}
        resp = await client.post(
            f"{RAG_API_URL}/ingest/burp",
            headers=_headers(),
            files=files
        )
        result = resp.json() if resp.status_code == 200 else {"error": resp.text}
        result["synthesized_items"] = len(items)
        return json.dumps(result, indent=2)


# ── Export tools (Platform → Burp) ──────────────────────────────────────────

@mcp.tool()
async def export_findings_burp_xml(
    severity: Annotated[Optional[str], Field(description="Filter by severity: high, medium, low, info")] = None,
    source: Annotated[Optional[str], Field(description="Filter by source tool: burp, zap, nuclei, etc.")] = None,
    ip: Annotated[Optional[str], Field(description="Filter by IP address")] = None,
    search: Annotated[Optional[str], Field(description="Search term for finding names/URLs")] = None,
    limit: Annotated[int, Field(description="Maximum findings to export")] = 100
) -> str:
    """Export platform findings as Burp-compatible XML for import into Burp Suite.

    Returns XML in Burp Scanner issue format that can be imported into Burp
    via Extensions or the "Import scanner results" feature.
    """
    params = {"limit": limit}
    if severity:
        params["severity"] = severity
    if source:
        params["source"] = source
    if ip:
        params["ip"] = ip
    if search:
        params["search"] = search

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.get(
            f"{RAG_API_URL}/export/burp",
            headers=_headers(),
            params=params
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": resp.text}, indent=2)


@mcp.tool()
async def export_sitemap_burp_xml(
    domain: Annotated[Optional[str], Field(description="Filter by domain name")] = None,
    asset_id: Annotated[Optional[str], Field(description="Filter by asset UUID")] = None
) -> str:
    """Export the platform's discovered sitemap as Burp-compatible XML.

    Returns sitemap data in Burp's items XML format for import into Burp's site map.
    """
    params = {}
    if domain:
        params["domain"] = domain
    if asset_id:
        params["asset_id"] = asset_id

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.get(
            f"{RAG_API_URL}/content-intel/sitemap/export/burp",
            headers=_headers(),
            params=params
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": resp.text}, indent=2)


@mcp.tool()
async def export_urls_txt(
    domain: Annotated[Optional[str], Field(description="Filter by domain name")] = None,
    asset_id: Annotated[Optional[str], Field(description="Filter by asset UUID")] = None
) -> str:
    """Export discovered URLs as plain text (one per line) for Burp's URL import or other tools.

    Useful for feeding into Burp's "Paste URL" feature, Intruder, or external tools.
    """
    params = {}
    if domain:
        params["domain"] = domain
    if asset_id:
        params["asset_id"] = asset_id

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.get(
            f"{RAG_API_URL}/content-intel/sitemap/export/urls",
            headers=_headers(),
            params=params
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": resp.text}, indent=2)


# ── Query tools ─────────────────────────────────────────────────────────────

@mcp.tool()
async def search_findings(
    severity: Annotated[Optional[str], Field(description="Filter by severity: high, medium, low, info")] = None,
    source: Annotated[Optional[str], Field(description="Filter by source tool: burp, zap, nuclei, etc.")] = None,
    cve: Annotated[Optional[str], Field(description="Filter by CVE ID, e.g. 'CVE-2021-44228'")] = None,
    url_pattern: Annotated[Optional[str], Field(description="Search URL pattern (partial match)")] = None,
    limit: Annotated[int, Field(description="Maximum results to return")] = 50
) -> str:
    """Search findings in the platform database with filters.

    Returns JSON array of matching findings with severity, URL, name, evidence, and source.
    """
    params = {"limit": limit}
    if severity:
        params["severity"] = severity
    if source:
        params["source"] = source
    if cve:
        params["search"] = cve
    if url_pattern:
        params["search"] = url_pattern

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.get(
            f"{RAG_API_URL}/findings",
            headers=_headers(),
            params=params
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_sitemap(
    domain: Annotated[str, Field(description="Domain name to query sitemap for, e.g. 'example.com'")]
) -> str:
    """Get the discovered sitemap for a domain including URLs, parameters, and metadata.

    Returns the content intelligence sitemap data showing all discovered pages,
    forms, parameters, and technologies for the specified domain.
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.get(
            f"{RAG_API_URL}/content-intel/sitemap",
            headers=_headers(),
            params={"domain": domain}
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_discovered_params(
    domain: Annotated[Optional[str], Field(description="Filter by domain or URL substring (case-insensitive)")] = None,
    url_pattern: Annotated[Optional[str], Field(description="Filter by URL pattern substring (case-insensitive)")] = None,
    param_name: Annotated[Optional[str], Field(description="Filter by parameter name substring (case-insensitive)")] = None,
    limit: Annotated[int, Field(description="Max rows to return (1-2000)")] = 200,
) -> str:
    """Get discovered parameters from crawled web applications.

    Returns parameters found in URLs, forms, and JavaScript files — useful for
    building Burp Intruder payloads or identifying injection points.
    """
    # The rag-api endpoint is /params (not /content-intel/params).
    # `domain` maps onto `url_pattern` server-side since the API filters URLs
    # via ILIKE substring matching.
    params: dict = {"limit": limit}
    if url_pattern:
        params["url_pattern"] = url_pattern
    elif domain:
        params["url_pattern"] = domain
    if param_name:
        params["param_name"] = param_name

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.get(
            f"{RAG_API_URL}/params",
            headers=_headers(),
            params=params,
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_scope() -> str:
    """Get the current engagement scope (target IPs, domains, and networks).

    Returns the authorized scope targets — useful for configuring Burp's
    target scope to match the engagement boundaries.
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.get(
            f"{RAG_API_URL}/scope/targets",
            headers=_headers()
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


if __name__ == "__main__":
    logger.info("Starting MCP Burp Integration Server on 0.0.0.0:9022")
    mcp.run(transport="streamable-http")
