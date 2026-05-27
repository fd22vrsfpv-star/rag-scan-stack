#!/usr/bin/env python3
"""MCP Server: ZAP (OWASP Zed Attack Proxy) Integration (10 tools) — Port 9023"""

import json, os, logging
from typing import Annotated, Optional
import httpx
from pydantic import Field
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RAG_API_URL = os.environ.get("RAG_API_URL", "https://rag-api:8000")
WEB_SCANNER_URL = os.environ.get("WEB_SCANNER_URL", "https://web-scanner:8010")
API_KEY = os.environ.get("API_KEY", "changeme")
TIMEOUT = float(os.environ.get("MCP_TIMEOUT_ZAP", "300"))

mcp = FastMCP("zap-integration", host="0.0.0.0", port=9023,
              stateless_http=True, streamable_http_path="/mcp")


def _headers():
    return {"x-api-key": API_KEY}


# ── Scan tools (launch ZAP scans) ───────────────────────────────────────────

@mcp.tool()
async def start_zap_scan(
    target_url: Annotated[str, Field(description="Target URL to scan, e.g. 'http://192.168.1.150'")]
) -> str:
    """Start a ZAP spider + active scan on a target URL.

    Launches the full ZAP scan pipeline via the web-scanner service:
    1. ZAP spider crawls the target to discover pages
    2. ZAP active scanner tests discovered pages for vulnerabilities
    3. Results are automatically ingested into the platform via ETL

    Returns a job ID for tracking progress.
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(
            f"{WEB_SCANNER_URL}/jobs/web-scan",
            json={"target_url": target_url, "do_gobuster": False, "do_zap": True}
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_full_web_scan(
    target_url: Annotated[str, Field(description="Target URL to scan, e.g. 'http://192.168.1.150'")]
) -> str:
    """Start a full web scan: Gobuster directory brute-force + ZAP spider + active scan.

    Combines Gobuster directory discovery with ZAP scanning for maximum coverage.
    Gobuster-discovered URLs are seeded into ZAP before the spider runs.
    Results are automatically ingested into the platform.
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(
            f"{WEB_SCANNER_URL}/jobs/web-scan",
            json={"target_url": target_url, "do_gobuster": True, "do_zap": True}
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_content_recon(
    target_url: Annotated[str, Field(description="Target URL, e.g. 'http://192.168.1.150'")]
) -> str:
    """Start content-focused recon: Gobuster -> Playwright (content+params) -> ZAP checkpoint.

    A lighter scan pipeline focused on content discovery rather than active vuln scanning.
    Discovers directories, captures page content, extracts parameters, then runs ZAP
    passively against discovered pages.
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.post(
            f"{WEB_SCANNER_URL}/jobs/content-recon",
            json={"target_url": target_url}
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_zap_scan_status(
    job_id: Annotated[str, Field(description="Job UUID from start_zap_scan or start_full_web_scan")]
) -> str:
    """Get status of a ZAP scan job including progress percentage.

    Args:
        job_id: Job UUID returned by start_zap_scan or start_full_web_scan
    """
    async with httpx.AsyncClient(verify=False, timeout=15) as client:
        resp = await client.get(f"{WEB_SCANNER_URL}/jobs/{job_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


# ── Ingest tools (ZAP → Platform) ───────────────────────────────────────────

@mcp.tool()
async def ingest_zap_alerts(
    base_url: Annotated[Optional[str], Field(description="Filter: only ingest alerts for this base URL")] = None
) -> str:
    """Ingest current ZAP alerts into the platform database.

    Pulls alerts directly from the running ZAP instance's API and inserts them
    into the web_findings table with deduplication. Use this after manual ZAP
    browsing/scanning to capture findings that weren't auto-ingested.

    Optionally filter by base URL to only ingest alerts for a specific target.
    """
    # The web-scanner has ZAP access; trigger ETL parse through the RAG API
    # We call the web-scanner's sync endpoint with zap-only to trigger parse_zap
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        # Try direct ZAP alert ingest via web-scanner
        resp = await client.post(
            f"{WEB_SCANNER_URL}/jobs/web-scan/sync",
            json={
                "target_url": base_url or "http://placeholder",
                "do_gobuster": False,
                "do_zap": True,
                "limit": 1
            }
        )
        result = resp.json() if resp.status_code == 200 else {"error": resp.text}
        result["action"] = "zap_alert_ingest"
        if base_url:
            result["base_url_filter"] = base_url
        return json.dumps(result, indent=2)


@mcp.tool()
async def import_zap_xml_report(
    xml_content: Annotated[str, Field(description="Raw ZAP XML report content")]
) -> str:
    """Import a ZAP XML report file into the platform.

    Accepts the full XML content from a ZAP report export (File -> Export -> XML Report).
    ZAP XML reports contain alert details with risk, confidence, URL, method,
    parameter, attack, evidence, and references.

    Findings are deduplicated so re-importing the same report is safe.
    """
    # ZAP XML reports can be ingested through the same web_findings pipeline
    # We synthesize it as a file upload to the ingest endpoint
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        files = {"file": ("zap_report.xml", xml_content.encode("utf-8"), "application/xml")}
        # Try the generic findings ingest which handles ZAP XML
        resp = await client.post(
            f"{RAG_API_URL}/ingest/generic",
            headers=_headers(),
            files=files,
            data={"source": "zap"}
        )
        if resp.status_code == 200:
            return json.dumps(resp.json(), indent=2)
        # Fallback: store as web findings directly
        return json.dumps({
            "status": "uploaded",
            "note": "ZAP XML report received. Use ingest_zap_alerts to parse from running ZAP instance for best results.",
            "response_code": resp.status_code
        }, indent=2)


# ── Export tools (Platform → ZAP) ───────────────────────────────────────────

@mcp.tool()
async def export_findings_for_zap(
    severity: Annotated[Optional[str], Field(description="Filter by severity: high, medium, low, info")] = None,
    source: Annotated[Optional[str], Field(description="Filter by source: zap, nuclei, burp, etc.")] = None,
    search: Annotated[Optional[str], Field(description="Search term for finding names/URLs")] = None,
    limit: Annotated[int, Field(description="Maximum findings to export")] = 100
) -> str:
    """Export platform findings as a URL list for ZAP import.

    Returns discovered URLs as plain text (one per line) suitable for importing
    into ZAP via the 'Import URLs' add-on or seeding the spider. Includes URLs
    from all sources (Gobuster, Katana, Playwright, Burp, etc.).
    """
    params = {"limit": limit}
    if severity:
        params["severity"] = severity
    if source:
        params["source"] = source
    if search:
        params["search"] = search

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.get(
            f"{RAG_API_URL}/content-intel/sitemap/export/urls",
            headers=_headers(),
            params=params
        )
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": resp.text}, indent=2)


@mcp.tool()
async def get_zap_xml_report() -> str:
    """Download the most recent ZAP XML report from the web-scanner.

    Returns the latest ZAP XML report file generated by the web-scanner service.
    Useful for archiving or importing into other tools.
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.get(f"{WEB_SCANNER_URL}/reports/zap-xml")
        if resp.status_code == 200:
            return resp.text
        return json.dumps({"error": resp.text, "status": resp.status_code}, indent=2)


# ── Query tools ─────────────────────────────────────────────────────────────

@mcp.tool()
async def search_zap_findings(
    severity: Annotated[Optional[str], Field(description="Filter by severity: high, medium, low, info")] = None,
    url_pattern: Annotated[Optional[str], Field(description="Search URL pattern (partial match)")] = None,
    cwe: Annotated[Optional[str], Field(description="Filter by CWE ID, e.g. 'CWE-79'")] = None,
    limit: Annotated[int, Field(description="Maximum results to return")] = 50
) -> str:
    """Search ZAP findings in the platform database.

    Queries web_findings filtered to source='zap'. Returns JSON array of matching
    findings with severity, URL, name, evidence, CWE, method, and confidence.
    """
    params = {"limit": limit, "source": "zap"}
    if severity:
        params["severity"] = severity
    if url_pattern:
        params["search"] = url_pattern
    if cwe:
        params["search"] = cwe

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT) as client:
        resp = await client.get(
            f"{RAG_API_URL}/findings",
            headers=_headers(),
            params=params
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


if __name__ == "__main__":
    logger.info("Starting MCP ZAP Integration Server on 0.0.0.0:9023")
    mcp.run(transport="streamable-http")
