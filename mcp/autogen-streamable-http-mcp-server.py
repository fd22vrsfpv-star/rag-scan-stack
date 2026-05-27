#!/usr/bin/env python3
"""
MCP Server using Streamable HTTP transport.

This version uses the modern Streamable HTTP transport (MCP 2025-03-26 spec)
which replaces the deprecated SSE transport. Works natively with Open WebUI.

Port: 8016
Endpoint: /mcp (POST for requests, GET for SSE streaming)
"""

import json
import os
import logging
from typing import Optional, Dict, Any

import httpx
from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API endpoints - use Docker service names when running in container
API_URL = os.environ.get("API_URL", "https://autogen-agents:8015")
RAG_API_URL = os.environ.get("RAG_API_URL", "https://rag-api:8000")
NMAP_URL = os.environ.get("NMAP_URL", "https://nmap_scanner:8012")
PLAYWRIGHT_URL = os.environ.get("PLAYWRIGHT_URL", "https://playwright-scanner:8014")
EXPLOIT_RUNNER_URL = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")
WEB_SCANNER_URL = os.environ.get("WEB_SCANNER_URL", "https://web-scanner:8010")
NUCLEI_URL = os.environ.get("NUCLEI_URL", "https://nuclei-runner:8011")
SCAN_RECOMMENDER_URL = os.environ.get("SCAN_RECOMMENDER_URL", "https://scan-recommender:8013")
PD_RUNNER_URL = os.environ.get("PD_RUNNER_URL", "https://pd-runner:8023")
OSINT_URL = os.environ.get("OSINT_URL", "https://osint-runner:8024")
BRUTUS_URL = os.environ.get("BRUTUS_URL", "https://brutus-runner:8025")

# Server config
HOST = os.environ.get("MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("MCP_PORT", "8016"))

# Configurable timeouts
TIMEOUT_SCAN = float(os.environ.get("MCP_TIMEOUT_SCAN", "300"))
TIMEOUT_QUICK = float(os.environ.get("MCP_TIMEOUT_QUICK", "30"))
TIMEOUT_STATUS = float(os.environ.get("MCP_TIMEOUT_STATUS", "15"))

# API Key for rag-api
API_KEY = os.environ.get("API_KEY", "changeme")

# Create FastMCP server with Streamable HTTP support
mcp = FastMCP(
    "autogen-pentest",
    host=HOST,
    port=PORT,
    stateless_http=True,  # Better for scalability
    streamable_http_path="/mcp",
)


def get_timeout(name: str) -> float:
    """Get appropriate timeout for the tool"""
    if name.startswith("start_"):
        return TIMEOUT_SCAN
    elif "status" in name:
        return TIMEOUT_STATUS
    else:
        return TIMEOUT_QUICK


# ============================================================================
# Pentest Session Management Tools
# ============================================================================

@mcp.tool()
async def start_pentest_session(
    session_name: str,
    target_description: str,
    initial_task: str,
    max_rounds: int = 200
) -> str:
    """Start an autonomous AI-powered penetration testing session.

    Args:
        session_name: Human-readable session name
        target_description: Description of target (e.g., '192.168.1.150')
        initial_task: Initial task for agents (e.g., 'Scan for open ports and vulnerabilities')
        max_rounds: Max conversation rounds (default: 200)
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{API_URL}/pentest", json={
            "session_name": session_name,
            "target_description": target_description,
            "initial_task": initial_task,
            "max_rounds": max_rounds
        })
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_session_status(session_id: str) -> str:
    """Get status of a pentest session.

    Args:
        session_id: Session UUID
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_STATUS) as client:
        resp = await client.get(f"{API_URL}/pentest/{session_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_session_scans(session_id: str) -> str:
    """Get comprehensive scan status for a pentest session including all related scans.

    Returns session start time, current phase, and status of all scans (masscan, nmap, nuclei, web_scan, playwright).

    Args:
        session_id: Session UUID
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_STATUS) as client:
        resp = await client.get(f"{API_URL}/pentest/{session_id}/scans")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def list_sessions(status: Optional[str] = None, limit: int = 50) -> str:
    """List all pentest sessions.

    Args:
        status: Filter by status (active, completed, failed, stopped)
        limit: Maximum number of sessions to return
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        params = {"limit": limit}
        if status:
            params["status"] = status
        resp = await client.get(f"{API_URL}/pentest/sessions", params=params)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def stop_session(session_id: str) -> str:
    """Stop a running pentest session.

    Args:
        session_id: Session UUID
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.post(f"{API_URL}/pentest/{session_id}/stop")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def resume_pentest_session(
    session_id: str,
    additional_instructions: str = "",
    max_rounds: int = 200
) -> str:
    """Resume a failed/stalled/stopped pentest session, reusing data already collected.

    Creates a new session that inherits context from the failed parent session.
    Agents will see all previously discovered assets, ports, and findings.

    Args:
        session_id: UUID of the failed session to resume
        additional_instructions: Optional extra instructions for the resumed session
        max_rounds: Max conversation rounds (default: 200)
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{API_URL}/pentest/{session_id}/resume", json={
            "max_rounds": max_rounds,
            "additional_instructions": additional_instructions or None
        })
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_session_messages(session_id: str, limit: int = 100) -> str:
    """Get conversation history for a session.

    Args:
        session_id: Session UUID
        limit: Maximum number of messages to return
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.get(f"{API_URL}/pentest/{session_id}/messages", params={"limit": limit})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def check_health() -> str:
    """Check autogen-agents service health and dependencies."""
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_STATUS) as client:
        resp = await client.get(f"{API_URL}/health")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


# ============================================================================
# Scanner Status Tools
# ============================================================================

@mcp.tool()
async def get_nmap_job_status(job_id: str) -> str:
    """Get status of an Nmap/Masscan scan job.

    Args:
        job_id: Job UUID returned from nmap/masscan scan
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_STATUS) as client:
        resp = await client.get(f"{NMAP_URL}/jobs/{job_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_nuclei_job_status(job_id: str) -> str:
    """Get status of a Nuclei vulnerability scan job.

    Args:
        job_id: Job UUID returned from nuclei scan
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_STATUS) as client:
        resp = await client.get(f"{NUCLEI_URL}/jobs/{job_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_web_scan_job_status(job_id: str) -> str:
    """Get status of a web scan job (Gobuster/ZAP).

    Args:
        job_id: Job UUID returned from web scan
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_STATUS) as client:
        resp = await client.get(f"{WEB_SCANNER_URL}/jobs/{job_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_playwright_scan_status(scan_id: str) -> str:
    """Get status of a Playwright browser security scan.

    Args:
        scan_id: Scan UUID returned from playwright scan
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_STATUS) as client:
        resp = await client.get(f"{PLAYWRIGHT_URL}/scan/{scan_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_all_active_jobs() -> str:
    """Get status of all active scan jobs across all scanners."""
    result = {"nmap_jobs": [], "web_jobs": [], "nuclei_jobs": [], "osint_jobs": [], "pd_jobs": [], "brutus_jobs": [], "errors": []}

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_STATUS) as client:
        # Get nmap jobs
        try:
            r = await client.get(f"{NMAP_URL}/jobs", timeout=5.0)
            if r.status_code == 200:
                result["nmap_jobs"] = r.json().get("jobs", [])
        except Exception as e:
            result["errors"].append(f"nmap: {str(e)}")

        # Get web jobs
        try:
            r = await client.get(f"{WEB_SCANNER_URL}/jobs", timeout=5.0)
            if r.status_code == 200:
                result["web_jobs"] = r.json().get("jobs", [])
        except Exception as e:
            result["errors"].append(f"web: {str(e)}")

        # Get nuclei jobs
        try:
            r = await client.get(f"{NUCLEI_URL}/jobs", timeout=5.0)
            if r.status_code == 200:
                result["nuclei_jobs"] = r.json().get("jobs", [])
        except Exception as e:
            result["errors"].append(f"nuclei: {str(e)}")

        # Get OSINT jobs
        try:
            r = await client.get(f"{OSINT_URL}/jobs", params={"status": "running"}, timeout=5.0)
            if r.status_code == 200:
                result["osint_jobs"] = r.json().get("jobs", [])
        except Exception as e:
            result["errors"].append(f"osint: {str(e)}")

        # Get PD runner jobs
        try:
            r = await client.get(f"{PD_RUNNER_URL}/jobs", params={"status": "running"}, timeout=5.0)
            if r.status_code == 200:
                result["pd_jobs"] = r.json().get("jobs", [])
        except Exception as e:
            result["errors"].append(f"pd: {str(e)}")

        # Get Brutus jobs
        try:
            r = await client.get(f"{BRUTUS_URL}/jobs", params={"status": "running"}, timeout=5.0)
            if r.status_code == 200:
                result["brutus_jobs"] = r.json().get("jobs", [])
        except Exception as e:
            result["errors"].append(f"brutus: {str(e)}")

    return json.dumps(result, indent=2)


@mcp.tool()
async def get_all_scanner_status() -> str:
    """Get comprehensive status of all scanner services."""
    services = {
        "nmap_scanner": {"url": f"{NMAP_URL}/health", "status": "unknown"},
        "playwright_scanner": {"url": f"{PLAYWRIGHT_URL}/health", "status": "unknown"},
        "web_scanner": {"url": f"{WEB_SCANNER_URL}/health", "status": "unknown"},
        "nuclei_runner": {"url": f"{NUCLEI_URL}/health", "status": "unknown"},
        "exploit_runner": {"url": f"{EXPLOIT_RUNNER_URL}/health", "status": "unknown"},
        "osint_runner": {"url": f"{OSINT_URL}/health", "status": "unknown"},
        "pd_runner": {"url": f"{PD_RUNNER_URL}/health", "status": "unknown"},
        "brutus_runner": {"url": f"{BRUTUS_URL}/health", "status": "unknown"},
    }

    async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
        for svc_name, info in services.items():
            try:
                resp = await client.get(info["url"])
                info["status"] = "healthy" if resp.status_code == 200 else "unhealthy"
            except Exception:
                info["status"] = "unreachable"

    return json.dumps({"services": services}, indent=2)


# ============================================================================
# Scanning Tools
# ============================================================================

@mcp.tool()
async def start_masscan(
    target: str,
    ports: str = "1-1000",
    rate: int = 1000
) -> str:
    """Start a fast Masscan port discovery scan. Run this FIRST for quick port discovery.

    Args:
        target: IP address, hostname, or CIDR range
        ports: Port range (e.g., '1-1000' for top 1000, '1-65535' for all)
        rate: Packets per second (default: 1000)
    """
    targets = [target] if isinstance(target, str) else target
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{NMAP_URL}/jobs/masscan-only", json={
            "targets": targets,
            "ports": ports,
            "rate": rate
        })
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_nmap_scan(
    target: str,
    ports: str = "1-1000",
    scan_type: str = "service"
) -> str:
    """Start an Nmap port scan with service detection. Run AFTER masscan finds open ports.

    Args:
        target: IP address, hostname, or CIDR range
        ports: Port range (e.g., '22,80,443' or '1-1000')
        scan_type: Scan type - 'quick', 'full', or 'service' (default)
    """
    targets = [target] if isinstance(target, str) else target
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{NMAP_URL}/jobs/masscan-then-nmap", json={
            "targets": targets,
            "ports": ports,
            "rate": 1000
        })
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_udp_scan(
    target: str,
    ports: str = "53,67,68,69,123,161,162,500,514,1900"
) -> str:
    """Start a UDP port scan. Slower but finds UDP services like DNS, SNMP, NTP.

    Args:
        target: IP address or hostname
        ports: UDP ports to scan (default: common UDP services)
    """
    targets = [target] if isinstance(target, str) else target
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{NMAP_URL}/jobs/nmap-udp", json={
            "targets": targets,
            "ports": ports
        })
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_web_scan(
    target_url: Optional[str] = None,
    do_gobuster: bool = True,
    use_zap: bool = True,
    limit: int = 25,
    wordlist: Optional[str] = None
) -> str:
    """Start web scanning (Gobuster + ZAP) against a target URL or web targets from database.

    Args:
        target_url: Specific target URL to scan (e.g., 'http://192.168.1.150')
        do_gobuster: Run Gobuster directory scan (default: True)
        use_zap: Run ZAP proxy scan (default: True)
        limit: Max targets from database if no URL provided
        wordlist: Wordlist for Gobuster - 'common', 'medium', or 'big'
    """
    scan_request = {
        "do_gobuster": do_gobuster,
        "do_zap": use_zap,
        "limit": limit,
    }
    if target_url:
        scan_request["target_url"] = target_url
    if wordlist:
        scan_request["wordlist"] = wordlist

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{WEB_SCANNER_URL}/jobs/web-scan", json=scan_request)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_nuclei_scan(
    target: Optional[str] = None,
    limit: int = 25,
    severity: str = "medium,high,critical",
    templates: Optional[str] = None
) -> str:
    """Start a Nuclei vulnerability scan on a target or targets from database.

    Args:
        target: Specific target IP/hostname (optional - scans from database if not provided)
        limit: Max targets from database
        severity: Severity filter (comma-separated: info,low,medium,high,critical)
        templates: Template tags (comma-separated: cve,vulnerabilities,exposures)
    """
    scan_request = {"severity": severity}
    if target:
        scan_request["target"] = target
    else:
        scan_request["limit"] = limit
    if templates:
        scan_request["tags"] = templates

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{NUCLEI_URL}/jobs/nuclei-scan", json=scan_request)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_playwright_scan(
    target_url: str,
    browser: str = "chromium",
    screenshot: bool = True
) -> str:
    """Start a Playwright browser-based security scan.

    Args:
        target_url: Target URL to scan
        browser: Browser to use - 'chromium', 'firefox', or 'webkit'
        screenshot: Capture screenshots (default: True)
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{PLAYWRIGHT_URL}/scan", json={
            "url": target_url,
            "browser": browser,
            "capture_screenshots": screenshot,
            "run_security_checks": True,
            "use_zap_proxy": True
        })
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


# ============================================================================
# Query Tools
# ============================================================================

@mcp.tool()
async def query_assets(
    ip_filter: Optional[str] = None,
    search: Optional[str] = None,
    provider: Optional[str] = None,
    limit: int = 100,
) -> str:
    """Query discovered assets from the database.

    Use `provider` to find cloud-hosted assets including vanity domains —
    provider="aws" returns every asset tagged AWS via CNAME/cert/HTTP-header
    signals, even when the hostname doesn't say amazonaws (e.g.
    cdn.example.com fronted by CloudFront).

    Args:
        ip_filter: Filter by IP pattern
        search: Substring match on hostname or IP
        provider: Cloud-hosting provider tag — aws, azure, cloudflare. Comma-separated for OR.
        limit: Maximum results
    """
    params: Dict[str, Any] = {"limit": limit}
    if ip_filter:
        params["search"] = ip_filter
    if search:
        params["search"] = search
    if provider:
        params["provider"] = provider

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.get(f"{RAG_API_URL}/assets", params=params, headers={"x-api-key": API_KEY})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def query_open_ports(
    ip: Optional[str] = None,
    port: Optional[int] = None,
    service: Optional[str] = None,
    limit: int = 100
) -> str:
    """Query discovered open ports and services.

    Args:
        ip: Filter by IP address
        port: Filter by port number
        service: Filter by service name
        limit: Maximum results
    """
    params = {"limit": limit}
    if ip:
        params["ip"] = ip
    if port:
        params["port"] = port
    if service:
        params["service"] = service

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.get(f"{RAG_API_URL}/ports/open", params=params, headers={"x-api-key": API_KEY})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def query_findings(
    severity: Optional[str] = None,
    ip: Optional[str] = None,
    limit: int = 100
) -> str:
    """Query vulnerability findings from all scanners.

    Args:
        severity: Filter by severity (info, low, medium, high, critical)
        ip: Filter by IP address
        limit: Maximum results
    """
    params = {"limit": limit}
    if severity:
        params["severity"] = severity
    if ip:
        params["ip"] = ip

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.get(f"{RAG_API_URL}/vulns", params=params, headers={"x-api-key": API_KEY})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def search_exploits(query: str, limit: int = 10) -> str:
    """Search the exploit database using semantic search (RAG).

    Args:
        query: Search query (CVE, service name, vulnerability type)
        limit: Maximum results
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.get(f"{SCAN_RECOMMENDER_URL}/rag/ask", params={"q": query, "top_k": limit})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def search_exploits_enhanced(
    query: str,
    service: Optional[str] = None,
    version: Optional[str] = None,
    cve: Optional[str] = None,
    limit: int = 10
) -> str:
    """Enhanced RAG search for exploits with CVE/service/version matching.

    Args:
        query: Search query
        service: Filter by service name (e.g., 'vsftpd', 'apache')
        version: Filter by version (e.g., '2.3.4')
        cve: Filter by CVE (e.g., 'CVE-2011-2523')
        limit: Maximum results
    """
    params = {"q": query, "top_k": limit}
    if service:
        params["service"] = service
    if version:
        params["version"] = version
    if cve:
        params["cve"] = cve

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.get(f"{SCAN_RECOMMENDER_URL}/rag/search/enhanced", params=params)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_next_scan_recommendation(target_ip: Optional[str] = None) -> str:
    """Get AI-powered recommendation for what to scan next based on current findings.

    Args:
        target_ip: Target IP to get recommendations for
    """
    params = {}
    if target_ip:
        params["target"] = target_ip

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.get(f"{SCAN_RECOMMENDER_URL}/next_scan", params=params)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


# ============================================================================
# Security Testing Tools (Exploit Execution)
# ============================================================================

@mcp.tool()
async def run_edb_script(
    edb_id: str,
    target_ip: str,
    target_port: int = 80,
    args: Optional[dict] = None
) -> str:
    """Run an ExploitDB security script for authorized penetration testing.

    Args:
        edb_id: ExploitDB ID (e.g., '51459')
        target_ip: Target IP address
        target_port: Target port (default: 80)
        args: Additional script arguments
    """
    script_request = {
        "edb_id": edb_id,
        "target_ip": target_ip,
        "target_port": target_port,
        "extra_args": args or {}
    }

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{EXPLOIT_RUNNER_URL}/execute/script", json=script_request)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text, "status_code": resp.status_code}, indent=2)


@mcp.tool()
async def run_msf_module(
    module_path: str,
    target_ip: str,
    target_port: Optional[int] = None,
    payload: Optional[str] = None,
    lhost: Optional[str] = None,
    lport: int = 4444,
    options: Optional[dict] = None
) -> str:
    """Run a Metasploit module for authorized penetration testing.

    Args:
        module_path: MSF module path (e.g., 'exploit/unix/ftp/vsftpd_234_backdoor')
        target_ip: Target IP (RHOSTS)
        target_port: Target port (RPORT)
        payload: Payload to use (e.g., 'cmd/unix/interact')
        lhost: Callback IP for reverse shells (auto-detected if not set)
        lport: Callback port for reverse shells (default: 4444)
        options: Additional module options
    """
    module_type = module_path.split("/")[0] if "/" in module_path else "auxiliary"

    msf_options = {"RHOSTS": target_ip}
    if target_port:
        msf_options["RPORT"] = target_port
    if payload:
        msf_options["PAYLOAD"] = payload
    if lhost:
        msf_options["LHOST"] = lhost
    if lport:
        msf_options["LPORT"] = lport
    if options:
        msf_options.update(options)

    msf_request = {
        "module_type": module_type,
        "module_name": module_path,
        "options": msf_options
    }

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{EXPLOIT_RUNNER_URL}/execute/msf", json=msf_request)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text, "status_code": resp.status_code}, indent=2)


@mcp.tool()
async def list_msf_sessions() -> str:
    """List active Metasploit sessions (shells, meterpreter)."""
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.get(f"{EXPLOIT_RUNNER_URL}/msf/sessions")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def list_msf_jobs() -> str:
    """List running Metasploit jobs (active exploits)."""
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.get(f"{EXPLOIT_RUNNER_URL}/msf/jobs")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def run_session_command(session_id: int, command: str) -> str:
    """Execute a command in an active Metasploit session.

    Args:
        session_id: Metasploit session ID
        command: Command to execute (e.g., 'whoami', 'id', 'cat /etc/passwd')
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.post(
            f"{EXPLOIT_RUNNER_URL}/msf/sessions/{session_id}/command",
            json={"command": command}
        )
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_msf_status() -> str:
    """Get Metasploit framework status including active jobs and sessions."""
    result = {"jobs": [], "sessions": [], "healthy": False}

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        try:
            jobs_resp = await client.get(f"{EXPLOIT_RUNNER_URL}/msf/jobs")
            if jobs_resp.status_code == 200:
                result["jobs"] = jobs_resp.json().get("jobs", [])

            sessions_resp = await client.get(f"{EXPLOIT_RUNNER_URL}/msf/sessions")
            if sessions_resp.status_code == 200:
                result["sessions"] = sessions_resp.json().get("sessions", [])

            result["healthy"] = True
        except Exception as e:
            result["error"] = str(e)

    return json.dumps(result, indent=2)


# ============================================================================
# OSINT Tools (ProjectDiscovery OSINT Runner)
# ============================================================================

@mcp.tool()
async def start_subfinder(
    domains: list[str],
    sources: Optional[str] = None,
    max_time: Optional[int] = None
) -> str:
    """Start subdomain enumeration using Subfinder.

    Args:
        domains: List of target domains (e.g., ['example.com', 'target.org'])
        sources: Comma-separated sources (e.g., 'virustotal,shodan,censys')
        max_time: Maximum execution time in seconds
    """
    payload = {"domains": domains}
    if sources:
        payload["sources"] = sources
    if max_time:
        payload["max_time"] = max_time

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/subfinder", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_dnsx(
    domains: list[str],
    record_types: Optional[str] = None
) -> str:
    """Start DNS resolution and enumeration using dnsx.

    Args:
        domains: List of domains/subdomains to resolve
        record_types: Comma-separated DNS record types (e.g., 'a,aaaa,cname,mx,ns,txt')
    """
    payload = {"domains": domains}
    if record_types:
        payload["record_types"] = record_types

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/dnsx", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_asnmap(targets: list[str]) -> str:
    """Map ASN numbers to CIDR ranges using asnmap.

    Args:
        targets: List of ASN numbers, IPs, or domains to map
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/asnmap", json={"targets": targets})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_uncover(
    query: str,
    engine: Optional[str] = None,
    limit: Optional[int] = None
) -> str:
    """Search Shodan, Censys, Fofa, and other engines using Uncover.

    Args:
        query: Search query (e.g., 'ssl.cert.subject.CN:example.com')
        engine: Search engine - 'shodan', 'censys', 'fofa', 'hunter', 'quake'
        limit: Maximum number of results
    """
    payload = {"query": query}
    if engine:
        payload["engine"] = engine
    if limit:
        payload["limit"] = limit

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/uncover", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_cloudlist(
    provider: str,
    config: Optional[dict] = None
) -> str:
    """Enumerate cloud assets (IPs, instances) for a given cloud provider.

    Args:
        provider: Cloud provider - 'aws', 'gcp', 'azure', 'do', 'scw'
        config: Provider-specific configuration dictionary
    """
    payload = {"provider": provider}
    if config:
        payload["config"] = config

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/cloudlist", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_alterx(
    domains: list[str],
    patterns: Optional[list[str]] = None
) -> str:
    """Generate subdomain wordlists using smart permutation patterns with AlterX.

    Args:
        domains: List of base domains for permutation
        patterns: Custom permutation patterns (optional)
    """
    payload = {"domains": domains}
    if patterns:
        payload["patterns"] = patterns

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/alterx", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_mapcidr(
    cidrs: list[str],
    operation: Optional[str] = None
) -> str:
    """Perform CIDR expansion, aggregation, or filtering using mapCIDR.

    Args:
        cidrs: List of CIDR ranges (e.g., ['192.168.1.0/24'])
        operation: Operation type - 'expand' (to IPs), 'aggregate', 'count', 'filter_ipv4', 'filter_ipv6'
    """
    payload = {"cidrs": cidrs}
    if operation:
        payload["operation"] = operation

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{OSINT_URL}/jobs/mapcidr", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_osint_job_status(job_id: str) -> str:
    """Get status and results of an OSINT runner job.

    Args:
        job_id: Job UUID returned from an OSINT tool
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_STATUS) as client:
        resp = await client.get(f"{OSINT_URL}/jobs/{job_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


# ============================================================================
# PD Runner Tools (Naabu, httpx, Katana, tlsx)
# ============================================================================

@mcp.tool()
async def start_naabu(
    targets: list[str],
    ports: Optional[str] = None,
    rate: Optional[int] = None
) -> str:
    """Start a fast port scan using Naabu (ProjectDiscovery port scanner).

    Args:
        targets: List of IPs, hostnames, or CIDR ranges
        ports: Port specification (e.g., '80,443', '1-1000', 'top-100')
        rate: Packets per second rate limit
    """
    payload = {"targets": targets}
    if ports:
        payload["ports"] = ports
    if rate:
        payload["rate"] = rate

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{PD_RUNNER_URL}/jobs/naabu", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_httpx_probe(
    targets: Optional[list[str]] = None,
    ports: Optional[str] = None,
    tech_detect: Optional[bool] = None
) -> str:
    """Probe HTTP servers for live hosts, status codes, titles, and technology detection using httpx.

    Args:
        targets: List of hosts/URLs to probe (uses discovered assets if not provided)
        ports: Ports to probe (e.g., '80,443,8080')
        tech_detect: Enable technology detection (Wappalyzer)
    """
    payload = {}
    if targets:
        payload["targets"] = targets
    if ports:
        payload["ports"] = ports
    if tech_detect is not None:
        payload["tech_detect"] = tech_detect

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{PD_RUNNER_URL}/jobs/httpx", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_katana(
    targets: Optional[list[str]] = None,
    depth: Optional[int] = None,
    js_crawl: Optional[bool] = None
) -> str:
    """Crawl web applications to discover endpoints, forms, and JavaScript files using Katana.

    Args:
        targets: List of target URLs to crawl (uses discovered web assets if not provided)
        depth: Maximum crawl depth (default: 3)
        js_crawl: Enable JavaScript file parsing and endpoint extraction
    """
    payload = {}
    if targets:
        payload["targets"] = targets
    if depth is not None:
        payload["depth"] = depth
    if js_crawl is not None:
        payload["js_crawl"] = js_crawl

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{PD_RUNNER_URL}/jobs/katana", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def start_tlsx(
    targets: Optional[list[str]] = None,
    ports: Optional[str] = None
) -> str:
    """Analyze TLS certificates, versions, and ciphers using tlsx.

    Args:
        targets: List of hosts to analyze (uses discovered assets if not provided)
        ports: Ports to check TLS on (e.g., '443,8443')
    """
    payload = {}
    if targets:
        payload["targets"] = targets
    if ports:
        payload["ports"] = ports

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{PD_RUNNER_URL}/jobs/tlsx", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_pd_job_status(job_id: str) -> str:
    """Get status and results of a PD runner job (naabu, httpx, katana, tlsx).

    Args:
        job_id: Job UUID returned from a PD runner tool
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_STATUS) as client:
        resp = await client.get(f"{PD_RUNNER_URL}/jobs/{job_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


# ============================================================================
# Brutus Tools (Credential Testing)
# ============================================================================

@mcp.tool()
async def start_brutus(
    targets: list[str],
    protocols: list[str],
    usernames: Optional[list[str]] = None,
    passwords: Optional[list[str]] = None
) -> str:
    """Start credential testing against target services using Brutus.

    Args:
        targets: List of target IPs or host:port combinations
        protocols: List of protocols to test (e.g., ['ssh', 'ftp', 'http-basic', 'smb', 'mysql', 'rdp'])
        usernames: Custom username list (uses defaults if not provided)
        passwords: Custom password list (uses defaults if not provided)
    """
    payload = {"targets": targets, "protocols": protocols}
    if usernames:
        payload["usernames"] = usernames
    if passwords:
        payload["passwords"] = passwords

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_SCAN) as client:
        resp = await client.post(f"{BRUTUS_URL}/jobs/brutus", json=payload)
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def get_brutus_job_status(job_id: str) -> str:
    """Get status and results of a Brutus credential testing job.

    Args:
        job_id: Job UUID returned from start_brutus
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_STATUS) as client:
        resp = await client.get(f"{BRUTUS_URL}/jobs/{job_id}")
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


# ============================================================================
# Consolidated OSINT Report
# ============================================================================

@mcp.tool()
async def get_osint_report(domain: Optional[str] = None) -> str:
    """Get a consolidated OSINT report aggregating data from all sources.

    Combines completed OSINT scan results, discovered assets, open ports,
    and vulnerability findings into a single report.

    Args:
        domain: Optional domain or IP to filter results by
    """
    report = {
        "osint_jobs": [],
        "assets": [],
        "ports": [],
        "findings": [],
        "summary": {},
        "errors": []
    }

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        headers = {"x-api-key": API_KEY}

        # 1. Completed OSINT jobs
        try:
            r = await client.get(f"{OSINT_URL}/jobs", params={"status": "completed", "limit": 50}, timeout=5.0)
            if r.status_code == 200:
                report["osint_jobs"] = r.json().get("jobs", [])
        except Exception as e:
            report["errors"].append(f"osint_jobs: {str(e)}")

        # 2. Discovered assets
        try:
            params = {"limit": 500}
            if domain:
                params["ip"] = domain
            r = await client.get(f"{RAG_API_URL}/assets", params=params, headers=headers, timeout=5.0)
            if r.status_code == 200:
                report["assets"] = r.json() if isinstance(r.json(), list) else r.json().get("assets", [])
        except Exception as e:
            report["errors"].append(f"assets: {str(e)}")

        # 3. Open ports
        try:
            params = {"limit": 500}
            if domain:
                params["ip"] = domain
            r = await client.get(f"{RAG_API_URL}/ports/open", params=params, headers=headers, timeout=5.0)
            if r.status_code == 200:
                report["ports"] = r.json() if isinstance(r.json(), list) else r.json().get("ports", [])
        except Exception as e:
            report["errors"].append(f"ports: {str(e)}")

        # 4. Findings
        try:
            params = {"limit": 200}
            if domain:
                params["ip"] = domain
            r = await client.get(f"{RAG_API_URL}/vulns", params=params, headers=headers, timeout=5.0)
            if r.status_code == 200:
                report["findings"] = r.json() if isinstance(r.json(), list) else r.json().get("findings", [])
        except Exception as e:
            report["errors"].append(f"findings: {str(e)}")

    # Build summary
    findings_list = report["findings"]
    severity_counts = {}
    for f in findings_list:
        sev = f.get("severity", "unknown") if isinstance(f, dict) else "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    scan_types = set()
    for job in report["osint_jobs"]:
        if isinstance(job, dict):
            scan_types.add(job.get("tool", job.get("type", "unknown")))

    report["summary"] = {
        "total_assets": len(report["assets"]),
        "total_open_ports": len(report["ports"]),
        "total_findings": len(findings_list),
        "findings_by_severity": severity_counts,
        "completed_scan_types": sorted(scan_types),
        "filter": domain or "all"
    }

    return json.dumps(report, indent=2)


# ============================================================================
# Cleanup Tools
# ============================================================================

@mcp.tool()
async def cleanup_findings(
    sources: str = "all",
    older_than_hours: Optional[int] = None,
    dry_run: bool = False
) -> str:
    """Delete web findings, playwright findings, and vulnerability records.

    Args:
        sources: Sources to clean - 'all', 'web', 'playwright', 'vulns', or specific like 'zap,gobuster'
        older_than_hours: Only delete findings older than this many hours
        dry_run: Preview what would be deleted (default: False)
    """
    params = {"sources": sources, "dry_run": dry_run}
    if older_than_hours:
        params["older_than_hours"] = older_than_hours

    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.post(f"{RAG_API_URL}/cleanup/findings", params=params, headers={"x-api-key": API_KEY})
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


@mcp.tool()
async def cleanup_old_sessions(older_than_hours: int = 24, status: str = "active") -> str:
    """Cancel pentest sessions older than specified hours.

    Args:
        older_than_hours: Age threshold in hours (default: 24)
        status: Status of sessions to clean (default: 'active')
    """
    async with httpx.AsyncClient(verify=False, timeout=TIMEOUT_QUICK) as client:
        resp = await client.post(f"{API_URL}/pentest/cleanup", params={
            "older_than_hours": older_than_hours,
            "status": status
        })
        return json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2)


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == "__main__":
    logger.info(f"Starting MCP Streamable HTTP Server on {HOST}:{PORT}")
    logger.info(f"Endpoint: http://{HOST}:{PORT}/mcp")

    # Run with Streamable HTTP transport
    mcp.run(transport="streamable-http")
