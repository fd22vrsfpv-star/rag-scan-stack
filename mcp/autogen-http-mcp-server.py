#!/usr/bin/env python3
"""
HTTP-based MCP server using SSE transport.

This version runs as a persistent HTTP server, allowing multiple clients
(Claude Desktop, Continue, custom tools) to connect simultaneously.

Port: 8016
Endpoints:
  - /sse (GET) - SSE event stream for responses
  - /messages (POST) - Send JSON-RPC messages
  - /health - Health check
"""

import asyncio
import json
import os
import logging
from contextlib import asynccontextmanager

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent

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

# Server config
HOST = os.environ.get("MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("MCP_PORT", "8016"))

# Configurable timeouts
TIMEOUT_SCAN = float(os.environ.get("MCP_TIMEOUT_SCAN", "300"))
TIMEOUT_QUICK = float(os.environ.get("MCP_TIMEOUT_QUICK", "30"))
TIMEOUT_STATUS = float(os.environ.get("MCP_TIMEOUT_STATUS", "15"))

# API Key for rag-api
API_KEY = os.environ.get("API_KEY", "changeme")

# Create MCP server
mcp_server = Server("autogen-pentest")

# Define tools
TOOLS = [
    # === Pentest Session Management ===
    Tool(
        name="start_pentest_session",
        description="Start an autonomous AI-powered penetration testing session",
        inputSchema={
            "type": "object",
            "properties": {
                "session_name": {"type": "string", "description": "Human-readable session name"},
                "target_description": {"type": "string", "description": "Description of target"},
                "initial_task": {"type": "string", "description": "Initial task for agents"},
                "max_rounds": {"type": "integer", "description": "Max conversation rounds", "default": 200}
            },
            "required": ["session_name", "target_description", "initial_task"]
        }
    ),
    Tool(
        name="get_session_status",
        description="Get status of a pentest session",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session UUID"}
            },
            "required": ["session_id"]
        }
    ),
    Tool(
        name="list_sessions",
        description="List all pentest sessions",
        inputSchema={
            "type": "object",
            "properties": {
                "status": {"type": "string", "enum": ["active", "completed", "failed", "stopped"]},
                "limit": {"type": "integer", "default": 50}
            }
        }
    ),
    Tool(
        name="stop_session",
        description="Stop a running pentest session",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "Session UUID"}
            },
            "required": ["session_id"]
        }
    ),
    Tool(
        name="cleanup_old_sessions",
        description="Cancel sessions older than specified hours",
        inputSchema={
            "type": "object",
            "properties": {
                "older_than_hours": {"type": "integer", "default": 24},
                "status": {"type": "string", "default": "active"}
            }
        }
    ),
    Tool(
        name="get_session_messages",
        description="Get conversation history for a session",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string"},
                "limit": {"type": "integer", "default": 100}
            },
            "required": ["session_id"]
        }
    ),
    Tool(
        name="check_health",
        description="Check autogen-agents service health",
        inputSchema={"type": "object", "properties": {}}
    ),

    # === Scanner Status Tools ===
    Tool(
        name="get_nmap_job_status",
        description="Get status of an Nmap/Masscan scan job",
        inputSchema={
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job UUID returned from nmap scan"}
            },
            "required": ["job_id"]
        }
    ),
    Tool(
        name="get_playwright_scan_status",
        description="Get status of a Playwright browser security scan",
        inputSchema={
            "type": "object",
            "properties": {
                "scan_id": {"type": "string", "description": "Scan UUID returned from playwright scan"}
            },
            "required": ["scan_id"]
        }
    ),
    Tool(
        name="get_msf_status",
        description="Get Metasploit framework status including active jobs and sessions",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="get_all_scanner_status",
        description="Get comprehensive status of all scanner services",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="get_nuclei_job_status",
        description="Get status of a Nuclei vulnerability scan job",
        inputSchema={
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job UUID returned from nuclei scan"}
            },
            "required": ["job_id"]
        }
    ),
    Tool(
        name="get_web_scan_job_status",
        description="Get status of a web scan job (Gobuster/ZAP)",
        inputSchema={
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job UUID returned from web scan"}
            },
            "required": ["job_id"]
        }
    ),
    Tool(
        name="get_all_active_jobs",
        description="Get status of all active scan jobs across all scanners",
        inputSchema={"type": "object", "properties": {}}
    ),

    # === Scanning Tools ===
    Tool(
        name="start_nmap_scan",
        description="Start an Nmap port scan against a target",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address, hostname, or CIDR range"},
                "ports": {"type": "string", "description": "Port range", "default": "1-1000"},
                "scan_type": {"type": "string", "enum": ["quick", "full", "service"], "default": "service"}
            },
            "required": ["target"]
        }
    ),
    Tool(
        name="start_web_scan",
        description="Start web scanning (Gobuster + ZAP) against a target URL or web targets from database",
        inputSchema={
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Specific target URL to scan (e.g., 'http://192.168.1.150')"},
                "do_gobuster": {"type": "boolean", "description": "Run Gobuster directory scan", "default": True},
                "use_zap": {"type": "boolean", "description": "Run ZAP proxy scan", "default": True},
                "limit": {"type": "integer", "description": "Max targets to scan from database (ignored if target_url provided)", "default": 25},
                "wordlist": {"type": "string", "enum": ["common", "medium", "big"], "description": "Wordlist for Gobuster"}
            }
        }
    ),
    Tool(
        name="start_nuclei_scan",
        description="Start a Nuclei vulnerability scan against a specific target or targets from database",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Specific target IP/hostname to scan (optional - scans from database if not provided)"},
                "limit": {"type": "integer", "description": "Max targets to scan from database", "default": 25},
                "severity": {"type": "string", "description": "Severity filter (comma-separated: info,low,medium,high,critical)", "default": "medium,high,critical"},
                "templates": {"type": "string", "description": "Template tags to use (comma-separated: cve,vulnerabilities,exposures,misconfigurations)"},
                "tags": {"type": "string", "description": "Additional template tags filter"}
            }
        }
    ),
    Tool(
        name="start_playwright_scan",
        description="Start a Playwright browser-based security scan",
        inputSchema={
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target URL"},
                "browser": {"type": "string", "enum": ["chromium", "firefox", "webkit"], "default": "chromium"},
                "screenshot": {"type": "boolean", "description": "Capture screenshots", "default": True}
            },
            "required": ["target_url"]
        }
    ),
    Tool(
        name="start_masscan",
        description="Start a fast Masscan port discovery scan (faster than nmap for large ranges)",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address, hostname, or CIDR range"},
                "ports": {"type": "string", "description": "Port range (e.g., '1-65535', '80,443,8080')", "default": "1-65535"},
                "rate": {"type": "integer", "description": "Packets per second", "default": 1000}
            },
            "required": ["target"]
        }
    ),
    Tool(
        name="start_udp_scan",
        description="Start a UDP port scan (slower but finds UDP services like DNS, SNMP, NTP)",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname"},
                "ports": {"type": "string", "description": "UDP ports to scan", "default": "53,67,68,69,123,161,162,500,514,1900"}
            },
            "required": ["target"]
        }
    ),
    Tool(
        name="get_next_scan_recommendation",
        description="Get AI-powered recommendation for what to scan next based on current findings",
        inputSchema={
            "type": "object",
            "properties": {
                "target_ip": {"type": "string", "description": "Target IP to get recommendations for"}
            }
        }
    ),
    Tool(
        name="rag_enhanced_search",
        description="Enhanced RAG search for exploits with keyword matching and semantic search",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (service name, CVE, version, etc.)"},
                "service": {"type": "string", "description": "Filter by service name"},
                "version": {"type": "string", "description": "Filter by version"},
                "limit": {"type": "integer", "description": "Max results", "default": 10}
            },
            "required": ["query"]
        }
    ),

    # === Query Tools ===
    Tool(
        name="query_assets",
        description="Query discovered assets from the database",
        inputSchema={
            "type": "object",
            "properties": {
                "ip_filter": {"type": "string", "description": "Filter by IP pattern"},
                "limit": {"type": "integer", "default": 100}
            }
        }
    ),
    Tool(
        name="query_open_ports",
        description="Query discovered open ports and services",
        inputSchema={
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Filter by IP"},
                "port": {"type": "integer", "description": "Filter by port"},
                "service": {"type": "string", "description": "Filter by service"},
                "limit": {"type": "integer", "default": 100}
            }
        }
    ),
    Tool(
        name="query_findings",
        description="Query vulnerability findings from all scanners",
        inputSchema={
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "ip": {"type": "string", "description": "Filter by IP"},
                "limit": {"type": "integer", "default": 100}
            }
        }
    ),
    Tool(
        name="search_exploits",
        description="Search the exploit database using semantic search (RAG)",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "default": 10}
            },
            "required": ["query"]
        }
    ),
    Tool(
        name="cleanup_findings",
        description="Delete web findings, playwright findings, and vulnerability records",
        inputSchema={
            "type": "object",
            "properties": {
                "sources": {"type": "string", "description": "Sources to clean: 'all', 'web', 'playwright', 'vulns', or specific like 'zap,gobuster'", "default": "all"},
                "older_than_hours": {"type": "integer", "description": "Only delete findings older than this many hours"},
                "dry_run": {"type": "boolean", "description": "Preview what would be deleted", "default": False}
            }
        }
    ),

    # === Security Testing Tools ===
    Tool(
        name="run_edb_script",
        description="Run an ExploitDB security script by EDB-ID against a target for authorized penetration testing",
        inputSchema={
            "type": "object",
            "properties": {
                "edb_id": {"type": "string", "description": "ExploitDB ID (e.g., '51459')"},
                "target_ip": {"type": "string", "description": "Target IP address"},
                "target_port": {"type": "integer", "description": "Target port"},
                "args": {"type": "object", "description": "Additional script arguments"}
            },
            "required": ["edb_id", "target_ip"]
        }
    ),
    Tool(
        name="run_msf_module",
        description="Run a Metasploit module against a target for authorized penetration testing",
        inputSchema={
            "type": "object",
            "properties": {
                "module_path": {"type": "string", "description": "MSF module path (e.g., 'auxiliary/scanner/http/http_version')"},
                "target_ip": {"type": "string", "description": "Target IP (RHOSTS)"},
                "target_port": {"type": "integer", "description": "Target port (RPORT)"},
                "payload": {"type": "string", "description": "Payload to use"},
                "lhost": {"type": "string", "description": "Callback IP for reverse shells (auto-detected if not set)"},
                "lport": {"type": "integer", "description": "Callback port for reverse shells (default: 4444)"},
                "options": {"type": "object", "description": "Additional module options"}
            },
            "required": ["module_path", "target_ip"]
        }
    ),
    Tool(
        name="list_msf_sessions",
        description="List active Metasploit sessions (shells, meterpreter)",
        inputSchema={
            "type": "object",
            "properties": {}
        }
    ),
    Tool(
        name="run_session_command",
        description="Execute a command in an active Metasploit session",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "integer", "description": "Metasploit session ID"},
                "command": {"type": "string", "description": "Command to execute (e.g., 'whoami', 'id', 'cat /etc/passwd')"}
            },
            "required": ["session_id", "command"]
        }
    ),
    Tool(
        name="list_msf_jobs",
        description="List running Metasploit jobs (active exploits)",
        inputSchema={
            "type": "object",
            "properties": {}
        }
    ),
]


@mcp_server.list_tools()
async def list_tools():
    return TOOLS


def get_timeout(name: str) -> float:
    """Get appropriate timeout for the tool"""
    if name.startswith("start_"):
        return TIMEOUT_SCAN
    elif name.startswith("get_") and "status" in name:
        return TIMEOUT_STATUS
    else:
        return TIMEOUT_QUICK


@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict):
    from datetime import datetime
    logger.info(f"[{datetime.now().strftime('%H:%M:%S')}] TOOL CALLED: {name} args={arguments}")
    timeout = get_timeout(name)

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        try:
            # === Pentest Session Management ===
            if name == "start_pentest_session":
                resp = await client.post(f"{API_URL}/pentest", json={
                    "session_name": arguments["session_name"],
                    "target_description": arguments["target_description"],
                    "initial_task": arguments["initial_task"],
                    "max_rounds": arguments.get("max_rounds", 200)
                })

            elif name == "get_session_status":
                resp = await client.get(f"{API_URL}/pentest/{arguments['session_id']}")

            elif name == "list_sessions":
                params = {"limit": arguments.get("limit", 50)}
                if "status" in arguments:
                    params["status"] = arguments["status"]
                resp = await client.get(f"{API_URL}/pentest/sessions", params=params)

            elif name == "stop_session":
                resp = await client.post(f"{API_URL}/pentest/{arguments['session_id']}/stop")

            elif name == "cleanup_old_sessions":
                resp = await client.post(f"{API_URL}/pentest/cleanup", params={
                    "older_than_hours": arguments.get("older_than_hours", 24),
                    "status": arguments.get("status", "active")
                })

            elif name == "get_session_messages":
                resp = await client.get(
                    f"{API_URL}/pentest/{arguments['session_id']}/messages",
                    params={"limit": arguments.get("limit", 100)}
                )

            elif name == "check_health":
                resp = await client.get(f"{API_URL}/health")

            # === Scanner Status Tools ===
            elif name == "get_nmap_job_status":
                job_id = arguments["job_id"]
                resp = await client.get(f"{NMAP_URL}/jobs/{job_id}")
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "get_playwright_scan_status":
                scan_id = arguments["scan_id"]
                resp = await client.get(f"{PLAYWRIGHT_URL}/scan/{scan_id}")
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "get_msf_status":
                result = {"jobs": [], "sessions": [], "healthy": False}
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
                return [TextContent(type="text", text=json.dumps(result, indent=2))]

            elif name == "get_all_scanner_status":
                services = {
                    "nmap_scanner": {"url": f"{NMAP_URL}/health", "status": "unknown"},
                    "playwright_scanner": {"url": f"{PLAYWRIGHT_URL}/health", "status": "unknown"},
                    "web_scanner": {"url": f"{WEB_SCANNER_URL}/health", "status": "unknown"},
                    "nuclei_runner": {"url": f"{NUCLEI_URL}/health", "status": "unknown"},
                    "exploit_runner": {"url": f"{EXPLOIT_RUNNER_URL}/health", "status": "unknown"},
                }
                for svc_name, info in services.items():
                    try:
                        resp = await client.get(info["url"], timeout=5.0)
                        info["status"] = "healthy" if resp.status_code == 200 else "unhealthy"
                    except Exception:
                        info["status"] = "unreachable"
                return [TextContent(type="text", text=json.dumps({"services": services}, indent=2))]

            elif name == "get_nuclei_job_status":
                job_id = arguments["job_id"]
                resp = await client.get(f"{NUCLEI_URL}/jobs/{job_id}")
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text, "status_code": resp.status_code}, indent=2))]

            elif name == "get_web_scan_job_status":
                job_id = arguments["job_id"]
                resp = await client.get(f"{WEB_SCANNER_URL}/jobs/{job_id}")
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text, "status_code": resp.status_code}, indent=2))]

            elif name == "get_all_active_jobs":
                result = {"nmap_jobs": [], "web_jobs": [], "nuclei_jobs": [], "errors": []}
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
                return [TextContent(type="text", text=json.dumps(result, indent=2))]

            # === Scanning Tools ===
            elif name == "start_nmap_scan":
                # API expects "targets" as array
                target = arguments["target"]
                targets = [target] if isinstance(target, str) else target
                resp = await client.post(f"{NMAP_URL}/jobs/masscan-then-nmap", json={
                    "targets": targets,
                    "ports": arguments.get("ports", "1-1000"),
                    "rate": 1000
                })
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_web_scan":
                # Web scanner - can scan specific URL or targets from database
                scan_request = {
                    "do_gobuster": arguments.get("do_gobuster", True),
                    "do_zap": arguments.get("use_zap", True),
                    "limit": arguments.get("limit", 25),
                    "wordlist": arguments.get("wordlist")
                }
                # Add target_url if provided for direct scanning
                if "target_url" in arguments:
                    scan_request["target_url"] = arguments["target_url"]
                resp = await client.post(f"{WEB_SCANNER_URL}/jobs/web-scan", json=scan_request)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_nuclei_scan":
                # Build request - can scan specific target or targets from database
                scan_request = {
                    "severity": arguments.get("severity", "medium,high,critical")
                }
                # If target specified, scan that specific target
                if "target" in arguments:
                    scan_request["target"] = arguments["target"]
                else:
                    scan_request["limit"] = arguments.get("limit", 25)
                # Add template filters if specified
                if "templates" in arguments:
                    scan_request["tags"] = arguments["templates"]
                if "tags" in arguments:
                    scan_request["tags"] = arguments.get("tags", scan_request.get("tags", ""))

                resp = await client.post(f"{NUCLEI_URL}/jobs/nuclei-scan", json=scan_request)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_playwright_scan":
                resp = await client.post(f"{PLAYWRIGHT_URL}/scan", json={
                    "url": arguments["target_url"],
                    "browser": arguments.get("browser", "chromium"),
                    "capture_screenshots": arguments.get("screenshot", True),
                    "run_security_checks": True,
                    "use_zap_proxy": True
                })
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_masscan":
                # Masscan-only fast port discovery
                target = arguments["target"]
                targets = [target] if isinstance(target, str) else target
                resp = await client.post(f"{NMAP_URL}/jobs/masscan-only", json={
                    "targets": targets,
                    "ports": arguments.get("ports", "1-65535"),
                    "rate": arguments.get("rate", 1000)
                })
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_udp_scan":
                # UDP port scanning
                target = arguments["target"]
                targets = [target] if isinstance(target, str) else target
                resp = await client.post(f"{NMAP_URL}/jobs/nmap-udp", json={
                    "targets": targets,
                    "ports": arguments.get("ports", "53,67,68,69,123,161,162,500,514,1900")
                })
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "get_next_scan_recommendation":
                # Get AI-powered scan recommendation
                params = {}
                if "target_ip" in arguments:
                    params["target"] = arguments["target_ip"]
                resp = await client.get(f"{SCAN_RECOMMENDER_URL}/next_scan", params=params)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "rag_enhanced_search":
                # Enhanced RAG search for exploits
                params = {
                    "q": arguments["query"],
                    "top_k": arguments.get("limit", 10)
                }
                if "service" in arguments:
                    params["service"] = arguments["service"]
                if "version" in arguments:
                    params["version"] = arguments["version"]
                resp = await client.get(f"{SCAN_RECOMMENDER_URL}/rag/search/enhanced", params=params)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            # === Query Tools ===
            elif name == "query_assets":
                params = {"limit": arguments.get("limit", 100)}
                if "ip_filter" in arguments:
                    params["ip"] = arguments["ip_filter"]
                resp = await client.get(f"{RAG_API_URL}/assets", params=params, headers={"x-api-key": API_KEY})
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "query_open_ports":
                params = {"limit": arguments.get("limit", 100)}
                for key in ["ip", "port", "service"]:
                    if key in arguments:
                        params[key] = arguments[key]
                resp = await client.get(f"{RAG_API_URL}/ports/open", params=params, headers={"x-api-key": API_KEY})
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "query_findings":
                # Use /vulns endpoint for vulnerability findings
                params = {"limit": arguments.get("limit", 100)}
                for key in ["severity", "ip"]:
                    if key in arguments:
                        params[key] = arguments[key]
                resp = await client.get(f"{RAG_API_URL}/vulns", params=params, headers={"x-api-key": API_KEY})
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "search_exploits":
                # /rag/ask expects GET with q= param (not POST with JSON)
                params = {
                    "q": arguments["query"],
                    "top_k": arguments.get("limit", 10)
                }
                resp = await client.get(f"{SCAN_RECOMMENDER_URL}/rag/ask", params=params)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "cleanup_findings":
                params = {
                    "sources": arguments.get("sources", "all"),
                    "dry_run": arguments.get("dry_run", False)
                }
                if "older_than_hours" in arguments:
                    params["older_than_hours"] = arguments["older_than_hours"]
                resp = await client.post(f"{RAG_API_URL}/cleanup/findings", params=params, headers={"x-api-key": API_KEY})
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            # === Security Testing Tools ===
            elif name == "run_edb_script":
                # Map MCP arguments to security-runner script API
                script_request = {
                    "edb_id": arguments["edb_id"],
                    "target_ip": arguments["target_ip"],
                    "target_port": arguments.get("target_port", 80),
                    "extra_args": arguments.get("args", {})
                }
                resp = await client.post(f"{EXPLOIT_RUNNER_URL}/execute/script", json=script_request, timeout=300)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text, "status_code": resp.status_code}, indent=2))]

            elif name == "run_msf_module":
                # Map MCP arguments to exploit-runner MSF API
                module_path = arguments["module_path"]
                # Parse module type from path (e.g., "exploit/unix/ftp/vsftpd_234_backdoor" -> "exploit")
                module_type = module_path.split("/")[0] if "/" in module_path else "auxiliary"
                module_name = module_path

                msf_options = {
                    "RHOSTS": arguments["target_ip"]
                }
                if "target_port" in arguments:
                    msf_options["RPORT"] = arguments["target_port"]
                if "payload" in arguments:
                    msf_options["PAYLOAD"] = arguments["payload"]
                # Pass through LHOST/LPORT if explicitly provided
                if "lhost" in arguments and arguments["lhost"]:
                    msf_options["LHOST"] = arguments["lhost"]
                if "lport" in arguments and arguments["lport"]:
                    msf_options["LPORT"] = arguments["lport"]
                # Merge any additional options
                if "options" in arguments:
                    msf_options.update(arguments["options"])

                msf_request = {
                    "module_type": module_type,
                    "module_name": module_name,
                    "options": msf_options
                }
                resp = await client.post(f"{EXPLOIT_RUNNER_URL}/execute/msf", json=msf_request, timeout=300)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text, "status_code": resp.status_code}, indent=2))]

            elif name == "list_msf_sessions":
                resp = await client.get(f"{EXPLOIT_RUNNER_URL}/msf/sessions", timeout=30)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "list_msf_jobs":
                resp = await client.get(f"{EXPLOIT_RUNNER_URL}/msf/jobs", timeout=30)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "run_session_command":
                session_id = arguments["session_id"]
                command = arguments["command"]
                resp = await client.post(
                    f"{EXPLOIT_RUNNER_URL}/msf/sessions/{session_id}/command",
                    json={"command": command},
                    timeout=60
                )
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            else:
                return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

            # Return response for standard API calls
            if resp.status_code == 200:
                return [TextContent(type="text", text=json.dumps(resp.json(), indent=2))]
            else:
                return [TextContent(type="text", text=json.dumps({"error": f"HTTP {resp.status_code}", "detail": resp.text}, indent=2))]

        except httpx.ConnectError as e:
            return [TextContent(type="text", text=json.dumps({"error": "Connection failed", "message": str(e)}, indent=2))]
        except httpx.TimeoutException:
            return [TextContent(type="text", text=json.dumps({"error": "Timeout", "message": f"Request timed out after {timeout}s"}, indent=2))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(type(e).__name__), "message": str(e)}, indent=2))]


# Create SSE transport - this handles both GET /sse and POST /messages
sse_transport = SseServerTransport("/messages")


async def handle_sse(scope, receive, send):
    """Handle SSE connection - client connects here to receive events (raw ASGI)"""
    logger.info(f"SSE connection request")
    async with sse_transport.connect_sse(scope, receive, send) as streams:
        await mcp_server.run(
            streams[0], streams[1], mcp_server.create_initialization_options()
        )


async def handle_messages(scope, receive, send):
    """Handle incoming JSON-RPC messages from client (raw ASGI)"""
    logger.info(f"Message received")
    await sse_transport.handle_post_message(scope, receive, send)


async def handle_health(request):
    """Health check endpoint"""
    return JSONResponse({
        "ok": True,
        "service": "mcp-server",
        "transport": "sse",
        "tools_count": len(TOOLS),
        "endpoints": {
            "sse": f"http://{HOST}:{PORT}/sse",
            "messages": f"http://{HOST}:{PORT}/messages"
        }
    })


async def handle_tools(request):
    """List available tools (for debugging)"""
    return JSONResponse({
        "tools": [{"name": t.name, "description": t.description[:100]} for t in TOOLS]
    })


# Create the Starlette app for non-MCP routes
starlette_app = Starlette(
    routes=[
        Route("/health", endpoint=handle_health),
        Route("/tools", endpoint=handle_tools),
    ],
)


async def app(scope, receive, send):
    """Main ASGI app that routes MCP and non-MCP requests"""
    if scope["type"] == "lifespan":
        await starlette_app(scope, receive, send)
        return

    path = scope.get("path", "")
    method = scope.get("method", "")

    if path == "/sse":
        await handle_sse(scope, receive, send)
    elif path.startswith("/messages"):
        await handle_messages(scope, receive, send)
    else:
        await starlette_app(scope, receive, send)


if __name__ == "__main__":
    logger.info(f"Starting MCP SSE Server on {HOST}:{PORT}")
    logger.info(f"SSE endpoint: http://{HOST}:{PORT}/sse")
    logger.info(f"Messages endpoint: http://{HOST}:{PORT}/messages")
    logger.info(f"Health endpoint: http://{HOST}:{PORT}/health")
    logger.info(f"Tools: {len(TOOLS)} available")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
