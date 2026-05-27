#!/usr/bin/env python3
"""
STDIO-based MCP server for Claude Desktop.

This version runs as a local command, communicating via stdin/stdout.
It forwards requests to the Docker services running on localhost.

Usage in claude_desktop_config.json:
{
  "mcpServers": {
    "rag-scan-stack": {
      "command": "python",
      "args": ["C:/path/to/mcp-stdio-server.py"]
    }
  }
}
"""

import asyncio
import json
import sys
import logging
from datetime import datetime

import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Disable logging to stderr to avoid interfering with STDIO
logging.basicConfig(level=logging.ERROR, stream=sys.stderr)
logger = logging.getLogger(__name__)

# API endpoints - localhost since running on host, not in Docker
API_URL = "http://localhost:8015"  # autogen-agents
RAG_API_URL = "http://localhost:8000"  # rag-api
NMAP_URL = "http://localhost:8012"  # nmap_scanner
PLAYWRIGHT_URL = "http://localhost:8014"  # playwright-scanner
EXPLOIT_RUNNER_URL = "http://localhost:8017"  # exploit-runner
WEB_SCANNER_URL = "http://localhost:8010"  # web-scanner
NUCLEI_URL = "http://localhost:8011"  # nuclei-runner
SCAN_RECOMMENDER_URL = "http://localhost:8013"  # scan-recommender
PD_RUNNER_URL = "http://localhost:8023"  # pd-runner
OSINT_URL = "http://localhost:8024"  # osint-runner
BRUTUS_URL = "http://localhost:8025"  # brutus-runner

# Timeouts
TIMEOUT_SCAN = 300.0
TIMEOUT_QUICK = 30.0
TIMEOUT_STATUS = 15.0

# API Key
API_KEY = "changeme"

# Create MCP server
mcp_server = Server("rag-scan-stack")

# Define tools
TOOLS = [
    # === Utility Tools ===
    Tool(
        name="echo",
        description="Test tool calling - echoes back the message",
        inputSchema={
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Message to echo back"}
            },
            "required": ["message"]
        }
    ),
    Tool(
        name="get_time",
        description="Get current server time",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="add",
        description="Add two numbers together",
        inputSchema={
            "type": "object",
            "properties": {
                "a": {"type": "number", "description": "First number"},
                "b": {"type": "number", "description": "Second number"}
            },
            "required": ["a", "b"]
        }
    ),

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
        name="resume_pentest_session",
        description="Resume a failed/stalled/stopped pentest session, reusing collected data",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "string", "description": "UUID of the failed session to resume"},
                "additional_instructions": {"type": "string", "description": "Extra instructions for the resumed session"},
                "max_rounds": {"type": "integer", "description": "Max conversation rounds", "default": 200}
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
        description="Check all scanner services health status",
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
        name="start_masscan",
        description="Start a fast Masscan port discovery scan",
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of IPs or CIDR ranges"},
                "ports": {"type": "string", "description": "Port range (e.g., '1-1000' or '1-65535')", "default": "1-1000"},
                "udp": {"type": "boolean", "description": "Scan UDP ports instead of TCP", "default": False},
                "rate": {"type": "integer", "description": "Packets per second", "default": 1000}
            },
            "required": ["targets"]
        }
    ),
    Tool(
        name="start_nmap_scan",
        description="Start an Nmap deep scan against a target",
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of IPs or hostnames"},
                "ports": {"type": "string", "description": "Port range or comma-separated ports", "default": "1-1000"},
                "scan_type": {"type": "string", "enum": ["quick", "full", "udp"], "description": "Scan type: quick (fast), full (service detection + vuln scripts), udp (UDP scan)", "default": "full"}
            },
            "required": ["targets"]
        }
    ),
    Tool(
        name="start_web_scan",
        description="Start web scanning (Gobuster + ZAP) against web targets in database",
        inputSchema={
            "type": "object",
            "properties": {
                "do_gobuster": {"type": "boolean", "description": "Run Gobuster directory scan", "default": True},
                "use_zap": {"type": "boolean", "description": "Run ZAP proxy scan", "default": True},
                "limit": {"type": "integer", "description": "Max targets to scan", "default": 25},
                "wordlist": {"type": "string", "enum": ["common", "medium", "big"], "description": "Wordlist for Gobuster"}
            }
        }
    ),
    Tool(
        name="start_nuclei_scan",
        description="Start a Nuclei vulnerability scan against targets in database",
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max targets to scan", "default": 25},
                "severity": {"type": "string", "description": "Severity filter (comma-separated: info,low,medium,high,critical)", "default": "medium,high,critical"}
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
        name="search_exploits_enhanced",
        description="Enhanced exploit search by CVE, service, or version",
        inputSchema={
            "type": "object",
            "properties": {
                "cve": {"type": "string", "description": "CVE identifier (e.g., CVE-2021-44228)"},
                "service": {"type": "string", "description": "Service name (e.g., apache, nginx, ssh)"},
                "version": {"type": "string", "description": "Version string to match"}
            }
        }
    ),
    Tool(
        name="get_recommendation",
        description="Get AI-powered next scan recommendations for a target IP",
        inputSchema={
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Target IP address"},
                "service": {"type": "string", "description": "Service type (e.g., http, ssh)"},
                "banner": {"type": "string", "description": "Banner information from service"}
            },
            "required": ["ip"]
        }
    ),

    # === Metasploit & ExploitDB Tools ===
    Tool(
        name="run_msf_module",
        description="Run a Metasploit module against a target",
        inputSchema={
            "type": "object",
            "properties": {
                "module_path": {"type": "string", "description": "Full module path (e.g., exploit/multi/http/apache_mod_cgi_bash_env_exec)"},
                "options": {"type": "object", "description": "Module options as key-value pairs (RHOSTS, RPORT, LHOST, etc.)"}
            },
            "required": ["module_path", "options"]
        }
    ),
    Tool(
        name="run_edb_script",
        description="Run an ExploitDB exploit script",
        inputSchema={
            "type": "object",
            "properties": {
                "edb_id": {"type": "string", "description": "ExploitDB ID (e.g., 50383)"},
                "rhost": {"type": "string", "description": "Target host IP"},
                "rport": {"type": "integer", "description": "Target port"}
            },
            "required": ["edb_id", "rhost"]
        }
    ),
    Tool(
        name="list_msf_sessions",
        description="List active Metasploit sessions (shells, meterpreter)",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="run_session_command",
        description="Execute a command in an active Metasploit session",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {"type": "integer", "description": "Session ID from list_msf_sessions"},
                "command": {"type": "string", "description": "Command to execute"}
            },
            "required": ["session_id", "command"]
        }
    ),
    Tool(
        name="list_msf_jobs",
        description="List running Metasploit background jobs",
        inputSchema={"type": "object", "properties": {}}
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

    # === Performance Metrics Tools ===
    Tool(
        name="get_scan_metrics",
        description="Get scan pipeline performance metrics - timing breakdowns, aggregate stats, recent scan durations, or LLM model comparisons",
        inputSchema={
            "type": "object",
            "properties": {
                "view": {"type": "string", "enum": ["recent", "aggregate", "session", "compare_models", "llm_requests"], "description": "View type: 'recent' (last N scans), 'aggregate' (stats over time), 'session' (per-session breakdown), 'compare_models' (LLM A/B test comparison), 'llm_requests' (raw per-LLM-call metrics)", "default": "recent"},
                "session_id": {"type": "string", "description": "Session UUID (required when view='session', optional filter for others)"},
                "scan_type": {"type": "string", "description": "Filter by scan type (masscan, nmap, playwright, etc.)"},
                "model": {"type": "string", "description": "Filter by LLM model name (for llm_requests view)"},
                "days": {"type": "integer", "description": "Look-back window in days (for aggregate/compare_models views)", "default": 30},
                "limit": {"type": "integer", "description": "Max results (for recent/llm_requests views)", "default": 20}
            }
        }
    ),

    # === OSINT Tools (ProjectDiscovery OSINT Runner) ===
    Tool(
        name="start_subfinder",
        description="Start subdomain enumeration using Subfinder",
        inputSchema={
            "type": "object",
            "properties": {
                "domains": {"type": "array", "items": {"type": "string"}, "description": "List of target domains"},
                "sources": {"type": "string", "description": "Comma-separated sources (e.g., 'virustotal,shodan,censys')"},
                "max_time": {"type": "integer", "description": "Maximum execution time in seconds"}
            },
            "required": ["domains"]
        }
    ),
    Tool(
        name="start_dnsx",
        description="Start DNS resolution and enumeration using dnsx",
        inputSchema={
            "type": "object",
            "properties": {
                "domains": {"type": "array", "items": {"type": "string"}, "description": "List of domains/subdomains to resolve"},
                "record_types": {"type": "string", "description": "Comma-separated DNS record types (e.g., 'a,aaaa,cname,mx,ns,txt')"}
            },
            "required": ["domains"]
        }
    ),
    Tool(
        name="start_asnmap",
        description="Map ASN numbers to CIDR ranges using asnmap",
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of ASN numbers, IPs, or domains to map"}
            },
            "required": ["targets"]
        }
    ),
    Tool(
        name="start_uncover",
        description="Search Shodan, Censys, Fofa, and other engines using Uncover",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "engine": {"type": "string", "description": "Search engine - 'shodan', 'censys', 'fofa', 'hunter', 'quake'"},
                "limit": {"type": "integer", "description": "Maximum number of results"}
            },
            "required": ["query"]
        }
    ),
    Tool(
        name="start_cloudlist",
        description="Enumerate cloud assets (IPs, instances) for a given cloud provider",
        inputSchema={
            "type": "object",
            "properties": {
                "provider": {"type": "string", "description": "Cloud provider - 'aws', 'gcp', 'azure', 'do', 'scw'"},
                "config": {"type": "object", "description": "Provider-specific configuration dictionary"}
            },
            "required": ["provider"]
        }
    ),
    Tool(
        name="start_alterx",
        description="Generate subdomain wordlists using smart permutation patterns with AlterX",
        inputSchema={
            "type": "object",
            "properties": {
                "domains": {"type": "array", "items": {"type": "string"}, "description": "List of base domains for permutation"},
                "patterns": {"type": "array", "items": {"type": "string"}, "description": "Custom permutation patterns"}
            },
            "required": ["domains"]
        }
    ),
    Tool(
        name="start_mapcidr",
        description="Perform CIDR expansion, aggregation, or filtering using mapCIDR",
        inputSchema={
            "type": "object",
            "properties": {
                "cidrs": {"type": "array", "items": {"type": "string"}, "description": "List of CIDR ranges"},
                "operation": {"type": "string", "description": "Operation: 'expand', 'aggregate', 'count', 'filter_ipv4', 'filter_ipv6'"}
            },
            "required": ["cidrs"]
        }
    ),
    Tool(
        name="get_osint_job_status",
        description="Get status and results of an OSINT runner job",
        inputSchema={
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job UUID returned from an OSINT tool"}
            },
            "required": ["job_id"]
        }
    ),

    # === PD Runner Tools (Naabu, httpx, Katana, tlsx) ===
    Tool(
        name="start_naabu",
        description="Start a fast port scan using Naabu (ProjectDiscovery port scanner)",
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of IPs, hostnames, or CIDR ranges"},
                "ports": {"type": "string", "description": "Port specification (e.g., '80,443', '1-1000', 'top-100')"},
                "rate": {"type": "integer", "description": "Packets per second rate limit"}
            },
            "required": ["targets"]
        }
    ),
    Tool(
        name="start_httpx_probe",
        description="Probe HTTP servers for live hosts, status codes, titles, and technology detection using httpx",
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of hosts/URLs to probe"},
                "ports": {"type": "string", "description": "Ports to probe (e.g., '80,443,8080')"},
                "tech_detect": {"type": "boolean", "description": "Enable technology detection (Wappalyzer)"}
            }
        }
    ),
    Tool(
        name="start_katana",
        description="Crawl web applications to discover endpoints, forms, and JavaScript files using Katana",
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of target URLs to crawl"},
                "depth": {"type": "integer", "description": "Maximum crawl depth (default: 3)"},
                "js_crawl": {"type": "boolean", "description": "Enable JavaScript file parsing and endpoint extraction"}
            }
        }
    ),
    Tool(
        name="start_tlsx",
        description="Analyze TLS certificates, versions, and ciphers using tlsx",
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of hosts to analyze"},
                "ports": {"type": "string", "description": "Ports to check TLS on (e.g., '443,8443')"}
            }
        }
    ),
    Tool(
        name="get_pd_job_status",
        description="Get status and results of a PD runner job (naabu, httpx, katana, tlsx)",
        inputSchema={
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job UUID returned from a PD runner tool"}
            },
            "required": ["job_id"]
        }
    ),

    # === Brutus Tools (Credential Testing) ===
    Tool(
        name="start_brutus",
        description="Start credential testing against target services using Brutus",
        inputSchema={
            "type": "object",
            "properties": {
                "targets": {"type": "array", "items": {"type": "string"}, "description": "List of target IPs or host:port combinations"},
                "protocols": {"type": "array", "items": {"type": "string"}, "description": "Protocols to test (e.g., ['ssh', 'ftp', 'http-basic', 'smb', 'mysql', 'rdp'])"},
                "usernames": {"type": "array", "items": {"type": "string"}, "description": "Custom username list"},
                "passwords": {"type": "array", "items": {"type": "string"}, "description": "Custom password list"}
            },
            "required": ["targets", "protocols"]
        }
    ),
    Tool(
        name="get_brutus_job_status",
        description="Get status and results of a Brutus credential testing job",
        inputSchema={
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "Job UUID returned from start_brutus"}
            },
            "required": ["job_id"]
        }
    ),

    # === Consolidated OSINT Report ===
    Tool(
        name="get_osint_report",
        description="Get a consolidated OSINT report aggregating completed scans, discovered assets, open ports, and findings",
        inputSchema={
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Optional domain or IP to filter results by"}
            }
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
    timeout = get_timeout(name)

    async with httpx.AsyncClient(verify=False, timeout=timeout) as client:
        try:
            # === Utility Tools ===
            if name == "echo":
                return [TextContent(type="text", text=json.dumps({"message": arguments["message"], "echo": "success"}))]

            elif name == "get_time":
                return [TextContent(type="text", text=json.dumps({"time": datetime.now().isoformat(), "timezone": "server"}))]

            elif name == "add":
                result = arguments["a"] + arguments["b"]
                return [TextContent(type="text", text=json.dumps({"a": arguments["a"], "b": arguments["b"], "result": result}))]

            # === Pentest Session Management ===
            elif name == "start_pentest_session":
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

            elif name == "resume_pentest_session":
                resp = await client.post(
                    f"{API_URL}/pentest/{arguments['session_id']}/resume",
                    json={
                        "max_rounds": arguments.get("max_rounds", 200),
                        "additional_instructions": arguments.get("additional_instructions")
                    }
                )

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
                # Check all services
                services = {}
                for svc_name, url in [
                    ("rag_api", f"{RAG_API_URL}/health"),
                    ("autogen_agents", f"{API_URL}/health"),
                    ("nmap_scanner", f"{NMAP_URL}/health"),
                    ("playwright_scanner", f"{PLAYWRIGHT_URL}/health"),
                    ("web_scanner", f"{WEB_SCANNER_URL}/health"),
                    ("nuclei_runner", f"{NUCLEI_URL}/health"),
                    ("exploit_runner", f"{EXPLOIT_RUNNER_URL}/health"),
                    ("scan_recommender", f"{SCAN_RECOMMENDER_URL}/health"),
                    ("osint_runner", f"{OSINT_URL}/health"),
                    ("pd_runner", f"{PD_RUNNER_URL}/health"),
                    ("brutus_runner", f"{BRUTUS_URL}/health"),
                ]:
                    try:
                        r = await client.get(url, timeout=5.0)
                        services[svc_name] = "healthy" if r.status_code == 200 else "unhealthy"
                    except Exception:
                        services[svc_name] = "unreachable"
                return [TextContent(type="text", text=json.dumps({"services": services}, indent=2))]

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
                services = {}
                for svc_name, url in [
                    ("nmap_scanner", f"{NMAP_URL}/health"),
                    ("playwright_scanner", f"{PLAYWRIGHT_URL}/health"),
                    ("web_scanner", f"{WEB_SCANNER_URL}/health"),
                    ("nuclei_runner", f"{NUCLEI_URL}/health"),
                    ("exploit_runner", f"{EXPLOIT_RUNNER_URL}/health"),
                    ("osint_runner", f"{OSINT_URL}/health"),
                    ("pd_runner", f"{PD_RUNNER_URL}/health"),
                    ("brutus_runner", f"{BRUTUS_URL}/health"),
                ]:
                    try:
                        r = await client.get(url, timeout=5.0)
                        services[svc_name] = "healthy" if r.status_code == 200 else "unhealthy"
                    except Exception:
                        services[svc_name] = "unreachable"
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
                result = {"nmap_jobs": [], "web_jobs": [], "nuclei_jobs": [], "osint_jobs": [], "pd_jobs": [], "brutus_jobs": [], "errors": []}
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
                return [TextContent(type="text", text=json.dumps(result, indent=2))]

            # === Scanning Tools ===
            elif name == "start_masscan":
                # Fast port discovery with masscan only
                targets = arguments["targets"]
                if isinstance(targets, str):
                    targets = [targets]
                payload = {
                    "targets": targets,
                    "ports": arguments.get("ports", "1-1000"),
                    "rate": arguments.get("rate", 1000)
                }
                if arguments.get("udp"):
                    payload["udp"] = True
                resp = await client.post(f"{NMAP_URL}/jobs/masscan-only", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_nmap_scan":
                # Nmap scan - uses masscan-then-nmap for full, nmap-udp for UDP
                targets = arguments.get("targets", [])
                if isinstance(targets, str):
                    targets = [targets]
                scan_type = arguments.get("scan_type", "full")

                # Choose endpoint based on scan type
                if scan_type == "udp":
                    endpoint = "/jobs/nmap-udp"
                else:  # quick or full - both use masscan-then-nmap
                    endpoint = "/jobs/masscan-then-nmap"

                resp = await client.post(f"{NMAP_URL}{endpoint}", json={
                    "targets": targets,
                    "ports": arguments.get("ports", "1-1000"),
                    "rate": 1000
                })
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_web_scan":
                # Web scanner scans targets from database
                resp = await client.post(f"{WEB_SCANNER_URL}/jobs/web-scan", json={
                    "do_gobuster": arguments.get("do_gobuster", True),
                    "do_zap": arguments.get("use_zap", True),
                    "limit": arguments.get("limit", 25),
                    "wordlist": arguments.get("wordlist")
                })
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_nuclei_scan":
                # Nuclei scans targets from database, not from parameters
                resp = await client.post(f"{NUCLEI_URL}/jobs/nuclei-scan", json={
                    "limit": arguments.get("limit", 25),
                    "severity": arguments.get("severity", "medium,high,critical")
                })
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
                params = {"limit": arguments.get("limit", 100)}
                for key in ["severity", "ip"]:
                    if key in arguments:
                        params[key] = arguments[key]
                resp = await client.get(f"{RAG_API_URL}/vulns", params=params, headers={"x-api-key": API_KEY})
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "search_exploits":
                resp = await client.post(f"{SCAN_RECOMMENDER_URL}/rag/ask", json={
                    "question": arguments["query"],
                    "top_k": arguments.get("limit", 10)
                })
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "search_exploits_enhanced":
                # Enhanced search by CVE, service, or version (GET with query params)
                params = {}
                if "cve" in arguments:
                    params["cve"] = arguments["cve"]
                if "service" in arguments:
                    params["service"] = arguments["service"]
                if "version" in arguments:
                    params["version"] = arguments["version"]
                resp = await client.get(f"{SCAN_RECOMMENDER_URL}/rag/search/enhanced", params=params)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "get_recommendation":
                # Get next scan recommendations (GET with query params)
                params = {"ip": arguments["ip"]}
                if "service" in arguments:
                    params["service"] = arguments["service"]
                if "banner" in arguments:
                    params["banner"] = arguments["banner"]
                resp = await client.get(f"{SCAN_RECOMMENDER_URL}/next_scan", params=params)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            # === Metasploit & ExploitDB Tools ===
            elif name == "run_msf_module":
                resp = await client.post(f"{EXPLOIT_RUNNER_URL}/msf/run", json={
                    "module_path": arguments["module_path"],
                    "options": arguments.get("options", {})
                })
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "run_edb_script":
                payload = {
                    "edb_id": arguments["edb_id"],
                    "rhost": arguments["rhost"]
                }
                if "rport" in arguments:
                    payload["rport"] = arguments["rport"]
                resp = await client.post(f"{EXPLOIT_RUNNER_URL}/edb/run", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "list_msf_sessions":
                resp = await client.get(f"{EXPLOIT_RUNNER_URL}/msf/sessions")
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "run_session_command":
                resp = await client.post(f"{EXPLOIT_RUNNER_URL}/msf/sessions/{arguments['session_id']}/command", json={
                    "command": arguments["command"]
                })
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "list_msf_jobs":
                resp = await client.get(f"{EXPLOIT_RUNNER_URL}/msf/jobs")
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

            # === Performance Metrics ===
            elif name == "get_scan_metrics":
                view = arguments.get("view", "recent")
                headers = {"x-api-key": API_KEY}
                if view == "session":
                    sid = arguments.get("session_id")
                    if not sid:
                        return [TextContent(type="text", text=json.dumps({"error": "session_id is required when view='session'"}))]
                    resp = await client.get(f"{RAG_API_URL}/metrics/session/{sid}", headers=headers)
                elif view == "aggregate":
                    params = {"days": arguments.get("days", 30)}
                    if "scan_type" in arguments:
                        params["scan_type"] = arguments["scan_type"]
                    resp = await client.get(f"{RAG_API_URL}/metrics/aggregate", params=params, headers=headers)
                elif view == "compare_models":
                    params = {"days": arguments.get("days", 7)}
                    if "session_id" in arguments:
                        params["session_id"] = arguments["session_id"]
                    resp = await client.get(f"{RAG_API_URL}/metrics/models/compare", params=params, headers=headers)
                elif view == "llm_requests":
                    params = {"limit": arguments.get("limit", 50)}
                    if "session_id" in arguments:
                        params["session_id"] = arguments["session_id"]
                    if "model" in arguments:
                        params["model"] = arguments["model"]
                    resp = await client.get(f"{RAG_API_URL}/metrics/models/requests", params=params, headers=headers)
                else:  # recent
                    params = {"limit": arguments.get("limit", 20)}
                    if "scan_type" in arguments:
                        params["scan_type"] = arguments["scan_type"]
                    resp = await client.get(f"{RAG_API_URL}/metrics/recent", params=params, headers=headers)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text, "status_code": resp.status_code}, indent=2))]

            # === OSINT Tools ===
            elif name == "start_subfinder":
                payload = {"domains": arguments["domains"]}
                if "sources" in arguments:
                    payload["sources"] = arguments["sources"]
                if "max_time" in arguments:
                    payload["max_time"] = arguments["max_time"]
                resp = await client.post(f"{OSINT_URL}/jobs/subfinder", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_dnsx":
                payload = {"domains": arguments["domains"]}
                if "record_types" in arguments:
                    payload["record_types"] = arguments["record_types"]
                resp = await client.post(f"{OSINT_URL}/jobs/dnsx", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_asnmap":
                resp = await client.post(f"{OSINT_URL}/jobs/asnmap", json={"targets": arguments["targets"]})
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_uncover":
                payload = {"query": arguments["query"]}
                if "engine" in arguments:
                    payload["engine"] = arguments["engine"]
                if "limit" in arguments:
                    payload["limit"] = arguments["limit"]
                resp = await client.post(f"{OSINT_URL}/jobs/uncover", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_cloudlist":
                payload = {"provider": arguments["provider"]}
                if "config" in arguments:
                    payload["config"] = arguments["config"]
                resp = await client.post(f"{OSINT_URL}/jobs/cloudlist", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_alterx":
                payload = {"domains": arguments["domains"]}
                if "patterns" in arguments:
                    payload["patterns"] = arguments["patterns"]
                resp = await client.post(f"{OSINT_URL}/jobs/alterx", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_mapcidr":
                payload = {"cidrs": arguments["cidrs"]}
                if "operation" in arguments:
                    payload["operation"] = arguments["operation"]
                resp = await client.post(f"{OSINT_URL}/jobs/mapcidr", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "get_osint_job_status":
                resp = await client.get(f"{OSINT_URL}/jobs/{arguments['job_id']}")
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            # === PD Runner Tools ===
            elif name == "start_naabu":
                payload = {"targets": arguments["targets"]}
                if "ports" in arguments:
                    payload["ports"] = arguments["ports"]
                if "rate" in arguments:
                    payload["rate"] = arguments["rate"]
                resp = await client.post(f"{PD_RUNNER_URL}/jobs/naabu", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_httpx_probe":
                payload = {}
                if "targets" in arguments:
                    payload["targets"] = arguments["targets"]
                if "ports" in arguments:
                    payload["ports"] = arguments["ports"]
                if "tech_detect" in arguments:
                    payload["tech_detect"] = arguments["tech_detect"]
                resp = await client.post(f"{PD_RUNNER_URL}/jobs/httpx", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_katana":
                payload = {}
                if "targets" in arguments:
                    payload["targets"] = arguments["targets"]
                if "depth" in arguments:
                    payload["depth"] = arguments["depth"]
                if "js_crawl" in arguments:
                    payload["js_crawl"] = arguments["js_crawl"]
                resp = await client.post(f"{PD_RUNNER_URL}/jobs/katana", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "start_tlsx":
                payload = {}
                if "targets" in arguments:
                    payload["targets"] = arguments["targets"]
                if "ports" in arguments:
                    payload["ports"] = arguments["ports"]
                resp = await client.post(f"{PD_RUNNER_URL}/jobs/tlsx", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "get_pd_job_status":
                resp = await client.get(f"{PD_RUNNER_URL}/jobs/{arguments['job_id']}")
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            # === Brutus Tools ===
            elif name == "start_brutus":
                payload = {"targets": arguments["targets"], "protocols": arguments["protocols"]}
                if "usernames" in arguments:
                    payload["usernames"] = arguments["usernames"]
                if "passwords" in arguments:
                    payload["passwords"] = arguments["passwords"]
                resp = await client.post(f"{BRUTUS_URL}/jobs/brutus", json=payload)
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            elif name == "get_brutus_job_status":
                resp = await client.get(f"{BRUTUS_URL}/jobs/{arguments['job_id']}")
                return [TextContent(type="text", text=json.dumps(resp.json() if resp.status_code == 200 else {"error": resp.text}, indent=2))]

            # === Consolidated OSINT Report ===
            elif name == "get_osint_report":
                report = {
                    "osint_jobs": [], "assets": [], "ports": [],
                    "findings": [], "summary": {}, "errors": []
                }
                hdrs = {"x-api-key": API_KEY}
                domain = arguments.get("domain")
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
                    r = await client.get(f"{RAG_API_URL}/assets", params=params, headers=hdrs, timeout=5.0)
                    if r.status_code == 200:
                        report["assets"] = r.json() if isinstance(r.json(), list) else r.json().get("assets", [])
                except Exception as e:
                    report["errors"].append(f"assets: {str(e)}")
                # 3. Open ports
                try:
                    params = {"limit": 500}
                    if domain:
                        params["ip"] = domain
                    r = await client.get(f"{RAG_API_URL}/ports/open", params=params, headers=hdrs, timeout=5.0)
                    if r.status_code == 200:
                        report["ports"] = r.json() if isinstance(r.json(), list) else r.json().get("ports", [])
                except Exception as e:
                    report["errors"].append(f"ports: {str(e)}")
                # 4. Findings
                try:
                    params = {"limit": 200}
                    if domain:
                        params["ip"] = domain
                    r = await client.get(f"{RAG_API_URL}/vulns", params=params, headers=hdrs, timeout=5.0)
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
                return [TextContent(type="text", text=json.dumps(report, indent=2))]

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


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await mcp_server.run(
            read_stream,
            write_stream,
            mcp_server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
