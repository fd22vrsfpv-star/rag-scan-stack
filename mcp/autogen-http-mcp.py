#!/usr/bin/env python3
"""
Lightweight MCP server that proxies to autogen-agents HTTP API.
Much faster than running the full MCP server via docker exec.

Provides tools for:
- Pentest session management
- Scanner status monitoring (Nmap, Playwright, Metasploit)
- System health checks
"""

import asyncio
import json
import os
import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# API endpoints - use localhost since this runs in WSL with port forwarding
API_URL = os.environ.get("API_URL", "http://localhost:8015")
RAG_API_URL = os.environ.get("RAG_API_URL", "http://localhost:8000")
NMAP_URL = os.environ.get("NMAP_URL", "http://localhost:8012")
PLAYWRIGHT_URL = os.environ.get("PLAYWRIGHT_URL", "http://localhost:8014")
EXPLOIT_RUNNER_URL = os.environ.get("EXPLOIT_RUNNER_URL", "http://localhost:8017")
WEB_SCANNER_URL = os.environ.get("WEB_SCANNER_URL", "http://localhost:8010")
NUCLEI_URL = os.environ.get("NUCLEI_URL", "http://localhost:8011")
SCAN_RECOMMENDER_URL = os.environ.get("SCAN_RECOMMENDER_URL", "http://localhost:8013")

# rag-api requires x-api-key on every data route and returns HTTP 422
# "missing header x-api-key" without it. This file never sent one, so every
# query_* tool failed regardless of whether its path was right.
API_KEY = os.environ.get("API_KEY", "changeme")
RAG_HEADERS = {"x-api-key": API_KEY}

# Configurable timeouts
TIMEOUT_SCAN = float(os.environ.get("MCP_TIMEOUT_SCAN", "300"))  # 5 min for scan operations
TIMEOUT_QUICK = float(os.environ.get("MCP_TIMEOUT_QUICK", "30"))  # 30s for quick queries
TIMEOUT_STATUS = float(os.environ.get("MCP_TIMEOUT_STATUS", "15"))  # 15s for status checks

app = Server("autogen-pentest-http")

# Define tools that map to HTTP endpoints
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
        description="""Get status of an Nmap/Masscan scan job.

Returns job status including:
- status: queued, running, completed, failed
- progress stage: masscan_starting, masscan, masscan_completed, ingest_masscan, nmap_enrichment, done
- result (if completed) or error (if failed)
- timestamps for creation, start, completion

Use after starting an nmap scan to monitor progress.""",
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
        description="""Get status of a Playwright browser security scan.

Returns:
- status: running, completed, failed
- findings_count, screenshots count
- start_time, end_time
- console_logs_count, errors_count

Use after starting a playwright scan to monitor progress.""",
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
        description="""Get Metasploit framework status including active jobs and sessions.

Returns:
- jobs: List of running Metasploit jobs (exploits, auxiliary modules)
- sessions: List of active sessions (shells, meterpreter)
- healthy: Whether exploit-runner service is available

Use to monitor exploit execution and shell access.""",
        inputSchema={"type": "object", "properties": {}}
    ),
    Tool(
        name="get_all_scanner_status",
        description="""Get comprehensive status of all scanner services.

Returns health status for each scanner:
- nmap_scanner: Nmap/Masscan service health
- playwright_scanner: Browser automation scanner health
- web_scanner: Gobuster/ZAP scanner health
- nuclei_runner: Nuclei vulnerability scanner health
- exploit_runner: Metasploit integration health

Use for dashboard overview of scanning infrastructure.""",
        inputSchema={"type": "object", "properties": {}}
    ),

    # === Scanning Tools ===
    Tool(
        name="start_nmap_scan",
        description="""Start an Nmap port scan against a target.

Workflow:
1. Masscan performs fast initial port discovery
2. Nmap performs detailed service version detection
3. Results stored in PostgreSQL database

Returns a job_id - use get_nmap_job_status to monitor progress.""",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address, hostname, or CIDR range (e.g., 10.0.1.0/24)"},
                "ports": {"type": "string", "description": "Port range. OMIT for the server default (nmap's top-1000 for nmap scans, full range for masscan discovery). Do NOT pass '1-1000' — that is the first 1000 port NUMBERS and misses mysql 3306, postgresql 5432, vnc 5900, tomcat 8180."},
                "scan_type": {"type": "string", "enum": ["quick", "full", "service"], "default": "service"}
            },
            "required": ["target"]
        }
    ),
    Tool(
        name="start_web_scan",
        description="""Start a web directory/content scan using Gobuster with optional ZAP proxy.

Enumerates directories, files, and endpoints on web servers.
Results are stored in the database for analysis.""",
        inputSchema={
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target URL (e.g., http://10.0.1.1:80)"},
                "wordlist": {"type": "string", "enum": ["common", "medium", "big", "raft-small", "raft-medium", "api-endpoints"], "default": "common"},
                "extensions": {"type": "string", "description": "File extensions to check (e.g., 'php,html,js')", "default": ""},
                "use_zap": {"type": "boolean", "description": "Route traffic through ZAP proxy", "default": True}
            },
            "required": ["target_url"]
        }
    ),
    Tool(
        name="start_nuclei_scan",
        description="""Start a Nuclei vulnerability scan using templates.

Scans for known vulnerabilities, misconfigurations, and exposures.
Uses community and custom templates.""",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Target URL or IP"},
                "templates": {"type": "string", "description": "Template tags/categories (e.g., 'cve,misconfiguration')", "default": ""},
                "severity": {"type": "string", "description": "Minimum severity (info,low,medium,high,critical)", "default": "medium"}
            },
            "required": ["target"]
        }
    ),
    Tool(
        name="start_playwright_scan",
        description="""Start a Playwright browser-based security scan.

Performs browser automation to detect:
- XSS vulnerabilities
- Security headers
- Cookie security
- Mixed content
- DOM-based issues

Returns scan_id - use get_playwright_scan_status to monitor.""",
        inputSchema={
            "type": "object",
            "properties": {
                "target_url": {"type": "string", "description": "Target URL to scan"},
                "browser": {"type": "string", "enum": ["chromium", "firefox", "webkit"], "default": "chromium"},
                "screenshot": {"type": "boolean", "description": "Capture screenshots", "default": True}
            },
            "required": ["target_url"]
        }
    ),

    # === Query Tools ===
    Tool(
        name="query_assets",
        description="""Query discovered assets (hosts/IPs) from the database.

Returns list of discovered hosts with metadata.""",
        inputSchema={
            "type": "object",
            "properties": {
                "ip_filter": {"type": "string", "description": "Filter by IP pattern (e.g., '10.0.1.%')"},
                "limit": {"type": "integer", "default": 100}
            }
        }
    ),
    Tool(
        name="query_open_ports",
        description="""Query discovered open ports and services from scan results.

Returns ports with service information, versions, and banners.""",
        inputSchema={
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Filter by specific IP"},
                "port": {"type": "integer", "description": "Filter by specific port"},
                "service": {"type": "string", "description": "Filter by service name (e.g., 'http', 'ssh')"},
                "limit": {"type": "integer", "default": 100}
            }
        }
    ),
    Tool(
        name="query_findings",
        description="""Query vulnerability findings from all scanners.

Returns consolidated findings with severity, CVE references, and remediation info.""",
        inputSchema={
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "ip": {"type": "string", "description": "Filter by IP address"},
                "limit": {"type": "integer", "default": 100}
            }
        }
    ),
    Tool(
        name="search_exploits",
        description="""List pending scan recommendations from the knowledge base.

NOTE: this does NOT do semantic/vector search. It previously claimed to, but
pointed at an endpoint that does not exist and always failed. It now reads
scan-recommender's /recommendations, which the KB populates per discovered
(ip, service) after each scan ingests.

Filtering is by IP or CIDR only. A free-text `query` cannot be applied and the
response will say so explicitly rather than pretend it filtered.""",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "An IP or CIDR to filter by. Free text is NOT searched — this endpoint has no text search."},
                "limit": {"type": "integer", "default": 10}
            },
            "required": ["query"]
        }
    ),
]

@app.list_tools()
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


@app.call_tool()
async def call_tool(name: str, arguments: dict):
    import sys
    from datetime import datetime
    print(f"[{datetime.now().strftime('%H:%M:%S')}] TOOL CALLED: {name} args={arguments}", file=sys.stderr, flush=True)
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
                try:
                    resp = await client.get(f"{NMAP_URL}/jobs/{job_id}")
                    if resp.status_code == 200:
                        return [TextContent(type="text", text=json.dumps(resp.json(), indent=2))]
                    elif resp.status_code == 404:
                        return [TextContent(type="text", text=json.dumps({
                            "error": "Job not found",
                            "job_id": job_id,
                            "hint": "Job may have expired or ID is incorrect"
                        }, indent=2))]
                    else:
                        return [TextContent(type="text", text=json.dumps({
                            "error": f"HTTP {resp.status_code}",
                            "detail": resp.text
                        }, indent=2))]
                except httpx.ConnectError:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "Connection failed",
                        "message": "Cannot connect to nmap_scanner. Is the service running?",
                        "hint": "Check if nmap_scanner container is running on port 8012"
                    }, indent=2))]

            elif name == "get_playwright_scan_status":
                scan_id = arguments["scan_id"]
                try:
                    resp = await client.get(f"{PLAYWRIGHT_URL}/scan/{scan_id}")
                    if resp.status_code == 200:
                        data = resp.json()
                        # Also try to get findings count
                        try:
                            findings_resp = await client.get(f"{PLAYWRIGHT_URL}/scan/{scan_id}/findings")
                            if findings_resp.status_code == 200:
                                findings_data = findings_resp.json()
                                data["findings"] = findings_data.get("findings", [])
                                data["findings_count"] = len(data["findings"])
                        except Exception:
                            pass  # Findings fetch is optional
                        return [TextContent(type="text", text=json.dumps(data, indent=2))]
                    elif resp.status_code == 404:
                        return [TextContent(type="text", text=json.dumps({
                            "error": "Scan not found",
                            "scan_id": scan_id
                        }, indent=2))]
                    else:
                        return [TextContent(type="text", text=json.dumps({
                            "error": f"HTTP {resp.status_code}",
                            "detail": resp.text
                        }, indent=2))]
                except httpx.ConnectError:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "Connection failed",
                        "message": "Cannot connect to playwright-scanner. Is the service running?",
                        "hint": "Check if playwright-scanner container is running on port 8014"
                    }, indent=2))]

            elif name == "get_msf_status":
                result = {
                    "jobs": [],
                    "sessions": [],
                    "healthy": False,
                    "error": None
                }
                try:
                    # Get active jobs
                    jobs_resp = await client.get(f"{EXPLOIT_RUNNER_URL}/msf/jobs")
                    if jobs_resp.status_code == 200:
                        result["jobs"] = jobs_resp.json().get("jobs", [])

                    # Get active sessions
                    sessions_resp = await client.get(f"{EXPLOIT_RUNNER_URL}/msf/sessions")
                    if sessions_resp.status_code == 200:
                        result["sessions"] = sessions_resp.json().get("sessions", [])

                    result["healthy"] = True
                    result["jobs_count"] = len(result["jobs"])
                    result["sessions_count"] = len(result["sessions"])

                except httpx.ConnectError:
                    result["error"] = "Cannot connect to exploit-runner. Is the service running?"
                    result["hint"] = "Check if exploit-runner container is running on port 8017"
                except Exception as e:
                    result["error"] = str(e)

                return [TextContent(type="text", text=json.dumps(result, indent=2))]

            elif name == "get_all_scanner_status":
                services = {
                    "nmap_scanner": {"url": f"{NMAP_URL}/health", "port": 8012, "status": "unknown"},
                    "playwright_scanner": {"url": f"{PLAYWRIGHT_URL}/health", "port": 8014, "status": "unknown"},
                    "web_scanner": {"url": f"{WEB_SCANNER_URL}/health", "port": 8010, "status": "unknown"},
                    "nuclei_runner": {"url": f"{NUCLEI_URL}/health", "port": 8011, "status": "unknown"},
                    "exploit_runner": {"url": f"{EXPLOIT_RUNNER_URL}/health", "port": 8017, "status": "unknown"},
                }

                # Check each service in parallel
                async def check_service(name: str, info: dict):
                    try:
                        resp = await client.get(info["url"], timeout=5.0)
                        if resp.status_code == 200:
                            info["status"] = "healthy"
                            try:
                                info["details"] = resp.json()
                            except Exception:
                                info["details"] = {"raw": resp.text[:200]}
                        else:
                            info["status"] = "unhealthy"
                            info["http_status"] = resp.status_code
                    except httpx.ConnectError:
                        info["status"] = "unreachable"
                        info["error"] = f"Cannot connect to port {info['port']}"
                    except httpx.TimeoutException:
                        info["status"] = "timeout"
                        info["error"] = "Health check timed out after 5s"
                    except Exception as e:
                        info["status"] = "error"
                        info["error"] = str(e)

                # Run all health checks concurrently
                await asyncio.gather(*[
                    check_service(name, info) for name, info in services.items()
                ])

                # Calculate summary
                healthy_count = sum(1 for s in services.values() if s["status"] == "healthy")
                summary = {
                    "total_services": len(services),
                    "healthy": healthy_count,
                    "unhealthy": len(services) - healthy_count,
                    "all_healthy": healthy_count == len(services)
                }

                return [TextContent(type="text", text=json.dumps({
                    "summary": summary,
                    "services": services
                }, indent=2))]

            # === Scanning Tools ===
            elif name == "start_nmap_scan":
                target = arguments["target"]
                ports = arguments.get("ports")  # None -> scanner picks the top-1000
                scan_type = arguments.get("scan_type", "service")

                # This request body was wrong in two ways and the tool could never
                # have worked:
                #
                #   "target": target       -> the endpoint requires `targets`, a LIST.
                #                             MasscanBody ignores unknown fields, so
                #                             `targets` was simply absent and every
                #                             call returned HTTP 422 "Field required".
                #   "nmap_options": "-sV"  -> not a MasscanBody field either, so it was
                #                             silently dropped. The quick/service
                #                             distinction never reached nmap.
                #
                # Service detection is expressed by `service_detection`, which is the
                # -sV this was reaching for. `scripts` is deliberately left unset so
                # the scanner's NMAP_SCRIPTS env default applies, rather than this
                # client inventing a script list of its own.
                targets = [target] if isinstance(target, str) else list(target)
                try:
                    resp = await client.post(f"{NMAP_URL}/jobs/masscan-then-nmap", json={
                        "targets": targets,
                        "rate": 1000,
                        "service_detection": scan_type in ("service", "full"),
                        **({"ports": ports} if ports else {})
                    })
                    if resp.status_code == 200:
                        result = resp.json()
                        return [TextContent(type="text", text=json.dumps({
                            "status": "started",
                            "job_id": result.get("job_id"),
                            "target": target,
                            # Report the scope that is actually in effect. Echoing a
                            # bare null here would read to the model as "no ports
                            # scanned" and invite it to retry with an explicit range.
                            "ports": ports or "server default (nmap top-1000)",
                            "service_detection": scan_type in ("service", "full"),
                            "message": "Scan started. Use get_nmap_job_status to monitor progress."
                        }, indent=2))]
                    else:
                        return [TextContent(type="text", text=json.dumps({
                            "error": f"HTTP {resp.status_code}",
                            "detail": resp.text
                        }, indent=2))]
                except httpx.ConnectError:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "Cannot connect to nmap_scanner",
                        "hint": "Is the nmap_scanner container running on port 8012?"
                    }, indent=2))]

            elif name == "start_web_scan":
                target_url = arguments["target_url"]
                wordlist = arguments.get("wordlist", "common")
                extensions = arguments.get("extensions", "")
                use_zap = arguments.get("use_zap", True)

                # /scan does not exist on web-scanner (HTTP 404). The real route is
                # /jobs/web-scan, whose JobReq wants `target_url` and `do_zap` — not
                # `url`/`use_zap`. It has no `extensions` field at all, so that
                # argument was never going to reach gobuster; it is dropped here
                # rather than sent to be silently ignored.
                try:
                    resp = await client.post(f"{WEB_SCANNER_URL}/jobs/web-scan", json={
                        "target_url": target_url,
                        "wordlist": wordlist,
                        "do_zap": use_zap
                    })
                    if resp.status_code == 200:
                        result = resp.json()
                        return [TextContent(type="text", text=json.dumps({
                            "status": "started",
                            "scan_id": result.get("scan_id", result.get("job_id")),
                            "target": target_url,
                            "message": "Web scan started."
                        }, indent=2))]
                    else:
                        return [TextContent(type="text", text=json.dumps({
                            "error": f"HTTP {resp.status_code}",
                            "detail": resp.text
                        }, indent=2))]
                except httpx.ConnectError:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "Cannot connect to web-scanner",
                        "hint": "Is the web-scanner container running on port 8010?"
                    }, indent=2))]

            elif name == "start_nuclei_scan":
                target = arguments["target"]
                templates = arguments.get("templates", "")
                severity = arguments.get("severity", "medium")

                # /scan does not exist on nuclei-runner (HTTP 404). The real route is
                # /jobs/nuclei-scan, and its template filter is `tags` (e.g. "cve,rce"),
                # not `templates`. `target` singular IS correct here — JobReq accepts
                # both `target` and `targets`.
                try:
                    resp = await client.post(f"{NUCLEI_URL}/jobs/nuclei-scan", json={
                        "target": target,
                        "severity": severity,
                        **({"tags": templates} if templates else {})
                    })
                    if resp.status_code == 200:
                        result = resp.json()
                        return [TextContent(type="text", text=json.dumps({
                            "status": "started",
                            "scan_id": result.get("scan_id", result.get("job_id")),
                            "target": target,
                            "message": "Nuclei scan started."
                        }, indent=2))]
                    else:
                        return [TextContent(type="text", text=json.dumps({
                            "error": f"HTTP {resp.status_code}",
                            "detail": resp.text
                        }, indent=2))]
                except httpx.ConnectError:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "Cannot connect to nuclei-runner",
                        "hint": "Is the nuclei-runner container running on port 8011?"
                    }, indent=2))]

            elif name == "start_playwright_scan":
                target_url = arguments["target_url"]
                browser = arguments.get("browser", "chromium")
                screenshot = arguments.get("screenshot", True)

                # The route and `url`/`browser` were correct, but the model field is
                # `capture_screenshots` — `screenshot` was silently ignored, so this
                # toggle never did anything and scans always ran with the default.
                try:
                    resp = await client.post(f"{PLAYWRIGHT_URL}/scan", json={
                        "url": target_url,
                        "browser": browser,
                        "capture_screenshots": screenshot
                    })
                    if resp.status_code == 200:
                        result = resp.json()
                        return [TextContent(type="text", text=json.dumps({
                            "status": "started",
                            "scan_id": result.get("scan_id"),
                            "target": target_url,
                            "message": "Playwright scan started. Use get_playwright_scan_status to monitor."
                        }, indent=2))]
                    else:
                        return [TextContent(type="text", text=json.dumps({
                            "error": f"HTTP {resp.status_code}",
                            "detail": resp.text
                        }, indent=2))]
                except httpx.ConnectError:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "Cannot connect to playwright-scanner",
                        "hint": "Is the playwright-scanner container running on port 8014?"
                    }, indent=2))]

            # === Query Tools ===
            elif name == "query_assets":
                params = {"limit": arguments.get("limit", 100)}
                if "ip_filter" in arguments:
                    params["ip"] = arguments["ip_filter"]

                try:
                    resp = await client.get(f"{RAG_API_URL}/assets", params=params, headers=RAG_HEADERS)
                    if resp.status_code == 200:
                        return [TextContent(type="text", text=json.dumps(resp.json(), indent=2))]
                    else:
                        return [TextContent(type="text", text=json.dumps({
                            "error": f"HTTP {resp.status_code}",
                            "detail": resp.text
                        }, indent=2))]
                except httpx.ConnectError:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "Cannot connect to rag-api",
                        "hint": "Is the rag-api container running on port 8000?"
                    }, indent=2))]

            elif name == "query_open_ports":
                params = {"limit": arguments.get("limit", 100)}
                if "ip" in arguments:
                    params["ip"] = arguments["ip"]
                if "service" in arguments:
                    params["service"] = arguments["service"]
                # /ports/open filters by ip/service/search only — there is no `port`
                # parameter, and FastAPI drops unknown query params, so the caller's
                # `port` silently did nothing. `search` is NOT a substitute: it
                # substring-matches service/product/banner, so search="80" matches
                # the text "80" in a banner, not port 80.
                #
                # The rows carry a real `port` field, so the filter is applied here
                # instead. Fetch a wider page when filtering, since the server would
                # otherwise apply `limit` before this filter ever sees the rows.
                port_filter = arguments.get("port")
                if port_filter is not None:
                    params["limit"] = 5000

                try:
                    # /ports does not exist (HTTP 404) — the route is /ports/open.
                    resp = await client.get(f"{RAG_API_URL}/ports/open", params=params, headers=RAG_HEADERS)
                    if resp.status_code == 200:
                        data = resp.json()
                        if port_filter is not None and isinstance(data, dict):
                            keep = [i for i in data.get("items", [])
                                    if str(i.get("port")) == str(port_filter)]
                            trimmed = keep[:arguments.get("limit", 100)]
                            data = {**data, "items": trimmed, "count": len(trimmed),
                                    "total": len(keep),
                                    "filtered_by": {"port": port_filter,
                                                    "note": "port filtered client-side; /ports/open has no port parameter"}}
                        return [TextContent(type="text", text=json.dumps(data, indent=2))]
                    else:
                        return [TextContent(type="text", text=json.dumps({
                            "error": f"HTTP {resp.status_code}",
                            "detail": resp.text
                        }, indent=2))]
                except httpx.ConnectError:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "Cannot connect to rag-api",
                        "hint": "Is the rag-api container running on port 8000?"
                    }, indent=2))]

            elif name == "query_findings":
                params = {"limit": arguments.get("limit", 100)}
                if "severity" in arguments:
                    params["severity"] = arguments["severity"]
                if "ip" in arguments:
                    params["ip"] = arguments["ip"]

                try:
                    # /findings does not exist (HTTP 404). Findings are served by
                    # /vulns, which takes the same ip/severity/limit filters.
                    resp = await client.get(f"{RAG_API_URL}/vulns", params=params, headers=RAG_HEADERS)
                    if resp.status_code == 200:
                        return [TextContent(type="text", text=json.dumps(resp.json(), indent=2))]
                    elif resp.status_code == 404:
                        return [TextContent(type="text", text=json.dumps({
                            "findings": [],
                            "message": "No findings in database. Run scans first."
                        }, indent=2))]
                    else:
                        return [TextContent(type="text", text=json.dumps({
                            "error": f"HTTP {resp.status_code}",
                            "detail": resp.text
                        }, indent=2))]
                except httpx.ConnectError:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "Cannot connect to rag-api",
                        "hint": "Is the rag-api container running on port 8000?"
                    }, indent=2))]

            elif name == "search_exploits":
                query = arguments["query"]
                limit = arguments.get("limit", 10)

                # /rag/ask does not exist on scan-recommender (HTTP 405). The
                # closest real capability is GET /recommendations, which lists the
                # KB-generated scan recommendations per discovered (ip, service).
                #
                # It filters by ip/service/status — there is NO free-text or vector
                # search, so `query` cannot be honoured as written. An IP or CIDR is
                # applied as the `ip` filter; anything else cannot be turned into a
                # server-side filter, and is reported back as unapplied rather than
                # dropped silently, so the model is not left believing it searched.
                params = {"limit": min(max(int(limit), 1), 500), "status": "pending"}
                q = str(query).strip()
                looks_like_ip = q and all(c.isdigit() or c in "./:" for c in q)
                if looks_like_ip:
                    params["ip"] = q
                try:
                    resp = await client.get(f"{SCAN_RECOMMENDER_URL}/recommendations", params=params)
                    if resp.status_code == 200:
                        payload = resp.json()
                        if not looks_like_ip and q:
                            payload = {
                                "note": (
                                    f"'{q}' was NOT used as a search term — /recommendations "
                                    f"filters by ip/service/status only and has no free-text "
                                    f"search. Showing pending recommendations instead. Pass an "
                                    f"IP or CIDR to filter."
                                ),
                                **(payload if isinstance(payload, dict) else {"recommendations": payload}),
                            }
                        return [TextContent(type="text", text=json.dumps(payload, indent=2))]
                    else:
                        return [TextContent(type="text", text=json.dumps({
                            "error": f"HTTP {resp.status_code}",
                            "detail": resp.text
                        }, indent=2))]
                except httpx.ConnectError:
                    return [TextContent(type="text", text=json.dumps({
                        "error": "Cannot connect to scan-recommender",
                        "hint": "Is the scan-recommender container running on port 8013?"
                    }, indent=2))]

            else:
                return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]

            # Return response for standard API calls
            if resp.status_code == 200:
                return [TextContent(type="text", text=json.dumps(resp.json(), indent=2))]
            else:
                return [TextContent(type="text", text=json.dumps({
                    "error": f"HTTP {resp.status_code}",
                    "detail": resp.text
                }, indent=2))]

        except httpx.ConnectError:
            return [TextContent(type="text", text=json.dumps({
                "error": "Connection failed",
                "message": "Cannot connect to autogen-agents. Is the service running?"
            }, indent=2))]
        except httpx.TimeoutException:
            return [TextContent(type="text", text=json.dumps({
                "error": "Timeout",
                "message": f"Request timed out after {timeout}s",
                "hint": "The operation may still be running. Check status later."
            }, indent=2))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({
                "error": str(type(e).__name__),
                "message": str(e)
            }, indent=2))]


async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
