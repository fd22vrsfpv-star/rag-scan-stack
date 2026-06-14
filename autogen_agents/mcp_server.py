"""
MCP Server for Autogen Agents
Exposes pentest automation capabilities via Model Context Protocol
Allows external AI assistants (Claude Desktop, etc.) to control agents
"""

import asyncio
import json
import sys
import os
from typing import Any, Dict, List, Optional
import uuid
import threading
import uvicorn
import logging
import traceback
import httpx

# Check if running in MCP mode BEFORE any other imports
# MCP mode requires suppressing all stderr output to avoid breaking the stdio protocol
MCP_MODE = os.environ.get("MCP_MODE", "false").lower() == "true"

if MCP_MODE:
    # Suppress ALL logging to stderr when in MCP mode
    # MCP uses stdio for communication - any stderr output breaks the protocol
    logging.getLogger().setLevel(logging.CRITICAL + 1)
    logging.getLogger("httpx").setLevel(logging.CRITICAL + 1)
    logging.getLogger("httpcore").setLevel(logging.CRITICAL + 1)
    logging.getLogger("scan_tools").setLevel(logging.CRITICAL + 1)
    logging.getLogger("pentest_sessions").setLevel(logging.CRITICAL + 1)

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Lazy imports - all heavy dependencies imported only when needed
# to speed up MCP server initialization and avoid blocking async handlers
# from db_utils import ...
# from scan_tools import ...
# from pentest_agents import PentestTeam
# import autogen_service
from log_manager import setup_log_capture

# Setup logger for MCP server
logger = logging.getLogger(__name__)

# Initialize MCP server
mcp_server = Server("autogen-pentest-agents")

# Flag to track if logging web server is running
_logging_server_started = False

# Log API URL for sending logs to the web UI
# Use host.docker.internal to reach the host from inside a docker exec process
# This allows the MCP process to call back to the FastAPI server running in the same container
LOG_API_URL = os.environ.get("MCP_API_URL", "http://host.docker.internal:8015")

# Service URLs for health checks and scanner status
NMAP_URL = os.environ.get("NMAP_URL", "https://nmap_scanner:8012")
WEB_SCANNER_URL = os.environ.get("WEB_SCANNER_URL", "https://web-scanner:8010")
NUCLEI_URL = os.environ.get("NUCLEI_URL", "https://nuclei-runner:8011")
PLAYWRIGHT_URL = os.environ.get("PLAYWRIGHT_URL", "https://playwright-scanner:8014")
EXPLOIT_RUNNER_URL = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")

# Configurable timeouts
MCP_TIMEOUT_SCAN = float(os.environ.get("MCP_TIMEOUT_SCAN", "300"))  # 5 min for scan operations
MCP_TIMEOUT_QUICK = float(os.environ.get("MCP_TIMEOUT_QUICK", "30"))  # 30s for quick queries
MCP_TIMEOUT_STATUS = float(os.environ.get("MCP_TIMEOUT_STATUS", "15"))  # 15s for status checks


async def check_scan_service_health(service_name: str, health_url: str, request_id: str) -> tuple[bool, str]:
    """
    Check if a scan service is healthy before attempting scan.

    Returns:
        Tuple of (is_healthy: bool, error_message: str or None)
    """
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            resp = await client.get(health_url)
            if resp.status_code == 200:
                await send_log("DEBUG", f"{service_name} health check passed", request_id)
                return True, None
            else:
                error_msg = f"{service_name} unhealthy: HTTP {resp.status_code}"
                await send_log("ERROR", error_msg, request_id)
                return False, error_msg
    except httpx.ConnectError as e:
        error_msg = f"{service_name} unreachable: Connection refused"
        await send_log("ERROR", error_msg, request_id)
        return False, error_msg
    except Exception as e:
        error_msg = f"{service_name} unreachable: {type(e).__name__}: {e}"
        await send_log("ERROR", error_msg, request_id)
        return False, error_msg


async def send_log(level: str, message: str, request_id: Optional[str] = None):
    """
    Send a log entry to the autogen-agents log viewer.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        message: Log message
        request_id: Optional request ID for correlation
    """
    # Format message with request_id for correlation
    formatted_msg = f"[{request_id}] {message}" if request_id else message

    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            await client.post(
                f"{LOG_API_URL}/logs/ingest",
                json={
                    "level": level,
                    "message": formatted_msg,
                    "source": "mcp-autogen-agents",
                    "request_id": request_id
                }
            )
    except Exception as e:
        # Log to stderr so it appears in docker logs instead of silently failing
        print(f"[MCP-LOG] {level}: {formatted_msg}", file=sys.stderr)
        if level in ("ERROR", "WARNING"):
            print(f"  (log API unavailable: {type(e).__name__})", file=sys.stderr)


def format_tool_response(result_str: str) -> str:
    """
    Format tool responses to be more readable in Claude Desktop

    If the response contains an error, format it in a user-friendly way.
    Otherwise, return the original response.

    Args:
        result_str: JSON string from a scan_tools function

    Returns:
        Formatted string suitable for display in Claude Desktop
    """
    try:
        result = json.loads(result_str)

        # Check if this is an error response
        if isinstance(result, dict) and "error" in result:
            error_type = result.get("error", "Unknown error")
            operation = result.get("operation", "Operation")

            # Build a user-friendly error message
            error_msg = f"❌ {operation} failed\n\n"
            error_msg += f"**Error Type**: {error_type}\n"

            # Add specific error details based on error type
            if "HTTP" in error_type:
                status_code = result.get("status_code", "unknown")
                url = result.get("url", "")
                error_msg += f"**Status Code**: {status_code}\n"
                error_msg += f"**URL**: {url}\n"

                if "detail" in result:
                    detail = result["detail"]
                    if isinstance(detail, dict):
                        detail = json.dumps(detail, indent=2)
                    error_msg += f"**Details**:\n```\n{detail}\n```\n"

            elif "JSON parsing failed" in error_type:
                error_msg += "**Issue**: Server returned non-JSON response\n"
                json_error = result.get("json_error", "")
                response_text = result.get("response_text", "")[:200]
                error_msg += f"**Parse Error**: {json_error}\n"
                error_msg += f"**Response Preview**: {response_text}...\n"

            elif "Connection failed" in error_type:
                detail = result.get("detail", "")
                hint = result.get("hint", "")
                error_msg += f"**Details**: {detail}\n"
                if hint:
                    error_msg += f"**Hint**: {hint}\n"

            elif "timeout" in error_type.lower():
                timeout = result.get("timeout", "unknown")
                error_msg += f"**Timeout**: {timeout}\n"
                error_msg += "**Suggestion**: Try reducing the scan scope or wait for current operations to complete\n"

            # Add request ID for debugging
            if "request_id" in result:
                error_msg += f"\n*Request ID: {result['request_id']}*\n"
                error_msg += "*View detailed logs at http://localhost:8015/logs/ui (filter by request ID)*\n"

            return error_msg

        # Not an error - return pretty-printed JSON
        return json.dumps(result, indent=2)

    except json.JSONDecodeError as e:
        # If we can't parse it, return as-is
        logger.warning(f"[MCP] Unable to parse tool response as JSON: {str(e)[:100]}")
        return result_str
    except Exception as e:
        # Fallback: return original with error note
        logger.error(f"[MCP] Error formatting tool response: {type(e).__name__}: {str(e)}")
        return f"{result_str}\n\n*(Error formatting response: {e})*"


# Tool definitions for MCP
TOOLS = [
    Tool(
        name="start_pentest_session",
        description="""Start an autonomous AI-powered penetration testing session.

The system uses a team of specialized AI agents:
- Coordinator: Manages workflow and priorities
- Reconnaissance: Plans recon strategy and recommends scans
- Scanner: Executes scans (Nmap, Web, Nuclei, Playwright)
- Analyzer: Analyzes findings and queries exploit database
- Reporter: Generates comprehensive reports

The agents will autonomously:
1. Analyze the target description
2. Query existing asset data
3. Plan and execute appropriate scans
4. Analyze vulnerabilities
5. Generate a detailed markdown report

Returns a session_id to monitor progress.""",
        inputSchema={
            "type": "object",
            "properties": {
                "target_description": {
                    "type": "string",
                    "description": (
                        "Description of the target (e.g., '192.168.1.0/24 web application', '10.0.1.50 SSH server')"
                    )
                },
                "session_name": {
                    "type": "string",
                    "description": "Human-readable name for this session"
                },
                "initial_task": {
                    "type": "string",
                    "description": (
                        "Initial task for the agents (e.g., 'Discover all services and test for vulnerabilities')"
                    )
                },
                "max_rounds": {
                    "type": "integer",
                    "description": "Maximum conversation rounds (default: 100). Status polling doesn't count towards this limit.",
                    "default": 100
                }
            },
            "required": ["target_description", "session_name", "initial_task"]
        }
    ),
    Tool(
        name="get_session_status",
        description="""Get the status of a pentest session.

Returns:
- session_id, session_name, status
- target_description
- started_at, ended_at timestamps
- message_count (agent conversation rounds)
- summary (if completed)
- configuration""",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "UUID of the session"
                }
            },
            "required": ["session_id"]
        }
    ),
    Tool(
        name="get_session_messages",
        description="""Get the agent conversation history for a session.

Shows the complete dialogue between agents including:
- Which agent said what
- Tool calls and results
- Decision making process
- Timestamps

Useful for understanding how the agents are working.""",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "UUID of the session"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of messages to return (default: 100)",
                    "default": 100
                }
            },
            "required": ["session_id"]
        }
    ),
    Tool(
        name="get_session_report",
        description="""Get the final penetration testing report for a completed session.

The report includes:
- Executive summary
- Detailed findings per asset
- Severity ratings
- Evidence and proof-of-concepts
- Remediation recommendations
- References

Report is in markdown format.""",
        inputSchema={
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "UUID of the session"
                }
            },
            "required": ["session_id"]
        }
    ),
    Tool(
        name="list_sessions",
        description="""List all pentest sessions with optional filtering.

Useful for:
- Seeing all active pentests
- Finding completed assessments
- Reviewing failed sessions""",
        inputSchema={
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "Filter by status: 'active', 'completed', 'failed', 'stopped'",
                    "enum": ["active", "completed", "failed", "stopped"]
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of sessions (default: 50)",
                    "default": 50
                }
            }
        }
    ),
    Tool(
        name="query_assets",
        description="""Query discovered assets from the database.

Returns information about:
- IP addresses
- Hostnames
- Operating systems
- Tags
- First/last seen timestamps

This shows what targets have been discovered by previous scans.""",
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default: 100)",
                    "default": 100
                }
            }
        }
    ),
    Tool(
        name="query_open_ports",
        description="""Query open ports from the database.

Returns:
- IP address and port
- Protocol (tcp/udp)
- Service name and version
- Banner information
- First/last seen

Shows the attack surface discovered by port scans.""",
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default: 100)",
                    "default": 100
                }
            }
        }
    ),
    Tool(
        name="query_vulnerabilities",
        description="""Query vulnerability findings from all scan sources.

Returns findings from:
- Nmap NSE scripts
- Web scanner (Gobuster + ZAP)
- Nuclei templates
- Playwright browser tests

Can filter by severity: info, low, medium, high, critical""",
        inputSchema={
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "description": "Filter by severity level",
                    "enum": ["info", "low", "medium", "high", "critical"]
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results (default: 100)",
                    "default": 100
                }
            }
        }
    ),
    Tool(
        name="start_nmap_scan",
        description="""Start an Nmap port scan on a specific IP address.

Performs service detection (-sV) and runs NSE scripts including:
- banner, http-title, ssl-cert
- ssh2-enum-algos, ssl-enum-ciphers
- vulscan for known vulnerabilities

Use this for detailed service fingerprinting.""",
        inputSchema={
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "Target IP address"
                },
                "ports": {
                    "type": "string",
                    "description": "Port range (e.g., '1-1000', '80,443,8080') (default: '1-1000')",
                    "default": "1-1000"
                },
                "service_detection": {
                    "type": "boolean",
                    "description": "Enable service detection (-sV) for detailed service/version fingerprinting (default: true)",
                    "default": true
                },
                "version_intensity": {
                    "type": "integer",
                    "description": "Service detection intensity 0-9 (9=aggressive, default: 9)",
                    "default": 9,
                    "minimum": 0,
                    "maximum": 9
                },
                "enable_scripts": {
                    "type": "boolean",
                    "description": "Enable NSE scripts for banner grabbing and vulnerability detection (default: true)",
                    "default": true
                }
            },
            "required": ["ip_address"]
        }
    ),
    Tool(
        name="start_web_scan",
        description="""Start a web application scan with Gobuster and ZAP.

- Gobuster: Directory/file enumeration
- ZAP: Proxy-based vulnerability scanning

Scans HTTP/HTTPS ports on discovered assets.""",
        inputSchema={
            "type": "object",
            "properties": {
                "do_gobuster": {
                    "type": "boolean",
                    "description": "Run Gobuster directory enumeration (default: true)",
                    "default": True
                },
                "do_zap": {
                    "type": "boolean",
                    "description": "Run ZAP vulnerability scanning (default: true)",
                    "default": True
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum targets to scan (default: 25)",
                    "default": 25
                }
            }
        }
    ),
    Tool(
        name="start_nuclei_scan",
        description="""Start a Nuclei template-based vulnerability scan.

Runs thousands of vulnerability checks from Nuclei templates:
- CVEs and known exploits
- Misconfigurations
- Exposed panels and files
- Technology-specific issues

Can filter by severity.""",
        inputSchema={
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "description": "Comma-separated severity levels (default: 'medium,high,critical')",
                    "default": "medium,high,critical"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum targets (default: 25)",
                    "default": 25
                }
            }
        }
    ),
    Tool(
        name="start_playwright_scan",
        description="""Start a browser-based security scan using Playwright.

Tests for client-side vulnerabilities:
- Clickjacking (missing X-Frame-Options)
- CSRF (missing tokens)
- Mixed content (HTTP on HTTPS)
- Security headers (CSP, HSTS, etc.)
- Cookie security (Secure, HttpOnly, SameSite)
- DOM-based issues

Can route through ZAP for additional testing.""",
        inputSchema={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target URL to scan"
                },
                "use_zap": {
                    "type": "boolean",
                    "description": "Route through ZAP proxy (default: true)",
                    "default": True
                },
                "capture_screenshots": {
                    "type": "boolean",
                    "description": "Capture page screenshots (default: true)",
                    "default": True
                }
            },
            "required": ["url"]
        }
    ),
    Tool(
        name="query_exploitdb",
        description="""Search the ExploitDB database via RAG for known exploits.

Use this to find:
- Public exploits for discovered vulnerabilities
- Proof-of-concept code
- Technical details about exploits

Query with service names, versions, or CVE IDs.""",
        inputSchema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query (e.g., 'apache 2.4.41 exploit', 'CVE-2021-44228')"
                },
                "top_k": {
                    "type": "integer",
                    "description": "Number of results to return (default: 5)",
                    "default": 5
                }
            },
            "required": ["query"]
        }
    ),
    Tool(
        name="get_scan_recommendations",
        description="""Get AI-powered scan recommendations based on context.

Analyzes the current state and suggests:
- Which scans to run next
- Priority targets
- Appropriate scan parameters

Uses Ollama LLM for intelligent recommendations.""",
        inputSchema={
            "type": "object",
            "properties": {
                "context": {
                    "type": "string",
                    "description": "Context description (e.g., 'Found Apache 2.4.41 on port 80')"
                }
            },
            "required": ["context"]
        }
    ),
    Tool(
        name="get_attack_vectors",
        description="""Get the prioritized attack vector map — findings mapped to MITRE
ATT&CK techniques with a unified risk score, ranked highest-risk first.

Use this to decide the NEXT-BEST ACTION: it tells you which finding/technique on which
target has the highest attack value (factoring severity, CVSS, CISA KEV, exploit
availability, ATT&CK tactic position, and asset criticality). Prefer this over raw
scan recommendations when choosing what to attack/investigate next.""",
        inputSchema={
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max vectors (default 15)"},
                "min_risk": {"type": "number", "description": "Only vectors at/above this risk score 0..100 (default 0)"}
            },
            "required": []
        }
    ),
    # ==========================================
    # Exploit Approval Workflow Tools
    # ==========================================
    Tool(
        name="list_pending_exploits",
        description="""List exploits queued for human approval.

Shows all pending exploits with:
- Exploit ID and title
- Target IP and port
- Service and version
- Customized command/payload
- Status and timestamps

Use this to review exploits before approving them.
IMPORTANT: Always review the customized_command before approving!""",
        inputSchema={
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "description": "Filter by status",
                    "enum": ["pending", "approved", "rejected", "executed", "failed"]
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum results (default: 20)",
                    "default": 20
                }
            }
        }
    ),
    Tool(
        name="get_pending_exploit_details",
        description="""Get full details of a pending exploit including the customized command.

Use this to review an exploit before approving it.
Shows the exact command that will be executed.""",
        inputSchema={
            "type": "object",
            "properties": {
                "exploit_id": {
                    "type": "string",
                    "description": "UUID of the pending exploit"
                }
            },
            "required": ["exploit_id"]
        }
    ),
    Tool(
        name="approve_exploit",
        description="""Approve a pending exploit for execution.

IMPORTANT: This is a human-in-the-loop safety control.
- Review the exploit details carefully before approving
- Verify the target IP and port are correct
- Confirm you have authorization to test this target
- Check the customized command for safety

After approval, the exploit can be executed.""",
        inputSchema={
            "type": "object",
            "properties": {
                "exploit_id": {
                    "type": "string",
                    "description": "UUID of the pending exploit to approve"
                },
                "notes": {
                    "type": "string",
                    "description": "Optional notes about the approval"
                }
            },
            "required": ["exploit_id"]
        }
    ),
    Tool(
        name="reject_exploit",
        description="""Reject a pending exploit.

Use this to prevent an exploit from being executed.
Provide a reason for the rejection.""",
        inputSchema={
            "type": "object",
            "properties": {
                "exploit_id": {
                    "type": "string",
                    "description": "UUID of the pending exploit to reject"
                },
                "reason": {
                    "type": "string",
                    "description": "Reason for rejection"
                }
            },
            "required": ["exploit_id", "reason"]
        }
    ),
    Tool(
        name="execute_approved_exploit",
        description="""Execute an exploit that has been approved.

IMPORTANT: Only works for exploits with status='approved'.
The exploit must be approved by a human first.

Returns the execution result including any output.""",
        inputSchema={
            "type": "object",
            "properties": {
                "exploit_id": {
                    "type": "string",
                    "description": "UUID of the approved exploit to execute"
                }
            },
            "required": ["exploit_id"]
        }
    ),
    Tool(
        name="get_exploit_result",
        description="""Get the result of an executed exploit.

Shows:
- Success/failure status
- Output from execution
- Session type (if a shell was obtained)
- Execution time""",
        inputSchema={
            "type": "object",
            "properties": {
                "exploit_id": {
                    "type": "string",
                    "description": "UUID of the exploit to get results for"
                }
            },
            "required": ["exploit_id"]
        }
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
                "job_id": {
                    "type": "string",
                    "description": "Job UUID returned from nmap scan"
                }
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
                "scan_id": {
                    "type": "string",
                    "description": "Scan UUID returned from playwright scan"
                }
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
    Tool(
        name="export_pentester_report",
        description="""Export a comprehensive penetration test report with full raw tool output.

Generates a downloadable report containing:
- Execution summary table (tool, target, status, exit code, duration)
- Full raw output for each tool execution
- Error output when available
- Findings summary for each execution

Perfect for manual pentester review and documentation.

Parameters:
- target: Optional IP/hostname to filter results
- format: 'markdown' (default) or 'text'
- status: Filter by execution status (completed/failed/timeout)

Returns the full report content as text.""",
        inputSchema={
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Optional target IP/hostname to filter results"
                },
                "format": {
                    "type": "string",
                    "enum": ["markdown", "text"],
                    "description": "Output format: 'markdown' (default) or 'text'",
                    "default": "markdown"
                },
                "status": {
                    "type": "string",
                    "enum": ["completed", "failed", "timeout"],
                    "description": "Filter by execution status"
                }
            }
        }
    ),
]


# Tool handlers
@mcp_server.list_tools()
async def list_tools() -> List[Tool]:
    """List all available MCP tools"""
    return TOOLS


@mcp_server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Handle tool calls from MCP clients"""

    # Generate request ID for log correlation
    request_id = f"mcp-{uuid.uuid4().hex[:8]}"

    try:
        # Log tool invocation
        await send_log("INFO", f"Tool '{name}' called with args: {json.dumps(arguments)}", request_id)

        if name == "start_pentest_session":
            # Call the autogen-agents HTTP API instead of importing heavy modules
            # This avoids blocking the MCP process with slow pyautogen imports
            async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
                try:
                    response = await client.post(
                        f"{LOG_API_URL}/pentest",
                        json={
                            "session_name": arguments["session_name"],
                            "target_description": arguments["target_description"],
                            "initial_task": arguments["initial_task"],
                            "max_rounds": arguments.get("max_rounds", 100)
                        }
                    )
                    response.raise_for_status()
                    result = response.json()
                    await send_log("INFO", f"Session started: {result.get('session_id')}", request_id)
                    return [TextContent(type="text", text=json.dumps(result, indent=2))]
                except httpx.HTTPError as e:
                    error_result = {
                        "error": "Failed to start session",
                        "message": str(e),
                        "status_code": getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
                    }
                    await send_log("ERROR", f"Failed to start session: {e}", request_id)
                    return [TextContent(type="text", text=json.dumps(error_result, indent=2))]

        elif name == "get_session_status":
            from db_utils import get_agent_session, get_agent_messages

            session_uuid = uuid.UUID(arguments["session_id"])
            session = get_agent_session(session_uuid)

            if not session:
                return [TextContent(type="text", text=json.dumps({"error": "Session not found"}, indent=2))]

            messages = get_agent_messages(session_uuid)

            result = {
                "session_id": str(session['id']),
                "session_name": session['session_name'],
                "status": session['status'],
                "target_description": session['target_description'],
                "started_at": session['created_at'].isoformat() if session['created_at'] else None,
                "ended_at": session['end_time'].isoformat() if session.get('end_time') else None,
                "message_count": len(messages),
                "summary": session.get('summary'),
                "configuration": session.get('configuration', {})
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "get_session_messages":
            from db_utils import get_agent_session, get_agent_messages

            session_uuid = uuid.UUID(arguments["session_id"])
            session = get_agent_session(session_uuid)

            if not session:
                return [TextContent(type="text", text=json.dumps({"error": "Session not found"}, indent=2))]

            messages = get_agent_messages(session_uuid, limit=arguments.get("limit", 100))

            result = {
                "session_id": arguments["session_id"],
                "messages": [
                    {
                        "agent_name": msg['agent_name'],
                        "role": msg['role'],
                        "content": msg['content'],
                        "timestamp": msg['created_at'].isoformat() if msg['created_at'] else None
                    }
                    for msg in messages
                ]
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "get_session_report":
            from db_utils import get_agent_session, get_agent_messages

            session_uuid = uuid.UUID(arguments["session_id"])
            session = get_agent_session(session_uuid)

            if not session:
                return [TextContent(type="text", text=json.dumps({"error": "Session not found"}, indent=2))]

            if session['status'] != 'completed':
                return [TextContent(type="text", text=json.dumps({
                    "error": f"Session is not completed yet. Current status: {session['status']}"
                }, indent=2))]

            # Get reporter's final message
            messages = get_agent_messages(session_uuid, limit=1000)
            reporter_messages = [msg for msg in messages if msg['agent_name'] == 'Reporter']

            if not reporter_messages:
                report = session.get('summary', 'No report available yet.')
            else:
                report = reporter_messages[-1]['content']

            result = {
                "session_id": arguments["session_id"],
                "session_name": session['session_name'],
                "target_description": session['target_description'],
                "report": report,
                "generated_at": reporter_messages[-1]['created_at'].isoformat() if reporter_messages else None,
                "status": session['status']
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "list_sessions":
            from db_utils import list_agent_sessions

            sessions = list_agent_sessions(
                status=arguments.get("status"),
                limit=arguments.get("limit", 50)
            )

            result = {
                "sessions": [
                    {
                        "session_id": str(s['id']),
                        "session_name": s['session_name'],
                        "status": s['status'],
                        "target_description": s['target_description'],
                        "created_at": s['created_at'].isoformat() if s['created_at'] else None,
                        "end_time": s['end_time'].isoformat() if s.get('end_time') else None
                    }
                    for s in sessions
                ],
                "total": len(sessions)
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "query_assets":
            from scan_tools import query_assets

            result = query_assets(limit=arguments.get("limit", 100))
            formatted_result = format_tool_response(result)
            return [TextContent(type="text", text=formatted_result)]

        elif name == "query_open_ports":
            from scan_tools import query_open_ports

            result = query_open_ports(limit=arguments.get("limit", 100))
            formatted_result = format_tool_response(result)
            return [TextContent(type="text", text=formatted_result)]

        elif name == "query_vulnerabilities":
            from scan_tools import query_vulnerabilities

            result = query_vulnerabilities(
                severity=arguments.get("severity"),
                limit=arguments.get("limit", 100)
            )
            formatted_result = format_tool_response(result)
            return [TextContent(type="text", text=formatted_result)]

        elif name == "start_nmap_scan":
            from scan_tools import start_nmap_scan

            ip = arguments["ip_address"]
            ports = arguments.get("ports", "1-1000")
            service_detection = arguments.get("service_detection", True)
            version_intensity = arguments.get("version_intensity", 9)
            enable_scripts = arguments.get("enable_scripts", True)

            # Pre-scan health check
            is_healthy, error_msg = await check_scan_service_health(
                "Nmap Scanner", f"{NMAP_URL}/health", request_id
            )
            if not is_healthy:
                return [TextContent(type="text", text=json.dumps({
                    "error": "Nmap Scanner service is not available",
                    "detail": error_msg,
                    "hint": "Check if nmap_scanner container is running: docker ps | grep nmap",
                    "request_id": request_id
                }, indent=2))]

            await send_log("INFO", f"Starting Nmap scan: target={ip}, ports={ports}, service_detection={service_detection}, version_intensity={version_intensity}", request_id)

            result = start_nmap_scan(
                ip_address=ip,
                ports=ports,
                service_detection=service_detection,
                version_intensity=version_intensity,
                enable_scripts=enable_scripts
            )

            # Parse and log result details
            try:
                result_data = json.loads(result)
                if "error" in result_data:
                    await send_log("ERROR", f"Nmap scan failed: {result_data.get('error')} - {result_data.get('detail', 'no details')}", request_id)
                elif result_data.get("ok"):
                    await send_log("INFO", f"Nmap scan started: job_id={result_data.get('job_id')}", request_id)
                else:
                    await send_log("WARNING", f"Nmap scan returned unexpected response", request_id)
            except json.JSONDecodeError as e:
                await send_log("ERROR", f"Nmap scan returned invalid JSON: {e}", request_id)

            formatted_result = format_tool_response(result)
            return [TextContent(type="text", text=formatted_result)]

        elif name == "start_web_scan":
            from scan_tools import start_web_scan

            # Pre-scan health check
            is_healthy, error_msg = await check_scan_service_health(
                "Web Scanner", f"{WEB_SCANNER_URL}/health", request_id
            )
            if not is_healthy:
                return [TextContent(type="text", text=json.dumps({
                    "error": "Web Scanner service is not available",
                    "detail": error_msg,
                    "hint": "Check if web-scanner container is running: docker ps | grep web-scanner",
                    "request_id": request_id
                }, indent=2))]

            await send_log("INFO", f"Starting web scan: gobuster={arguments.get('do_gobuster', True)}, zap={arguments.get('do_zap', True)}", request_id)

            result = start_web_scan(
                do_gobuster=arguments.get("do_gobuster", True),
                do_zap=arguments.get("do_zap", True),
                limit=arguments.get("limit", 25)
            )

            # Parse and log result details
            try:
                result_data = json.loads(result)
                if "error" in result_data:
                    await send_log("ERROR", f"Web scan failed: {result_data.get('error')} - {result_data.get('detail', 'no details')}", request_id)
                elif result_data.get("ok"):
                    await send_log("INFO", f"Web scan started: job_id={result_data.get('job_id')}", request_id)
                else:
                    await send_log("WARNING", f"Web scan returned unexpected response", request_id)
            except json.JSONDecodeError as e:
                await send_log("ERROR", f"Web scan returned invalid JSON: {e}", request_id)

            formatted_result = format_tool_response(result)
            return [TextContent(type="text", text=formatted_result)]

        elif name == "start_nuclei_scan":
            from scan_tools import start_nuclei_scan

            # Pre-scan health check
            is_healthy, error_msg = await check_scan_service_health(
                "Nuclei Scanner", f"{NUCLEI_URL}/health", request_id
            )
            if not is_healthy:
                return [TextContent(type="text", text=json.dumps({
                    "error": "Nuclei Scanner service is not available",
                    "detail": error_msg,
                    "hint": "Check if nuclei-runner container is running: docker ps | grep nuclei",
                    "request_id": request_id
                }, indent=2))]

            await send_log("INFO", f"Starting Nuclei scan: severity={arguments.get('severity', 'medium,high,critical')}", request_id)

            result = start_nuclei_scan(
                limit=arguments.get("limit", 25),
                severity=arguments.get("severity", "medium,high,critical")
            )

            # Parse and log result details
            try:
                result_data = json.loads(result)
                if "error" in result_data:
                    await send_log("ERROR", f"Nuclei scan failed: {result_data.get('error')} - {result_data.get('detail', 'no details')}", request_id)
                elif result_data.get("ok"):
                    await send_log("INFO", f"Nuclei scan started: job_id={result_data.get('job_id')}", request_id)
                else:
                    await send_log("WARNING", f"Nuclei scan returned unexpected response", request_id)
            except json.JSONDecodeError as e:
                await send_log("ERROR", f"Nuclei scan returned invalid JSON: {e}", request_id)

            formatted_result = format_tool_response(result)
            return [TextContent(type="text", text=formatted_result)]

        elif name == "start_playwright_scan":
            from scan_tools import start_playwright_scan

            url = arguments["url"]

            # Pre-scan health check
            is_healthy, error_msg = await check_scan_service_health(
                "Playwright Scanner", f"{PLAYWRIGHT_URL}/health", request_id
            )
            if not is_healthy:
                return [TextContent(type="text", text=json.dumps({
                    "error": "Playwright Scanner service is not available",
                    "detail": error_msg,
                    "hint": "Check if playwright-scanner container is running: docker ps | grep playwright",
                    "request_id": request_id
                }, indent=2))]

            await send_log("INFO", f"Starting Playwright scan: url={url}", request_id)

            result = start_playwright_scan(
                url=url,
                use_zap=arguments.get("use_zap", True),
                capture_screenshots=arguments.get("capture_screenshots", True)
            )

            # Parse and log result details
            try:
                result_data = json.loads(result)
                if "error" in result_data:
                    await send_log("ERROR", f"Playwright scan failed: {result_data.get('error')} - {result_data.get('detail', 'no details')}", request_id)
                elif result_data.get("ok") or result_data.get("scan_id"):
                    await send_log("INFO", f"Playwright scan started: scan_id={result_data.get('scan_id', 'unknown')}", request_id)
                else:
                    await send_log("WARNING", f"Playwright scan returned unexpected response", request_id)
            except json.JSONDecodeError as e:
                await send_log("ERROR", f"Playwright scan returned invalid JSON: {e}", request_id)

            formatted_result = format_tool_response(result)
            return [TextContent(type="text", text=formatted_result)]

        elif name == "query_exploitdb":
            from scan_tools import query_exploitdb

            result = query_exploitdb(
                query=arguments["query"],
                top_k=arguments.get("top_k", 5)
            )
            formatted_result = format_tool_response(result)
            return [TextContent(type="text", text=formatted_result)]

        elif name == "get_scan_recommendations":
            from scan_tools import get_scan_recommendations

            result = get_scan_recommendations(context=arguments["context"])
            formatted_result = format_tool_response(result)
            return [TextContent(type="text", text=formatted_result)]

        elif name == "get_attack_vectors":
            from scan_tools import get_attack_vectors

            result = get_attack_vectors(
                limit=arguments.get("limit", 15),
                min_risk=arguments.get("min_risk", 0.0),
            )
            return [TextContent(type="text", text=format_tool_response(result))]

        # ==========================================
        # Exploit Approval Workflow Handlers
        # ==========================================
        elif name == "list_pending_exploits":
            from db_utils import list_pending_exploits

            await send_log("INFO", f"Listing pending exploits with status filter: {arguments.get('status')}", request_id)

            exploits = list_pending_exploits(
                status=arguments.get("status"),
                limit=arguments.get("limit", 20)
            )

            result = {
                "exploits": [
                    {
                        "id": str(e["id"]),
                        "exploit_id": e["exploit_id"],
                        "exploit_title": e["exploit_title"],
                        "source": e["source"],
                        "exploit_type": e.get("exploit_type"),
                        "target_ip": str(e["target_ip"]),
                        "target_port": e.get("target_port"),
                        "target_service": e.get("target_service"),
                        "target_version": e.get("target_version"),
                        "status": e["status"],
                        "match_confidence": float(e["match_confidence"]) if e.get("match_confidence") else None,
                        "created_at": e["created_at"].isoformat() if e.get("created_at") else None,
                        "reviewed_at": e["reviewed_at"].isoformat() if e.get("reviewed_at") else None,
                    }
                    for e in exploits
                ],
                "total": len(exploits),
                "hint": "Use get_pending_exploit_details to see the full customized command before approving"
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "get_pending_exploit_details":
            from db_utils import get_pending_exploit

            exploit_id = arguments["exploit_id"]
            await send_log("INFO", f"Getting details for exploit: {exploit_id}", request_id)

            exploit = get_pending_exploit(exploit_id)

            if not exploit:
                return [TextContent(type="text", text=json.dumps({
                    "error": "Exploit not found",
                    "exploit_id": exploit_id
                }, indent=2))]

            result = {
                "id": str(exploit["id"]),
                "exploit_id": exploit["exploit_id"],
                "exploit_title": exploit["exploit_title"],
                "source": exploit["source"],
                "exploit_type": exploit.get("exploit_type"),
                "target_ip": str(exploit["target_ip"]),
                "target_port": exploit.get("target_port"),
                "target_service": exploit.get("target_service"),
                "target_version": exploit.get("target_version"),
                "customized_command": exploit["customized_command"],
                "parameters": exploit.get("parameters", {}),
                "match_confidence": float(exploit["match_confidence"]) if exploit.get("match_confidence") else None,
                "status": exploit["status"],
                "reviewed_by": exploit.get("reviewed_by"),
                "reviewed_at": exploit["reviewed_at"].isoformat() if exploit.get("reviewed_at") else None,
                "rejection_reason": exploit.get("rejection_reason"),
                "created_at": exploit["created_at"].isoformat() if exploit.get("created_at") else None,
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "approve_exploit":
            from db_utils import approve_exploit, get_pending_exploit

            exploit_id = arguments["exploit_id"]
            notes = arguments.get("notes", "")

            await send_log("INFO", f"Approving exploit: {exploit_id}", request_id)

            # First verify the exploit exists and is pending
            exploit = get_pending_exploit(exploit_id)
            if not exploit:
                return [TextContent(type="text", text=json.dumps({
                    "error": "Exploit not found",
                    "exploit_id": exploit_id
                }, indent=2))]

            if exploit["status"] != "pending":
                return [TextContent(type="text", text=json.dumps({
                    "error": f"Exploit cannot be approved - current status is '{exploit['status']}'",
                    "exploit_id": exploit_id,
                    "hint": "Only 'pending' exploits can be approved"
                }, indent=2))]

            # Approve the exploit
            success = approve_exploit(exploit_id, reviewed_by="mcp_user", notes=notes)

            if success:
                await send_log("INFO", f"Exploit approved: {exploit_id} - {exploit['exploit_title']}", request_id)
                result = {
                    "status": "approved",
                    "exploit_id": exploit_id,
                    "exploit_title": exploit["exploit_title"],
                    "target": f"{exploit['target_ip']}:{exploit.get('target_port', 'N/A')}",
                    "message": "Exploit approved. Use execute_approved_exploit to run it.",
                    "notes": notes
                }
            else:
                await send_log("ERROR", f"Failed to approve exploit: {exploit_id}", request_id)
                result = {
                    "error": "Failed to approve exploit",
                    "exploit_id": exploit_id
                }

            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "reject_exploit":
            from db_utils import reject_exploit, get_pending_exploit

            exploit_id = arguments["exploit_id"]
            reason = arguments["reason"]

            await send_log("INFO", f"Rejecting exploit: {exploit_id}, reason: {reason}", request_id)

            # First verify the exploit exists and is pending
            exploit = get_pending_exploit(exploit_id)
            if not exploit:
                return [TextContent(type="text", text=json.dumps({
                    "error": "Exploit not found",
                    "exploit_id": exploit_id
                }, indent=2))]

            if exploit["status"] != "pending":
                return [TextContent(type="text", text=json.dumps({
                    "error": f"Exploit cannot be rejected - current status is '{exploit['status']}'",
                    "exploit_id": exploit_id,
                    "hint": "Only 'pending' exploits can be rejected"
                }, indent=2))]

            # Reject the exploit
            success = reject_exploit(exploit_id, reviewed_by="mcp_user", reason=reason)

            if success:
                await send_log("INFO", f"Exploit rejected: {exploit_id} - {reason}", request_id)
                result = {
                    "status": "rejected",
                    "exploit_id": exploit_id,
                    "exploit_title": exploit["exploit_title"],
                    "reason": reason,
                    "message": "Exploit rejected and will not be executed."
                }
            else:
                await send_log("ERROR", f"Failed to reject exploit: {exploit_id}", request_id)
                result = {
                    "error": "Failed to reject exploit",
                    "exploit_id": exploit_id
                }

            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "execute_approved_exploit":
            from scan_tools import execute_approved_exploit

            exploit_id = arguments["exploit_id"]

            await send_log("INFO", f"Executing approved exploit: {exploit_id}", request_id)

            result = execute_approved_exploit(exploit_id)
            formatted_result = format_tool_response(result)

            # Log the result
            try:
                result_data = json.loads(result)
                if result_data.get("success"):
                    await send_log("INFO", f"Exploit executed successfully: {exploit_id}", request_id)
                elif "error" in result_data:
                    await send_log("ERROR", f"Exploit execution failed: {result_data.get('error')}", request_id)
            except json.JSONDecodeError:
                pass

            return [TextContent(type="text", text=formatted_result)]

        elif name == "get_exploit_result":
            from db_utils import get_exploit_result, get_pending_exploit

            exploit_id = arguments["exploit_id"]

            await send_log("INFO", f"Getting exploit result: {exploit_id}", request_id)

            # First get the pending exploit to check status
            exploit = get_pending_exploit(exploit_id)
            if not exploit:
                return [TextContent(type="text", text=json.dumps({
                    "error": "Exploit not found",
                    "exploit_id": exploit_id
                }, indent=2))]

            # Get execution result if it exists
            exec_result = get_exploit_result(exploit_id)

            if not exec_result:
                result = {
                    "exploit_id": exploit_id,
                    "exploit_title": exploit["exploit_title"],
                    "status": exploit["status"],
                    "message": f"No execution result found. Current status: {exploit['status']}",
                    "hint": "The exploit may not have been executed yet."
                }
            else:
                result = {
                    "exploit_id": exploit_id,
                    "exploit_title": exploit["exploit_title"],
                    "status": exploit["status"],
                    "execution_result": {
                        "success": exec_result["success"],
                        "output": exec_result.get("output"),
                        "session_type": exec_result.get("session_type"),
                        "executed_at": exec_result["executed_at"].isoformat() if exec_result.get("executed_at") else None,
                    }
                }

            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        # === Scanner Status Tools ===
        elif name == "get_nmap_job_status":
            job_id = arguments["job_id"]
            await send_log("INFO", f"Getting Nmap job status: {job_id}", request_id)

            try:
                async with httpx.AsyncClient(verify=False, timeout=MCP_TIMEOUT_STATUS) as client:
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
                    "hint": "Check if nmap_scanner container is running"
                }, indent=2))]

        elif name == "get_playwright_scan_status":
            scan_id = arguments["scan_id"]
            await send_log("INFO", f"Getting Playwright scan status: {scan_id}", request_id)

            try:
                async with httpx.AsyncClient(verify=False, timeout=MCP_TIMEOUT_STATUS) as client:
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
                    "hint": "Check if playwright-scanner container is running"
                }, indent=2))]

        elif name == "get_msf_status":
            await send_log("INFO", "Getting Metasploit status", request_id)

            result = {
                "jobs": [],
                "sessions": [],
                "healthy": False,
                "error": None
            }
            try:
                async with httpx.AsyncClient(verify=False, timeout=MCP_TIMEOUT_STATUS) as client:
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
                result["hint"] = "Check if exploit-runner container is running"
            except Exception as e:
                result["error"] = str(e)

            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "get_all_scanner_status":
            await send_log("INFO", "Getting all scanner status", request_id)

            services = {
                "nmap_scanner": {"url": f"{NMAP_URL}/health", "status": "unknown"},
                "playwright_scanner": {"url": f"{PLAYWRIGHT_URL}/health", "status": "unknown"},
                "web_scanner": {"url": f"{WEB_SCANNER_URL}/health", "status": "unknown"},
                "nuclei_runner": {"url": f"{NUCLEI_URL}/health", "status": "unknown"},
                "exploit_runner": {"url": f"{EXPLOIT_RUNNER_URL}/health", "status": "unknown"},
            }

            async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
                # Check each service in parallel
                async def check_service(svc_name: str, info: dict):
                    try:
                        resp = await client.get(info["url"])
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
                        info["error"] = "Connection refused"
                    except httpx.TimeoutException:
                        info["status"] = "timeout"
                        info["error"] = "Health check timed out"
                    except Exception as e:
                        info["status"] = "error"
                        info["error"] = str(e)

                # Run all health checks concurrently
                await asyncio.gather(*[
                    check_service(svc_name, info) for svc_name, info in services.items()
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

        elif name == "export_pentester_report":
            from report_generator import (
                db_get_tool_results,
                generate_pentester_markdown_report,
                generate_pentester_text_report
            )

            target = arguments.get("target")
            format_type = arguments.get("format", "markdown")
            status_filter = arguments.get("status")

            await send_log("INFO", f"Exporting pentester report (target={target}, format={format_type}, status={status_filter})", request_id)

            # Get results with raw output included
            results = db_get_tool_results(
                target=target,
                include_raw=True,
                status_filter=status_filter
            )

            if format_type == "text":
                report = generate_pentester_text_report(results, target)
            else:
                report = generate_pentester_markdown_report(results, target)

            await send_log("INFO", f"Generated pentester report with {len(results)} tool executions", request_id)

            return [TextContent(type="text", text=report)]

        else:
            error_msg = f"Unknown tool: {name}"
            logger.error(f"[MCP] {error_msg}")
            await send_log("WARNING", f"Unknown tool requested: {name}", request_id)
            return [TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]

    except Exception as e:
        # Log the exception with full details
        error_detail = {
            "error": f"{type(e).__name__}: {str(e)}",
            "tool": name,
            "arguments": arguments,
            "traceback": traceback.format_exc()
        }
        logger.error(f"[MCP] Tool execution failed: {json.dumps(error_detail, indent=2)}")
        await send_log("ERROR", f"Tool '{name}' failed: {type(e).__name__}: {str(e)}", request_id)

        # Return user-friendly error to Claude Desktop
        return [TextContent(type="text", text=json.dumps({
            "error": str(e),
            "tool": name,
            "hint": "Check logs at http://localhost:8015/logs/ui for details"
        }, indent=2))]


def start_logging_webserver():
    """
    Start the logging web server in a background thread
    This allows viewing logs at http://localhost:8015/logs/ui while using MCP
    """
    global _logging_server_started

    if _logging_server_started:
        return

    # Setup log capture (always needed for MCP logging)
    setup_log_capture()

    # Check if port 8015 is already in use (container is running FastAPI)
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("0.0.0.0", 8015))
        sock.close()
        port_available = True
    except OSError:
        port_available = False
        sock.close()

    if not port_available:
        # Port already in use - the container's FastAPI server is running
        print("✓ Logging web interface already running on port 8015", file=sys.stderr)
        print("✓ View logs at: http://localhost:8015/logs/ui", file=sys.stderr)
        _logging_server_started = True
        return

    # Port is available - start the web server in background thread
    # Use lazy import to avoid blocking MCP server initialization
    print("🔍 Starting logging web interface on port 8015...", file=sys.stderr)
    print("   View logs at: http://localhost:8015/logs/ui", file=sys.stderr)

    # Run server in a separate thread with lazy import
    def run_server():
        try:
            # Import heavy dependencies INSIDE the thread to avoid blocking
            from autogen_service import app

            # Configure uvicorn
            config = uvicorn.Config(
                app=app,
                host="0.0.0.0",
                port=8015,
                log_level="warning",
                access_log=False
            )
            server = uvicorn.Server(config)

            # Run the server
            asyncio.run(server.serve())
        except Exception as e:
            logger.error(f"Failed to start logging web server: {e}")

    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()

    _logging_server_started = True
    print("✓ Logging web interface starting in background", file=sys.stderr)
    print("✓ Diagnostic logs will be available at http://localhost:8015/logs/ui", file=sys.stderr)


async def run_mcp_server():
    """Run the MCP server with stdio transport"""
    # Setup log capture so MCP calls are logged
    # The FastAPI server provides the web UI, but we need to capture logs
    # in this process too since MCP runs as a separate process via docker exec
    # Use silent=True to avoid stderr output that could interfere with MCP protocol
    setup_log_capture(silent=True)

    # Note: Do NOT print to stderr here - it interferes with MCP stdio protocol
    # The health check is done lazily on first scan operation instead

    async with stdio_server() as (read_stream, write_stream):
        await mcp_server.run(
            read_stream,
            write_stream,
            mcp_server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(run_mcp_server())
