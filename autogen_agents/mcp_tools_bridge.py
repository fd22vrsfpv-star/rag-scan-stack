"""
MCP Tools Bridge for Autogen Agents.

Dynamically discovers tools from MCP servers (built-in + third-party)
and registers them as callable functions in the autogen agent chat.

This bridges the MCP ecosystem with the autogen multi-agent system,
so any tool added via Settings → MCP Servers becomes available
in the built-in agent chat.
"""

import asyncio
import json
import logging
import os
from typing import Any, Callable, Dict, List, Optional

import httpx

log = logging.getLogger("mcp-bridge")

# MCP servers to discover tools from (name, port)
# Built-in servers are always checked; third-party loaded from registry
BUILTIN_MCP_SERVERS = [
    ("sessions", 9016),
    ("scanning", 9017),
    ("recon", 9018),
    ("exploit", 9019),
    ("credentials", 9020),
    ("pipelines", 9021),
    ("burp", 9022),
    ("zap", 9023),
]

# Tools already registered natively in scan_tools.py — skip these to avoid conflicts
NATIVE_TOOL_NAMES = {
    # Query tools
    "query_assets", "query_open_ports", "query_vulnerabilities", "query_exploitdb",
    "get_scan_recommendations", "get_web_findings", "query_credential_findings",
    "search_all_findings",
    # Scan tools
    "start_full_scan", "start_deep_port_scan", "start_pipeline_scan",
    "start_smb_vuln_scan", "start_credential_check", "start_masscan",
    "start_nmap_scan", "start_udp_scan", "start_web_scan", "start_nuclei_scan",
    "start_playwright_scan", "start_nikto_scan",
    # Job status
    "get_nmap_job_status", "get_web_scan_job_status", "get_nuclei_job_status",
    "get_playwright_job_status", "wait_for_job_completion", "get_all_active_jobs",
    "get_session_scan_status", "get_pd_job_status", "get_brutus_job_status",
    "get_osint_job_status",
    # PD tools
    "start_httpx_probe", "start_naabu", "start_katana",
    # Brutus
    "start_brutus",
    # OSINT
    "start_subfinder", "start_dnsx", "start_asnmap", "start_uncover",
    "start_cloudlist", "start_passive_recon", "get_passive_recon_plan",
    # Exploit tools
    "match_vuln_to_exploits", "search_msf_modules", "customize_exploit",
    "queue_exploit_for_approval", "get_exploit_approval_status",
    "list_pending_exploits", "execute_approved_exploit",
}

# Map tool name patterns to agent roles for smart registration
AGENT_ROLE_PATTERNS = {
    "scanner": ["start_", "launch_", "run_", "scan_"],
    "reconnaissance": ["recon_", "discover_", "enumerate_", "spider_"],
    "analyzer": ["search_", "query_", "get_", "list_", "check_"],
    "exploit": ["exploit_", "msf_", "payload_", "shell_"],
}

MCP_HOST = os.environ.get("MCP_STREAMABLE_HOST", "mcp-streamable")


class MCPToolDefinition:
    """Parsed MCP tool definition."""

    def __init__(self, name: str, description: str, parameters: dict, server_name: str, port: int):
        self.name = name
        self.description = description
        self.parameters = parameters  # JSON Schema
        self.server_name = server_name
        self.port = port

    def __repr__(self):
        return f"<MCPTool {self.server_name}:{self.name}>"


def _parse_mcp_response(resp) -> dict:
    """Parse MCP response — handles both plain JSON and SSE (text/event-stream)."""
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        # Parse SSE: find lines starting with "data: "
        for line in resp.text.split("\n"):
            line = line.strip()
            if line.startswith("data: "):
                try:
                    return json.loads(line[6:])
                except json.JSONDecodeError:
                    continue
        return {}
    else:
        try:
            return resp.json()
        except Exception:
            return {}


def _discover_tools_sync(servers: List[tuple]) -> List[MCPToolDefinition]:
    """Synchronously discover tools from MCP servers."""
    tools = []
    for server_name, port in servers:
        try:
            resp = httpx.post(
                f"https://{MCP_HOST}:{port}/mcp",
                json={
                    "jsonrpc": "2.0", "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "clientInfo": {"name": "autogen-bridge", "version": "1.0"},
                    },
                },
                headers={"Accept": "application/json, text/event-stream"},
                timeout=5,
            )
            if resp.status_code != 200:
                continue

            # List tools
            resp2 = httpx.post(
                f"https://{MCP_HOST}:{port}/mcp",
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                headers={"Accept": "application/json, text/event-stream"},
                timeout=5,
            )
            if resp2.status_code != 200:
                continue

            data = _parse_mcp_response(resp2)
            result = data.get("result", data)
            for tool in result.get("tools", []):
                tools.append(MCPToolDefinition(
                    name=tool["name"],
                    description=tool.get("description", "").split("\n")[0].strip()[:300],
                    parameters=tool.get("inputSchema", {}),
                    server_name=server_name,
                    port=port,
                ))
            log.info(f"Discovered {len(result.get('tools', []))} tools from {server_name} (port {port})")
        except Exception as e:
            log.debug(f"Failed to discover tools from {server_name}:{port}: {e}")
    return tools


def _get_third_party_servers() -> List[tuple]:
    """Load enabled third-party servers from registry."""
    try:
        import yaml
    except ImportError:
        return []
    registry_path = os.environ.get("MCP_REGISTRY_PATH", "/app/third_party/registry.yaml")
    if not os.path.exists(registry_path):
        return []
    try:
        with open(registry_path) as f:
            data = yaml.safe_load(f) or {}
        servers = data.get("servers") or []
        return [(s["name"], s.get("port", 9030)) for s in servers if s.get("enabled", False)]
    except Exception:
        return []


def _create_tool_function(tool_def: MCPToolDefinition) -> Callable:
    """Create an autogen-compatible wrapper function for an MCP tool."""
    port = tool_def.port
    tool_name = tool_def.name

    def mcp_tool_wrapper(**kwargs) -> str:
        """Dynamically generated MCP tool caller."""
        try:
            resp = httpx.post(
                f"https://{MCP_HOST}:{port}/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": tool_name, "arguments": kwargs},
                },
                headers={"Accept": "application/json, text/event-stream"},
                timeout=120,
            )
            if resp.status_code != 200:
                return json.dumps({"error": f"MCP call failed: HTTP {resp.status_code}"})
            data = _parse_mcp_response(resp)
            if "error" in data:
                return json.dumps({"error": data["error"]})
            result = data.get("result", data)
            # Extract text content from MCP response format
            content = result.get("content", [])
            if isinstance(content, list) and len(content) > 0:
                texts = [c.get("text", "") for c in content if c.get("type") == "text"]
                if texts:
                    return "\n".join(texts)
            return json.dumps(result, indent=2)
        except httpx.TimeoutException:
            return json.dumps({"error": f"MCP tool {tool_name} timed out after 120s"})
        except Exception as e:
            return json.dumps({"error": f"MCP tool {tool_name} failed: {str(e)}"})

    # Set function metadata for autogen
    mcp_tool_wrapper.__name__ = tool_name
    mcp_tool_wrapper.__doc__ = tool_def.description
    return mcp_tool_wrapper


def _classify_tool_role(tool_name: str, description: str) -> str:
    """Determine which agent should have access to a tool."""
    name_lower = tool_name.lower()
    desc_lower = description.lower()

    for role, prefixes in AGENT_ROLE_PATTERNS.items():
        for prefix in prefixes:
            if name_lower.startswith(prefix):
                return role

    # Fallback heuristics from description
    if any(w in desc_lower for w in ["scan", "launch", "spider", "crawl"]):
        return "scanner"
    if any(w in desc_lower for w in ["search", "query", "find", "list", "get", "check"]):
        return "analyzer"
    if any(w in desc_lower for w in ["exploit", "payload", "shell", "inject"]):
        return "exploit"
    if any(w in desc_lower for w in ["recon", "discover", "enumerate", "osint"]):
        return "reconnaissance"

    return "scanner"  # Default


def discover_and_register_mcp_tools(team) -> Dict[str, int]:
    """
    Discover all MCP tools and register them on the appropriate autogen agents.

    Args:
        team: PentestTeam instance with .scanner, .analyzer, .exploit, .reconnaissance, .executor

    Returns:
        Dict with counts per server: {"scanning": 5, "mcp-everything": 12, ...}
    """
    # Gather all servers (built-in + third-party)
    all_servers = list(BUILTIN_MCP_SERVERS)
    third_party = _get_third_party_servers()
    all_servers.extend(third_party)

    # Discover tools
    all_tools = _discover_tools_sync(all_servers)
    log.info(f"Total MCP tools discovered: {len(all_tools)}")

    # Filter out tools that already exist natively
    new_tools = [t for t in all_tools if t.name not in NATIVE_TOOL_NAMES]
    log.info(f"New MCP tools to register (excluding {len(all_tools) - len(new_tools)} native duplicates): {len(new_tools)}")

    # Agent map
    agent_map = {
        "scanner": team.scanner,
        "reconnaissance": team.reconnaissance,
        "analyzer": team.analyzer,
        "exploit": team.exploit,
    }

    counts: Dict[str, int] = {}
    registered_names = set()

    for tool_def in new_tools:
        # Skip duplicates (same tool from multiple servers)
        if tool_def.name in registered_names:
            continue

        func = _create_tool_function(tool_def)
        role = _classify_tool_role(tool_def.name, tool_def.description)
        agent = agent_map.get(role, team.scanner)

        try:
            # Register for LLM (tool shows up in agent's available tools)
            agent.register_for_llm(
                name=tool_def.name,
                description=f"[MCP:{tool_def.server_name}] {tool_def.description}"[:500],
            )(func)

            # Register for execution (executor can run it)
            team.executor.register_for_execution(name=tool_def.name)(func)

            registered_names.add(tool_def.name)
            counts[tool_def.server_name] = counts.get(tool_def.server_name, 0) + 1
            log.debug(f"Registered MCP tool: {tool_def.name} → {role} agent (from {tool_def.server_name})")
        except Exception as e:
            log.warning(f"Failed to register MCP tool {tool_def.name}: {e}")

    log.info(f"Registered {len(registered_names)} MCP tools: {counts}")
    return counts
