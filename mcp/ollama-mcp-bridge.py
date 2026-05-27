#!/usr/bin/env python3
"""
Direct Ollama <-> MCP Bridge

Bypasses Continue and properly passes MCP tools to Ollama.
Use this when Continue is your frontend (it doesn't pass tools to Ollama).
Skip this if using Claude Desktop (it handles MCP tools natively).

Run: python3 ollama-mcp-bridge.py
"""

import json
import httpx
import asyncio
from datetime import datetime

# Configuration
OLLAMA_URL = "http://localhost:11434"
MODEL = "hermes3:8b"
API_KEY = "changeme"  # For rag-api authentication

# API endpoints
API_URL = "http://localhost:8015"          # autogen-agents
RAG_API_URL = "http://localhost:8000"       # rag-api
NMAP_URL = "http://localhost:8012"          # nmap-scanner
NUCLEI_URL = "http://localhost:8011"        # nuclei-runner
WEB_SCANNER_URL = "http://localhost:8010"   # web-scanner
PLAYWRIGHT_URL = "http://localhost:8014"    # playwright-scanner
SCAN_RECOMMENDER_URL = "http://localhost:8013"  # scan-recommender

# MCP tool definitions in Ollama format
MCP_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "check_health",
            "description": "Check autogen-agents service health",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_all_scanner_status",
            "description": "Get status of all scanner services",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "query_assets",
            "description": "List discovered hosts/assets from scans",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip_filter": {"type": "string", "description": "Filter by IP pattern"},
                    "limit": {"type": "integer", "default": 100}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "query_open_ports",
            "description": "List discovered open ports and services",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "Filter by IP"},
                    "port": {"type": "integer", "description": "Filter by port"},
                    "service": {"type": "string", "description": "Filter by service name"},
                    "limit": {"type": "integer", "default": 100}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "query_findings",
            "description": "List vulnerability findings from scanners",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "ip": {"type": "string", "description": "Filter by IP"},
                    "limit": {"type": "integer", "default": 100}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_exploits",
            "description": "Search exploit database using semantic search (RAG)",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query (e.g., 'SMB remote code execution')"},
                    "limit": {"type": "integer", "default": 10}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "start_nmap_scan",
            "description": "Start an Nmap port scan against a target",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP, hostname, or CIDR range"},
                    "ports": {"type": "string", "description": "Port range", "default": "1-1000"},
                    "scan_type": {"type": "string", "enum": ["quick", "full", "service"], "default": "service"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "start_nuclei_scan",
            "description": "Start a Nuclei vulnerability scan",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or IP"},
                    "severity": {"type": "string", "default": "medium"}
                },
                "required": ["target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "start_web_scan",
            "description": "Start web directory enumeration scan using Gobuster",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Target URL"},
                    "wordlist": {"type": "string", "enum": ["common", "medium", "big"], "default": "common"}
                },
                "required": ["target_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "start_playwright_scan",
            "description": "Start a Playwright browser-based security scan",
            "parameters": {
                "type": "object",
                "properties": {
                    "target_url": {"type": "string", "description": "Target URL"},
                    "browser": {"type": "string", "enum": ["chromium", "firefox", "webkit"], "default": "chromium"}
                },
                "required": ["target_url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "start_pentest_session",
            "description": "Start an autonomous AI-powered penetration testing session",
            "parameters": {
                "type": "object",
                "properties": {
                    "session_name": {"type": "string", "description": "Human-readable session name"},
                    "target_description": {"type": "string", "description": "Description of target"},
                    "initial_task": {"type": "string", "description": "Initial task for agents"},
                    "max_rounds": {"type": "integer", "default": 200}
                },
                "required": ["session_name", "target_description", "initial_task"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_sessions",
            "description": "List all pentest sessions",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "enum": ["active", "completed", "failed", "stopped"]},
                    "limit": {"type": "integer", "default": 50}
                }
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_session_status",
            "description": "Get status of a specific pentest session",
            "parameters": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string", "description": "Session UUID"}
                },
                "required": ["session_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_msf_status",
            "description": "Get Metasploit framework status including active jobs and sessions",
            "parameters": {"type": "object", "properties": {}}
        }
    }
]


async def execute_tool(name: str, arguments: dict) -> str:
    """Execute a tool and return the result"""
    headers = {"x-api-key": API_KEY}

    async with httpx.AsyncClient(verify=False, timeout=60) as client:
        try:
            # === Health & Status ===
            if name == "check_health":
                resp = await client.get(f"{API_URL}/health")

            elif name == "get_all_scanner_status":
                # Check multiple services
                services = {}
                for svc, url in [
                    ("nmap", f"{NMAP_URL}/health"),
                    ("nuclei", f"{NUCLEI_URL}/health"),
                    ("web_scanner", f"{WEB_SCANNER_URL}/health"),
                    ("playwright", f"{PLAYWRIGHT_URL}/health"),
                ]:
                    try:
                        r = await client.get(url, timeout=5)
                        services[svc] = "healthy" if r.status_code == 200 else "unhealthy"
                    except:
                        services[svc] = "unreachable"
                return json.dumps({"services": services})

            # === Query Tools (use rag-api with API key) ===
            elif name == "query_assets":
                params = {"limit": arguments.get("limit", 100)}
                if "ip_filter" in arguments:
                    params["ip"] = arguments["ip_filter"]
                resp = await client.get(f"{RAG_API_URL}/assets", params=params, headers=headers)

            elif name == "query_open_ports":
                params = {"limit": arguments.get("limit", 100)}
                for key in ["ip", "port", "service"]:
                    if key in arguments:
                        params[key] = arguments[key]
                resp = await client.get(f"{RAG_API_URL}/ports/open", params=params, headers=headers)

            elif name == "query_findings":
                params = {"limit": arguments.get("limit", 100)}
                for key in ["severity", "ip"]:
                    if key in arguments:
                        params[key] = arguments[key]
                resp = await client.get(f"{RAG_API_URL}/vulns", params=params, headers=headers)

            elif name == "search_exploits":
                resp = await client.post(
                    f"{SCAN_RECOMMENDER_URL}/rag/ask",
                    json={"question": arguments["query"], "top_k": arguments.get("limit", 10)}
                )

            # === Scanning Tools ===
            elif name == "start_nmap_scan":
                resp = await client.post(f"{NMAP_URL}/jobs/masscan-then-nmap", json={
                    "target": arguments["target"],
                    "ports": arguments.get("ports", "1-1000"),
                    "nmap_options": "-sV" if arguments.get("scan_type") == "service" else "-sT"
                })

            elif name == "start_nuclei_scan":
                resp = await client.post(f"{NUCLEI_URL}/scan", json={
                    "target": arguments["target"],
                    "severity": arguments.get("severity", "medium")
                })

            elif name == "start_web_scan":
                resp = await client.post(f"{WEB_SCANNER_URL}/scan", json={
                    "url": arguments["target_url"],
                    "wordlist": arguments.get("wordlist", "common")
                })

            elif name == "start_playwright_scan":
                resp = await client.post(f"{PLAYWRIGHT_URL}/scan", json={
                    "url": arguments["target_url"],
                    "browser": arguments.get("browser", "chromium")
                })

            # === Pentest Sessions ===
            elif name == "start_pentest_session":
                resp = await client.post(f"{API_URL}/pentest", json={
                    "session_name": arguments["session_name"],
                    "target_description": arguments["target_description"],
                    "initial_task": arguments["initial_task"],
                    "max_rounds": arguments.get("max_rounds", 200)
                })

            elif name == "list_sessions":
                params = {"limit": arguments.get("limit", 50)}
                if "status" in arguments:
                    params["status"] = arguments["status"]
                resp = await client.get(f"{API_URL}/pentest/sessions", params=params)

            elif name == "get_session_status":
                resp = await client.get(f"{API_URL}/pentest/{arguments['session_id']}")

            elif name == "get_msf_status":
                result = {"jobs": [], "sessions": []}
                try:
                    jobs = await client.get(f"{API_URL}/msf/jobs")
                    if jobs.status_code == 200:
                        result["jobs"] = jobs.json().get("jobs", [])
                except:
                    pass
                return json.dumps(result)

            else:
                return json.dumps({"error": f"Unknown tool: {name}"})

            return resp.text if resp.status_code == 200 else json.dumps({"error": resp.text})

        except Exception as e:
            return json.dumps({"error": str(e)})


async def chat(user_message: str, history: list) -> str:
    """Send message to Ollama with tools and handle tool calls"""

    messages = [
        {
            "role": "system",
            "content": """You are a SECURITY SCANNER OPERATOR with direct access to penetration testing tools.

RULES:
1. ALWAYS USE TOOLS - Never explain how to run commands manually
2. ONLY REPORT ACTUAL RESULTS - Never fabricate scan data
3. ACT IMMEDIATELY - Don't ask for confirmation, execute the tool

TOOL MAPPING:
- Health/status checks -> check_health, get_all_scanner_status
- Port scanning -> start_nmap_scan
- Vulnerability scanning -> start_nuclei_scan
- Web enumeration -> start_web_scan
- Browser testing -> start_playwright_scan
- Query results -> query_assets, query_open_ports, query_findings
- Exploit search -> search_exploits
- AI pentest -> start_pentest_session, list_sessions

After receiving tool results, provide a concise summary."""
        }
    ] + history + [
        {"role": "user", "content": user_message}
    ]

    async with httpx.AsyncClient(verify=False, timeout=120) as client:
        start_time = asyncio.get_event_loop().time()
        resp = await client.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": MODEL,
                "messages": messages,
                "tools": MCP_TOOLS,
                "stream": False
            }
        )
        elapsed = asyncio.get_event_loop().time() - start_time

        result = resp.json()
        assistant_message = result.get("message", {})

        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Response ({elapsed:.2f}s)")

        tool_calls = assistant_message.get("tool_calls", [])

        if tool_calls:
            print(f"Tool calls: {len(tool_calls)}")

            tool_results = []
            for tc in tool_calls:
                func = tc.get("function", {})
                tool_name = func.get("name")
                tool_args = func.get("arguments", {})

                if isinstance(tool_args, str):
                    try:
                        tool_args = json.loads(tool_args)
                    except:
                        tool_args = {}

                print(f"  -> {tool_name}({json.dumps(tool_args)})")

                tool_result = await execute_tool(tool_name, tool_args)
                tool_results.append({
                    "tool": tool_name,
                    "result": tool_result[:1000]
                })

                print(f"  <- {tool_result[:200]}...")

            # Send results back to model
            messages.append(assistant_message)
            messages.append({
                "role": "tool",
                "content": json.dumps(tool_results)
            })

            resp2 = await client.post(
                f"{OLLAMA_URL}/api/chat",
                json={"model": MODEL, "messages": messages, "stream": False}
            )
            final = resp2.json()
            return final.get("message", {}).get("content", "No response")

        else:
            content = assistant_message.get("content", "No response")
            print(f"No tool calls. Direct response.")
            return content


async def main():
    print("=" * 60)
    print("Ollama MCP Bridge - Direct Tool Access")
    print("=" * 60)
    print(f"Model: {MODEL}")
    print(f"Tools: {len(MCP_TOOLS)} available")
    print("-" * 60)
    print("Examples:")
    print("  - check health")
    print("  - scan 192.168.1.150")
    print("  - query open ports")
    print("  - find exploits for SMB")
    print("  - list sessions")
    print("  - quit")
    print("=" * 60)

    history = []

    while True:
        try:
            user_input = input("\n> ").strip()
            if not user_input:
                continue
            if user_input.lower() in ["quit", "exit", "q"]:
                break

            response = await chat(user_input, history)
            print(f"\n{response}")

            history.append({"role": "user", "content": user_input})
            history.append({"role": "assistant", "content": response})

            if len(history) > 10:
                history = history[-10:]

        except (KeyboardInterrupt, EOFError):
            break
        except Exception as e:
            print(f"Error: {e}")

    print("\nGoodbye!")


if __name__ == "__main__":
    asyncio.run(main())
