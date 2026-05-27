#!/usr/bin/env python3
"""
MCP Server for RAG Scan Stack Health Monitoring

This MCP server provides health check tools for Claude Desktop/Code by calling
the RAG API HTTP endpoints. It's a lightweight wrapper that exposes health check
functionality to AI assistants.

Architecture:
- MCP Server (this file) -> HTTP API (rag-api) -> Health Check Script

This approach is cleaner than running bash scripts directly and avoids permission issues.
"""

import asyncio
import json
import uuid
from typing import Any, Dict, Optional
import httpx
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Configuration
API_BASE_URL = "http://localhost:8000"
LOG_API_URL = "http://localhost:8015"  # autogen-agents for logging
REQUEST_TIMEOUT = 60.0  # Increased timeout for comprehensive health checks

# Create MCP server instance
app = Server("rag-scan-stack-health")


async def send_log(level: str, message: str, request_id: Optional[str] = None):
    """
    Send a log entry to the autogen-agents log viewer.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        message: Log message
        request_id: Optional request ID for correlation
    """
    try:
        async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
            await client.post(
                f"{LOG_API_URL}/logs/ingest",
                json={
                    "level": level,
                    "message": message,
                    "source": "mcp-health-check",
                    "request_id": request_id
                }
            )
    except Exception:
        # Don't let logging failures break the MCP server
        pass


async def call_health_api(endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Call the RAG API health check endpoint.

    Args:
        endpoint: API endpoint path (e.g., "/health/")
        params: Optional query parameters

    Returns:
        JSON response from the API

    Raises:
        httpx.HTTPError: If the API request fails
    """
    url = f"{API_BASE_URL}{endpoint}"

    async with httpx.AsyncClient(verify=False, timeout=REQUEST_TIMEOUT) as client:
        try:
            response = await client.get(url, params=params or {})
            response.raise_for_status()
            return response.json()
        except httpx.TimeoutException:
            return {
                "error": "timeout",
                "message": f"Health check timed out after {REQUEST_TIMEOUT} seconds",
                "endpoint": endpoint
            }
        except httpx.HTTPError as e:
            return {
                "error": "http_error",
                "message": str(e),
                "endpoint": endpoint,
                "status_code": getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None
            }
        except Exception as e:
            return {
                "error": "unknown",
                "message": str(e),
                "endpoint": endpoint
            }


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available MCP tools for health checking."""
    return [
        Tool(
            name="check_system_health",
            description="""
Perform a comprehensive health check of all RAG Scan Stack components.

This checks:
- Docker daemon and networking (3 checks)
- PostgreSQL connectivity and schema (3 checks)
- Ollama service and LLM models (1 check)
- All microservices - 8 services (rag-api, web-scanner, nuclei-runner, nmap-scanner,
  scan-recommender, playwright-scanner, autogen-agents, llm-query)
- Kong API Gateway (1 check)
- Scanning tools (4 checks: nmap, nuclei, gobuster, playwright)

Total: 19 automated checks

Returns detailed results with health score and operational readiness.
            """.strip(),
            inputSchema={
                "type": "object",
                "properties": {
                    "format": {
                        "type": "string",
                        "enum": ["json", "mcp"],
                        "default": "mcp",
                        "description": "Output format: 'json' for detailed output, 'mcp' for MCP-optimized format"
                    },
                    "verbose": {
                        "type": "boolean",
                        "default": False,
                        "description": "Include verbose output with additional details"
                    }
                }
            }
        ),
        Tool(
            name="check_database_schema",
            description="""
Verify the PostgreSQL database schema is complete and correct.

Checks:
- Database connectivity
- Expected table count (21 tables)
- Critical tables exist: assets, ports, web_findings, vulns,
  scan_recommendations, agent_sessions, agent_messages

Returns schema verification status with details about any missing tables.
            """.strip(),
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="check_service",
            description="""
Check the health status of an individual RAG Scan Stack service.

Supported services:
- web-scanner (port 8010) - Web vulnerability scanner with gobuster
- nuclei-runner (port 8011) - Nuclei template scanner
- nmap-scanner (port 8012) - Nmap port and service scanner
- scan-recommender (port 8013) - AI-powered scan recommendation engine
- playwright-scanner (port 8014) - Browser-based scanner
- autogen-agents (port 8015) - Autonomous pentesting agents
- llm-query (port 8002) - LLM query service
- kong (port 7080) - API Gateway
- rag-api (port 8000) - Main RAG API

Returns service availability status, URL, and health check result.
            """.strip(),
            inputSchema={
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Name of the service to check",
                        "enum": [
                            "web-scanner",
                            "nuclei-runner",
                            "nmap-scanner",
                            "scan-recommender",
                            "playwright-scanner",
                            "autogen-agents",
                            "llm-query",
                            "kong",
                            "rag-api"
                        ]
                    }
                },
                "required": ["service_name"]
            }
        ),
        Tool(
            name="list_running_containers",
            description="""
List all Docker containers in the RAG Scan Stack with their status.

Returns:
- Total container count
- Number of running containers
- Detailed information for each container:
  - Container name
  - Status (Up/Exited/etc)
  - Image name
  - Port mappings

Useful for verifying all required services are running and identifying any stopped containers.
            """.strip(),
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="quick_health_check",
            description="""
Perform a quick health check to verify the RAG API is responsive.

This is a fast, lightweight check that simply verifies the API is accessible.
Useful for:
- Quick uptime verification
- Load balancer health probes
- Rapid status checks

Returns OK status if the API is responsive.
            """.strip(),
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        Tool(
            name="check_ollama_status",
            description="""
Check Ollama LLM service status including GPU/CPU usage and loaded models.

Returns:
- Whether Ollama is using GPU or CPU
- Currently loaded models and their memory usage
- Available models
- Total VRAM/RAM being used

Useful for understanding LLM performance characteristics and troubleshooting.
            """.strip(),
            inputSchema={
                "type": "object",
                "properties": {}
            }
        )
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool execution requests from Claude."""

    # Generate request ID for log correlation
    request_id = f"mcp-{uuid.uuid4().hex[:8]}"

    try:
        # Log tool invocation
        await send_log("INFO", f"Tool '{name}' called with args: {json.dumps(arguments)}", request_id)

        if name == "check_system_health":
            # Get parameters
            format_type = arguments.get("format", "mcp")
            verbose = arguments.get("verbose", False)

            await send_log("INFO", "Starting comprehensive system health check", request_id)

            # Try comprehensive check first, fall back to individual checks if it fails
            result = await call_health_api(
                "/health/",
                params={"format": format_type, "verbose": str(verbose).lower()}
            )

            # Check for errors - if comprehensive check fails, use individual endpoints
            if "error" in result or result.get("detail"):
                # Comprehensive check not available, check individual services
                services_to_check = [
                    ("rag-api", 8000), ("web-scanner", 8010), ("nuclei-runner", 8011),
                    ("nmap-scanner", 8012), ("scan-recommender", 8013),
                    ("playwright-scanner", 8014), ("autogen-agents", 8015),
                    ("llm-query", 8002), ("kong", 7080)
                ]

                # Check database
                db_result = await call_health_api("/health/database")
                db_healthy = db_result.get("status") == "healthy" and "error" not in db_result

                # Check services
                healthy = 1 if db_healthy else 0
                total = 1 + len(services_to_check)
                service_status = []

                for svc_name, port in services_to_check:
                    svc_result = await call_health_api(f"/health/service/{svc_name}")
                    is_healthy = svc_result.get("available") and "error" not in svc_result
                    if is_healthy:
                        healthy += 1
                    icon = "✅" if is_healthy else "❌"
                    service_status.append(f"{icon} {svc_name} (port {port})")

                health_pct = int((healthy / total) * 100)
                status = "HEALTHY" if health_pct >= 90 else "DEGRADED" if health_pct >= 70 else "UNHEALTHY"

                response = f"""## RAG Scan Stack Health Check

**Status**: {status}
**Health Score**: {health_pct}%

### Summary
- Total: {total} components
- Healthy: ✅ {healthy}
- Unhealthy: ❌ {total - healthy}

### Database
{"✅" if db_healthy else "❌"} PostgreSQL ({db_result.get('table_count', 0)}/{db_result.get('expected_tables', 21)} tables)

### Services
{chr(10).join(service_status)}

{'✅ System ready for operations' if health_pct >= 80 else '❌ System NOT ready'}
"""
                await send_log("INFO", f"Health check complete (fallback): {status} - {health_pct}% ({healthy}/{total} healthy)", request_id)
                return [TextContent(type="text", text=response)]

            # Format successful response
            summary = result.get("summary", {})
            status = result.get("status", "unknown")

            # Build response text
            response = f"""## RAG Scan Stack Health Check

**Status**: {status.upper()}
**Health Score**: {summary.get('health_percentage', 0)}%

### Summary
- Total Checks: {summary.get('total', 0)}
- Passed: ✅ {summary.get('passed', 0)}
- Failed: ❌ {summary.get('failed', 0)}
- Warnings: ⚠️  {summary.get('warnings', 0)}

### System Readiness
{'✅ System is ready for scanning operations' if result.get('ready_for_operations') else '❌ System is NOT ready - failures detected'}

"""

            # Add failed checks if any
            checks = result.get("checks", [])
            failed_checks = [c for c in checks if c.get("status") == "fail"]
            if failed_checks:
                response += "\n### Failed Checks\n"
                for check in failed_checks:
                    response += f"- ❌ **{check.get('check')}**: {check.get('message')}\n"
                    if check.get('details'):
                        response += f"  Details: {check.get('details')}\n"

            # Add access points
            access_points = result.get("access_points", {})
            if access_points:
                response += "\n### Access Points\n"
                for name, url in access_points.items():
                    response += f"- {name.replace('_', ' ').title()}: {url}\n"

            # Add verbose output if requested
            if verbose and checks:
                response += "\n### All Checks\n"
                for check in checks:
                    status_icon = "✅" if check.get("status") == "pass" else "❌" if check.get("status") == "fail" else "⚠️"
                    response += f"{status_icon} **{check.get('check')}**: {check.get('message')}\n"

            await send_log("INFO", f"Health check complete: {status.upper()} - {summary.get('health_percentage', 0)}% ({summary.get('passed', 0)}/{summary.get('total', 0)} passed)", request_id)
            return [TextContent(type="text", text=response)]

        elif name == "check_database_schema":
            await send_log("INFO", "Checking database schema", request_id)
            result = await call_health_api("/health/database")

            if "error" in result:
                return [TextContent(
                    type="text",
                    text=f"❌ Database check failed: {result['message']}"
                )]

            status = result.get("status", "unknown")
            response = f"""## Database Schema Check

**Status**: {status.upper()}

### Table Counts
- Current: {result.get('table_count', 0)} tables
- Expected: {result.get('expected_tables', 21)} tables

### Critical Tables
{'✅ All critical tables present' if result.get('critical_tables_present') else '❌ Some critical tables missing'}
"""

            missing = result.get("missing_tables", [])
            if missing:
                response += f"\n### Missing Tables\n"
                for table in missing:
                    response += f"- ❌ {table}\n"

            await send_log("INFO", f"Database schema check: {status.upper()} - {result.get('table_count', 0)}/{result.get('expected_tables', 21)} tables", request_id)
            return [TextContent(type="text", text=response)]

        elif name == "check_service":
            service_name = arguments.get("service_name")
            await send_log("INFO", f"Checking service: {service_name}", request_id)
            if not service_name:
                return [TextContent(
                    type="text",
                    text="❌ Error: service_name is required"
                )]

            result = await call_health_api(f"/health/service/{service_name}")

            if "error" in result:
                return [TextContent(
                    type="text",
                    text=f"❌ Service check failed: {result['message']}"
                )]

            status_icon = "✅" if result.get("available") else "❌"
            response = f"""## Service Health: {service_name}

{status_icon} **Status**: {result.get('status', 'unknown').upper()}
**Available**: {'Yes' if result.get('available') else 'No'}
**URL**: {result.get('url')}
**Message**: {result.get('message')}
"""

            await send_log("INFO", f"Service check '{service_name}': {'available' if result.get('available') else 'unavailable'}", request_id)
            return [TextContent(type="text", text=response)]

        elif name == "list_running_containers":
            await send_log("INFO", "Listing Docker containers", request_id)
            result = await call_health_api("/health/containers")

            if "error" in result:
                return [TextContent(
                    type="text",
                    text=f"❌ Container list failed: {result['message']}"
                )]

            response = f"""## Docker Containers

**Total**: {result.get('total', 0)} containers
**Running**: {result.get('running', 0)} containers

### Container Details
"""

            containers = result.get("containers", [])
            for container in containers:
                status = container.get("status", "Unknown")
                is_running = status.startswith("Up")
                status_icon = "✅" if is_running else "❌"

                response += f"\n{status_icon} **{container.get('name')}**\n"
                response += f"  - Status: {status}\n"
                response += f"  - Image: {container.get('image')}\n"

                ports = container.get("ports")
                if ports:
                    response += f"  - Ports: {', '.join(ports)}\n"

            await send_log("INFO", f"Container list: {result.get('running', 0)}/{result.get('total', 0)} running", request_id)
            return [TextContent(type="text", text=response)]

        elif name == "quick_health_check":
            await send_log("INFO", "Running quick health check", request_id)
            result = await call_health_api("/health/quick")

            if "error" in result:
                return [TextContent(
                    type="text",
                    text=f"❌ Quick health check failed: {result['message']}"
                )]

            status = result.get("status", "unknown")
            if status == "ok":
                await send_log("INFO", "Quick health check: OK", request_id)
                return [TextContent(
                    type="text",
                    text=f"✅ RAG API is healthy and responsive\n\nService: {result.get('service')}\nTimestamp: {result.get('timestamp')}"
                )]
            else:
                await send_log("WARNING", f"Quick health check: status={status}", request_id)
                return [TextContent(
                    type="text",
                    text=f"⚠️  RAG API responded but status is: {status}"
                )]

        elif name == "check_ollama_status":
            await send_log("INFO", "Checking Ollama status", request_id)

            ollama_url = "http://localhost:11434"

            try:
                async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                    # Get running models (shows GPU/CPU usage)
                    ps_response = await client.get(f"{ollama_url}/api/ps")
                    ps_data = ps_response.json() if ps_response.status_code == 200 else {"models": []}

                    # Get available models
                    tags_response = await client.get(f"{ollama_url}/api/tags")
                    tags_data = tags_response.json() if tags_response.status_code == 200 else {"models": []}

                running_models = ps_data.get("models", [])
                available_models = tags_data.get("models", [])

                # Determine if using GPU or CPU
                processor_type = "CPU (System Memory)"
                total_size = 0
                gpu_layers = 0

                for model in running_models:
                    size_vram = model.get("size_vram", 0)
                    size = model.get("size", 0)
                    total_size += size
                    if size_vram and size_vram > 0:
                        processor_type = "GPU (VRAM)"
                        gpu_layers += model.get("details", {}).get("gpu_layers", 0)

                # Format sizes
                def format_size(bytes_size):
                    if bytes_size >= 1024**3:
                        return f"{bytes_size / (1024**3):.1f} GB"
                    elif bytes_size >= 1024**2:
                        return f"{bytes_size / (1024**2):.1f} MB"
                    return f"{bytes_size} bytes"

                response = f"""## Ollama LLM Status

**Processor**: {processor_type}
**Running Models**: {len(running_models)}
**Available Models**: {len(available_models)}

### Currently Loaded Models
"""

                if running_models:
                    for model in running_models:
                        name = model.get("name", "unknown")
                        size = model.get("size", 0)
                        size_vram = model.get("size_vram", 0)
                        processor = "GPU" if size_vram and size_vram > 0 else "CPU"
                        expires = model.get("expires_at", "N/A")

                        response += f"""
**{name}**
- Memory: {format_size(size)}
- VRAM: {format_size(size_vram) if size_vram else "N/A"}
- Processor: {processor}
"""
                else:
                    response += "\n*No models currently loaded in memory*\n"

                response += "\n### Available Models\n"
                for model in available_models[:10]:  # Limit to 10
                    name = model.get("name", "unknown")
                    size = model.get("size", 0)
                    params = model.get("details", {}).get("parameter_size", "N/A")
                    quant = model.get("details", {}).get("quantization_level", "N/A")
                    response += f"- **{name}** ({params}, {quant}) - {format_size(size)}\n"

                if len(available_models) > 10:
                    response += f"\n*...and {len(available_models) - 10} more models*\n"

                # Add GPU status note
                if processor_type == "CPU (System Memory)":
                    response += """
### GPU Status
⚠️  **Ollama is running on CPU** - No GPU acceleration detected.

To enable GPU:
1. Install NVIDIA Container Toolkit
2. Ensure WSL2 GPU passthrough is configured (Windows)
3. Restart Docker with GPU support
"""

                await send_log("INFO", f"Ollama status: {processor_type}, {len(running_models)} loaded, {len(available_models)} available", request_id)
                return [TextContent(type="text", text=response)]

            except httpx.ConnectError:
                await send_log("ERROR", "Cannot connect to Ollama", request_id)
                return [TextContent(
                    type="text",
                    text="❌ Cannot connect to Ollama at http://localhost:11434\n\nIs Ollama running? Try: `docker compose up -d ollama`"
                )]
            except Exception as e:
                await send_log("ERROR", f"Ollama check failed: {str(e)}", request_id)
                return [TextContent(
                    type="text",
                    text=f"❌ Error checking Ollama: {str(e)}"
                )]

        else:
            await send_log("WARNING", f"Unknown tool requested: {name}", request_id)
            return [TextContent(
                type="text",
                text=f"❌ Unknown tool: {name}"
            )]

    except Exception as e:
        await send_log("ERROR", f"Tool '{name}' failed with exception: {str(e)}", request_id)
        return [TextContent(
            type="text",
            text=f"❌ Error executing tool '{name}': {str(e)}"
        )]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
