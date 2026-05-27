# RAG Scan Stack - MCP Health Check Server

This directory contains the MCP (Model Context Protocol) server for the RAG Scan Stack health monitoring system.

## Overview

The MCP Health Check Server exposes system health monitoring tools that can be used by Claude Desktop, Claude Code, or other MCP-compatible clients to check the status and readiness of all scanning services.

## Architecture

The MCP server is a lightweight wrapper around the RAG API HTTP endpoints:

```
Claude Desktop/Code → MCP Server → HTTP API (port 8000) → Health Check Scripts → Docker/Services
```

**Benefits of this architecture:**
- ✅ No file permission issues (no direct script execution)
- ✅ Consistent interface across different access methods (MCP, HTTP, CLI)
- ✅ Better error handling and logging
- ✅ Easier deployment and maintenance
- ✅ Works even when running in restricted environments

## Features

### Available Tools

1. **check_system_health**
   - Comprehensive health check of all services
   - Checks Docker containers, databases, Ollama models, and scanning tools
   - Returns structured health report with pass/fail/warning status
   - Supports multiple output formats (text, JSON, MCP)

2. **check_database_schema**
   - Verifies all 21 required database tables exist
   - Ensures database schema is up-to-date
   - Provides detailed table status

3. **check_service**
   - Check health of individual services
   - Tests specific service endpoints
   - Useful for troubleshooting

4. **list_running_containers**
   - Lists all Docker containers in the stack
   - Shows current status and health
   - Quick overview of running services

## Installation

### Prerequisites

**System Requirements:**
- RAG Scan Stack running with Docker Compose
- RAG API accessible at `http://localhost:8000`
- Python 3.10 or later

**Python Dependencies:**
```bash
# Install MCP SDK and httpx
pip install mcp httpx

# Or use requirements.txt
cd /opt/rag-scan-stack/mcp
pip install -r requirements.txt
```

### Claude Desktop Configuration

Add this to your Claude Desktop configuration:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "rag-scan-stack-health": {
      "command": "python",
      "args": [
        "/opt/rag-scan-stack/mcp/health-check-server.py"
      ],
      "env": {
        "PYTHONPATH": "/opt/rag-scan-stack"
      }
    }
  }
}
```

### Claude Code Configuration

Add to `.claude/mcp.json` in your project:

```json
{
  "mcpServers": {
    "rag-scan-stack-health": {
      "command": "python",
      "args": [
        "./mcp/health-check-server.py"
      ]
    }
  }
}
```

## Usage

### From Claude Desktop/Code

Once configured, you can ask Claude to check system health:

```
Check if all RAG Scan Stack services are healthy
```

```
Verify the database schema is complete
```

```
Check the status of the nuclei-runner service
```

```
List all running containers
```

### Direct Testing

Test the MCP server directly:

```bash
# Run the health check script directly
./scripts/check_system_health.sh

# With JSON output
./scripts/check_system_health.sh --json

# With MCP format
./scripts/check_system_health.sh --mcp

# Verbose mode
./scripts/check_system_health.sh --verbose
```

## Tool Details

### check_system_health

**Input Parameters:**
- `format` (optional): Output format - "text", "json", or "mcp" (default: "mcp")
- `verbose` (optional): Include detailed output (default: false)

**Output:**
```json
{
  "status": "healthy",
  "total_checks": 19,
  "passed": 19,
  "failed": 0,
  "warnings": 0,
  "health_score": 100,
  "ready_for_operations": true
}
```

**Checks Performed:**
- ✓ Docker availability and daemon
- ✓ Docker network configuration
- ✓ All required containers running
- ✓ PostgreSQL database connectivity
- ✓ Database schema (21 tables)
- ✓ Critical tables exist
- ✓ Ollama service and models
- ✓ Service health endpoints (8 services)
- ✓ Kong API Gateway
- ✓ Scanning tools (nmap, nuclei, gobuster, playwright)

### check_database_schema

**Input Parameters:** None

**Output:** Detailed report of database tables and schema status

**Actions:**
- Counts total tables
- Verifies all 21 required tables
- Checks critical tables
- Provides fix suggestions if issues found

### check_service

**Input Parameters:**
- `service` (required): Service name to check
  - Options: rag-api, web-scanner, nuclei-runner, nmap-scanner, scan-recommender, playwright-scanner, autogen-agents, llm-query, kong, ollama

**Output:** Service status, endpoint, and response

### list_running_containers

**Input Parameters:** None

**Output:** List of all containers with status and health information

## Health Score Interpretation

| Score | Status | Description |
|-------|--------|-------------|
| 100% | ✅ Excellent | All services operational |
| 90-99% | ⚠️ Good | Minor issues or warnings |
| 70-89% | ⚠️ Degraded | Some services down |
| <70% | ❌ Critical | Multiple failures |

## Troubleshooting

### MCP Server Not Responding

1. Check Python is installed: `python --version`
2. Verify MCP SDK installed: `pip show mcp`
3. Test script directly: `./scripts/check_system_health.sh`
4. Check Claude logs for errors

### Services Showing Unhealthy

1. Check Docker containers: `docker compose ps`
2. View service logs: `docker compose logs [service-name]`
3. Verify ports not blocked: `netstat -an | grep LISTEN`
4. Run individual service check:
   ```bash
   curl http://localhost:8000/health
   ```

### Database Issues

1. Run schema verification: `./scripts/ensure_db_schema.sh`
2. Check PostgreSQL: `docker compose logs rag-postgres`
3. Verify database tables:
   ```bash
   docker exec rag-postgres psql -U app -d scans -c '\dt'
   ```

### Container Not Running

1. Check container status: `docker compose ps`
2. Restart container: `docker compose restart [service-name]`
3. Rebuild container: `docker compose up -d --build [service-name]`
4. Check logs: `docker compose logs [service-name]`

## Integration Examples

### Python Client

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def check_health():
    server_params = StdioServerParameters(
        command="python",
        args=["./mcp/health-check-server.py"]
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Call health check tool
            result = await session.call_tool(
                "check_system_health",
                {"format": "json"}
            )

            print(result.content[0].text)
```

### Shell Script

```bash
#!/bin/bash
# Health check wrapper

# Source the health check
source ./scripts/check_system_health.sh

# Run checks
check_docker
check_containers
check_database
check_services

# Exit with appropriate code
if [[ $FAILED_CHECKS -eq 0 ]]; then
    exit 0
else
    exit 1
fi
```

## Automation

### Cron Job

Add to crontab for periodic health checks:

```bash
# Check health every 15 minutes
*/15 * * * * /opt/rag-scan-stack/scripts/check_system_health.sh >> /var/log/rag-health.log 2>&1

# Alert on failures
*/15 * * * * /opt/rag-scan-stack/scripts/check_system_health.sh || echo "RAG Stack health check failed" | mail -s "RAG Alert" admin@example.com
```

### Systemd Service

Create `/etc/systemd/system/rag-health-check.service`:

```ini
[Unit]
Description=RAG Scan Stack Health Check
After=docker.service

[Service]
Type=oneshot
ExecStart=/opt/rag-scan-stack/scripts/check_system_health.sh
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Create timer `/etc/systemd/system/rag-health-check.timer`:

```ini
[Unit]
Description=Run RAG Health Check every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
```

Enable:
```bash
sudo systemctl enable --now rag-health-check.timer
```

## Development

### Adding New Checks

1. Edit `scripts/check_system_health.sh`
2. Add new check function:
   ```bash
   check_my_new_service() {
       log_info "Checking my new service..."

       # Perform check
       if [check passes]; then
           log_success "Service is healthy"
           add_result "my_service" "pass" "Service operational" ""
           return 0
       else
           log_error "Service is down"
           add_result "my_service" "fail" "Service not responding" ""
           return 1
       fi
   }
   ```

3. Call function in `main()`:
   ```bash
   check_my_new_service
   ```

### Adding New MCP Tools

1. Edit `mcp/health-check-server.py`
2. Add tool to `list_tools()`:
   ```python
   Tool(
       name="my_new_tool",
       description="Description of what it does",
       inputSchema={
           "type": "object",
           "properties": {
               "param": {
                   "type": "string",
                   "description": "Parameter description"
               }
           }
       }
   )
   ```

3. Add handler in `call_tool()`:
   ```python
   elif name == "my_new_tool":
       # Implementation
       return [TextContent(type="text", text="Result")]
   ```

## Support

For issues or questions:
1. Check the main project README
2. Review logs: `docker compose logs`
3. Run health check with `--verbose` flag
4. Check MCP server logs in Claude Desktop/Code

## License

Part of the RAG Scan Stack project.
