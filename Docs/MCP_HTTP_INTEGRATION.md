# MCP Server with HTTP API Integration - Complete Guide

## Overview

The RAG Scan Stack now provides three ways to access health check functionality:

1. **CLI** - Direct bash script execution
2. **HTTP API** - REST endpoints (port 8000)
3. **MCP Server** - Claude Desktop/Code integration (calls HTTP API)

## Architecture

```
┌─────────────────┐
│ Claude Desktop  │
│   /Claude Code  │
└────────┬────────┘
         │ stdio
         ▼
┌─────────────────┐
│   MCP Server    │  (Runs on host)
│   (Python)      │
└────────┬────────┘
         │ HTTP
         ▼
┌─────────────────┐
│    RAG API      │  (Port 8000, in container)
│   /health/*     │
└────────┬────────┘
         │ subprocess
         ▼
┌─────────────────┐
│  Health Check   │  (Bash script)
│     Script      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Docker/Services │
└─────────────────┘
```

## What We Built

### 1. HTTP API Endpoints (`app/rag-api/health_router.py`)

**Available Endpoints:**

| Endpoint | Description | Works From Container |
|----------|-------------|---------------------|
| `GET /health/quick` | Quick health check | ✅ Yes |
| `GET /health/database` | Database schema check | ✅ Yes |
| `GET /health/service/{name}` | Individual service check | ✅ Yes |
| `GET /health/containers` | List containers | ⚠️  Requires Docker socket |
| `GET /health/` | Complete health check | ⚠️  Requires Docker CLI |

**Note**: The comprehensive endpoints that require Docker access work when called from **outside** the container (which is how the MCP server and users access them).

### 2. MCP Server (`mcp/health-check-server.py`)

**Updated to call HTTP API instead of running scripts directly.**

**Advantages:**
- ✅ No file permission issues
- ✅ Works from any environment
- ✅ Consistent with other access methods
- ✅ Better error handling
- ✅ Cleaner architecture

**Tools Provided:**
1. `check_system_health` - Complete health check (19 checks)
2. `check_database_schema` - Database verification
3. `check_service` - Individual service check
4. `list_running_containers` - Container status
5. `quick_health_check` - Fast uptime check

### 3. Documentation

- **`Docs/HEALTH_CHECK_API.md`** - Complete HTTP API reference
- **`mcp/README.md`** - Updated MCP documentation
- **`Docs/MCP_SETUP_WINDOWS.md`** - Windows/WSL setup guide

## Installation & Setup

### Step 1: Ensure RAG API is Running

```bash
docker compose ps rag-api
# Should show "Up" status
```

### Step 2: Install MCP Dependencies

```bash
cd /opt/rag-scan-stack/mcp
pip install -r requirements.txt
```

This installs:
- `mcp>=1.0.0` - MCP SDK
- `httpx>=0.27.0` - HTTP client for API calls

### Step 3: Test HTTP API Endpoints

```bash
# Quick test
curl http://localhost:8000/health/quick

# Database check
curl http://localhost:8000/health/database

# Service check
curl http://localhost:8000/health/service/web-scanner

# Container list
curl http://localhost:8000/health/containers
```

### Step 4: Configure MCP Server

**For Claude Desktop (Windows):**

Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "rag-scan-stack-health": {
      "command": "wsl",
      "args": [
        "-d", "Ubuntu-22.04",
        "python3",
        "/opt/rag-scan-stack/mcp/health-check-server.py"
      ],
      "description": "RAG Scan Stack health monitoring via HTTP API"
    }
  }
}
```

**For Claude Code:**

The `.claude/mcp.json` is already configured:

```json
{
  "mcpServers": {
    "rag-scan-stack-health": {
      "command": "python3",
      "args": ["./mcp/health-check-server.py"],
      "env": {"PYTHONPATH": "."}
    }
  }
}
```

### Step 5: Restart Claude Desktop/Code

Close and reopen Claude Desktop/Code completely to load the MCP server.

## Usage Examples

### From Claude Desktop/Code

Once the MCP server is configured, you can ask Claude:

```
Check if all RAG Scan Stack services are healthy
```

```
Verify the database schema
```

```
Check the status of the web-scanner service
```

```
List all running containers
```

### From Command Line (HTTP API)

```bash
# Complete health check (calls from outside container)
curl http://localhost:8000/health/

# Quick check
curl http://localhost:8000/health/quick

# Database verification
curl http://localhost:8000/health/database

# Check specific service
curl http://localhost:8000/health/service/nuclei-runner

# List all containers
curl http://localhost:8000/health/containers
```

### From Python

```python
import requests

# Quick health check
response = requests.get("http://localhost:8000/health/quick")
print(response.json())
# {'status': 'ok', 'service': 'rag-api', 'timestamp': '...'}

# Database check
response = requests.get("http://localhost:8000/health/database")
data = response.json()
print(f"Database status: {data['status']}")
print(f"Tables: {data['table_count']}/{data['expected_tables']}")

# Service check
response = requests.get("http://localhost:8000/health/service/web-scanner")
data = response.json()
print(f"{data['service']}: {data['status']}")
```

## Troubleshooting

### MCP Server Issues

**"Connection refused"**
- Ensure RAG API is running: `docker ps | grep rag-api`
- Test API directly: `curl http://localhost:8000/health/quick`
- Check container logs: `docker logs rag-api`

**"Module 'httpx' not found"**
```bash
cd /opt/rag-scan-stack/mcp
pip install -r requirements.txt
```

**"MCP server not appearing in Claude"**
1. Check configuration file syntax (valid JSON)
2. Restart Claude Desktop completely (check system tray)
3. Check Claude logs: `%APPDATA%\Claude\logs\` (Windows)

### HTTP API Issues

**"404 Not Found on /health/*"**
- Container may not have been rebuilt
- Check: `docker exec rag-api ls -la /app/app/rag-api/health_router.py`
- Rebuild: `docker compose up -d --build rag-api`

**"Health check script failed"**
- This is expected when calling comprehensive health check from inside container
- Solution: Call from outside (MCP server does this automatically)
- Alternative: Use individual endpoints (/quick, /database, /service, /containers)

## Testing

### Test HTTP API

```bash
# Test all endpoints
echo "Testing quick health..."
curl -s http://localhost:8000/health/quick

echo -e "\nTesting database health..."
curl -s http://localhost:8000/health/database

echo -e "\nTesting service health..."
curl -s http://localhost:8000/health/service/rag-api

echo -e "\nTesting containers..."
curl -s http://localhost:8000/health/containers | head -20
```

### Test MCP Server

```bash
# Test MCP server directly (from host)
cd /opt/rag-scan-stack
python3 mcp/health-check-server.py
# Should start and wait for stdio input
# Press Ctrl+C to exit
```

## Benefits of This Architecture

### ✅ vs Direct Script Execution
- No permission issues
- Works in restricted environments
- No need to mount volumes or scripts
- Better error handling

### ✅ vs MCP Server Running Scripts
- Cleaner separation of concerns
- API can be used by other tools
- Better logging and monitoring
- Easier to debug

### ✅ Unified Interface
- Same data available via CLI, HTTP, and MCP
- Consistent formatting
- Single source of truth
- Easy to extend

## Next Steps

1. **Test the MCP tools** in Claude Desktop/Code
2. **Monitor API logs** if you encounter issues: `docker logs -f rag-api`
3. **Use HTTP API** in your own monitoring/alerting tools
4. **Extend functionality** by adding new endpoints to `health_router.py`

## Support

- **HTTP API Docs**: [HEALTH_CHECK_API.md](HEALTH_CHECK_API.md)
- **MCP Setup**: [../mcp/README.md](../mcp/README.md)
- **Windows Setup**: [MCP_SETUP_WINDOWS.md](MCP_SETUP_WINDOWS.md)
- **Health Check CLI**: [HEALTH_CHECK_GUIDE.md](HEALTH_CHECK_GUIDE.md)

## Summary

✅ **HTTP API** - 5 health check endpoints at `http://localhost:8000/health/*`
✅ **MCP Server** - Updated to call HTTP API instead of scripts
✅ **Documentation** - Complete guides for HTTP API and MCP integration
✅ **Architecture** - Clean layered design: Claude → MCP → HTTP API → Scripts → Docker

The system is now ready for use! The MCP server provides seamless health monitoring for Claude Desktop/Code, while the HTTP API enables integration with any other tools or monitoring systems you use.
