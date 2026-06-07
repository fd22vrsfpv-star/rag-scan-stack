# MCP Setup Guide for Windows

This guide explains how to configure the RAG Scan Stack MCP servers in Claude Desktop on Windows with WSL2.

## Prerequisites

- Windows 10/11 with WSL2
- Docker Desktop for Windows
- Claude Desktop installed
- Python installed in WSL (already present in your Ubuntu-22.04 distro)

## Configuration Options

You have **two MCP servers** to configure:

1. **autogen-pentest** - AI autonomous penetration testing agents
2. **rag-scan-stack-health** - System health monitoring

## Claude Desktop Configuration File Location

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

**Full path example:** `C:\Users\YourUsername\AppData\Roaming\Claude\claude_desktop_config.json`

## Recommended Configuration (Fixed)

Here's the corrected configuration with proper syntax:

```json
{
  "mcpServers": {
    "autogen-pentest": {
      "command": "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
      "args": [
        "exec",
        "-i",
        "autogen-agents",
        "python",
        "/app/mcp_server.py"
      ],
      "description": "AI-powered autonomous penetration testing agents with RAG-enhanced vulnerability analysis"
    },
    "rag-scan-stack-health": {
      "command": "wsl",
      "args": [
        "-d",
        "Ubuntu-22.04",
        "python3",
        "/opt/rag-scan-stack/mcp/health-check-server.py"
      ],
      "description": "RAG Scan Stack health monitoring and system status checks"
    }
  }
}
```

## Issues Fixed in Your Configuration

### 1. Missing Comma
**Before:**
```json
"description": "AI-powered autonomous penetration testing agents with RAG-enhanced vulnerability analysis"
}
"rag-scan-stack-health": {  // ❌ Missing comma before this
```

**After:**
```json
"description": "AI-powered autonomous penetration testing agents with RAG-enhanced vulnerability analysis"
},  // ✅ Added comma
"rag-scan-stack-health": {
```

### 2. Windows Path Format
**Before:**
```json
"args": ["/opt/rag-scan-stack/mcp/health-check-server.py"]  // ❌ Linux path without WSL wrapper
```

**After:**
```json
"args": [
  "-d",
  "Ubuntu-22.04",
  "python3",
  "/opt/rag-scan-stack/mcp/health-check-server.py"
]  // ✅ Proper WSL invocation
```

## Alternative Configuration Options

### Option 1: Using WSL Path Format (Recommended)

```json
{
  "mcpServers": {
    "rag-scan-stack-health": {
      "command": "wsl",
      "args": [
        "-d",
        "Ubuntu-22.04",
        "python3",
        "/opt/rag-scan-stack/mcp/health-check-server.py"
      ]
    }
  }
}
```

### Option 2: Using Windows Python (if installed)

```json
{
  "mcpServers": {
    "rag-scan-stack-health": {
      "command": "python",
      "args": [
        "\\\\wsl$\\Ubuntu-22.04\\opt\\rag-scan-stack\\mcp\\health-check-server.py"
      ]
    }
  }
}
```

### Option 3: Using Docker Exec (like autogen-pentest)

First, ensure the health check script is accessible in a container, then:

```json
{
  "mcpServers": {
    "rag-scan-stack-health": {
      "command": "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
      "args": [
        "exec",
        "-i",
        "rag-api",
        "python",
        "/app/mcp/health-check-server.py"
      ]
    }
  }
}
```

## Setup Steps

### Step 1: Verify Prerequisites

```powershell
# Check Docker is running
docker ps

# Check WSL is working
wsl -d Ubuntu-22.04 -- echo "WSL is working"

# Check Python in WSL
wsl -d Ubuntu-22.04 -- python3 --version

# Check MCP package installed
wsl -d Ubuntu-22.04 -- python3 -c "import mcp; print('MCP installed')"
```

### Step 2: Install MCP in WSL (if needed)

```powershell
# Install MCP package in WSL
wsl -d Ubuntu-22.04 -- bash -c "cd /opt/rag-scan-stack/mcp && pip install -r requirements.txt"
```

### Step 3: Test Health Check Script

```powershell
# Test the health check script works
wsl -d Ubuntu-22.04 -- /opt/rag-scan-stack/scripts/optional/check_system_health.sh

# Test the MCP server can start (Ctrl+C to exit)
wsl -d Ubuntu-22.04 -- python3 /opt/rag-scan-stack/mcp/health-check-server.py
```

### Step 4: Update Claude Desktop Config

1. **Open the config file:**
   ```powershell
   notepad "%APPDATA%\Claude\claude_desktop_config.json"
   ```

2. **Replace the entire contents** with the recommended configuration above

3. **Save and close** the file

### Step 5: Restart Claude Desktop

1. **Completely close** Claude Desktop (check system tray)
2. **Restart** Claude Desktop
3. **Verify MCP servers** loaded - look for server icons/indicators

### Step 6: Test the MCP Tools

In Claude Desktop, ask:

```
Check if all RAG Scan Stack services are healthy
```

```
List all running containers
```

```
What's the database schema status?
```

## Troubleshooting

### Issue: "Cannot find docker.exe"

**Solution:**
```json
// Find your docker.exe path
// Common locations:
"command": "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe"
// Or
"command": "C:\\ProgramData\\DockerDesktop\\version-bin\\docker.exe"
```

### Issue: "WSL distribution not found"

**Solution:**
```powershell
# List WSL distributions
wsl -l -v

# Use the exact name from the list
// Example output:
//   NAME            STATE           VERSION
// * Ubuntu-22.04    Running         2

// Then use in config:
"args": ["-d", "Ubuntu-22.04", ...]
```

### Issue: "Module 'mcp' not found"

**Solution:**
```powershell
# Install in WSL
wsl -d Ubuntu-22.04 -- bash -c "cd /opt/rag-scan-stack/mcp && pip install mcp"
```

### Issue: "Container 'autogen-agents' not running"

**Solution:**
```powershell
# Start the container
wsl -d Ubuntu-22.04 -- bash -c "cd /opt/rag-scan-stack && docker compose up -d autogen-agents"
```

### Issue: "Claude Desktop not loading MCP servers"

**Checklist:**
1. ✓ Config file has valid JSON syntax
2. ✓ All commas are present
3. ✓ All paths use double backslashes `\\`
4. ✓ Claude Desktop completely restarted
5. ✓ Check Claude Desktop logs: `%APPDATA%\Claude\logs`

### Issue: "Permission denied"

**Solution:**
```powershell
# Make script executable in WSL
wsl -d Ubuntu-22.04 -- chmod +x /opt/rag-scan-stack/mcp/health-check-server.py
wsl -d Ubuntu-22.04 -- chmod +x /opt/rag-scan-stack/scripts/optional/check_system_health.sh
```

## Testing Individual Components

### Test Docker Access
```powershell
"C:\Program Files\Docker\Docker\resources\bin\docker.exe" ps
```

### Test WSL Access
```powershell
wsl -d Ubuntu-22.04 -- ls /opt/rag-scan-stack
```

### Test Python Script
```powershell
wsl -d Ubuntu-22.04 -- python3 /opt/rag-scan-stack/mcp/health-check-server.py
# Should start MCP server (Ctrl+C to exit)
```

### Test Docker Exec
```powershell
"C:\Program Files\Docker\Docker\resources\bin\docker.exe" exec -i autogen-agents python /app/mcp_server.py
# Should start MCP server (Ctrl+C to exit)
```

## Validation Commands

### Verify Configuration Syntax

```powershell
# Use Python to validate JSON
python -m json.tool "%APPDATA%\Claude\claude_desktop_config.json"

# Or use PowerShell
Get-Content "$env:APPDATA\Claude\claude_desktop_config.json" | ConvertFrom-Json
```

### Check MCP Server Status in Claude

After setup, Claude Desktop should show:
- MCP server indicators in the interface
- Available tools when you type "/"
- Tool suggestions when asking relevant questions

## Complete Working Example

Here's a complete, tested configuration:

```json
{
  "mcpServers": {
    "autogen-pentest": {
      "command": "C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe",
      "args": [
        "exec",
        "-i",
        "autogen-agents",
        "python",
        "/app/mcp_server.py"
      ],
      "env": {},
      "description": "AI-powered autonomous penetration testing agents"
    },
    "rag-scan-stack-health": {
      "command": "wsl",
      "args": [
        "-d",
        "Ubuntu-22.04",
        "python3",
        "/opt/rag-scan-stack/mcp/health-check-server.py"
      ],
      "env": {
        "PYTHONPATH": "/opt/rag-scan-stack"
      },
      "description": "RAG Scan Stack health monitoring"
    }
  }
}
```

## Available MCP Tools

### From autogen-pentest:
- Autonomous penetration testing
- Vulnerability analysis
- RAG-enhanced exploit suggestions

### From rag-scan-stack-health:
- **check_system_health** - Complete system health check (19 checks)
- **check_database_schema** - Database table verification
- **check_service** - Individual service health
- **list_running_containers** - Container status overview

## Best Practices

1. **Always validate JSON** before saving the config
2. **Use double backslashes** for Windows paths: `C:\\Program Files\\`
3. **Include all commas** between objects
4. **Test each server** individually before combining
5. **Check Claude logs** if servers don't load: `%APPDATA%\Claude\logs\`
6. **Keep containers running** - MCP servers need them active

## Quick Reference

| Item | Location |
|------|----------|
| Config File | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Logs | `%APPDATA%\Claude\logs\` |
| WSL Project | `/opt/rag-scan-stack` |
| Windows Project | `\\wsl$\Ubuntu-22.04\opt\rag-scan-stack` |
| Docker Path | `C:\Program Files\Docker\Docker\resources\bin\docker.exe` |

## Next Steps

After successful setup:

1. **Test all tools**: Ask Claude to check system health
2. **Start scanning**: Use the autogen-pentest tools
3. **Monitor health**: Regularly check with health tools
4. **Review logs**: Check for any warnings or errors

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Validate JSON syntax
3. Review Claude Desktop logs
4. Test components individually
5. Ensure all containers are running

For detailed MCP documentation, see:
- [MCP Server README](../mcp/README.md)
- [Health Check Guide](HEALTH_CHECK_GUIDE.md)
