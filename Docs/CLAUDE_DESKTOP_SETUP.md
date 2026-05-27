# Claude Desktop Setup Guide for Penetration Testing Framework

This guide helps you configure Claude Desktop (running on Windows) to work with the containerized penetration testing framework.

## 🎉 New Features

### Automatic Logging Web Interface ✅
When you connect via Claude Desktop, the MCP server now automatically starts a web interface for viewing diagnostic logs:

- **URL**: http://localhost:8015/logs/ui
- **Features**: Real-time log viewing, error filtering, request tracking
- **Use Case**: Debug scan errors, monitor operations, view detailed error messages

**See logs while scanning:**
1. Connect to pentest tools via Claude Desktop
2. Open http://localhost:8015/logs/ui in your browser
3. Enable "Auto-refresh" to see logs in real-time
4. Filter by "ERROR" to troubleshoot issues

### Improved Error Messages ✅
JSON errors are now formatted in a user-friendly way in Claude Desktop:
- Clear error descriptions instead of raw JSON
- Helpful suggestions for common issues
- Request IDs for tracking in the web UI

## Quick Fix Summary

### Previous Issues Fixed ✅
1. **Fixed Nmap Scanner Endpoint**: Changed from `/scan` to `/jobs/masscan-then-nmap`
2. **Added Masscan-Only Function**: New `start_masscan()` function for fast port scans
3. **Improved Error Messages**: Errors now include the attempted URL for debugging
4. **Added Logging Web Interface**: View detailed logs while using Claude Desktop

## How the MCP Server Works

When Claude Desktop connects to the penetration testing framework:

1. **MCP Server runs INSIDE Docker**: The command `docker exec -i autogen-agents python /app/mcp_server.py` executes code inside the `autogen-agents` container
2. **Logging Web Server starts automatically**: The MCP server launches the logging interface on port 8015
3. **Internal DNS works**: Because the MCP server runs inside Docker, it can use internal DNS names like `nmap_scanner:8012`, `web-scanner:8010`, etc.
4. **No Windows DNS issues**: The Windows host doesn't need to resolve these names

## Available Scan Functions

### 1. Fast Port Scan (Masscan Only)
```python
start_masscan(
    targets="192.168.1.0/24",  # Comma-separated IPs or CIDRs
    ports="1-1000",             # Port range
    rate=1000                   # Packets per second
)
```

**Use when**: You need a quick port discovery across many hosts

### 2. Full Port Scan with Service Detection (Masscan + Nmap)
```python
start_nmap_scan(
    ip_address="192.168.1.100",  # Single IP or CIDR
    ports="1-1000"                # Port range
)
```

**Use when**: You need detailed service version information

### 3. Web Application Scan
```python
start_playwright_scan(
    url="http://example.com",
    use_zap=True,
    capture_screenshots=True
)
```

**Use when**: Scanning web applications for XSS, CSRF, etc.

### 4. Vulnerability Scan (Nuclei)
```python
start_nuclei_scan(
    limit=25,
    severity="medium,high,critical"
)
```

**Use when**: Testing known vulnerabilities with Nuclei templates

## Troubleshooting

### Not Seeing Log Output
**Symptom**: Scans are running but you don't see logs
**Solution**:
1. Open http://localhost:8015/logs/ui in your browser
2. The logging web interface runs automatically when using Claude Desktop
3. Enable "Auto-refresh (5s)" to see logs in real-time
4. If the web UI doesn't load, restart Claude Desktop to restart the MCP server

### JSON Errors in Claude Desktop
**Symptom**: Seeing "JSON error" messages when scans fail
**Explanation**: These are now formatted error messages, not actual bugs!
- The error messages show exactly what went wrong (404, timeout, connection error, etc.)
- Use the Request ID to find detailed logs in the web UI
- Common causes and solutions are included in the error message

**To debug:**
1. Note the Request ID from the error message
2. Open http://localhost:8015/logs/ui
3. Paste the Request ID into the "Request ID" filter
4. View all logs related to that specific operation

### Error: "404 Not Found" on nmap_scanner
**Cause**: Old version of `scan_tools.py` using wrong endpoint
**Solution**: Container has been rebuilt with correct endpoints

### Error: "nmap_scanner" DNS not found
**Cause**: Trying to access from Windows host instead of Docker network
**Solution**: Use the MCP server (which runs inside Docker) or use `localhost:8012`

### Error: "relation 'agent_sessions' does not exist"
**Cause**: Database schema was incomplete
**Solution**: Database has been migrated with all necessary tables

### Logging Web UI Not Loading
**Symptom**: http://localhost:8015/logs/ui doesn't load
**Possible Causes**:
1. MCP server not running (Claude Desktop not connected)
2. Port 8015 is blocked or in use
3. Container networking issue

**Solution**:
1. Disconnect and reconnect in Claude Desktop
2. Check if port 8015 is accessible: `curl http://localhost:8015/health`
3. Check container logs: `docker logs autogen-agents`

## Testing the Setup

### From Claude Desktop
Simply ask Claude to perform scans:
- "Scan 192.168.1.1 for open ports"
- "Run a web scan on http://testphp.vulnweb.com"
- "Check for vulnerabilities on the discovered services"

### From Command Line (Inside Container)
```bash
# Test from inside autogen-agents container
docker exec autogen-agents python3 -c "
from scan_tools import start_masscan
print(start_masscan('192.168.1.1', '80,443'))
"
```

### From Windows Host (Direct API)
```powershell
# Test nmap_scanner directly
curl -X POST http://localhost:8012/jobs/masscan-only `
  -H "Content-Type: application/json" `
  -d '{\"targets\": [\"192.168.1.1\"], \"ports\": \"80,443\", \"rate\": 500}'
```

## Service URLs

### From Inside Docker Network (MCP Server Uses These)
- RAG API: `http://rag-api:8000`
- Nmap Scanner: `http://nmap_scanner:8012`
- Web Scanner: `http://web-scanner:8010`
- Nuclei: `http://nuclei-runner:8011`
- Playwright: `http://playwright-scanner:8014`
- Scan Recommender: `http://scan-recommender:8013`

### From Windows Host (Direct Access)
- RAG API: `http://localhost:8000`
- Nmap Scanner: `http://localhost:8012`
- Web Scanner: `http://localhost:8010`
- Nuclei: `http://localhost:8011`
- Playwright: `http://localhost:8014`
- Scan Recommender: `http://localhost:8013`

## Environment Variables

The `autogen-agents` container uses these environment variables (already configured in `docker-compose.yml`):

```yaml
RAG_API_URL: "http://rag-api:8000"
WEB_SCANNER_URL: "http://web-scanner:8010"
NUCLEI_URL: "http://nuclei-runner:8011"
NMAP_URL: "http://nmap_scanner:8012"
PLAYWRIGHT_URL: "http://playwright-scanner:8014"
SCAN_RECOMMENDER_URL: "http://scan-recommender:8013"
```

These are internal Docker network addresses and should not be changed for Claude Desktop usage.

## API Documentation

View interactive API documentation for each service:
- **Nmap Scanner**: http://localhost:8012/docs
- **Playwright**: http://localhost:8014/docs
- **Web Scanner**: http://localhost:8010/docs
- **Nuclei**: http://localhost:8011/docs

## Verifying the Fix

1. **Check container is running**:
   ```bash
   docker ps | grep autogen-agents
   ```

2. **Test the MCP server**:
   ```bash
   docker exec -i autogen-agents python /app/mcp_server.py
   ```
   (Press Ctrl+C to exit)

3. **Verify scan_tools.py is updated**:
   ```bash
   docker exec autogen-agents grep -A 5 "jobs/masscan" /app/scan_tools.py
   ```

## Need Help?

- **API Reference**: See `/utils/agents/API_ENDPOINTS.md`
- **Check logs**: `docker logs autogen-agents`
- **Service health**: `curl http://localhost:8012/health`
- **Database status**: `docker exec rag-postgres psql -U app -d scans -c "\dt"`
