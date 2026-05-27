# Diagnostic Logging Guide

## Overview

The scan_tools.py module now includes comprehensive diagnostic logging to help debug JSON errors, connection issues, and understand the complete flow of scan requests.

**🎉 NEW: Web Interface for Log Viewing**

Access the interactive web interface at: **http://localhost:8015/logs/ui**

Features:
- Real-time log viewing with auto-refresh
- Filter by log level, search terms, or request ID
- Export logs as JSON
- Live statistics dashboard
- Dark theme optimized for readability

**✨ Now works with Claude Desktop!** The MCP server automatically starts the logging web interface in the background, so you can view logs while using Claude Desktop.

## Using Logs with Claude Desktop

When you connect via Claude Desktop (using the MCP server), the logging web interface is automatically available at http://localhost:8015/logs/ui.

**What happens when you connect:**
1. Claude Desktop runs: `docker exec -i autogen-agents python /app/mcp_server.py`
2. The MCP server automatically starts the logging web server in a background thread
3. All scan operations are logged in real-time
4. You can view logs at http://localhost:8015/logs/ui while using Claude Desktop

**To view logs while using Claude Desktop:**
1. Connect to your pentest tools via Claude Desktop as usual
2. Open your web browser to: http://localhost:8015/logs/ui
3. Enable "Auto-refresh (5s)" to see logs in real-time as scans run
4. Filter by "ERROR" to see only failed operations

**When you see JSON errors in Claude Desktop:**
- These are now formatted in a user-friendly way with details and suggestions
- Check the web logging UI for detailed diagnostic information
- Use the Request ID from the error message to filter logs in the web UI

## Features

### 1. Request/Response Logging
Every API call is now logged with:
- Request ID for tracking
- HTTP method and URL
- Request body (in debug mode)
- Response status code
- Response body (on errors or in debug mode)
- Execution time

### 2. Detailed Error Information
When errors occur, you get:
- **HTTP Errors**: Status code, error details, response body
- **JSON Parse Errors**: Exact parse error, raw response text
- **Timeout Errors**: Which service timed out and after how long
- **Connection Errors**: Service name, network details, troubleshooting hints
- **Unexpected Errors**: Full exception with traceback

### 3. Log Levels
- **INFO**: Normal operation (successful requests, service initialization)
- **ERROR**: Failed requests, JSON errors, connection issues
- **DEBUG**: Verbose logging (request bodies, response bodies, headers)

## Usage

### Normal Mode (Default)

By default, only important information is logged:

```bash
2025-10-15 00:21:01 [INFO] scan_tools: ScanTools initialized with:
2025-10-15 00:21:01 [INFO] scan_tools:   RAG API: http://rag-api:8000
2025-10-15 00:21:01 [INFO] scan_tools:   Nmap: http://nmap_scanner:8012
2025-10-15 00:21:01 [INFO] scan_tools:   Debug mode: False

2025-10-15 12:34:56 [INFO] scan_tools: [Nmap scan of 192.168.1.1_1697382896000] Starting: Nmap scan of 192.168.1.1
2025-10-15 12:34:56 [INFO] scan_tools: ✓ 200 POST http://nmap_scanner:8012/jobs/masscan-then-nmap
2025-10-15 12:34:56 [INFO] scan_tools: [Nmap scan of 192.168.1.1_1697382896000] Success: Nmap scan of 192.168.1.1
```

### Debug Mode (Verbose)

Enable debug mode to see full request/response details:

#### Option 1: Environment Variable (Persistent)

Edit `docker-compose.yml`:

```yaml
autogen-agents:
  image: autogen-agents
  environment:
    SCAN_DEBUG: "true"  # Add this line
    RAG_API_URL: "http://rag-api:8000"
    # ... other variables
```

Then rebuild and restart:

```bash
docker-compose up -d autogen-agents
```

#### Option 2: Temporary (Single Session)

```bash
docker exec autogen-agents sh -c 'export SCAN_DEBUG=true && python /app/mcp_server.py'
```

### Debug Mode Output Example

```bash
2025-10-15 12:34:56 [INFO] scan_tools: [Nmap scan of 192.168.1.1_1697382896000] Starting: Nmap scan of 192.168.1.1
2025-10-15 12:34:56 [DEBUG] scan_tools: → POST http://nmap_scanner:8012/jobs/masscan-then-nmap
2025-10-15 12:34:56 [DEBUG] scan_tools:   Request body: {
  "targets": ["192.168.1.1"],
  "ports": "1-1000",
  "rate": 1000,
  "interface": "eth0"
}
2025-10-15 12:34:58 [INFO] scan_tools: ✓ 200 POST http://nmap_scanner:8012/jobs/masscan-then-nmap
2025-10-15 12:34:58 [DEBUG] scan_tools:   Response headers: {'content-type': 'application/json', 'content-length': '234'}
2025-10-15 12:34:58 [DEBUG] scan_tools:   Response body: {
  "ok": true,
  "masscan_out": "/app/nmap_out/masscan_1697382896.json",
  "job_id": "abc123..."
}
2025-10-15 12:34:58 [INFO] scan_tools: [Nmap scan of 192.168.1.1_1697382896000] Success: Nmap scan of 192.168.1.1
```

## Error Scenarios

### 1. JSON Parse Error

**Symptom**: "seeing a lot of json errors"

**Log Output**:
```bash
2025-10-15 12:45:10 [ERROR] scan_tools: [Nmap scan of 10.0.0.1_1697383510000] JSON parse error: {
  "error": "JSON parsing failed",
  "operation": "Nmap scan of 10.0.0.1",
  "url": "http://nmap_scanner:8012/jobs/masscan-then-nmap",
  "json_error": "Expecting value: line 1 column 1 (char 0)",
  "response_text": "<html><body>404 Not Found</body></html>",
  "status_code": 200,
  "request_id": "Nmap scan of 10.0.0.1_1697383510000"
}
```

**What it means**: The server returned non-JSON content (HTML, plain text, or empty response)

**Common Causes**:
- Wrong endpoint URL
- Server returned HTML error page
- Empty response body

### 2. HTTP 404 Error

**Log Output**:
```bash
2025-10-15 12:50:20 [ERROR] scan_tools: [Nmap scan of 10.0.0.1_1697383820000] Failed: {
  "error": "HTTP 404",
  "operation": "Nmap scan of 10.0.0.1",
  "url": "http://nmap_scanner:8012/scan",
  "status_code": 404,
  "detail": {
    "detail": "Not Found"
  },
  "request_id": "Nmap scan of 10.0.0.1_1697383820000"
}
```

**What it means**: The endpoint doesn't exist on the server

**Solution**: Check API_ENDPOINTS.md for correct endpoint paths

### 3. Connection Error

**Log Output**:
```bash
2025-10-15 13:00:30 [ERROR] scan_tools: [Nmap scan of 10.0.0.1_1697384430000] Connection error: {
  "error": "Connection failed",
  "operation": "Nmap scan of 10.0.0.1",
  "url": "http://nmap_scanner:8012/jobs/masscan-then-nmap",
  "detail": "[Errno 111] Connection refused",
  "request_id": "Nmap scan of 10.0.0.1_1697384430000",
  "hint": "Check if the service is running and network is accessible"
}
```

**What it means**: Cannot connect to the service

**Common Causes**:
- Service is not running: `docker ps | grep nmap_scanner`
- Service is starting: Wait a few seconds and retry
- Network issue: Check Docker network with `docker network ls`

### 4. Timeout Error

**Log Output**:
```bash
2025-10-15 13:10:40 [ERROR] scan_tools: [Nmap scan of 10.0.0.0/24_1697385040000] Timeout: {
  "error": "Request timeout",
  "operation": "Nmap scan of 10.0.0.0/24",
  "url": "http://nmap_scanner:8012/jobs/masscan-then-nmap",
  "timeout": "300s",
  "request_id": "Nmap scan of 10.0.0.0/24_1697385040000"
}
```

**What it means**: The request took longer than 5 minutes (300 seconds)

**Common Causes**:
- Scanning a very large network
- Slow network response
- Service is hung or overloaded

**Solution**: Reduce scope (fewer IPs, fewer ports) or wait for current operation to complete

## Viewing Logs

### Web Interface (Recommended)

The easiest way to view logs is through the web interface:

**Access URL**: http://localhost:8015/logs/ui

**Works with both:**
- ✅ Claude Desktop (MCP server mode)
- ✅ Direct API access (FastAPI server mode)

**Features**:
1. **Real-time Viewing**: See logs as they arrive with auto-refresh (5-second intervals)
2. **Filtering**:
   - By log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
   - By search term in message
   - By request ID to track specific operations
   - By limit (50, 100, 200, 500, 1000 logs)
3. **Statistics Dashboard**:
   - Total logs received
   - Error count
   - Info count
   - Debug count
   - Current buffer utilization
4. **Export**: Download all logs as formatted JSON file
5. **Clear**: Reset log buffer for fresh debugging sessions
6. **Color-coded**: Each log level has distinct colors for easy scanning

**Usage Example**:
1. Open http://localhost:8015/logs/ui in your browser
2. Enable "Auto-refresh" to see logs in real-time
3. Filter by "ERROR" to see only failed operations
4. Search for specific IP address or operation name
5. Click on a request ID to copy it, then paste in "Request ID" filter to see all logs for that operation

### REST API Endpoints

You can also query logs programmatically:

```bash
# Get last 100 logs
curl http://localhost:8015/logs?limit=100

# Get only ERROR logs
curl http://localhost:8015/logs?level=ERROR&limit=50

# Search for specific term
curl http://localhost:8015/logs?search=192.168.1.1

# Filter by request ID
curl http://localhost:8015/logs?request_id=Nmap_scan_of_192.168.1.1_1760488339506

# Get statistics
curl http://localhost:8015/logs/stats

# Export all logs as JSON
curl http://localhost:8015/logs/export > logs.json

# Clear all logs
curl -X DELETE http://localhost:8015/logs
```

### Docker Logs (Traditional)

You can still view logs using Docker commands:

```bash
# Follow all logs
docker logs -f autogen-agents

# Follow only scan_tools logs
docker logs -f autogen-agents 2>&1 | grep scan_tools

# Follow only errors
docker logs -f autogen-agents 2>&1 | grep ERROR
```

### Historical Logs

```bash
# Last 100 lines
docker logs autogen-agents --tail 100

# All logs since a specific time
docker logs autogen-agents --since 2025-10-15T12:00:00

# Save logs to file for analysis
docker logs autogen-agents > scan_tools_debug.log 2>&1
```

### Filter by Request ID

Each operation gets a unique request ID. To track a specific scan:

```bash
# Find all logs for a specific operation
docker logs autogen-agents 2>&1 | grep "1697382896000"
```

## Troubleshooting Workflow

1. **Enable Debug Mode** (if not already enabled)
   ```bash
   # Temporary for testing
   docker exec autogen-agents env SCAN_DEBUG=true python -c "from scan_tools import start_nmap_scan; print(start_nmap_scan('192.168.1.1', '80,443'))"
   ```

2. **Check Service Status**
   ```bash
   # Are all services running?
   docker ps | grep -E "(nmap|web-scanner|nuclei|playwright|scan-recommender|rag-api)"

   # Check specific service health
   curl http://localhost:8012/health  # nmap_scanner
   curl http://localhost:8000/health  # rag-api
   ```

3. **Verify Endpoints**
   ```bash
   # Check API documentation
   curl http://localhost:8012/docs  # Opens in browser

   # Test endpoint manually
   curl -X POST http://localhost:8012/jobs/masscan-only \
     -H "Content-Type: application/json" \
     -d '{"targets": ["192.168.1.1"], "ports": "80,443", "rate": 500}'
   ```

4. **Examine Logs**
   ```bash
   # Look for the exact error
   docker logs autogen-agents 2>&1 | grep -A 5 -B 5 "error"

   # Check for specific request
   docker logs autogen-agents 2>&1 | grep "192.168.1.1"
   ```

5. **Test Network Connectivity**
   ```bash
   # Can autogen-agents reach nmap_scanner?
   docker exec autogen-agents curl http://nmap_scanner:8012/health

   # Check DNS resolution
   docker exec autogen-agents nslookup nmap_scanner
   ```

## Common JSON Error Patterns

### Pattern 1: HTML Response from API

**Error**: `json_error: "Expecting value: line 1 column 1"`
**Response**: `<html>...`

**Cause**: Server returned HTML error page (404, 500, etc.)
**Solution**: Check endpoint URL and service logs

### Pattern 2: Empty Response

**Error**: `json_error: "Expecting value: line 1 column 1"`
**Response**: `""`

**Cause**: Server returned 200 OK but empty body
**Solution**: Check if service is processing request correctly

### Pattern 3: Malformed JSON

**Error**: `json_error: "Expecting ',' delimiter: line 5 column 10"`
**Response**: `{incomplete json...`

**Cause**: Server crashed mid-response or truncated output
**Solution**: Check service logs for crashes, increase timeout if needed

## Request ID Format

Request IDs help track operations through the logs:

```
Format: {operation_description}_{timestamp_milliseconds}

Examples:
- Nmap scan of 192.168.1.1_1697382896000
- Query open ports (limit=100)_1697382896500
- Playwright scan of http://example.com_1697382897000
```

## Performance Impact

**Normal Mode**:
- Minimal performance impact
- ~1-2% overhead for logging successful operations
- Essential information for troubleshooting

**Debug Mode**:
- 3-5% performance impact
- Logs full request/response bodies
- Use only when actively debugging

## Log Retention

Logs are not persisted by default. For long-term retention:

```yaml
# docker-compose.yml
autogen-agents:
  logging:
    driver: "json-file"
    options:
      max-size: "10m"
      max-file: "3"
```

Or use a centralized logging solution (ELK, Splunk, etc.)

## Examples

### Example 1: Successful Nmap Scan (Normal Mode)

```
2025-10-15 14:23:10 [INFO] scan_tools: [Nmap scan of 10.252.30.206_1697389390000] Starting: Nmap scan of 10.252.30.206
2025-10-15 14:23:12 [INFO] scan_tools: ✓ 200 POST http://nmap_scanner:8012/jobs/masscan-then-nmap
2025-10-15 14:23:12 [INFO] scan_tools: [Nmap scan of 10.252.30.206_1697389390000] Success: Nmap scan of 10.252.30.206
```

### Example 2: Failed Query with Details (Debug Mode)

```
2025-10-15 14:25:20 [INFO] scan_tools: [Query vulnerabilities (limit=100, severity=critical)_1697389520000] Starting: Query vulnerabilities
2025-10-15 14:25:20 [DEBUG] scan_tools: → GET http://rag-api:8000/vulns?limit=100&severity=critical
2025-10-15 14:25:21 [INFO] scan_tools: ✗ 500 GET http://rag-api:8000/vulns
2025-10-15 14:25:21 [ERROR] scan_tools: [Query vulnerabilities (limit=100, severity=critical)_1697389520000] Failed: {
  "error": "HTTP 500",
  "operation": "Query vulnerabilities (limit=100, severity=critical)",
  "url": "http://rag-api:8000/vulns",
  "status_code": 500,
  "detail": {
    "detail": "Internal server error: relation 'vulns' does not exist"
  },
  "request_id": "Query vulnerabilities (limit=100, severity=critical)_1697389520000"
}
```

## Quick Start: Debugging JSON Errors

If you're seeing JSON errors and want to quickly understand what's happening:

### 1. Open the Web Interface
```
http://localhost:8015/logs/ui
```

### 2. Enable Auto-Refresh
Click the "Auto-refresh (5s)" checkbox in the interface

### 3. Filter by ERROR
Select "ERROR" from the "Log Level" dropdown

### 4. Run Your Scan
Execute your scan from Claude Desktop or via API call

### 5. Watch the Logs
You'll immediately see:
- What URL was called
- What response came back
- Whether it was a JSON parse error, HTTP error, timeout, or connection issue
- The exact error message and response text

### 6. Export for Analysis
Click "📥 Export JSON" to download all logs for offline analysis or sharing

## Web Interface Screenshots

**Main Dashboard**:
- Purple gradient header with title
- 5 statistics cards showing totals
- Filter controls for level, search, request ID, and limit
- Action buttons for refresh, export, and clear
- Dark-themed log entries with color-coded borders

**Log Entry Format**:
```
[INFO]  2025-10-15 12:34:56
[Query assets (limit=5)_1760488339506] Starting: Query assets (limit=5)
Request ID: Query assets (limit=5)_1760488339506 | scan_tools.query_assets:189
```

**Error Example**:
```
[ERROR]  2025-10-15 12:34:57
[Query assets (limit=5)_1760488339506] Failed: {
  "error": "HTTP 404",
  "operation": "Query assets (limit=5)",
  "url": "http://rag-api:8000/assets",
  "status_code": 404,
  "detail": {"detail": "Not Found"}
}
Request ID: Query assets (limit=5)_1760488339506 | scan_tools._make_request:121
```

## API Reference

### GET /logs
Query logs with filtering

**Query Parameters**:
- `level` (optional): DEBUG, INFO, WARNING, ERROR, CRITICAL
- `limit` (optional, 1-1000): Number of logs to return (default: 100)
- `search` (optional): Search term in messages
- `request_id` (optional): Filter by request ID

**Response**:
```json
{
  "logs": [
    {
      "timestamp": "2025-10-15T12:34:56.789012",
      "level": "ERROR",
      "logger": "scan_tools",
      "message": "[Request_123] Failed: HTTP 404",
      "module": "scan_tools",
      "function": "_make_request",
      "line": 121,
      "request_id": "Request_123"
    }
  ],
  "count": 1,
  "filters": {...}
}
```

### GET /logs/stats
Get logging statistics

**Response**:
```json
{
  "ok": true,
  "stats": {
    "total_received": 150,
    "by_level": {
      "DEBUG": 0,
      "INFO": 120,
      "WARNING": 5,
      "ERROR": 25,
      "CRITICAL": 0
    },
    "started_at": "2025-10-15T00:31:12.737446",
    "current_buffer_size": 150,
    "max_buffer_size": 1000
  }
}
```

### GET /logs/export
Export all logs as JSON file (download)

### DELETE /logs
Clear all logs from buffer

**Response**:
```json
{
  "ok": true,
  "message": "All logs cleared successfully"
}
```

### GET /logs/ui
Serve the interactive HTML web interface

## Related Documentation

- **API Endpoints**: See `/utils/agents/API_ENDPOINTS.md`
- **Command Flow**: See `/utils/agents/COMMAND_FLOW.md`
- **Claude Desktop Setup**: See `/utils/agents/CLAUDE_DESKTOP_SETUP.md`
- **Network Interface**: See `/utils/agents/ETH0_DEFAULT.md`

## Support

If you encounter persistent JSON errors after checking all of the above:

1. Open web interface: http://localhost:8015/logs/ui
2. Enable auto-refresh and filter by ERROR
3. Run your scan and observe the detailed error information
4. Export logs: Click "📥 Export JSON" button
5. Check service health: `curl http://localhost:8012/health`
6. Review recent changes to docker-compose.yml or service configurations
