# HTTP API Guide for Autogen Agents

## Overview

Use the HTTP API at `http://localhost:8015` to interact with the pentest agents. All logs from scan operations will be visible in the web UI at http://localhost:8015/logs/ui.

## Quick Start

### 1. View Available Endpoints

Visit the API documentation:
```bash
curl http://localhost:8015/health
```

### 2. Start a Penetration Testing Session

```bash
curl -X POST http://localhost:8015/pentest \
  -H "Content-Type: application/json" \
  -d '{
    "session_name": "My First Pentest",
    "target_description": "192.168.1.100 - Web server",
    "initial_task": "Scan for open ports and web vulnerabilities",
    "max_rounds": 10
  }'
```

This returns a `session_id` that you can use to monitor progress.

### 3. Check Session Status

```bash
curl http://localhost:8015/pentest/{session_id}
```

Replace `{session_id}` with the actual session ID from step 2.

### 4. View Session Messages (Agent Conversation)

```bash
curl http://localhost:8015/pentest/{session_id}/messages
```

### 5. Get Final Report (When Completed)

```bash
curl http://localhost:8015/pentest/{session_id}/report
```

## View Logs

**Web UI** (Recommended):
```
http://localhost:8015/logs/ui
```

Features:
- Real-time log viewing with auto-refresh
- Filter by log level (INFO, ERROR, etc.)
- Search by keyword or request ID
- Export logs as JSON
- Live statistics dashboard

**API**:
```bash
# Get last 100 logs
curl http://localhost:8015/logs?limit=100

# Get only ERROR logs
curl "http://localhost:8015/logs?level=ERROR&limit=50"

# Search for specific IP
curl "http://localhost:8015/logs?search=192.168.1.100"

# Get statistics
curl http://localhost:8015/logs/stats
```

## List All Sessions

```bash
# All sessions
curl http://localhost:8015/sessions

# Only active sessions
curl "http://localhost:8015/sessions?status=active"

# Only completed sessions
curl "http://localhost:8015/sessions?status=completed"
```

## Stop a Running Session

```bash
curl -X POST http://localhost:8015/pentest/{session_id}/stop
```

## Example Workflow

```bash
# 1. Start a session
SESSION_ID=$(curl -s -X POST http://localhost:8015/pentest \
  -H "Content-Type: application/json" \
  -d '{
    "session_name": "Pentest Lab Network",
    "target_description": "192.168.100.0/24 - Lab environment",
    "initial_task": "Discover all hosts, scan for vulnerabilities",
    "max_rounds": 20
  }' | jq -r '.session_id')

echo "Session ID: $SESSION_ID"

# 2. Monitor progress (check every 30 seconds)
watch -n 30 "curl -s http://localhost:8015/pentest/$SESSION_ID | jq '.'"

# 3. View logs in browser
#    Open: http://localhost:8015/logs/ui
#    Enable auto-refresh to see real-time updates

# 4. When complete, get the report
curl -s http://localhost:8015/pentest/$SESSION_ID/report | jq -r '.report' > pentest_report.md
```

## Viewing Logs in Docker (Alternative)

If you prefer command-line logs:

```bash
# Follow all logs
docker logs -f autogen-agents

# Only scan_tools logs
docker logs -f autogen-agents 2>&1 | grep "scan_tools"

# Only errors
docker logs -f autogen-agents 2>&1 | grep "ERROR"
```

## Debugging Tips

1. **No logs appearing in Web UI?**
   - Logs only appear when using the HTTP API (not MCP/Claude Desktop)
   - Check docker logs: `docker logs autogen-agents --tail 50`

2. **Session stuck?**
   - Check session status: `curl http://localhost:8015/pentest/{session_id}`
   - View messages to see where agents are: `curl http://localhost:8015/pentest/{session_id}/messages`
   - Stop if needed: `curl -X POST http://localhost:8015/pentest/{session_id}/stop`

3. **Want more detailed logs?**
   - Set `SCAN_DEBUG=true` in docker-compose.yml
   - Rebuild: `docker-compose up -d --build autogen-agents`

## Next Steps

- See DIAGNOSTIC_LOGGING.md for detailed logging documentation
- See API_ENDPOINTS.md for complete API reference
- See CLAUDE_DESKTOP_SETUP.md for MCP configuration (note: MCP logs go to docker logs, not web UI)
