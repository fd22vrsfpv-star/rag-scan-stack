# MCP Integration Guide

Model Context Protocol (MCP) integration for Autogen Pentest Agents, enabling external AI assistants like Claude Desktop to control the penetration testing infrastructure.

## Overview

The Autogen Agents service now supports **dual interfaces**:

1. **FastAPI REST API** (Port 8015) - For programmatic access via HTTP
2. **MCP Protocol** (stdio) - For AI assistant integration via Claude Desktop, etc.

Both interfaces provide access to the same capabilities:
- Autonomous pentest sessions with AI agents
- Individual scan control (Nmap, Web, Nuclei, Playwright)
- Query operations (assets, ports, vulnerabilities)
- ExploitDB searches via RAG

## Architecture

```
┌────────────────────────────────────┐
│     External AI Assistant          │
│     (Claude Desktop, etc.)         │
└───────────────┬────────────────────┘
                │
                │ MCP Protocol (stdio)
                │
┌───────────────▼────────────────────┐
│   Autogen Agents Container         │
│                                    │
│  ┌──────────────┐  ┌────────────┐ │
│  │ MCP Server   │  │  FastAPI   │ │
│  │ (stdio mode) │  │  (REST)    │ │
│  └──────┬───────┘  └─────┬──────┘ │
│         │                 │        │
│         └────────┬────────┘        │
│                  │                 │
│         ┌────────▼─────────┐      │
│         │ Pentest Agents   │      │
│         │  & Scan Tools    │      │
│         └──────────────────┘      │
└────────────────────────────────────┘
                │
    ┌───────────┴───────────┐
    │                       │
┌───▼────┐            ┌─────▼─────┐
│ Scans  │            │ Database  │
│Services│            │(Postgres) │
└────────┘            └───────────┘
```

## Setup for Claude Desktop

### 1. Ensure Service is Running

```bash
# Start the entire stack
cd /utils/agents
docker compose up -d

# Verify autogen-agents is running
docker ps | grep autogen-agents
curl http://localhost:8015/health
```

### 2. Configure Claude Desktop

Copy the MCP configuration to Claude Desktop's config directory:

**macOS:**
```bash
# Create config directory if it doesn't exist
mkdir -p ~/Library/Application\ Support/Claude/

# Copy the MCP config
cp /utils/agents/autogen_agents/claude_desktop_config.json \
   ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**Windows:**
```powershell
# Create config directory
New-Item -ItemType Directory -Force -Path "$env:APPDATA\Claude"

# Copy the MCP config
Copy-Item /utils/agents/autogen_agents/claude_desktop_config.json `
          "$env:APPDATA\Claude\claude_desktop_config.json"
```

**Linux:**
```bash
mkdir -p ~/.config/Claude/
cp /utils/agents/autogen_agents/claude_desktop_config.json \
   ~/.config/Claude/claude_desktop_config.json
```

### 3. Verify Configuration

The config file should look like:
```json
{
  "mcpServers": {
    "autogen-pentest": {
      "command": "docker",
      "args": [
        "exec",
        "-i",
        "autogen-agents",
        "python",
        "/app/mcp_server.py"
      ],
      "description": "AI-powered autonomous penetration testing..."
    }
  }
}
```

### 4. Restart Claude Desktop

Close and reopen Claude Desktop to load the MCP configuration.

### 5. Verify Connection

In Claude Desktop, check for the MCP tools:
- You should see a tools icon or MCP indicator
- The autogen-pentest server should be listed
- 25+ tools should be available

## Available MCP Tools

Claude Desktop (and other MCP clients) will have access to these tools:

### Session Management

**start_pentest_session**
- Start an autonomous AI-powered pentest
- Agents will plan, execute, analyze, and report
- Parameters: target_description, session_name, initial_task, max_rounds

**get_session_status**
- Check status of a running/completed session
- Returns: status, message_count, summary, timestamps

**get_session_messages**
- View agent conversation history
- See how agents are collaborating
- Parameters: session_id, limit

**get_session_report**
- Get final markdown report from completed session
- Includes findings, remediation, references

**list_sessions**
- List all pentest sessions
- Filter by status (active, completed, failed, stopped)

### Data Queries

**query_assets**
- List discovered assets (IPs, hostnames)
- Shows what has been found by previous scans

**query_open_ports**
- List all open ports
- Includes service detection info

**query_vulnerabilities**
- Get vulnerability findings from all sources
- Filter by severity (info, low, medium, high, critical)

### Individual Scans

**start_nmap_scan**
- Launch Nmap port scan on specific IP
- Service detection + NSE scripts

**start_web_scan**
- Launch Gobuster + ZAP on web services
- Directory enumeration + vulnerability scanning

**start_nuclei_scan**
- Run Nuclei template-based scanning
- Thousands of CVE/misconfiguration checks

**start_playwright_scan**
- Browser-based security testing
- Tests for XSS, CSRF, clickjacking, headers, etc.

### Analysis

**query_exploitdb**
- Search ExploitDB via RAG
- Find public exploits for discovered services

**get_scan_recommendations**
- Get AI recommendations for next scans
- Based on current context

### Reports

**export_pentester_report**
- Export comprehensive penetration test report with raw tool output
- Perfect for manual pentester review and documentation
- Parameters:
  - `target`: Optional IP/hostname to filter results
  - `format`: `"markdown"` (default) or `"text"`
  - `status`: Filter by `"completed"`, `"failed"`, or `"timeout"`
- Returns:
  - Execution summary table (tool, target, status, exit code, duration)
  - Full raw output for each tool execution
  - Error output when available
  - Findings summary for each execution

## Usage Examples in Claude Desktop

### Example 1: Autonomous Pentest

> **You:** I need to assess the security of my internal network at 10.0.1.0/24. Can you run a comprehensive penetration test?

> **Claude:** I'll start an autonomous pentest session for your network. Let me use the autogen pentest agents.

*Claude calls: start_pentest_session*
```json
{
  "target_description": "10.0.1.0/24 internal network",
  "session_name": "Internal Network Assessment Q1 2025",
  "initial_task": "Discover all services and test for high-severity vulnerabilities",
  "max_rounds": 200
}
```

> **Claude:** I've started pentest session 550e8400-e29b-41d4-a716-446655440000. The AI agents are now working autonomously. Let me check the status...

*Claude calls: get_session_status*

> **Claude:** The agents have discovered 5 hosts and are currently running Nmap scans. I'll monitor progress and let you know when the report is ready.

### Example 2: Targeted Scan

> **You:** I found a web server at 192.168.1.50. Can you test it for common web vulnerabilities?

> **Claude:** I'll run a browser-based security scan using Playwright.

*Claude calls: start_playwright_scan*
```json
{
  "url": "https://192.168.1.50",
  "use_zap": true,
  "capture_screenshots": true
}
```

> **Claude:** The scan has started. It will test for:
> - Clickjacking vulnerabilities
> - CSRF protection
> - Security headers
> - Mixed content issues
> - Cookie security
> - And more...

### Example 3: Exploit Research

> **You:** I found Apache 2.4.41 running on port 80. Are there any known exploits?

> **Claude:** Let me search the ExploitDB database for Apache 2.4.41 exploits.

*Claude calls: query_exploitdb*
```json
{
  "query": "Apache 2.4.41 exploit",
  "top_k": 5
}
```

> **Claude:** I found 3 relevant exploits:
> 1. CVE-2021-41773 - Path Traversal...
> 2. CVE-2021-42013 - Path Traversal Bypass...
> 3. [Details of exploits]

### Example 4: Review Previous Findings

> **You:** What vulnerabilities have been found so far?

> **Claude:** Let me query the database for all vulnerability findings.

*Claude calls: query_vulnerabilities*
```json
{
  "limit": 100
}
```

> **Claude:** I found 12 vulnerabilities across all scans:
> - 2 critical (SQL injection, remote code execution)
> - 5 high (XSS, insecure deserialization)
> - 5 medium (missing security headers, weak ciphers)

### Example 5: Monitor Autonomous Agents

> **You:** Can you show me what the AI agents are discussing for session 550e8400-e29b-41d4-a716-446655440000?

> **Claude:** Let me get the agent conversation.

*Claude calls: get_session_messages*
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "limit": 50
}
```

> **Claude:** Here's the latest agent activity:
>
> **Coordinator**: Let's prioritize the web application testing based on the open ports.
>
> **Reconnaissance**: I found 3 web services. Recommend Playwright scan on 10.0.1.50:443.
>
> **Scanner**: Executing Playwright scan now...
>
> **Analyzer**: Found 2 high-severity issues: missing CSP header and HttpOnly cookie flag...

### Example 6: Export Pentester Report

> **You:** Generate a full penetration test report for 192.168.1.50 with all the raw tool output

> **Claude:** I'll export a comprehensive report with all tool execution details.

*Claude calls: export_pentester_report*
```json
{
  "target": "192.168.1.50",
  "format": "markdown"
}
```

> **Claude:** Here's the penetration test report:
>
> # Penetration Test Tool Execution Report
> **Target:** 192.168.1.50
> **Total Executions:** 12
>
> ## Execution Summary
> | Tool | Target | Status | Exit Code | Duration |
> |------|--------|--------|-----------|----------|
> | nmap | 192.168.1.50 | completed | 0 | 45.2s |
> | nikto | 192.168.1.50 | completed | 0 | 120.5s |
> ...
>
> ## Tool Outputs
> ### nmap - 192.168.1.50
> **Command:** `nmap -sV -sC 192.168.1.50`
> ```
> Starting Nmap 7.94...
> PORT   STATE SERVICE VERSION
> 22/tcp open  ssh     OpenSSH 8.2
> 80/tcp open  http    Apache 2.4.41
> ```

### Example 7: Review Failed Scans

> **You:** Show me only the failed tool executions so I can troubleshoot

> **Claude:** I'll filter for failed executions only.

*Claude calls: export_pentester_report*
```json
{
  "status": "failed",
  "format": "text"
}
```

> **Claude:** Here are the 3 failed tool executions:
>
> 1. **hydra** - 192.168.1.50:22 - Exit code 255
>    Error: `[ERROR] File for logins not found: users.txt`
>
> 2. **nikto** - 192.168.1.50:443 - Exit code 1
>    Error: `SSL connection failed`
>
> Would you like me to help troubleshoot these failures?

## Advanced Usage

### Chain Multiple Operations

Claude can intelligently chain operations:

> **You:** Test all web applications for security issues

Claude will:
1. Call `query_open_ports` to find web services
2. Call `start_web_scan` for each service
3. Call `start_playwright_scan` for browser testing
4. Call `query_vulnerabilities` to summarize results

### Context-Aware Recommendations

> **You:** What should I scan next?

Claude will:
1. Call `query_assets` to see discovered targets
2. Call `query_open_ports` to see services
3. Call `get_scan_recommendations` with context
4. Suggest prioritized scanning strategy

### Continuous Monitoring

> **You:** Keep monitoring the pentest session and tell me when it's done

Claude will:
1. Periodically call `get_session_status`
2. Notify when status changes to "completed"
3. Automatically call `get_session_report`
4. Present the final findings

## Troubleshooting

### MCP Server Not Connecting

**Check service is running:**
```bash
docker ps | grep autogen-agents
docker logs autogen-agents
```

**Test MCP server manually:**
```bash
docker exec -i autogen-agents python /app/mcp_server.py
```

**Verify Docker is accessible:**
```bash
docker exec autogen-agents echo "Connected"
```

### Claude Desktop Not Showing Tools

**Verify config file location:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`

**Check config syntax:**
```bash
cat ~/.config/Claude/claude_desktop_config.json | jq .
```

**Restart Claude Desktop:**
- Completely quit and reopen the application
- Check for MCP indicators in the UI

### Permission Issues

**Docker socket access (Linux):**
```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

**Container permissions:**
```bash
docker exec autogen-agents ls -la /app/
```

## Security Considerations

### Access Control

The MCP server has the same permissions as the autogen-agents container:
- Can start scans on any reachable network
- Has full database access
- Can execute autonomous pentests

**Recommendations:**
1. Only configure MCP on trusted workstations
2. Use network segmentation for scan targets
3. Monitor agent session logs
4. Review autonomous pentest findings before acting

### API Keys

MCP tools use the same API_KEY configured in the service:
- Tools automatically inject the key
- No need to provide keys in MCP calls
- Ensure API_KEY is changed from default

### Audit Trail

All MCP-initiated operations are logged:
```bash
# View agent session logs
docker logs autogen-agents | grep "MCP"

# Query database for session history
docker exec -it rag-postgres psql -U app -d scans \
  -c "SELECT * FROM agent_sessions ORDER BY created_at DESC LIMIT 10;"
```

## Comparison: REST API vs MCP

| Feature | REST API | MCP |
|---------|----------|-----|
| **Access** | HTTP requests | Claude Desktop |
| **Port** | 8015 | stdio |
| **Authentication** | API key header | Container-level |
| **Use Case** | Automation, integrations | AI-assisted testing |
| **Learning Curve** | curl/Postman | Natural language |
| **Async Operations** | Callbacks/polling | Natural polling by AI |
| **Discovery** | Swagger docs | Tool descriptions |

## Best Practices

### For Autonomous Pentests

1. **Clear Target Descriptions**: Provide IP ranges, specific services, or URLs
2. **Descriptive Session Names**: Include date, project name for tracking
3. **Specific Initial Tasks**: Guide the coordinator with clear objectives
4. **Monitor Progress**: Ask Claude to check status periodically
5. **Review Reports**: Always validate AI-generated findings

### For Individual Scans

1. **Start with Reconnaissance**: Query assets and ports first
2. **Progressive Testing**: Start with passive, move to active scans
3. **Context is Key**: Share findings with Claude for better recommendations
4. **Correlate Results**: Ask Claude to compare findings across tools

### For Exploit Research

1. **Be Specific**: Include version numbers in queries
2. **Cross-Reference**: Ask Claude to validate with vulnerability database
3. **Check Applicability**: Discuss if the exploit matches your target

## Integration with Other Tools

### n8n Workflows

Trigger MCP-initiated pentests from n8n:
1. n8n webhook receives alert
2. Calls REST API to start pentest
3. Claude monitors via MCP
4. Reports findings back to n8n

### SIEM Integration

Feed findings to SIEM:
1. Claude queries vulnerabilities via MCP
2. Exports to SIEM-compatible format
3. Creates tickets for high-severity issues

### CI/CD Pipelines

Automated security testing:
1. Deploy application to staging
2. Trigger pentest via REST API
3. Claude monitors and validates findings
4. Block deployment if critical issues found

## Future Enhancements

- **SSE Transport**: Web-based MCP access
- **Authentication**: Per-tool access control
- **Streaming**: Real-time agent message streams
- **Webhooks**: Push notifications for session completion
- **Multi-tenant**: Isolated pentest environments

## References

- [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)
- [Claude Desktop MCP Guide](https://docs.anthropic.com/claude/docs/mcp)
- [Autogen Documentation](https://microsoft.github.io/autogen/)
- [Autogen Agents README](README.md)

## Support

For issues with MCP integration:

1. Check [Troubleshooting](#troubleshooting) section
2. Review Docker logs: `docker logs autogen-agents`
3. Test REST API: `curl http://localhost:8015/health`
4. Verify MCP manually: `docker exec -i autogen-agents python /app/mcp_server.py`
