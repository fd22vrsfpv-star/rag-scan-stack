# Open WebUI Setup for RAG-Scan-Stack

This guide covers setting up Open WebUI as an interface for the RAG-Scan-Stack penetration testing toolkit.

## Overview

Open WebUI provides a web-based chat interface that connects to Ollama and can execute custom tools. This setup enables:

- Chat with local LLMs (qwen2.5, llama3, mistral, etc.)
- Execute 32+ pentest tools via natural language
- Query scan results and exploit databases
- Control AI-powered autonomous pentest sessions

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Open WebUI    │────▶│     Ollama      │     │   RAG-Scan-     │
│  (Port 3000)    │     │  (Port 11434)   │     │     Stack       │
└────────┬────────┘     └─────────────────┘     └────────┬────────┘
         │                                               │
         │              ┌─────────────────┐              │
         └─────────────▶│  Custom Tools   │◀─────────────┘
                        │  (HTTP calls)   │
                        └─────────────────┘
```

## Quick Start

### 1. Start Services

```bash
docker compose up -d open-webui mcp-server mcp-test
```

### 2. Access Open WebUI

Open http://localhost:3000 in your browser.

### 3. Create Account

First user becomes admin. Authentication is disabled but an account is required.

### 4. Configure Ollama Connection

1. Go to **Settings** (gear icon) → **Admin Settings** → **Connections**
2. Set Ollama URL: `http://host.docker.internal:11434`
3. Click **Verify Connection**

If verification fails, try your WSL2 IP instead:
```bash
hostname -I | awk '{print $1}'
# Use: http://<WSL2-IP>:11434
```

### 5. Import Tools

1. Go to **Workspace** → **Tools**
2. Click **"+"** to create new tool
3. Download tool code: http://localhost:9999/all_tools.py
4. Paste entire content into the editor
5. Click **Save**

### 6. Set System Prompt

Go to **Workspace** → **Models** → Select your model → **Edit** → Set system prompt:

```
You are a penetration testing assistant with access to the RAG-Scan-Stack toolset. You help security professionals conduct authorized penetration tests.

## Available Tools

**Scanning:**
- `start_nmap_scan(target, scan_type)` - Port scan (target: IP/CIDR, scan_type: default/quick/full/stealth)
- `start_nuclei_scan(target)` - Vulnerability scan (target: URL)
- `start_web_scan(target_url)` - Web app scan with Gobuster + ZAP

**Results:**
- `query_ports()` - Get discovered ports/services
- `query_findings()` - Get vulnerability findings
- `get_active_jobs()` - Check running scan status

**Exploits:**
- `search_exploits(query)` - Search exploit database (e.g., "Apache RCE")
- `run_msf_module(module_path, rhosts)` - Run Metasploit module
- `list_msf_sessions()` - List active shells/meterpreter

**AI Pentest:**
- `start_pentest_session(session_name, target, task)` - Start autonomous AI pentest
- `get_session_status(session_id)` - Check AI session status
- `list_sessions()` - List all AI sessions

**Health:**
- `check_health()` - Check all service status

## Workflow

1. **Recon**: Start with `start_nmap_scan` to find open ports
2. **Enumerate**: Use `query_ports` to review results
3. **Vuln Scan**: Run `start_nuclei_scan` on web services
4. **Research**: Use `search_exploits` to find relevant exploits
5. **Exploit**: Use `run_msf_module` for authorized testing

## Rules
- Always confirm authorization before scanning/exploiting
- Check `get_active_jobs` before starting new scans
- Use tools proactively - don't just describe what you would do
- Report findings clearly with severity levels
```

## Tool Reference

### Utilities

| Tool | Parameters | Description |
|------|------------|-------------|
| `echo` | `message` | Echo back a message (test tool calling) |
| `get_time` | - | Get current server time |
| `add` | `a`, `b` | Add two numbers |
| `check_health` | - | Check all service health status |

### Scanning Tools

| Tool | Parameters | Description |
|------|------------|-------------|
| `start_nmap_scan` | `target`, `scan_type`, `ports` | Start Nmap port scan |
| `start_masscan` | `target`, `ports`, `rate` | Fast port discovery |
| `start_nuclei_scan` | `target`, `severity` | Vulnerability scan |
| `start_web_scan` | `target_url`, `wordlist` | Web app scan (Gobuster + ZAP) |
| `start_playwright_scan` | `target_url` | Browser-based security scan |

**Scan Types for Nmap:**
- `default` - Standard scan
- `quick` - Fast scan, common ports only
- `full` - All ports, service detection
- `stealth` - SYN scan, less detectable
- `udp` - UDP port scan

### Scan Status

| Tool | Parameters | Description |
|------|------------|-------------|
| `get_nmap_status` | `job_id` | Get Nmap/Masscan job status |
| `get_nuclei_status` | `job_id` | Get Nuclei job status |
| `get_web_scan_status` | `job_id` | Get web scan status |
| `get_active_jobs` | - | Get all active jobs |

### Database Queries

| Tool | Parameters | Description |
|------|------------|-------------|
| `query_ports` | `target` (optional) | Query discovered ports |
| `query_findings` | `severity`, `target` | Query vulnerability findings |
| `query_assets` | `asset_type` | Query discovered assets |

**Severity Levels:** `info`, `low`, `medium`, `high`, `critical`

### Exploit Search

| Tool | Parameters | Description |
|------|------------|-------------|
| `search_exploits` | `query`, `limit` | Semantic search for exploits |
| `search_exploits_enhanced` | `query`, `keywords` | Enhanced search with keywords |

**Example Queries:**
- "Apache remote code execution"
- "SSH authentication bypass"
- "SMB vulnerability Windows"
- "FTP anonymous login"

### Metasploit Tools

| Tool | Parameters | Description |
|------|------------|-------------|
| `run_msf_module` | `module_path`, `rhosts`, `rport`, `payload` | Run MSF module |
| `run_edb_script` | `edb_id`, `target`, `options` | Run ExploitDB script |
| `list_msf_sessions` | - | List active sessions |
| `run_session_command` | `session_id`, `command` | Execute command in session |
| `list_msf_jobs` | - | List running MSF jobs |
| `get_msf_status` | - | Get MSF framework status |

**Example Module Paths:**
- `exploit/unix/ftp/vsftpd_234_backdoor`
- `exploit/multi/http/apache_mod_cgi_bash_env_exec`
- `auxiliary/scanner/smb/smb_version`

### AI Pentest Sessions

| Tool | Parameters | Description |
|------|------------|-------------|
| `start_pentest_session` | `session_name`, `target`, `task` | Start AI pentest |
| `get_session_status` | `session_id` | Get session status |
| `get_session_messages` | `session_id` | Get conversation history |
| `list_sessions` | `status` | List all sessions |
| `stop_session` | `session_id` | Stop running session |

**Session Statuses:** `active`, `completed`, `failed`, `stopped`

### Recommendations

| Tool | Parameters | Description |
|------|------------|-------------|
| `get_recommendation` | `target` (optional) | Get AI-powered next steps |

## Usage Examples

### Basic Tool Test
```
User: What time is it?
Assistant: [calls get_time()] Current time: 2026-02-02T02:30:45.123456
```

### Port Scanning
```
User: Scan 192.168.1.150 for open ports
Assistant: [calls start_nmap_scan(target="192.168.1.150", scan_type="default")]
Started Nmap scan, job ID: abc123...

User: What's the status?
Assistant: [calls get_nmap_status(job_id="abc123")]
Scan complete. Found ports: 21 (ftp), 22 (ssh), 80 (http), 443 (https)...
```

### Vulnerability Scanning
```
User: Scan http://192.168.1.150 for vulnerabilities
Assistant: [calls start_nuclei_scan(target="http://192.168.1.150")]
Started Nuclei scan...

User: Show me high severity findings
Assistant: [calls query_findings(severity="high")]
Found 3 high severity vulnerabilities...
```

### Exploit Research
```
User: Find exploits for vsftpd
Assistant: [calls search_exploits(query="vsftpd backdoor")]
Found: EDB-17491 - vsftpd 2.3.4 Backdoor Command Execution
       MSF: exploit/unix/ftp/vsftpd_234_backdoor
```

### Running Exploits
```
User: Try the vsftpd backdoor exploit on 192.168.1.150
Assistant: [calls run_msf_module(module_path="exploit/unix/ftp/vsftpd_234_backdoor", rhosts="192.168.1.150")]
Exploit launched...

User: Do we have a session?
Assistant: [calls list_msf_sessions()]
Session 1: Shell (192.168.1.150:6200)
```

### AI Pentest Session
```
User: Start an autonomous pentest of 192.168.1.150
Assistant: [calls start_pentest_session(session_name="test1", target="192.168.1.150", task="Perform full reconnaissance and identify vulnerabilities")]
Started session: abc-123-def...

User: What's happening?
Assistant: [calls get_session_status(session_id="abc-123-def")]
Status: active, Round: 5/30, Currently running Nmap scan...
```

## Recommended Models

| Model | Size | Tool Support | Notes |
|-------|------|--------------|-------|
| `qwen2.5:32b` | 20GB | Excellent | Best for complex tasks |
| `qwen2.5:14b` | 9GB | Good | Good balance |
| `qwen2.5:7b` | 4GB | Good | Lighter weight |
| `llama3.1:8b` | 5GB | Good | Fast responses |
| `mistral:7b` | 4GB | Good | Reliable |

## Troubleshooting

### Tools not being called

1. **Check tool is imported**: Workspace → Tools → Verify tool is listed
2. **Check model supports tools**: Use qwen2.5, llama3.1, or mistral
3. **Be explicit**: "Use the start_nmap_scan tool to scan 192.168.1.1"
4. **Check tool is enabled for chat**: Click settings in chat, enable tools

### Ollama connection failed

1. **Check Ollama is running**: `ollama list` in PowerShell
2. **Try WSL2 IP**: `hostname -I` in WSL, use that IP
3. **Check firewall**: Ensure port 11434 is accessible

### Services unreachable

1. **Check containers**: `docker compose ps`
2. **Check logs**: `docker logs <service-name>`
3. **Restart services**: `docker compose restart`

### Tool returns error

1. **Check service health**: Use `check_health()` tool
2. **Check specific service**: `docker logs nmap_scanner`
3. **Verify network**: Services must be on `agents_net` network

## Files Reference

| File | Description |
|------|-------------|
| `/opt/rag-scan-stack/open-webui/tools/all_tools.py` | Complete tool set (32 tools) |
| `/opt/rag-scan-stack/open-webui/tools/test_tools.py` | Simple test tools |
| `/opt/rag-scan-stack/open-webui/tools/pentest_tools.py` | Core pentest tools |
| `/opt/rag-scan-stack/docker-compose.yml` | Docker configuration |

## Service Ports

| Service | Port | Description |
|---------|------|-------------|
| Open WebUI | 3000 | Web interface |
| Ollama | 11434 | LLM API (on Windows host) |
| MCP Server | 8016 | MCP tools endpoint |
| MCP Test | 8020 | Test MCP server |
| Autogen Agents | 8015 | AI pentest sessions |
| RAG API | 8000 | Exploit search API |
| Nmap Scanner | 8012 | Port scanning |
| Nuclei Runner | 8011 | Vulnerability scanning |
| Web Scanner | 8010 | Web app scanning |
| Exploit Runner | 8017 | Metasploit interface |

## Security Notes

- Only use against authorized targets
- Open WebUI has authentication disabled by default
- Tools execute real scans and exploits
- Session data is stored in Docker volumes
- API keys should be changed in production
