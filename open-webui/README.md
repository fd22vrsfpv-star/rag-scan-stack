# Open WebUI Setup for RAG-Scan-Stack

## Access

Open WebUI is available at: **http://localhost:3000**

## Initial Setup

1. **Create an account** (first user becomes admin, auth is disabled but account needed)

2. **Verify Ollama connection:**
   - Go to **Settings (gear icon) → Admin Settings → Connections**
   - Ollama URL should be: `http://host.docker.internal:11434`
   - Click "Verify Connection" to test
   - If it fails, try using your WSL2 IP instead (run `hostname -I` in WSL)

3. **Select a model:**
   - In Settings, set default model to `qwen2.5:32b` (or your preferred model)
   - Models with good tool support: qwen2.5, llama3.1, mistral

## Importing Pentest Tools

Open WebUI uses "Tools" (formerly Functions) for tool calling. Import our tools:

### Option 1: Import via UI

1. Go to **Workspace → Tools**
2. Click **"+"** to create a new tool
3. Copy the content from one of these files:
   - `/opt/rag-scan-stack/open-webui/tools/pentest_tools.py` - Full pentest tools
   - `/opt/rag-scan-stack/open-webui/tools/test_tools.py` - Simple test tools

4. Paste the code and save

### Option 2: Use Pre-made Tool JSON

Import from Open WebUI's community tools or create custom ones.

## Available Tools

### Test Tools (test_tools.py)
- `echo_message` - Echo back a message (test basic tool calling)
- `get_current_time` - Get current server time
- `add_numbers` - Add two numbers
- `greet_person` - Generate a greeting
- `check_mcp_test_server` - Check MCP test server health
- `check_all_services` - Check all RAG-Scan-Stack services

### Pentest Tools (pentest_tools.py)
- `check_mcp_health` - Check MCP server status
- `start_nmap_scan` - Start port scanning
- `start_nuclei_scan` - Start vulnerability scanning
- `start_web_scan` - Start web app scanning
- `search_exploits` - Search exploit database (RAG)
- `query_open_ports` - Query discovered ports
- `query_findings` - Query vulnerability findings
- `run_msf_module` - Run Metasploit module
- `list_msf_sessions` - List active sessions
- `run_session_command` - Execute session command
- `start_pentest_session` - Start AI pentest session
- `get_session_status` - Get session status
- `list_sessions` - List all sessions
- `get_all_active_jobs` - Get active scan jobs
- `get_scan_recommendation` - Get AI recommendations

## Testing Tool Calling

1. Import `test_tools.py` first
2. Start a new chat
3. Try these prompts:
   - "What time is it?" (should call `get_current_time`)
   - "Add 5 and 7" (should call `add_numbers`)
   - "Say hello to John" (should call `greet_person`)
   - "Check all services" (should call `check_all_services`)

## Troubleshooting

### Tools not being called
- Make sure the model supports tool calling (qwen2.5, llama3.1, mistral)
- Check that tools are enabled in chat settings
- Try being explicit: "Use the add_numbers tool to add 5 and 7"

### Ollama connection failed
- Try using WSL2 IP: `http://172.23.20.74:11434`
- Make sure Ollama is running on Windows
- Check firewall settings

### Services unreachable
- Run `docker compose ps` to check service status
- Check logs: `docker logs <service-name>`
