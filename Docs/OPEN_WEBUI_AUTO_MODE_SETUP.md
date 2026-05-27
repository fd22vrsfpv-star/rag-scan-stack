# Open WebUI Tool Calling - Auto Mode Setup Guide

## Why Auto Mode Works

Open WebUI 0.8.3 has two tool calling modes:

| Mode | How It Works | Status |
|------|--------------|--------|
| **Native** | Sends tools via Ollama API, model returns tool_calls | ❌ **BROKEN** - Open WebUI receives tool_calls but doesn't execute them |
| **Auto** | Adds tools to system prompt, model outputs JSON | ✅ **WORKS** - Open WebUI parses JSON and executes tools |

## Step-by-Step Setup

### 1. Access Open WebUI

Open: **http://localhost:3000**

### 2. Go to Model Settings

- Click your **profile icon** (top right corner)
- Select **"Settings"**
- Go to **"Models"** tab

### 3. Configure llama3.1:8b

Find **llama3.1:8b** in the model list:

- Look for **"Function Calling"** dropdown
- Change from **"Native"** to **"Auto"**
- Click **"Save"** or apply changes

### 4. Verify Tool Servers Are Loaded

Check that Open WebUI loaded the tool servers:

```bash
docker logs open-webui 2>&1 | grep "Initialized.*tool"
```

Should show: `Initialized 5 tool server(s)`

### 5. Start a Fresh Chat

- Click **"New Chat"**
- Ensure **llama3.1:8b** is selected at top
- **Important**: Don't use old chats - they have cached prompts

### 6. Enable Tools

- Look for **🔧 Tools icon** (usually near message input or top toolbar)
- Click it to open tools panel
- **Toggle ON** the tool servers you want:
  - ✅ Pentest Sessions (17 tools)
  - ✅ Scanning Tools (16 tools)
  - ✅ Recon Tools (9 tools)
  - ✅ Exploit Tools (8 tools)
  - ✅ Scan Pipelines (3 tools)

### 7. Test Tool Calling

Send a simple test:
```
check_health
```

**Expected Behavior**:
1. Model outputs JSON: `{"name": "tool_check_health_post", "parameters": {}}`
2. Open WebUI parses the JSON
3. Open WebUI calls: `http://mcpo:8080/sessions/check_health`
4. Tool returns result
5. Model generates final response with the result

### 8. Monitor Logs (Optional)

In another terminal, watch for tool execution:

```bash
# Watch Open WebUI logs
docker logs -f open-webui

# Watch MCPO receive requests
docker logs -f mcpo
```

## Troubleshooting

### Issue: "50 tools provided but model returned text only"

**Cause**: Function Calling is still set to "Native"

**Fix**:
1. Settings → Models → llama3.1:8b
2. Change to **"Auto"**
3. Start **NEW** chat

### Issue: Model explains tool instead of calling it

**Causes**:
- Custom system prompt interfering
- Old chat with cached prompts
- Too many tools (50+) overwhelming the model

**Fixes**:
1. Check for custom system prompts - **clear them**
2. Use a **brand new chat**
3. Disable some tool servers to reduce from 50 to ~17 tools

### Issue: Tools not showing in UI

**Cause**: Tool servers didn't load

**Fix**:
```bash
# Check logs
docker logs open-webui 2>&1 | grep -i "tool server"

# Should show 5 tool servers loaded
# If showing 0, restart Open WebUI:
docker-compose restart open-webui
```

### Issue: Custom system prompt won't clear

**Fix**: Start a completely new chat - don't edit existing ones

## Current Configuration

**File**: `/opt/rag_scan_stack/docker-compose.yml`

```yaml
open-webui:
  environment:
    - DEFAULT_MODELS=llama3.1:8b
    - TOOLS_FUNCTION_CALLING_PROMPT_TEMPLATE=  # Empty = allows both modes
    - ENABLE_TOOLS=true
    - TOOL_SERVER_CONNECTIONS=[...5 tool servers...]
```

**Per-Model Setting** (in UI):
- llama3.1:8b → Function Calling: **Auto** ✅

## Available Tools (Total: 53)

### Pentest Sessions (17 tools)
- check_health, echo, add, get_time
- start_pentest_session, get_session_status, list_sessions
- query_assets, query_open_ports, query_findings
- cleanup_findings, cleanup_old_sessions
- etc.

### Scanning Tools (16 tools)
- start_masscan, start_nmap_scan, start_naabu
- start_nuclei_scan, start_web_scan
- start_httpx_probe, start_katana
- get_job_status for various scanners
- get_all_active_jobs

### Recon Tools (9 tools)
- subfinder, dnsx, asnmap
- uncover, cloudlist, alterx, mapcidr

### Exploit Tools (8 tools)
- search_exploits, get_metasploit_modules
- run_metasploit_exploit
- get_exploitdb_scripts

### Scan Pipelines (3 tools)
- start_full_port_scan
- start_web_pipeline
- get_pipeline_status

## Success Criteria

When working correctly, you should see:

1. **In UI**: Tools toggle showing enabled (green)
2. **In logs**: `✅ 50 TOOLS:` (not `⚠️ NO TOOLS IN REQUEST`)
3. **Model behavior**: Outputs JSON, not explanations
4. **Tool execution**: Actual HTTP calls to MCPO
5. **Results**: Model receives tool output and responds with it

═══════════════════════════════════════════════════════════════

Last Updated: 2026-02-20
Status: Ready to test
