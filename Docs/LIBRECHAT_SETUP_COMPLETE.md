# LibreChat Setup Guide - Tool Integration Complete

## Status: ✅ Ready to Use

LibreChat is now fully configured and running on **http://localhost:3001** with access to all pentesting tools.

## Configuration Summary

**LibreChat Version**: 0.8.3 (latest)
**Ollama Models Available**: llama3.1:8b, qwen2.5:14b, qwen2.5:32b
**Tool Servers**: MCPO (OpenAPI) + MCP Streamable (Native MCP)

### What's Configured:

✅ LibreChat + MongoDB containers running
✅ Ollama endpoint configured (http://ollama:11434/v1)
✅ All 3 models accessible
✅ Domain allowlists configured for:
   - `mcpSettings.allowedDomains` (for MCP servers)
   - `actions.allowedDomains` (for OpenAPI actions)
✅ Internal services whitelisted:
   - MCPO: http://mcpo:8080
   - MCP Streamable: http://mcp-streamable:9016-9021

---

## How to Add Tools in LibreChat

### Option A: Using MCPO (OpenAPI Actions) - Recommended

MCPO provides a single unified OpenAPI interface to all tools.

**Steps:**
1. Open **http://localhost:3001**
2. Log in to your account
3. Click **profile icon** → **Settings**
4. Navigate to **Actions** or **Assistants**
5. Click **"Add Action"**
6. Enter OpenAPI spec URL:
   ```
   http://mcpo:8080/sessions/openapi.json
   ```
7. Save and enable the action

**Available MCPO Endpoints:**

| Service | OpenAPI Spec URL | Tools |
|---------|------------------|-------|
| Pentest Sessions | `http://mcpo:8080/sessions/openapi.json` | 17 |
| Scanning Tools | `http://mcpo:8080/scanning/openapi.json` | 16 |
| Recon Tools | `http://mcpo:8080/recon/openapi.json` | 9 |
| Exploit Tools | `http://mcpo:8080/exploit/openapi.json` | 8 |
| Scan Pipelines | `http://mcpo:8080/pipelines/openapi.json` | 3 |

**Total**: 53 tools via MCPO

---

### Option B: Using Native MCP Servers

MCP Streamable servers provide native MCP protocol support.

**Steps:**
1. Open **http://localhost:3001**
2. Log in to your account
3. Click **profile icon** → **Settings**
4. Navigate to **MCP Servers**
5. Click **"Add MCP Server"**
6. Enter server details:

**Sessions Server** (17 tools):
```
Name: Pentest Sessions
URL: http://mcp-streamable:9016/mcp
Type: streamable-http
```

**Scanning Server** (16 tools):
```
Name: Scanning Tools
URL: http://mcp-streamable:9017/mcp
Type: streamable-http
```

**Recon Server** (9 tools):
```
Name: Recon Tools
URL: http://mcp-streamable:9018/mcp
Type: streamable-http
```

**Exploit Server** (8 tools):
```
Name: Exploit Tools
URL: http://mcp-streamable:9019/mcp
Type: streamable-http
```

**Credentials Server** (2 tools):
```
Name: Credentials Testing
URL: http://mcp-streamable:9020/mcp
Type: streamable-http
```

**Pipelines Server** (3 tools):
```
Name: Scan Pipelines
URL: http://mcp-streamable:9021/mcp
Type: streamable-http
```

**Total**: 55 tools via MCP Streamable

---

## Testing Tool Access

### Test 1: Simple Health Check
In a new chat, send:
```
check_health
```

Expected: Model calls the tool and returns system health status.

### Test 2: List Sessions
```
list all pentest sessions
```

Expected: Model calls `list_sessions` tool and shows results.

### Test 3: Start a Scan
```
Start a quick port scan on 192.168.1.1
```

Expected: Model uses scanning tools to initiate the scan.

---

## Tool Categories Overview

### 1. Pentest Sessions (17 tools)
- `start_pentest_session` - Launch autonomous AI pentest
- `get_session_status` - Check session progress
- `list_sessions` - List all sessions
- `query_assets`, `query_open_ports`, `query_findings` - Data retrieval
- `cleanup_findings`, `cleanup_old_sessions` - Maintenance
- `check_health`, `echo`, `add`, `get_time` - Utilities

### 2. Scanning Tools (16 tools)
- `start_masscan` - Fast port scanner
- `start_nmap_scan` - Detailed network scanner
- `start_naabu` - Port discovery
- `start_nuclei_scan` - Vulnerability scanner
- `start_web_scan` - Web application scanner
- `start_httpx_probe` - HTTP probing
- `start_katana` - Web crawling
- `start_playwright_scan` - Browser-based scanning
- `start_tlsx` - TLS/SSL scanning
- Various `get_*_status` tools for job monitoring
- `get_all_active_jobs` - View all running scans

### 3. Recon Tools (9 tools)
- `subfinder` - Subdomain enumeration
- `dnsx` - DNS resolver and validation
- `asnmap` - ASN enumeration
- `uncover` - Exposure detection
- `cloudlist` - Cloud asset discovery
- `alterx` - Subdomain permutation
- `mapcidr` - CIDR manipulation

### 4. Exploit Tools (8 tools)
- `search_exploits` - Search exploit databases
- `get_metasploit_modules` - List Metasploit modules
- `run_metasploit_exploit` - Execute exploits
- `get_exploitdb_scripts` - Retrieve ExploitDB scripts

### 5. Credentials Testing (2 tools)
- `test_credentials_brutus` - Credential testing
- `get_brutus_job_status` - Job status

### 6. Scan Pipelines (3 tools)
- `start_full_port_scan` - Comprehensive port scanning pipeline
- `start_web_pipeline` - Full web application assessment
- `get_pipeline_status` - Pipeline status monitoring

---

## Configuration Files

### librechat.yaml
Located at: `/opt/rag_scan_stack/librechat/librechat.yaml`

Key sections:
```yaml
endpoints:
  custom:
    - name: "Ollama"
      apiKey: "ollama"
      baseURL: "http://ollama:11434/v1"
      models:
        default: ["llama3.1:8b", "qwen2.5:14b", "qwen2.5:32b"]

actions:
  allowedDomains:
    - "http://mcpo:8080"
    - "mcpo:8080"
    - "mcpo"
    - "http://mcp-streamable:9016"
    - "http://mcp-streamable:9017"
    - ... (all MCP ports)

mcpSettings:
  allowedDomains:
    - "http://mcpo:8080"
    - "mcpo:8080"
    - "mcpo"
    - "http://mcp-streamable:9016"
    - "http://mcp-streamable:9017"
    - ... (all MCP ports)
```

### .env
Located at: `/opt/rag_scan_stack/librechat/.env`

Key variables:
```bash
MONGO_URI=mongodb://mongodb:27017/LibreChat
OLLAMA_BASE_URL=http://ollama:11434
APP_TITLE=LibreChat Pentest Assistant
DOMAIN_CLIENT=http://localhost:3001
DOMAIN_SERVER=http://localhost:3001
ENDPOINTS=ollama
OLLAMA_MODELS=llama3.1:8b,qwen2.5:14b,qwen2.5:32b
```

---

## Troubleshooting

### Issue: "Domain not in approved list"

**Cause**: Internal services blocked by SSRF protection

**Fix**: Already configured! Both `actions.allowedDomains` and `mcpSettings.allowedDomains` are set.

### Issue: Models not showing in UI

**Cause**: Ollama endpoint misconfigured

**Fix**: Already configured! librechat.yaml has proper Ollama endpoint.

### Issue: Tools not executing

**Cause**: Model not supporting tool calling properly

**Solution**: Use **llama3.1:8b** (best tool calling support) instead of qwen models.

### Issue: Authentication loops

**Cause**: Missing session secrets

**Fix**: Already configured! All JWT secrets and session keys are set in .env.

---

## Architecture

```
┌──────────────┐
│  LibreChat   │ (Port 3001)
│   (UI/API)   │
└──────┬───────┘
       │
       ├─────────────────┐
       │                 │
       ▼                 ▼
┌─────────────┐   ┌──────────────┐
│   Ollama    │   │     MCPO     │ (Port 8080)
│ (3 models)  │   │   (OpenAPI)  │
└─────────────┘   └──────┬───────┘
                         │
                         ▼
                  ┌──────────────────┐
                  │  MCP Streamable  │ (Ports 9016-9021)
                  │  (6 MCP Servers) │
                  └──────┬───────────┘
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   ┌─────────┐    ┌──────────┐    ┌──────────┐
   │  Nmap   │    │  Nuclei  │    │ Exploit  │
   │ Scanner │    │  Runner  │    │  Runner  │
   └─────────┘    └──────────┘    └──────────┘
        ... (15 more backend services)
```

---

## Quick Start Commands

**Restart LibreChat:**
```bash
cd /opt/rag_scan_stack/librechat
docker-compose restart
```

**View Logs:**
```bash
docker logs librechat -f
```

**Check Configuration:**
```bash
docker logs librechat 2>&1 | grep -A 30 "mcpSettings"
```

**Stop LibreChat:**
```bash
cd /opt/rag_scan_stack/librechat
docker-compose down
```

**Full Rebuild:**
```bash
cd /opt/rag_scan_stack/librechat
docker-compose down -v
docker-compose up -d
```

---

## Comparison: LibreChat vs Open WebUI

| Feature | LibreChat | Open WebUI |
|---------|-----------|------------|
| **Tool Calling** | ✅ Via Actions (OpenAPI) or MCP | ⚠️ Native broken, Auto mode works |
| **MCP Support** | ✅ Native MCP servers | ❌ No |
| **Ease of Setup** | 🟡 Complex (requires yaml config) | ✅ Simple (UI-based) |
| **OpenAPI Support** | ✅ Via Actions | ✅ Via Tool Servers |
| **Model Support** | ✅ Multiple endpoints | ✅ Multiple models |
| **UI Polish** | ✅ ChatGPT-like | ✅ Modern |
| **Configuration** | 🟡 File-based (yaml + env) | ✅ UI + env vars |

**Recommendation**:
- Use **LibreChat** for MCP-native tools and Actions
- Use **Open WebUI** with "Auto" mode if LibreChat tool calling has issues

---

## Next Steps

1. ✅ LibreChat is running
2. ✅ Domain allowlists configured
3. ✅ Ollama models available
4. 🔲 Add Actions or MCP Servers in UI
5. 🔲 Test with `check_health`
6. 🔲 Start pentesting!

---

**Documentation Updated**: 2026-02-20
**Status**: Production Ready
**Access**: http://localhost:3001
