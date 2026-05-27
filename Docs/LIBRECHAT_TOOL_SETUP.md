# LibreChat Tool Calling Setup

## Current Status

✅ LibreChat running on http://localhost:3001
✅ Ollama endpoint configured (http://ollama:11434/v1)
✅ Models available: llama3.1:8b, qwen2.5:14b, qwen2.5:32b

## Tool Calling Options for LibreChat

LibreChat v0.8.3 supports tools in several ways:

### Option 1: Native Ollama Tool Calling ⭐ **RECOMMENDED**

LibreChat may automatically support Ollama's native function calling with llama3.1:8b.

**How to test:**
1. In LibreChat chat, select **llama3.1:8b**
2. Send a message that would require a tool
3. LibreChat should automatically handle tool calls if the model supports them

**Verification needed**: Does LibreChat 0.8.3 pass tools to Ollama via the `/v1/chat/completions` endpoint?

### Option 2: Custom Actions/Plugins

LibreChat supports adding custom actions via OpenAPI specs.

**To configure via UI:**
1. Settings → **Actions** or **Plugins**
2. Click **"Add Action"**
3. Provide OpenAPI spec URL:
   - Pentest Sessions: `http://mcpo:8080/sessions/openapi.json`
   - Scanning Tools: `http://mcpo:8080/scanning/openapi.json`
   - Recon Tools: `http://mcpo:8080/recon/openapi.json`
   - Exploit Tools: `http://mcpo:8080/exploit/openapi.json`
   - Scan Pipelines: `http://mcpo:8080/pipelines/openapi.json`

**Note**: UI location varies by LibreChat version

### Option 3: MCP Servers (Model Context Protocol)

LibreChat v0.8.3+ has MCP support. Our MCPO servers could be configured as MCP servers.

**Configuration** would go in `librechat.yaml`:
```yaml
mcp:
  servers:
    pentest_sessions:
      command: "docker"
      args: ["exec", "mcp-streamable", "python", "mcp-sessions.py"]
```

## MCPO Tool Server URLs

All accessible from LibreChat container:

| Server | OpenAPI Spec URL | Tool Count |
|--------|------------------|------------|
| Pentest Sessions | http://mcpo:8080/sessions/openapi.json | 17 |
| Scanning Tools | http://mcpo:8080/scanning/openapi.json | 16 |
| Recon Tools | http://mcpo:8080/recon/openapi.json | 9 |
| Exploit Tools | http://mcpo:8080/exploit/openapi.json | 8 |
| Scan Pipelines | http://mcpo:8080/pipelines/openapi.json | 3 |

## Testing Tool Calling

### Test 1: Check if tools are automatically available

In chat, try:
```
What tools do you have access to?
```

If LibreChat has native Ollama tool support, llama3.1:8b should see tools automatically.

### Test 2: Try calling a specific tool

```
Use the check_health tool to check system status
```

or

```
Check the health of all backend services
```

### Test 3: Verify tool was actually called

Check LibreChat logs:
```bash
docker logs librechat 2>&1 | grep -i "tool\|function"
```

Check MCPO logs to see if it received the request:
```bash
docker logs mcpo | tail -20
```

## Next Steps

1. **First**: Test if LibreChat automatically supports Ollama's native tool calling
2. **If not**: Configure tools via UI (Actions/Plugins)
3. **If UI config not available**: Use MCP server configuration
4. **Fallback**: Return to Open WebUI with "Auto" mode (confirmed working)

## Comparison: LibreChat vs Open WebUI

| Feature | LibreChat 0.8.3 | Open WebUI 0.8.3 |
|---------|-----------------|------------------|
| Native Tool Calling | Unknown (testing) | ❌ Broken |
| Prompt-based Tools | Unknown | ✅ Works ("Auto" mode) |
| OpenAPI Integration | ✅ Via Actions | ✅ Via Tool Servers |
| MCP Support | ✅ Yes | ❌ No |
| Ease of Setup | 🤔 Complex | ✅ Simple |

═══════════════════════════════════════════════════════════════

Created: 2026-02-20
