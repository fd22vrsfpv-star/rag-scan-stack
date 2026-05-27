# Open WebUI Tool Calling - WORKING SOLUTION ✅

## The Problem

Open WebUI 0.8.3 has **BROKEN native tool calling** for Ollama:
- Native mode sends tools to Ollama correctly
- Ollama returns tool_calls properly
- BUT Open WebUI doesn't execute them!

## The Solution: Use "Auto" Mode ✅

**"Auto" mode (prompt-based tool calling) WORKS in Open WebUI 0.8.3**

### How to Configure:

1. **Open**: http://localhost:3000

2. **Go to Settings**:
   - Click your profile icon (top right)
   - Settings → Models

3. **Configure llama3.1:8b**:
   - Find llama3.1:8b in the model list
   - Under **"Function Calling"** dropdown
   - Select: **"Auto"** (NOT "Native")
   - Save

4. **Start a New Chat**:
   - Click "New Chat"
   - Select **llama3.1:8b** model
   - Enable tools (🔧 icon)
   - Toggle ON the tool servers you want

5. **Test**:
   ```
   check_health
   ```

## How It Works

**Auto Mode (Prompt-Based)**:
1. Open WebUI adds tool definitions to system prompt
2. Model outputs JSON: `{"name": "check_health", "parameters": {}}`
3. Open WebUI **parses the JSON and executes the tool** ✅
4. Tool result is sent back to model
5. Model generates final response

**Native Mode (BROKEN in 0.8.3)**:
1. Open WebUI sends tools via Ollama API
2. Model returns proper tool_calls
3. Open WebUI **ignores them and does nothing** ❌

## Configuration Summary

```yaml
# docker-compose.yml for Open WebUI
environment:
  - DEFAULT_MODELS=llama3.1:8b
  - TOOLS_FUNCTION_CALLING_PROMPT_TEMPLATE=  # Empty = allow both modes
  - ENABLE_TOOLS=true
```

**Per-Model Setting** (most important):
- Settings → Models → llama3.1:8b
- Function Calling: **Auto** ✅

## Tool Servers

Open WebUI should have loaded these:
- ✅ Pentest Sessions (17 tools)
- ✅ Scanning Tools (16 tools)
- ✅ Recon Tools (9 tools)
- ✅ Exploit Tools (8 tools)
- ✅ Scan Pipelines (3 tools)

Total: 50+ tools available

## Expected Behavior

When you send `check_health`:

```
[User] check_health

[Model thinks and outputs JSON]
{"name": "tool_check_health_post", "parameters": {}}

[Open WebUI executes the tool]
Calling http://mcpo:8080/sessions/check_health...

[Tool returns result]
{"status": "healthy", "services": [...]}

[Model generates response]
"The system health check shows all services are running normally..."
```

## Troubleshooting

### Tools not being called?

1. **Check Function Calling mode**:
   ```bash
   # Should be "Auto" not "Native"
   Settings → Models → llama3.1:8b → Function Calling: Auto
   ```

2. **Check tools are enabled**:
   - Click 🔧 icon in chat
   - Verify tool servers show green/enabled

3. **Check tool servers loaded**:
   ```bash
   docker logs open-webui 2>&1 | grep "Initialized.*tool"
   # Should show: Initialized 5 tool server(s)
   ```

4. **Try reducing tool count**:
   - Disable all but Pentest Sessions
   - Reduces from 50 to 17 tools
   - Makes it easier for model to choose

### Model still explaining instead of calling?

- Make sure you're in a **NEW chat** (not old one with cached prompts)
- **Clear system prompt** (Settings → check for custom prompts)
- Try explicit command: `Use the check_health tool now`

## References

- GitHub Issue #12161: Native tool calling doesn't execute tools
- Open WebUI Discussions: "Auto" mode works, "Native" mode broken in 0.8.3
- Ollama docs: llama3.1:8b has excellent native tool calling support

═══════════════════════════════════════════════════════════════

Last Updated: 2026-02-20
