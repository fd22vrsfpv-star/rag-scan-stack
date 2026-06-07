# Tool Calling & Model Selection Guide

The stack's Open WebUI surface (port 3000) lets you invoke pentest tools through natural-language chat — but that only works when the model you've selected actually supports **native tool / function calling** (returning a `tool_calls` field on the response) and when Open WebUI is configured to use that native path rather than prompt-based fallback.

This guide documents the working configuration and the model-selection trade-offs that matter for tool calling. It supersedes the original "qwen2.5 doesn't tool-call" narrative — the stack's default model is now `gemma4:31b`, and the surrounding Open WebUI configuration described here is what wires it to the tool servers.

## Current default

`docker-compose.yml` defaults `OLLAMA_MODEL` to **`gemma4:31b`** in six places (scan-recommender, autogen-agents, ollama-init pull list, llm_query, pentest-dashboard, and the default for unset env). The `./scripts/setup.sh` Phase 8 step auto-pulls it on first run.

To override: set `OLLAMA_MODEL=<your-choice>` in `.env`. Every service in the stack reads the same variable, so a single change cascades.

## Open WebUI configuration

Tool calling only works end-to-end when these three are correct:

```yaml
# docker-compose.yml (or .env-driven)

# 1. Pick a model that actually supports tool calling natively
- OLLAMA_MODEL=${OLLAMA_MODEL:-gemma4:31b}

# 2. Disable prompt-based fallback so Open WebUI uses the model's
#    native tool_calls API rather than instructing it to emit JSON
#    in the chat body.  Empty string = native path.
- TOOLS_FUNCTION_CALLING_PROMPT_TEMPLATE=

# 3. Tool server connections include the FULL path on the URL
#    field; there is no separate `path` key.
- TOOL_SERVER_CONNECTIONS=[
    {"type":"openapi","url":"http://mcpo:8080/sessions"},
    {"type":"openapi","url":"http://mcpo:8080/scanning"},
    {"type":"openapi","url":"http://mcpo:8080/recon"},
    {"type":"openapi","url":"http://mcpo:8080/exploit"},
    {"type":"openapi","url":"http://mcpo:8080/pipelines"}
  ]
```

The `url` field must include the segment where MCPO exposes the OpenAPI spec at `{url}/openapi.json` (e.g. `http://mcpo:8080/sessions/openapi.json`). Splitting URL + path across two keys was a previous source of confusion; it does not work.

## Model comparison

Tool-calling support varies by model family. Updated for the current Ollama library:

| Model | Tool calling | Approx size | Notes |
|---|---|---|---|
| **`gemma4:31b`** ⭐ | ✅ Native, reliable | ~20 GB | Current stack default. Strong general-purpose; tool calls return cleanly. |
| `gemma4:9b` | ✅ Native, reliable | ~6 GB | Smaller gemma4; recommended on 16 GB hosts. |
| `llama3.3:70b` | ✅ Native, reliable | ~40 GB | Higher quality for hosts with ≥ 64 GB RAM. |
| `llama3.1:8b` | ✅ Native, reliable | ~5 GB | Was the prior default; still works. |
| `mistral:7b` | ✅ Native, reliable | ~4 GB | Fast and competent for smaller hosts. |
| `qwen3:4b` | ✅ Native, reliable | ~3 GB | Lightest practical option. |
| `qwen2.5:14b` | ❌ Poor | ~9 GB | **Avoid for tool calling.** Treats tool definitions as prose. Was the source of the prior "Thai-language response / explains the tool instead of calling it" bug. |
| `qwen2.5:32b` | ⚠️ Limited | ~19 GB | Same family limitations as 14b at larger scale. Text generation only. |
| `qwen3-vl:30b` | ✅ Native, reliable | ~18 GB | Newer Qwen 3 series VL; works for text + tool calls. |
| `deepseek-v4-flash:cloud` | ✅ Routed | n/a | Cloud-routed; check account quota before relying on it. |

The cutoff between "works" and "doesn't work" tends to be the model family's release vintage, not the parameter count — Qwen 2.5 had broken tool-call support across the family; Qwen 3.x fixed it. Gemma 3 introduced native tool calls; Gemma 4 carries that forward.

## Using tool calling in Open WebUI

1. Open the dashboard at `http://localhost:3000`.
2. New chat → model dropdown → select `gemma4:31b` (or another model from the ✅ rows above).
3. Click the 🔧 **Tools** icon in the chat input.
4. Toggle on the tool servers you want available:
   - Pentest Sessions (17 tools)
   - Scanning Tools (16 tools)
   - Recon Tools (9 tools)
   - Exploit Tools (8 tools)
   - Scan Pipelines (3 tools)
5. Tool-calling **mode** should be `Auto` so the model decides when to call.
6. Try an explicit command:
   ```
   check_health
   list sessions
   start pentest session on 192.168.1.100 named demo
   scan 192.168.1.100 ports 1-1000
   ```

## Troubleshooting

**Model is explaining the tool instead of calling it** — you've selected one of the ❌ models above. Switch to a ✅ row.

**Open WebUI says "N tools provided but model returned text only"** — usually means `TOOLS_FUNCTION_CALLING_PROMPT_TEMPLATE` is set to `auto` (prompt-based fallback). Fix:

```bash
docker exec open-webui env | grep TOOLS_FUNCTION_CALLING_PROMPT_TEMPLATE
# Should be empty.  If it shows 'auto':
docker compose up -d --force-recreate open-webui
```

**Tools tab is empty / no tool servers** — MCPO didn't start, OR the URLs in `TOOL_SERVER_CONNECTIONS` are wrong. Check:

```bash
docker logs mcpo --tail 50          # MCPO startup
docker exec open-webui curl -s http://mcpo:8080/sessions/openapi.json | head -5   # reachable from inside open-webui
```

**Tool calls hang / time out** — verify the underlying tool runner is responding:

```bash
docker logs nmap_scanner --tail 50  # scan tool calls
docker logs scan-recommender --tail 50   # KB-driven recs
```

**Need to verify native tool calling end-to-end** — bypass Open WebUI and hit Ollama directly:

```bash
curl -s http://localhost:11434/api/chat -d '{
  "model": "gemma4:31b",
  "messages": [{"role": "user", "content": "Use the check_health tool"}],
  "tools": [{"type": "function", "function": {"name": "check_health"}}]
}' | jq .message.tool_calls
```

A non-null `tool_calls` array means native tool calling is working. A response with the tool name as prose means the model doesn't support it.

## Available models on your host

List what's actually pulled:

```bash
ollama list
```

Pull a different one:

```bash
ollama pull gemma4:9b           # smaller alternative
ollama pull qwen3:4b            # smallest viable
ollama pull llama3.3:70b        # high-end, needs ≥ 64 GB RAM
```

`nomic-embed-text` should always be in the list — it's the embedding model used by the RAG pipeline (KB search, exploit chunks, playbook lookup). Without it, `/rag/ask` and the recon agent's KB lookups fail.

## Related stack components

- The **scan-recommender** uses the same `OLLAMA_MODEL` env for its `/tools/recommend` and `/rag/ask` endpoints — model changes apply uniformly.
- **CT log scans** were migrated from crt.sh to Certspotter (no model dependency; called out here only because operators sometimes ask whether changing the model affects passive recon — it doesn't).
- **Setup script** Phase 8 (`./scripts/setup.sh`) auto-pulls the configured model + `nomic-embed-text` on first install and verifies they're reachable from inside the containers.
