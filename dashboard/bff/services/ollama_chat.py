"""LLM streaming with tool call interception loop.

Supports Ollama (default), OpenAI, Anthropic, and Azure backends.
Backend is selected via the LLM_BACKEND env var / settings.llm_backend.
"""

import json
import logging
import time
from typing import AsyncGenerator, Optional
import httpx
from config import get_settings
from services.tool_definitions import TOOLS, PROFILE_PROMPTS, BURP_SYSTEM_SUPPLEMENT, get_tools_for_profile
from services.tool_executor import execute_tool

log = logging.getLogger("ollama_chat")

# Hard cap on tool-call rounds per chat turn. Multi-step orchestration prompts
# (e.g. the AWS-infra → MicroBurst pivot saved query) routinely need 1 + 3·N
# + 4·M + 1 calls — 30 is generous without letting a runaway loop chew GPU.
# Operators see "max_rounds_reached: true" in the final event when this fires.
MAX_TOOL_ROUNDS = 30

# ── LLM tuning defaults (anti-hallucination tuned) ──────────────────────
# These are compile-time defaults. Users override via Settings → LLM Tuning,
# which writes to app_settings and is read by _load_llm_tuning() each call.
LLM_TUNING_DEFAULTS = {
    "temperature": 0.3,       # low = more deterministic (Ollama default is 0.8)
    "top_p": 0.85,            # nucleus sampling
    "top_k": 40,              # top-k sampling
    "repeat_penalty": 1.1,    # penalize repetition
    "num_ctx": 16384,         # context window tokens — 16K leaves room for the
                              # system prompt + multi-step tool chains + 50-row
                              # tool results without compaction (Ollama default 2048).
    "num_predict": 4096,      # max output tokens
    "seed": 0,                # 0 = random; set >0 for reproducible output
}

# In-process cache of tuning params (refreshed every 60s from app_settings)
_tuning_cache: dict = {}
_tuning_cache_ts: float = 0
_TUNING_CACHE_TTL = 60


def _load_llm_tuning() -> dict:
    """Read LLM tuning params from app_settings (cached 60s). Returns merged dict."""
    global _tuning_cache, _tuning_cache_ts
    now = time.time()
    if _tuning_cache and _tuning_cache_ts > now - _TUNING_CACHE_TTL:
        return _tuning_cache

    settings = get_settings()
    result = dict(LLM_TUNING_DEFAULTS)
    try:
        import httpx as _hx
        for key in LLM_TUNING_DEFAULTS:
            resp = _hx.get(
                f"{settings.rag_api_url}/settings/config/llm.{key}",
                headers={"x-api-key": settings.api_key},
                verify=False, timeout=5,
            )
            if resp.status_code == 200:
                val = resp.json().get("value", "")
                if val:
                    try:
                        result[key] = type(LLM_TUNING_DEFAULTS[key])(val)
                    except (ValueError, TypeError):
                        pass
    except Exception as e:
        log.debug("Failed to load LLM tuning from DB: %s", e)

    _tuning_cache = result
    _tuning_cache_ts = now
    return result
SYSTEM_PROMPT = """LANGUAGE: English. All responses must be in English.

You are a penetration testing AI assistant embedded in a security dashboard. You have access to tools that can:
- Query discovered assets, open ports, and vulnerabilities
- Launch scans (masscan, nmap, nuclei, web scans, etc.)
- Search for exploits in ExploitDB and Metasploit
- Check job statuses and get recommendations
- Manage findings and cleanup data

Always use tools to look up real data before answering questions about the target environment. Be precise, technical, and security-focused. When launching scans, confirm the target and parameters. Format responses clearly with severity levels and actionable recommendations. Remember: respond in English only."""

_TIMEOUT = httpx.Timeout(300.0, connect=10.0)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def stream_chat(
    messages: list[dict],
    model: str,
    context: dict | None = None,
    profile: str = "recon",
    user_system_prompt: str | None = None,
    attached_files: list[dict] | None = None,
    allowed_tools: list[str] | None = None,
) -> AsyncGenerator[dict, None]:
    """Stream chat with LLM, intercepting and executing tool calls.

    `allowed_tools` (when set) restricts the model's tool catalog AND the
    dispatcher's accept-list to exactly that set of names — layers 2+3 of
    the LLM-hardening stack used by saved-query presets.
    """
    settings = get_settings()
    backend = settings.llm_backend

    # Build system prompt with optional profile supplement
    system_prompt = SYSTEM_PROMPT
    profile_supplement = PROFILE_PROMPTS.get(profile)
    if profile_supplement:
        system_prompt = f"{SYSTEM_PROMPT}\n\n{profile_supplement}"
    if user_system_prompt and user_system_prompt.strip():
        system_prompt = f"{user_system_prompt.strip()}\n\n{system_prompt}"

    # Resolve tools for the selected profile, then narrow to the preset's
    # allow-list when one is in force. Filtering at the catalog stage means
    # the model never sees forbidden tools in its prompt.
    tools = get_tools_for_profile(profile)
    if allowed_tools:
        allowed_set = {n for n in allowed_tools if isinstance(n, str)}
        tools = [t for t in tools if t.get("function", {}).get("name") in allowed_set]
        log.info("Preset allowlist active: %d → %d tools (allowed=%s)",
                 len(get_tools_for_profile(profile)), len(tools), sorted(allowed_set))
    log.info("Using profile '%s' with %d tools (backend=%s, allowed_tools=%s)",
             profile, len(tools), backend, "set" if allowed_tools else "none")

    # Add Burp-specific guidance when Burp tools are available
    if any(t.get("_mcp_server") == "burpsuite-pro" for t in tools):
        system_prompt = f"{system_prompt}\n\n{BURP_SYSTEM_SUPPLEMENT}"

    # Build messages with system prompt
    chat_messages = [{"role": "system", "content": system_prompt}]
    if context:
        ctx_msg = f"Current dashboard context: {json.dumps(context, default=str)[:2000]}"
        chat_messages.append({"role": "system", "content": ctx_msg})

    # Attached files: pre-fetch content and inject directly into context.
    # For files ≤512KB text, the content is included inline so the LLM has
    # it immediately without needing to call read_uploaded_file. For larger
    # or binary files, we still provide the tool-based fallback.
    _MAX_INLINE_BYTES = 512 * 1024  # 512 KB — fits comfortably in 8K-32K context
    if attached_files:
        for f in attached_files:
            fid = f.get("id", "")
            name = f.get("name", "(unnamed)")
            size = int(f.get("size", 0))
            ctype = f.get("content_type", "application/octet-stream")
            # Try to pre-fetch the file content server-side
            content_text = None
            if size <= _MAX_INLINE_BYTES:
                try:
                    import httpx as _hx
                    r = _hx.get(
                        f"{settings.rag_api_url}/evidence/{fid}/content",
                        headers={"x-api-key": settings.api_key},
                        verify=False, timeout=15,
                    )
                    if r.status_code == 200:
                        try:
                            content_text = r.content.decode("utf-8")
                        except UnicodeDecodeError:
                            pass  # binary — fall back to tool
                except Exception as e:
                    log.warning("Pre-fetch file %s failed: %s", fid, e)

            if content_text:
                # Inject the FULL file content directly — LLM doesn't need to call any tool
                chat_messages.append({
                    "role": "system",
                    "content": (
                        f"The user attached a file for analysis. "
                        f"File: {name!r} ({ctype}, {size} bytes). "
                        f"The COMPLETE file content is below — analyze it thoroughly.\n\n"
                        f"--- BEGIN FILE: {name} ---\n"
                        f"{content_text}\n"
                        f"--- END FILE: {name} ---"
                    ),
                })
                log.info("Injected file %s (%d bytes) directly into context", name, len(content_text))
            else:
                # Large or binary file — tell the LLM to use the tool
                chat_messages.append({
                    "role": "system",
                    "content": (
                        f"The user attached a file: {name!r} ({ctype}, {size} bytes, id={fid}). "
                        f"This file is too large or binary to include directly. "
                        f"Use the `read_uploaded_file` tool with file_id='{fid}' to retrieve "
                        f"its content in chunks. Keep calling with start=<next_start> until eof=true."
                    ),
                })

    chat_messages.extend(messages)

    # Override model for non-Ollama backends
    if backend == "openai":
        model = settings.openai_model or model
    elif backend == "anthropic":
        model = settings.anthropic_model or model
    elif backend == "azure":
        model = settings.azure_model or model

    # Load tuning params (cached 60s from app_settings, with anti-hallucination defaults)
    tuning = _load_llm_tuning()
    log.info("LLM tuning: temp=%.2f top_p=%.2f top_k=%d repeat_penalty=%.2f ctx=%d",
             tuning["temperature"], tuning["top_p"], tuning["top_k"],
             tuning["repeat_penalty"], tuning["num_ctx"])

    # Track (tool_name, args_json) → call count across this turn so we can
    # break out of "model calls the same tool with the same args N times"
    # loops. Common pattern: model hallucinates example.com, gets empty
    # result, asks "scan it?", nudge fires, model retries the same call.
    seen_calls: dict[str, int] = {}
    DUPLICATE_CALL_CAP = 3

    for round_num in range(MAX_TOOL_ROUNDS):
        log.info("Chat round %d/%d (model=%s, backend=%s)", round_num + 1, MAX_TOOL_ROUNDS, model, backend)

        tool_calls = []
        content_buffer = ""

        # Select streaming function based on backend — all receive tuning params
        if backend == "openai":
            stream_fn = _stream_openai_compatible(
                f"{settings.openai_api_base.rstrip('/')}/v1/chat/completions",
                {"Authorization": f"Bearer {settings.openai_api_key}"},
                model, chat_messages, tools, tuning,
            )
        elif backend == "azure":
            azure_url = _azure_chat_url(settings.azure_endpoint, settings.azure_model, settings.azure_api_version)
            stream_fn = _stream_openai_compatible(
                azure_url,
                {"api-key": settings.azure_api_key},
                model, chat_messages, tools, tuning,
            )
        elif backend == "anthropic":
            stream_fn = _stream_anthropic(settings, model, chat_messages, tools, system_prompt, tuning)
        else:
            stream_fn = _stream_ollama(settings, model, chat_messages, tools, tuning)

        async for chunk in stream_fn:
            if chunk.get("message", {}).get("tool_calls"):
                tool_calls.extend(chunk["message"]["tool_calls"])
            elif chunk.get("message", {}).get("content"):
                text = chunk["message"]["content"]
                content_buffer += text
                yield {"type": "text", "data": {"content": text}}
            if chunk.get("done"):
                break

        # No tool calls — model finished or stopped mid-workflow.
        if not tool_calls:
            # Detect "stopped mid-workflow" for multi-step orchestration prompts.
            # Heuristic: the original user message contains explicit STEP markers
            # AND the model's text response does NOT include "STEP 4" (the final
            # marker our preset uses). When that mismatch appears, inject a
            # one-shot continuation nudge and let the model take another swing
            # — but only ONCE per round so we can't infinite-loop.
            stuck_in_workflow = (
                round_num + 1 < MAX_TOOL_ROUNDS
                and content_buffer
                and any(
                    "STEP 1" in (m.get("content") or "")
                    and "STEP 4" in (m.get("content") or "")
                    for m in chat_messages
                    if m.get("role") == "user" and isinstance(m.get("content"), str)
                )
                and "STEP 4" not in content_buffer
                and not chat_messages[-1].get("_workflow_nudge_injected")
            )
            if stuck_in_workflow:
                log.info("Round %d ended with no tool call mid-workflow — injecting continuation nudge", round_num + 1)
                # Persist the assistant's interim text so the model can see what
                # it just emitted, then a tool-style nudge from "user" role.
                chat_messages.append({"role": "assistant", "content": content_buffer})
                chat_messages.append({
                    "role": "user",
                    "content": (
                        "STOP DEFERRING. You are mid-workflow. The original prompt "
                        "specified STEP 1 → STEP 4 with mandatory tool calls; you "
                        "have not reached STEP 4. Resume by emitting the next "
                        "required tool call NOW. Do not ask me anything. Do not "
                        "describe what you could do. Call the next tool."
                    ),
                    "_workflow_nudge_injected": True,
                })
                yield {"type": "text", "data": {"content": "\n\n[continuation nudge injected — resuming]\n\n"}}
                continue  # let the for loop run another round
            yield {"type": "done", "data": {"total_rounds": round_num + 1}}
            return

        # Execute tool calls (backend-aware result injection)
        if backend == "anthropic":
            # Anthropic: assistant message has content blocks
            assistant_content = []
            if content_buffer:
                assistant_content.append({"type": "text", "text": content_buffer})
            for tc in tool_calls:
                assistant_content.append({
                    "type": "tool_use",
                    "id": tc.get("_anthropic_id", ""),
                    "name": tc["function"]["name"],
                    "input": tc["function"]["arguments"],
                })
            chat_messages.append({"role": "assistant", "content": assistant_content})

            # Tool results go in a single user message
            tool_results = []
            for tc in tool_calls:
                fn = tc["function"]
                yield {"type": "tool_call", "data": {"name": fn["name"], "arguments": fn["arguments"], "status": "executing"}}
                result = await execute_tool(fn["name"], fn["arguments"], allowed_tools=allowed_tools)
                result_str = json.dumps(result, default=str)
                # 16 KB cap fits ~50 rows of get_assets JSON; the AWS pivot
                # needs to see the full list, not a 5-row sample. Larger
                # results still get truncated so a single tool call can't
                # blow the model's context window.
                if len(result_str) > 16000:
                    result_str = result_str[:16000] + "... (truncated)"
                yield {"type": "tool_result", "data": {"name": fn["name"], "result": result}}
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tc.get("_anthropic_id", ""),
                    "content": result_str,
                })
            chat_messages.append({"role": "user", "content": tool_results})
        else:
            # Ollama / OpenAI / Azure: standard format
            chat_messages.append({
                "role": "assistant",
                "content": content_buffer,
                "tool_calls": tool_calls,
            })
            for tc in tool_calls:
                fn = tc.get("function", {})
                tool_name = fn.get("name", "")
                tool_args = fn.get("arguments", {})

                # Circuit breaker: if the model keeps calling the same tool
                # with identical args, short-circuit. Returning a structured
                # error gives the model something different to react to;
                # otherwise it loops on identical empty results forever.
                try:
                    sig = f"{tool_name}|{json.dumps(tool_args, sort_keys=True, default=str)}"
                except Exception:
                    sig = f"{tool_name}|{tool_args!r}"
                seen_calls[sig] = seen_calls.get(sig, 0) + 1
                if seen_calls[sig] > DUPLICATE_CALL_CAP:
                    log.warning("Circuit breaker: %s called %d times this turn — refusing", tool_name, seen_calls[sig])
                    result = {
                        "error": "duplicate_call_loop",
                        "message": (
                            f"REFUSED: you have called {tool_name} with these "
                            f"exact args {DUPLICATE_CALL_CAP} times in this "
                            "turn. The result is not changing. Stop retrying. "
                            "Either move to the next step or write the final "
                            "report with what you have."
                        ),
                        "calls_so_far": seen_calls[sig],
                    }
                    yield {"type": "tool_result", "data": {"name": tool_name, "result": result}}
                    chat_messages.append({"role": "tool", "content": json.dumps(result)})
                    continue

                yield {"type": "tool_call", "data": {"name": tool_name, "arguments": tool_args, "status": "executing"}}
                result = await execute_tool(tool_name, tool_args, allowed_tools=allowed_tools)
                result_str = json.dumps(result, default=str)
                # 16 KB cap fits ~50 rows of get_assets JSON; the AWS pivot
                # needs to see the full list, not a 5-row sample. Larger
                # results still get truncated so a single tool call can't
                # blow the model's context window.
                if len(result_str) > 16000:
                    result_str = result_str[:16000] + "... (truncated)"
                yield {"type": "tool_result", "data": {"name": tool_name, "result": result}}
                chat_messages.append({"role": "tool", "content": result_str})

    yield {"type": "done", "data": {"total_rounds": MAX_TOOL_ROUNDS, "max_rounds_reached": True}}


# ---------------------------------------------------------------------------
# Ollama streaming (original)
# ---------------------------------------------------------------------------

async def _stream_ollama(settings, model: str, messages: list[dict], tools: list[dict],
                         tuning: dict | None = None):
    """Stream from Ollama /api/chat endpoint."""
    url = f"{settings.ollama_url}/api/chat"
    t = tuning or LLM_TUNING_DEFAULTS
    payload = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "stream": True,
        "options": {
            "temperature": t.get("temperature", 0.3),
            "top_p": t.get("top_p", 0.85),
            "top_k": t.get("top_k", 40),
            "repeat_penalty": t.get("repeat_penalty", 1.1),
            "num_ctx": t.get("num_ctx", 16384),
            "num_predict": t.get("num_predict", 4096),
            **({"seed": t["seed"]} if t.get("seed", 0) > 0 else {}),
        },
    }
    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
        async with client.stream("POST", url, json=payload) as resp:
            async for line in resp.aiter_lines():
                if not line.strip():
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    log.debug("Non-JSON line from Ollama: %s", line[:100])


# ---------------------------------------------------------------------------
# OpenAI-compatible streaming (OpenAI + Azure)
# ---------------------------------------------------------------------------

async def _stream_openai_compatible(
    url: str, auth_headers: dict, model: str,
    messages: list[dict], tools: list[dict],
    tuning: dict | None = None,
):
    """
    Stream from an OpenAI-compatible chat completions endpoint.

    Works for both OpenAI API and Azure OpenAI. Yields normalized chunks
    in the same format as _stream_ollama.
    """
    # Convert tools from Ollama format (which IS OpenAI format) — pass through.
    # Strip internal underscore-prefixed keys (e.g. _mcp_server) so the OpenAI
    # API doesn't reject them; tool execution still routes correctly because the
    # tool *name* dispatch in execute_tool() handles MCP tools by name.
    clean_tools = []
    for t in tools:
        clean = {k: v for k, v in t.items() if not k.startswith("_")}
        clean_tools.append(clean)

    t = tuning or LLM_TUNING_DEFAULTS
    headers = {"Content-Type": "application/json", **auth_headers}
    payload = {
        "model": model,
        "messages": messages,
        "stream": True,
        "temperature": t.get("temperature", 0.3),
        "top_p": t.get("top_p", 0.85),
        "max_tokens": t.get("num_predict", 4096),
    }
    if clean_tools:
        payload["tools"] = clean_tools

    # Accumulators for streamed tool calls (OpenAI streams them incrementally)
    pending_tool_calls: dict[int, dict] = {}  # index → {id, name, arguments_str}

    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
        async with client.stream("POST", url, json=payload, headers=headers) as resp:
            async for line in resp.aiter_lines():
                line = line.strip()
                if not line or line == "data: [DONE]":
                    continue
                if line.startswith("data: "):
                    line = line[6:]
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue

                choice = (data.get("choices") or [{}])[0]
                delta = choice.get("delta", {})
                finish = choice.get("finish_reason")

                # Text content
                if delta.get("content"):
                    yield {"message": {"content": delta["content"]}, "done": False}

                # Tool call deltas (streamed incrementally by index)
                for tc_delta in delta.get("tool_calls", []):
                    idx = tc_delta.get("index", 0)
                    if idx not in pending_tool_calls:
                        pending_tool_calls[idx] = {
                            "id": tc_delta.get("id", ""),
                            "name": tc_delta.get("function", {}).get("name", ""),
                            "arguments_str": "",
                        }
                    fn_delta = tc_delta.get("function", {})
                    if fn_delta.get("name"):
                        pending_tool_calls[idx]["name"] = fn_delta["name"]
                    if fn_delta.get("arguments"):
                        pending_tool_calls[idx]["arguments_str"] += fn_delta["arguments"]

                # Finished
                if finish:
                    if pending_tool_calls:
                        tool_calls = []
                        for idx in sorted(pending_tool_calls):
                            tc = pending_tool_calls[idx]
                            try:
                                args = json.loads(tc["arguments_str"]) if tc["arguments_str"] else {}
                            except json.JSONDecodeError:
                                args = {"_raw": tc["arguments_str"]}
                            tool_calls.append({
                                "function": {"name": tc["name"], "arguments": args},
                            })
                        yield {"message": {"tool_calls": tool_calls}, "done": True}
                    else:
                        yield {"done": True}
                    return

    # Safety: if stream ends without finish_reason
    if pending_tool_calls:
        tool_calls = []
        for idx in sorted(pending_tool_calls):
            tc = pending_tool_calls[idx]
            try:
                args = json.loads(tc["arguments_str"]) if tc["arguments_str"] else {}
            except json.JSONDecodeError:
                args = {"_raw": tc["arguments_str"]}
            tool_calls.append({"function": {"name": tc["name"], "arguments": args}})
        yield {"message": {"tool_calls": tool_calls}, "done": True}
    else:
        yield {"done": True}


# ---------------------------------------------------------------------------
# Anthropic streaming
# ---------------------------------------------------------------------------

def _convert_tools_to_anthropic(tools: list[dict]) -> list[dict]:
    """Convert OpenAI/Ollama tool format to Anthropic tool format. MCP-discovered
    tools (carrying `_mcp_server`) are included — execute_tool() dispatches by
    name and routes them to the right MCP server."""
    result = []
    for t in tools:
        fn = t.get("function", t)
        result.append({
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
        })
    return result


def _extract_system_for_anthropic(messages: list[dict]) -> tuple[str, list[dict]]:
    """
    Extract system messages from the messages array for Anthropic.

    Anthropic requires system as a top-level parameter, not in the messages array.
    Returns (system_text, filtered_messages).
    """
    system_parts = []
    filtered = []
    for msg in messages:
        if msg.get("role") == "system":
            system_parts.append(msg.get("content", ""))
        else:
            filtered.append(msg)
    return "\n\n".join(system_parts), filtered


async def _stream_anthropic(
    settings, model: str, messages: list[dict],
    tools: list[dict], system_prompt: str,
    tuning: dict | None = None,
):
    """
    Stream from Anthropic messages API.

    Yields normalized chunks in the same format as _stream_ollama.
    Handles Anthropic's typed SSE events and tool_use blocks.
    """
    t = tuning or LLM_TUNING_DEFAULTS
    system_text, filtered_messages = _extract_system_for_anthropic(messages)
    anthropic_tools = _convert_tools_to_anthropic(tools)

    headers = {
        "x-api-key": settings.anthropic_api_key,
        "anthropic-version": "2023-06-01",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": t.get("num_predict", 4096),
        "stream": True,
        "messages": filtered_messages,
        "temperature": t.get("temperature", 0.3),
        "top_p": t.get("top_p", 0.85),
        "top_k": t.get("top_k", 40),
    }
    if system_text:
        payload["system"] = system_text
    if anthropic_tools:
        payload["tools"] = anthropic_tools

    # Track current block state for tool_use accumulation
    current_block_type = None  # "text" or "tool_use"
    current_tool_id = ""
    current_tool_name = ""
    tool_json_buffer = ""
    accumulated_tool_calls = []

    async with httpx.AsyncClient(verify=False, timeout=_TIMEOUT) as client:
        async with client.stream("POST", "https://api.anthropic.com/v1/messages",
                                  json=payload, headers=headers) as resp:
            async for line in resp.aiter_lines():
                line = line.strip()
                if not line:
                    continue

                # Anthropic SSE: "event: <type>" then "data: <json>"
                if line.startswith("event: "):
                    continue  # we parse the data line instead

                if not line.startswith("data: "):
                    continue
                try:
                    data = json.loads(line[6:])
                except json.JSONDecodeError:
                    continue

                event_type = data.get("type", "")

                if event_type == "content_block_start":
                    block = data.get("content_block", {})
                    current_block_type = block.get("type")
                    if current_block_type == "tool_use":
                        current_tool_id = block.get("id", "")
                        current_tool_name = block.get("name", "")
                        tool_json_buffer = ""

                elif event_type == "content_block_delta":
                    delta = data.get("delta", {})
                    delta_type = delta.get("type")
                    if delta_type == "text_delta":
                        text = delta.get("text", "")
                        if text:
                            yield {"message": {"content": text}, "done": False}
                    elif delta_type == "input_json_delta":
                        tool_json_buffer += delta.get("partial_json", "")

                elif event_type == "content_block_stop":
                    if current_block_type == "tool_use" and current_tool_name:
                        try:
                            args = json.loads(tool_json_buffer) if tool_json_buffer else {}
                        except json.JSONDecodeError:
                            log.warning("Failed to parse Anthropic tool args: %s", tool_json_buffer[:200])
                            args = {"_raw": tool_json_buffer}
                        accumulated_tool_calls.append({
                            "function": {"name": current_tool_name, "arguments": args},
                            "_anthropic_id": current_tool_id,
                        })
                    current_block_type = None
                    current_tool_name = ""
                    current_tool_id = ""
                    tool_json_buffer = ""

                elif event_type == "message_delta":
                    stop_reason = data.get("delta", {}).get("stop_reason")
                    if stop_reason == "tool_use" and accumulated_tool_calls:
                        yield {"message": {"tool_calls": accumulated_tool_calls}, "done": True}
                        return
                    elif stop_reason == "end_turn":
                        yield {"done": True}
                        return

                elif event_type == "message_stop":
                    if accumulated_tool_calls:
                        yield {"message": {"tool_calls": accumulated_tool_calls}, "done": True}
                    else:
                        yield {"done": True}
                    return

    # Safety fallback
    if accumulated_tool_calls:
        yield {"message": {"tool_calls": accumulated_tool_calls}, "done": True}
    else:
        yield {"done": True}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _azure_chat_url(endpoint: str, model: str, api_version: str) -> str:
    """Build Azure chat completions URL."""
    base = endpoint.rstrip("/")
    if ".models.ai.azure.com" in base:
        return f"{base}/v1/chat/completions"
    return f"{base}/openai/deployments/{model}/chat/completions?api-version={api_version}"
