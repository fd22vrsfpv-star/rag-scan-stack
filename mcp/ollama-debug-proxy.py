#!/usr/bin/env python3
"""
Ollama Debug Proxy — Intercepts Open WebUI ↔ Ollama traffic.
Shows tool definitions, tool calls, system prompts, token stats, and timing.

Run as container (docker-compose) or standalone:
  OLLAMA_URL=http://ollama:11434 python ollama-debug-proxy.py

Then point Open WebUI's Ollama connection to this proxy.
Visit /logs for a live web-based log viewer.
"""

import json
import os
import sys
import time
import threading
import io
from collections import deque
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import urllib.request
import urllib.error

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11435")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "21434"))
LOG_FILE = os.environ.get("LOG_FILE", "/tmp/ollama-debug.log")
MAX_LOG_ENTRIES = 500

# ── In-memory log ring buffer ────────────────────────────────────────
log_entries = deque(maxlen=MAX_LOG_ENTRIES)
log_lock = threading.Lock()
request_counter = 0
counter_lock = threading.Lock()


class C:
    """ANSI colours"""
    H = '\033[95m'; B = '\033[94m'; CY = '\033[96m'; G = '\033[92m'
    Y = '\033[93m'; R = '\033[91m'; E = '\033[0m'; BO = '\033[1m'
    DIM = '\033[2m'


def next_id():
    global request_counter
    with counter_lock:
        request_counter += 1
        return request_counter


def log(msg, color=None, rid=None, category="info"):
    ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
    prefix = f"[{ts}]"
    if rid:
        prefix += f" #{rid}"
    line = f"{prefix} {msg}"

    with open(LOG_FILE, 'a') as f:
        f.write(line + '\n')

    with log_lock:
        log_entries.append({"ts": ts, "rid": rid, "msg": msg, "cat": category})

    if color:
        print(f"{color}{line}{C.E}", flush=True)
    else:
        print(line, flush=True)


def summarise_messages(messages):
    """Return a compact summary of the message history."""
    lines = []
    for i, msg in enumerate(messages):
        role = msg.get('role', '?')
        content = msg.get('content', '')
        tc = msg.get('tool_calls', [])

        if role == 'system':
            # Show first 120 chars of system prompt
            snip = (content[:120] + '...') if len(content) > 120 else content
            snip = snip.replace('\n', ' ')
            lines.append(f"  [{i}] system ({len(content)} chars): {snip}")
        elif role == 'tool':
            tid = msg.get('tool_call_id', '?')[:8]
            snip = (content[:100] + '...') if len(str(content)) > 100 else content
            lines.append(f"  [{i}] tool({tid}): {snip}")
        elif tc:
            names = [t.get('function', {}).get('name', '?') for t in tc]
            lines.append(f"  [{i}] {role}: [TOOL_CALLS: {', '.join(names)}]")
        else:
            snip = (str(content)[:120] + '...') if len(str(content)) > 120 else str(content)
            snip = snip.replace('\n', ' ')
            lines.append(f"  [{i}] {role}: {snip}")
    return '\n'.join(lines)


def format_tools_full(tools):
    """List every tool name provided in the request."""
    if not tools:
        return None
    names = []
    for t in tools:
        if isinstance(t, dict):
            if 'function' in t:
                names.append(t['function'].get('name', '?'))
            else:
                names.append(t.get('name', '?'))
    return names


def format_tool_calls(tool_calls):
    """Pretty-print tool calls from a response."""
    if not tool_calls:
        return None
    parts = []
    for tc in tool_calls:
        func = tc.get('function', {})
        name = func.get('name', '?')
        args = func.get('arguments', {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except Exception:
                pass
        args_str = json.dumps(args, ensure_ascii=False)
        if len(args_str) > 200:
            args_str = args_str[:200] + '...'
        parts.append(f"{name}({args_str})")
    return parts


# ── Proxy Handler ────────────────────────────────────────────────────

class OllamaDebugProxy(BaseHTTPRequestHandler):

    def _proxy_forward(self, method):
        rid = next_id()
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length else b''

        # ── Serve log viewer ─────────────────────────────────────
        if self.path == '/logs' and method == 'GET':
            return self._serve_logs_ui()
        if self.path == '/logs/json' and method == 'GET':
            return self._serve_logs_json()
        if self.path == '/proxy/health' and method == 'GET':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "requests": request_counter,
                                         "target": OLLAMA_URL}).encode())
            return

        # ── Log the request ──────────────────────────────────────
        log(f"{'━'*70}", C.H, rid)
        log(f"→ {method} {self.path}", C.BO, rid, "request")

        data = {}
        tool_names = []
        if body and (self.path.startswith('/api/chat') or self.path.startswith('/v1/chat/completions')):
            try:
                data = json.loads(body)
                model = data.get('model', '?')
                messages = data.get('messages', [])
                tools = data.get('tools', [])
                stream = data.get('stream', False)

                log(f"  Model: {model}  |  Stream: {stream}  |  Messages: {len(messages)}", C.CY, rid)

                # Message summary with content preview
                log(summarise_messages(messages), C.DIM, rid, "messages")

                # Show last user message preview (first 150 chars)
                for msg in reversed(messages):
                    if msg.get('role') == 'user':
                        content = msg.get('content', '')
                        if isinstance(content, str) and content:
                            preview = content[:150].replace('\n', ' ')
                            if len(content) > 150:
                                preview += '...'
                            log(f"  📝 User: {preview}", C.DIM, rid, "request_content")
                        break

                # Tools
                tool_names = format_tools_full(tools) or []
                if tool_names:
                    log(f"  ✅ {len(tool_names)} TOOLS: {', '.join(tool_names)}", C.G + C.BO, rid, "tools")
                else:
                    log(f"  ⚠️  NO TOOLS IN REQUEST", C.R + C.BO, rid, "warning")

            except json.JSONDecodeError as e:
                log(f"  JSON parse error: {e}", C.R, rid, "error")
        elif body:
            log(f"  Body: {len(body)} bytes", C.DIM, rid)

        # ── Forward to Ollama ────────────────────────────────────
        target = f"{OLLAMA_URL}{self.path}"
        headers = {'Content-Type': self.headers.get('Content-Type', 'application/json')}
        for h in ('Accept', 'Authorization'):
            if self.headers.get(h):
                headers[h] = self.headers[h]

        req = urllib.request.Request(target, data=body if body else None,
                                     headers=headers, method=method)
        start = time.time()

        try:
            with urllib.request.urlopen(req, timeout=600) as resp:
                is_stream = data.get('stream', False)

                if is_stream:
                    self._handle_stream(resp, data, tool_names, start, rid)
                else:
                    self._handle_non_stream(resp, data, tool_names, start, rid)

        except urllib.error.HTTPError as e:
            elapsed = time.time() - start
            err_body = e.read().decode('utf-8', errors='replace')[:500]
            log(f"  ✖ HTTP {e.code} from Ollama ({elapsed:.2f}s): {err_body}", C.R, rid, "error")
            self.send_response(e.code)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": err_body}).encode())

        except urllib.error.URLError as e:
            log(f"  ✖ Connection error: {e}", C.R, rid, "error")
            self.send_response(502)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": f"Cannot reach Ollama: {e}"}).encode())

        except Exception as e:
            log(f"  ✖ Unexpected error: {e}", C.R, rid, "error")
            self.send_response(500)
            self.end_headers()

    def _handle_stream(self, resp, data, tool_names, start, rid):
        """Forward streaming response, capturing tool calls and content."""
        self.send_response(200)
        for h, v in resp.headers.items():
            if h.lower() not in ('transfer-encoding', 'content-length', 'connection'):
                self.send_header(h, v)
        self.end_headers()

        full_content = ""
        tool_calls_accum = []
        token_count = 0
        chunk_count = 0
        line_buffer = b""
        raw_chunk_count = 0

        for raw_line in resp:
            raw_chunk_count += 1

            # Forward raw bytes directly
            self.wfile.write(raw_line)
            self.wfile.flush()

            # Log first few raw chunks for debugging
            if raw_chunk_count <= 3:
                preview = raw_line[:100].decode('utf-8', errors='replace').replace('\n', '\\n')
                log(f"  🔍 Raw chunk {raw_chunk_count}: {preview}{'...' if len(raw_line) > 100 else ''}", C.DIM, rid, "debug")

            # Accumulate bytes into buffer
            line_buffer += raw_line

            # Process complete lines (ending with \n)
            while b'\n' in line_buffer:
                line, line_buffer = line_buffer.split(b'\n', 1)
                line_str = line.decode('utf-8', errors='replace').strip()

                if not line_str or line_str == 'data: [DONE]':
                    continue

                # Handle SSE format: "data: {...}"
                if line_str.startswith('data:'):
                    json_str = line_str[5:].strip()

                    try:
                        chunk = json.loads(json_str)
                        chunk_count += 1

                        # Log first chunk structure for debugging
                        if chunk_count == 1:
                            chunk_keys = list(chunk.keys())
                            log(f"  🔍 First chunk keys: {chunk_keys}", C.DIM, rid, "debug")

                        # Support both OpenAI v1 format and Ollama native format for streaming
                        if 'choices' in chunk:
                            # OpenAI v1 streaming format
                            choices = chunk.get('choices', [])
                            if choices:
                                delta = choices[0].get('delta', {})
                                content = delta.get('content', '')
                                if content:
                                    full_content += content

                                if 'tool_calls' in delta:
                                    tool_calls_accum.extend(delta['tool_calls'])

                            # Check if done (OpenAI format uses finish_reason)
                            if choices and choices[0].get('finish_reason'):
                                usage = chunk.get('usage', {})
                                token_count = usage.get('completion_tokens', 0)
                        else:
                            # Ollama native streaming format
                            msg = chunk.get('message', {})
                            content = msg.get('content', '')
                            if content:
                                full_content += content

                            if 'tool_calls' in msg:
                                tool_calls_accum.extend(msg['tool_calls'])

                            if chunk.get('done'):
                                token_count = chunk.get('eval_count', 0)

                    except json.JSONDecodeError as e:
                        # Only log first 3 decode errors
                        if chunk_count < 3:
                            preview = json_str[:100]
                            log(f"  ⚠️  Chunk decode error: {e} | Preview: {preview}", C.DIM, rid, "debug")
                    except Exception as e:
                        if chunk_count < 3:
                            log(f"  ⚠️  Chunk error: {type(e).__name__}: {e}", C.DIM, rid, "debug")

        # Log streaming summary
        if chunk_count > 0:
            log(f"  📊 Parsed {chunk_count} chunks | Content: {len(full_content)} chars | Tools: {len(tool_calls_accum)}", C.DIM, rid, "debug")
        else:
            log(f"  ⚠️  No valid chunks parsed from stream (received {raw_chunk_count} raw chunks)", C.Y, rid, "warning")

        elapsed = time.time() - start
        self._log_response(full_content, tool_calls_accum, tool_names,
                           token_count, elapsed, rid)

    def _parse_streaming_body(self, response_body, tool_names, start, rid):
        """Parse a streaming response body that was already read."""
        response_text = response_body.decode('utf-8', errors='replace')

        full_content = ""
        tool_calls_accum = []
        token_count = 0
        chunk_count = 0

        # Split into lines and process each "data:" line
        for line in response_text.split('\n'):
            line = line.strip()
            if not line or line == 'data: [DONE]':
                continue

            if line.startswith('data:'):
                chunk_count += 1
                json_str = line[5:].strip()  # Remove "data:" prefix

                # Debug first few chunks
                if chunk_count <= 3:
                    preview = json_str[:150]
                    log(f"  🔍 Chunk {chunk_count}: {preview}{'...' if len(json_str) > 150 else ''}", C.DIM, rid, "debug")

                try:
                    chunk = json.loads(json_str)

                    # OpenAI v1 streaming format
                    if 'choices' in chunk:
                        for choice in chunk.get('choices', []):
                            delta = choice.get('delta', {})
                            content = delta.get('content', '')
                            if content:
                                full_content += content

                            # Accumulate tool calls
                            if 'tool_calls' in delta:
                                for tc in delta['tool_calls']:
                                    tool_calls_accum.append(tc)

                        # Check usage in final chunk
                        usage = chunk.get('usage', {})
                        if usage:
                            token_count = usage.get('completion_tokens', 0)

                    # Ollama native streaming format
                    elif 'message' in chunk:
                        msg = chunk['message']
                        content = msg.get('content', '')
                        if content:
                            full_content += content

                        # Accumulate tool calls
                        if 'tool_calls' in msg:
                            for tc in msg['tool_calls']:
                                tool_calls_accum.append(tc)

                        if chunk.get('done'):
                            token_count = chunk.get('eval_count', 0)

                except json.JSONDecodeError as e:
                    if chunk_count <= 2:
                        log(f"  ⚠️  Streaming chunk {chunk_count} decode error: {e}", C.DIM, rid, "debug")
                except Exception as e:
                    if chunk_count <= 2:
                        log(f"  ⚠️  Streaming chunk {chunk_count} error: {type(e).__name__}", C.DIM, rid, "debug")

        # Log streaming summary
        if chunk_count > 0:
            log(f"  📊 Parsed {chunk_count} chunks | Content: {len(full_content)} chars | Tools: {len(tool_calls_accum)}", C.DIM, rid, "debug")

        elapsed = time.time() - start
        self._log_response(full_content, tool_calls_accum, tool_names,
                           token_count, elapsed, rid)

    def _handle_non_stream(self, resp, data, tool_names, start, rid):
        """Forward non-streaming response."""
        response_body = resp.read()
        elapsed = time.time() - start

        # Check if response is actually streaming (starts with "data:")
        response_text = response_body.decode('utf-8', errors='replace')
        if response_text.strip().startswith('data:'):
            log(f"  ⚠️  Response is streaming despite stream=false in request", C.Y, rid, "warning")
            # Parse as streaming response
            self._parse_streaming_body(response_body, tool_names, start, rid)
            return

        full_content = ""
        tool_calls_found = []
        token_count = 0
        parse_error = None

        try:
            resp_data = json.loads(response_body)

            # Support both OpenAI v1 format and Ollama native format
            if 'choices' in resp_data:
                # OpenAI v1 format: {"choices": [{"message": {...}}]}
                choices = resp_data.get('choices', [])
                if choices:
                    msg = choices[0].get('message', {})
                    full_content = msg.get('content', '')
                    tool_calls_found = msg.get('tool_calls', [])
                usage = resp_data.get('usage', {})
                token_count = usage.get('completion_tokens', 0)
            else:
                # Ollama native format: {"message": {...}}
                msg = resp_data.get('message', {})
                full_content = msg.get('content', '')
                tool_calls_found = msg.get('tool_calls', [])
                token_count = resp_data.get('eval_count', 0)

            # Log raw response structure for debugging if content is empty
            if not full_content and not tool_calls_found:
                resp_keys = list(resp_data.keys())
                log(f"  📋 Response keys: {resp_keys}", C.DIM, rid, "debug")

                # Check for common response patterns
                if 'error' in resp_data:
                    log(f"  ⚠️  Error in response: {resp_data.get('error')}", C.Y, rid, "warning")
                elif 'model' in resp_data:
                    log(f"  📦 Model: {resp_data.get('model')}", C.DIM, rid, "debug")
        except json.JSONDecodeError as e:
            parse_error = f"JSON decode error: {e}"
            log(f"  ⚠️  {parse_error}", C.Y, rid, "warning")
            # Try to show first 200 chars of response for debugging
            preview = response_text[:200]
            log(f"  📄 Response preview: {preview}", C.DIM, rid, "debug")
        except Exception as e:
            parse_error = f"Unexpected error: {type(e).__name__}: {e}"
            log(f"  ⚠️  {parse_error}", C.Y, rid, "warning")

        self.send_response(200)
        self.send_header('Content-Type', resp.headers.get('Content-Type', 'application/json'))
        self.send_header('Content-Length', str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)

        self._log_response(full_content, tool_calls_found, tool_names,
                           token_count, elapsed, rid)

    def _log_response(self, content, tool_calls, tool_names, tokens, elapsed, rid):
        tps = tokens / elapsed if elapsed > 0 and tokens > 0 else 0
        stats = f"{elapsed:.2f}s"
        if tokens:
            stats += f" | {tokens} tok | {tps:.1f} tok/s"
        log(f"← RESPONSE ({stats})", C.BO, rid, "response")

        # Show content first if present
        if content:
            snip = content[:250].replace('\n', ' ')
            if len(content) > 250:
                snip += '...'
            log(f"  💬 {snip}", C.B, rid, "content")

        # Show tool calls
        if tool_calls:
            calls = format_tool_calls(tool_calls)
            for c in (calls or []):
                log(f"  🔧 TOOL CALL: {c}", C.G + C.BO, rid, "tool_call")

        # Warning if no content and no tool calls
        if not content and not tool_calls:
            log(f"  (empty response)", C.DIM, rid)
        elif not tool_calls and tool_names:
            log(f"  ⚠️  {len(tool_names)} tools provided but model returned text only!",
                C.Y + C.BO, rid, "warning")

        log(f"{'━'*70}", C.H, rid)

    # ── Log viewer endpoints ─────────────────────────────────────

    def _serve_logs_json(self):
        with log_lock:
            entries = list(log_entries)
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(entries, ensure_ascii=False).encode())

    def _serve_logs_ui(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(LOGS_HTML.encode())

    # ── HTTP method dispatch ─────────────────────────────────────

    def do_POST(self):
        self._proxy_forward('POST')

    def do_GET(self):
        self._proxy_forward('GET')

    def do_HEAD(self):
        rid = next_id()
        log(f"HEAD {self.path}", C.DIM, rid)
        try:
            req = urllib.request.Request(f"{OLLAMA_URL}{self.path}", method='HEAD')
            with urllib.request.urlopen(req, timeout=10) as resp:
                self.send_response(resp.status)
                for h, v in resp.headers.items():
                    self.send_header(h, v)
                self.end_headers()
        except Exception:
            self.send_response(200)
            self.end_headers()

    def do_DELETE(self):
        self._proxy_forward('DELETE')

    def log_message(self, fmt, *args):
        pass  # Suppress default logging


# ── Web-based log viewer ─────────────────────────────────────────────

LOGS_HTML = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><title>Ollama Debug Proxy</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0d1117; color:#c9d1d9; font-family:'JetBrains Mono',monospace; font-size:13px; }
  #header { background:#161b22; padding:12px 20px; border-bottom:1px solid #30363d;
            display:flex; align-items:center; gap:16px; }
  #header h1 { font-size:16px; color:#58a6ff; }
  #header .stats { color:#8b949e; font-size:12px; }
  #controls { display:flex; gap:8px; margin-left:auto; }
  #controls button { background:#21262d; color:#c9d1d9; border:1px solid #30363d;
                     padding:4px 12px; border-radius:4px; cursor:pointer; font-size:12px; }
  #controls button:hover { background:#30363d; }
  #controls button.active { background:#1f6feb; border-color:#1f6feb; }
  #log { padding:8px 16px; overflow-y:auto; height:calc(100vh - 52px); }
  .entry { padding:2px 0; white-space:pre-wrap; word-break:break-all; line-height:1.5; }
  .entry .ts { color:#484f58; }
  .entry .rid { color:#8b949e; font-weight:bold; }
  .cat-request { color:#d2a8ff; font-weight:bold; }
  .cat-response { color:#79c0ff; font-weight:bold; }
  .cat-tools { color:#3fb950; font-weight:bold; }
  .cat-tool_call { color:#3fb950; }
  .cat-warning { color:#d29922; font-weight:bold; }
  .cat-error { color:#f85149; font-weight:bold; }
  .cat-content { color:#8b949e; }
  .cat-messages { color:#484f58; }
  .cat-info { color:#c9d1d9; }
  .separator { color:#30363d; }
  #filter { background:#0d1117; color:#c9d1d9; border:1px solid #30363d;
            padding:4px 8px; border-radius:4px; font-size:12px; width:200px; }
</style></head><body>
<div id="header">
  <h1>Ollama Debug Proxy</h1>
  <span class="stats" id="stats">Loading...</span>
  <div id="controls">
    <input type="text" id="filter" placeholder="Filter logs...">
    <button onclick="toggleAutoScroll()" id="scrollBtn" class="active">Auto-scroll</button>
    <button onclick="clearLog()">Clear</button>
  </div>
</div>
<div id="log"></div>
<script>
let autoScroll = true;
let filter = '';
let lastCount = 0;

function toggleAutoScroll() {
  autoScroll = !autoScroll;
  document.getElementById('scrollBtn').classList.toggle('active', autoScroll);
}
function clearLog() {
  document.getElementById('log').innerHTML = '';
  lastCount = 0;
}
document.getElementById('filter').addEventListener('input', e => {
  filter = e.target.value.toLowerCase();
  lastCount = 0;
  document.getElementById('log').innerHTML = '';
  fetchLogs();
});

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function renderEntry(e) {
  if (filter && !e.msg.toLowerCase().includes(filter) && !(e.cat||'').includes(filter)) return '';
  const cat = e.cat || 'info';
  if (e.msg.startsWith('━')) return `<div class="entry separator">${e.msg}</div>`;
  const rid = e.rid ? `<span class="rid">#${e.rid}</span> ` : '';
  return `<div class="entry"><span class="ts">[${e.ts}]</span> ${rid}<span class="cat-${cat}">${escHtml(e.msg)}</span></div>`;
}

async function fetchLogs() {
  try {
    const r = await fetch('/logs/json');
    const entries = await r.json();
    const el = document.getElementById('log');
    const newEntries = filter ? entries : entries.slice(lastCount);
    if (filter) el.innerHTML = '';
    let html = '';
    for (const e of (filter ? entries : newEntries)) {
      html += renderEntry(e);
    }
    if (html) {
      el.insertAdjacentHTML('beforeend', html);
      if (autoScroll) el.scrollTop = el.scrollHeight;
    }
    lastCount = entries.length;
    document.getElementById('stats').textContent =
      `${entries.length} log entries | refreshing every 1s`;
  } catch(e) {
    document.getElementById('stats').textContent = 'Error fetching logs';
  }
}

fetchLogs();
setInterval(fetchLogs, 1000);
</script></body></html>"""


# ── Main ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    with open(LOG_FILE, 'w') as f:
        f.write(f"=== Ollama Debug Proxy started at {datetime.now(timezone.utc).isoformat()} ===\n")

    print(f"""{C.H}{'━'*60}
  Ollama Debug Proxy
{'━'*60}{C.E}
{C.CY}Listening on:{C.E}  0.0.0.0:{PROXY_PORT}
{C.CY}Forwarding to:{C.E} {OLLAMA_URL}
{C.CY}Log file:{C.E}      {LOG_FILE}
{C.CY}Log viewer:{C.E}    http://localhost:{PROXY_PORT}/logs

{C.Y}To use:{C.E}
  Change Open WebUI Ollama URL to point to this proxy.

{C.G}Watching for requests...{C.E}
""", flush=True)

    try:
        server = ThreadingHTTPServer(('0.0.0.0', PROXY_PORT), OllamaDebugProxy)
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{C.Y}Shutting down...{C.E}")
        sys.exit(0)
