#!/usr/bin/env python3
"""
Stdio-to-Streamable-HTTP Bridge for MCP Servers.

Wraps ANY stdio-based MCP server (Claude Desktop format) and exposes it
as a streamable-http server. This lets you import third-party MCP tools
(npm, pip, GitHub) into the pentest stack without rewriting them.

Usage:
    python stdio_bridge.py --port 9030 --cmd "npx @anthropic/burpsuite-mcp"
    python stdio_bridge.py --port 9031 --cmd "python -m github_mcp_server"
    python stdio_bridge.py --port 9032 --cmd "node /path/to/server.js"
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import uuid
from typing import Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
import uvicorn

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("stdio-bridge")

app = FastAPI()

# Global state
_process: Optional[asyncio.subprocess.Process] = None
_cmd: str = ""
_server_name: str = "stdio-bridge"
_lock = asyncio.Lock()
_pending: dict = {}  # request_id -> asyncio.Future


async def _start_process():
    """Start the stdio MCP server subprocess."""
    global _process
    if _process and _process.returncode is None:
        return  # Already running

    log.info(f"Starting stdio MCP server: {_cmd}")
    _process = await asyncio.create_subprocess_shell(
        _cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env={**os.environ},
    )
    # Start reading stdout in background
    asyncio.create_task(_read_stdout())
    asyncio.create_task(_read_stderr())
    log.info(f"Stdio process started (PID {_process.pid})")


async def _read_stdout():
    """Read JSON-RPC responses from the subprocess stdout."""
    global _process
    if not _process or not _process.stdout:
        return
    buffer = b""
    while True:
        try:
            chunk = await _process.stdout.read(65536)
            if not chunk:
                log.warning("Stdio process stdout closed")
                break
            buffer += chunk
            # Try to parse complete JSON messages (newline-delimited)
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    msg_id = msg.get("id")
                    if msg_id and msg_id in _pending:
                        _pending[msg_id].set_result(msg)
                    else:
                        log.debug(f"Unmatched response: {str(msg)[:200]}")
                except json.JSONDecodeError:
                    log.debug(f"Non-JSON stdout: {line[:200]}")
        except Exception as e:
            log.error(f"Stdout read error: {e}")
            break


async def _read_stderr():
    """Log stderr from the subprocess."""
    global _process
    if not _process or not _process.stderr:
        return
    while True:
        try:
            line = await _process.stderr.readline()
            if not line:
                break
            log.info(f"[stdio-stderr] {line.decode().strip()}")
        except Exception:
            break


async def _send_request(method: str, params: dict = None, req_id: str = None) -> dict:
    """Send a JSON-RPC request to the stdio process and wait for response."""
    global _process
    await _start_process()

    if not _process or not _process.stdin:
        return {"error": {"code": -1, "message": "Stdio process not running"}}

    if not req_id:
        req_id = str(uuid.uuid4())

    request = {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": method,
    }
    if params:
        request["params"] = params

    # Create future for response
    future = asyncio.get_event_loop().create_future()
    _pending[req_id] = future

    try:
        async with _lock:
            _process.stdin.write(json.dumps(request).encode() + b"\n")
            await _process.stdin.drain()

        # Wait for response (timeout 60s)
        response = await asyncio.wait_for(future, timeout=60.0)
        return response
    except asyncio.TimeoutError:
        log.warning(f"Request timed out: {method}")
        return {"error": {"code": -2, "message": f"Timeout waiting for {method}"}}
    except Exception as e:
        return {"error": {"code": -3, "message": str(e)}}
    finally:
        _pending.pop(req_id, None)


# ── MCP Streamable-HTTP Endpoints ──────────────────────────────────

@app.post("/mcp")
async def mcp_endpoint(request: Request):
    """Handle MCP JSON-RPC requests (streamable-http transport)."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    method = body.get("method", "")
    params = body.get("params", {})
    req_id = body.get("id")

    # Handle initialize locally (bridge metadata)
    if method == "initialize":
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": _server_name,
                    "version": "1.0.0",
                },
            },
        })

    # Forward everything else to the stdio process
    response = await _send_request(method, params, req_id)
    return JSONResponse(response)


@app.get("/health")
async def health():
    running = _process is not None and _process.returncode is None
    return {"ok": running, "server": _server_name, "cmd": _cmd, "pid": _process.pid if _process else None}


@app.on_event("startup")
async def startup():
    await _start_process()


@app.on_event("shutdown")
async def shutdown():
    global _process
    if _process and _process.returncode is None:
        _process.terminate()
        try:
            await asyncio.wait_for(_process.wait(), timeout=5)
        except asyncio.TimeoutError:
            _process.kill()


def main():
    global _cmd, _server_name
    parser = argparse.ArgumentParser(description="Stdio-to-HTTP MCP Bridge")
    parser.add_argument("--port", type=int, required=True, help="HTTP port to listen on")
    parser.add_argument("--cmd", type=str, required=True, help="Command to run the stdio MCP server")
    parser.add_argument("--name", type=str, default="stdio-bridge", help="Server name")
    args = parser.parse_args()

    _cmd = args.cmd
    _server_name = args.name
    log.info(f"Starting stdio bridge on port {args.port}: {_cmd}")
    uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="info")


if __name__ == "__main__":
    main()
