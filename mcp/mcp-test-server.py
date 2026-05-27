#!/usr/bin/env python3
"""
Simple MCP test server for debugging MCP client integrations.
Returns basic data to verify tool execution is working.

Port: 8018
"""

import asyncio
import json
import os
import logging
from datetime import datetime

import uvicorn
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse
from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

HOST = os.environ.get("MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("MCP_PORT", "8018"))

mcp_server = Server("mcp-test")

# Simple test tools
TOOLS = [
    Tool(
        name="echo",
        description="Echo back the input message. Use this to test basic tool calling.",
        inputSchema={
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Message to echo back"}
            },
            "required": ["message"]
        }
    ),
    Tool(
        name="get_time",
        description="Get the current server time. No parameters needed.",
        inputSchema={
            "type": "object",
            "properties": {}
        }
    ),
    Tool(
        name="add_numbers",
        description="Add two numbers together and return the result.",
        inputSchema={
            "type": "object",
            "properties": {
                "a": {"type": "number", "description": "First number"},
                "b": {"type": "number", "description": "Second number"}
            },
            "required": ["a", "b"]
        }
    ),
    Tool(
        name="get_info",
        description="Get basic server information.",
        inputSchema={
            "type": "object",
            "properties": {}
        }
    ),
    Tool(
        name="greet",
        description="Generate a greeting for a person.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Name of person to greet"}
            },
            "required": ["name"]
        }
    )
]

@mcp_server.list_tools()
async def list_tools():
    return TOOLS

@mcp_server.call_tool()
async def call_tool(name: str, arguments: dict):
    logger.info(f">>> TOOL CALLED: {name} with args: {arguments}")

    try:
        if name == "echo":
            message = arguments.get("message", "")
            result = f"Echo: {message}"

        elif name == "get_time":
            result = f"Current time: {datetime.now().isoformat()}"

        elif name == "add_numbers":
            a = arguments.get("a", 0)
            b = arguments.get("b", 0)
            result = f"{a} + {b} = {a + b}"

        elif name == "get_info":
            result = json.dumps({
                "server": "mcp-test",
                "version": "1.0.0",
                "tools_count": len(TOOLS),
                "status": "healthy"
            }, indent=2)

        elif name == "greet":
            name_arg = arguments.get("name", "World")
            result = f"Hello, {name_arg}! Welcome to the MCP test server."

        else:
            result = f"Unknown tool: {name}"

        logger.info(f"<<< TOOL RESULT: {result}")
        return [TextContent(type="text", text=result)]

    except Exception as e:
        logger.error(f"Tool error: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]

# SSE transport
sse_transport = SseServerTransport("/messages")

async def handle_sse(request):
    logger.info("SSE connection established")
    async with sse_transport.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await mcp_server.run(
            streams[0], streams[1], mcp_server.create_initialization_options()
        )

async def handle_messages(request):
    logger.info("Message received")
    await sse_transport.handle_post_message(request.scope, request.receive, request._send)

async def health(request):
    return JSONResponse({
        "ok": True,
        "service": "mcp-test-server",
        "transport": "sse",
        "tools_count": len(TOOLS),
        "tools": [t.name for t in TOOLS],
        "endpoints": {
            "sse": f"http://{HOST}:{PORT}/sse",
            "messages": f"http://{HOST}:{PORT}/messages"
        }
    })

async def tools_list(request):
    return JSONResponse({
        "tools": [{"name": t.name, "description": t.description} for t in TOOLS]
    })

app = Starlette(
    debug=True,
    routes=[
        Route("/sse", handle_sse),
        Route("/messages", handle_messages, methods=["POST"]),
        Route("/health", health),
        Route("/tools", tools_list),
    ]
)

if __name__ == "__main__":
    logger.info(f"Starting MCP test server on {HOST}:{PORT}")
    logger.info(f"Tools: {[t.name for t in TOOLS]}")
    logger.info(f"SSE endpoint: http://{HOST}:{PORT}/sse")
    uvicorn.run(app, host=HOST, port=PORT)
