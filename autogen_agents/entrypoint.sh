#!/bin/bash
# Entrypoint for autogen-agents service
# Supports both FastAPI (default) and MCP server modes

set -e

# If first arg is "mcp", run MCP server
if [ "$1" = "mcp" ]; then
    echo "Starting MCP server..."
    exec python /app/mcp_server.py
else
    # Default: Run FastAPI server
    echo "Starting FastAPI server..."
    if [ -f /certs/server.key ] && [ -f /certs/server.crt ]; then
        exec uvicorn autogen_service:app --host 0.0.0.0 --port 8015 --log-level info \
            --ssl-keyfile=/certs/server.key --ssl-certfile=/certs/server.crt
    else
        exec uvicorn autogen_service:app --host 0.0.0.0 --port 8015 --log-level info
    fi
fi
