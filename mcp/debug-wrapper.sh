#!/bin/bash
# Debug wrapper for MCP server

LOG_FILE="/opt/rag-scan-stack/mcp/debug.log"

{
    echo "=== MCP Server Debug Log - $(date) ==="
    echo "Working directory: $(pwd)"
    echo "Python version: $(python3 --version)"
    echo "Python path: $(which python3)"
    echo "Script path: /opt/rag-scan-stack/mcp/health-check-server.py"
    echo "Script exists: $(test -f /opt/rag-scan-stack/mcp/health-check-server.py && echo 'Yes' || echo 'No')"
    echo "Script readable: $(test -r /opt/rag-scan-stack/mcp/health-check-server.py && echo 'Yes' || echo 'No')"
    echo "Script executable: $(test -x /opt/rag-scan-stack/mcp/health-check-server.py && echo 'Yes' || echo 'No')"
    echo "User: $(whoami)"
    echo "Groups: $(groups)"
    echo "File permissions: $(ls -l /opt/rag-scan-stack/mcp/health-check-server.py)"
    echo ""
    echo "Testing Python imports..."
    python3 -c "import mcp; import httpx; print('✓ Imports successful')" 2>&1
    echo ""
    echo "Starting MCP server..."
    echo "---"
} >> "$LOG_FILE" 2>&1

# Run the actual server
exec python3 /opt/rag-scan-stack/mcp/health-check-server.py "$@" 2>> "$LOG_FILE"
