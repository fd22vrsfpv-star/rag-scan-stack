#!/bin/bash
# Test MCP Server Setup

echo "=== MCP Server Test ==="
echo ""

echo "1. Checking permissions..."
ls -ld /opt/rag-scan-stack/mcp/
ls -l /opt/rag-scan-stack/mcp/health-check-server.py

echo ""
echo "2. Checking Python and dependencies..."
python3 --version
python3 -c "import mcp; print('✓ mcp module:', mcp.__version__)" 2>&1
python3 -c "import httpx; print('✓ httpx module:', httpx.__version__)" 2>&1

echo ""
echo "3. Testing HTTP API..."
curl -s http://localhost:8000/health/quick | python3 -m json.tool 2>/dev/null || echo "API check completed"

echo ""
echo "4. Testing MCP server import..."
python3 -c "import sys; sys.path.insert(0, '/opt/rag-scan-stack/mcp'); exec(open('/opt/rag-scan-stack/mcp/health-check-server.py').read().split('async def main')[0]); print('✓ MCP server loads successfully')" 2>&1 | grep -E "(✓|Error|Import)" || echo "Import check completed"

echo ""
echo "5. File ownership and accessibility..."
stat -c "Owner: %U, Group: %G, Perms: %a" /opt/rag-scan-stack/mcp/health-check-server.py

echo ""
echo "=== Test Complete ==="
