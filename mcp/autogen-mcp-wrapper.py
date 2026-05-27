#!/usr/bin/env python3
"""
WSL wrapper for the autogen MCP server.
Runs directly in WSL instead of via docker exec for better performance.
"""
import sys
import os

# Add the autogen_agents directory to path
sys.path.insert(0, '/opt/rag-scan-stack/autogen_agents')

# Set environment to use host.docker.internal for API calls
os.environ['MCP_API_URL'] = 'http://localhost:8015'
os.environ['MCP_MODE'] = 'true'

# Import and run the MCP server
from mcp_server import run_mcp_server
import asyncio

if __name__ == "__main__":
    asyncio.run(run_mcp_server())
