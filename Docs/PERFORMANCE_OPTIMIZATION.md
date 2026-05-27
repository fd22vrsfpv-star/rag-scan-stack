# Performance Optimization Guide

## Current MCP Performance

### Measured Timings
- **MCP Server Startup**: ~0.31s (imports + initialization)
- **ScanTools Init**: ~0.11s
- **Database Queries**: <0.01s (fast)
- **API Calls**: Direct calls are fast

### The Issue

Claude Desktop MCP uses `docker exec -i autogen-agents python /app/mcp_server.py` which:
1. Starts a fresh Python process for **every tool call**
2. Re-imports all modules (0.31s overhead)
3. Re-initializes ScanTools
4. Then executes the tool

This is standard MCP behavior, but adds ~0.5-1s latency per call.

## Optimization Options

### Option 1: Accept the Latency (Recommended)
This is the standard MCP pattern. The 0.5s overhead is unavoidable with stdio-based MCP.

**Why this is actually fine:**
- Actual scan operations take seconds/minutes anyway
- Query operations complete in <1s total
- The overhead is consistent and predictable

### Option 2: Reduce Import Overhead

Make imports faster by caching:

```python
# scan_tools.py - Use connection pooling
self.client = httpx.Client(
    timeout=300.0,
    limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
)
```

**Estimated improvement**: Saves ~0.05s per call

### Option 3: Pre-warm the Container

Keep MCP server "warm" by calling it periodically:

```bash
# Add to crontab or systemd timer
*/5 * * * * docker exec autogen-agents python -c "from scan_tools import get_scan_tools; get_scan_tools()" > /dev/null 2>&1
```

**Estimated improvement**: Minimal, Python still needs to start

### Option 4: Use HTTP API Instead

For interactive work, use the HTTP API which has persistent connections:

```bash
# Fast - uses persistent FastAPI server
curl -X POST http://localhost:8015/pentest -H "Content-Type: application/json" -d '{...}'
```

**Estimated improvement**: ~0.3s faster per call

### Option 5: Reduce Tool Complexity (Advanced)

Split tools into "lightweight" and "heavyweight":
- Lightweight: query_*, list_* (keep current MCP)
- Heavyweight: start_*_scan (use background HTTP API)

## Recommended Approach

**For most users:** Accept the 0.5-1s latency. It's the MCP standard.

**For power users:**
1. Use HTTP API for rapid-fire queries
2. Use MCP for autonomous agent sessions
3. Enable HTTP/2 and connection pooling

## Measuring Your Performance

```bash
# Test MCP call speed
time docker exec -i autogen-agents python /app/mcp_server.py <<EOF
{"jsonrpc":"2.0","id":1,"method":"tools/list"}
EOF

# Test HTTP API speed
time curl -s http://localhost:8015/health

# Test database speed
docker exec rag-postgres psql -U app -d scans -c "\timing on" -c "SELECT COUNT(*) FROM assets;"
```

## Debugging Slow Calls

If a specific tool call is slow:

1. **Check docker logs** for the operation timing:
   ```bash
   docker logs autogen-agents --tail 20 2>&1 | grep "\[.*\]"
   ```

2. **Check service health**:
   ```bash
   curl http://localhost:8012/health  # nmap
   curl http://localhost:8000/health  # rag-api
   curl http://localhost:8013/health  # scan-recommender
   ```

3. **Enable debug mode**:
   ```bash
   # docker-compose.yml
   environment:
     SCAN_DEBUG: "true"
   ```

## Known Slow Operations

These operations are inherently slow (not optimization issues):

| Operation | Expected Time | Why |
|-----------|--------------|-----|
| start_nmap_scan | 30-300s | Masscan + Nmap service detection |
| start_web_scan | 60-600s | Gobuster + ZAP scanning |
| start_nuclei_scan | 30-180s | Thousands of template checks |
| query_exploitdb | 2-10s | RAG similarity search |
| get_scan_recommendations | 3-15s | Ollama LLM generation |

Query operations (query_assets, query_ports, query_vulns) should be <2s total.

## Future Improvements

Potential optimizations for v2:

1. **Long-running MCP server** - Use transport-level connection instead of stdio
2. **Connection pooling** - Reuse HTTP connections to backend services
3. **Caching** - Cache database query results for 30s
4. **Lazy loading** - Only import heavy modules when needed
5. **Pre-forked workers** - Keep warm Python processes ready

## Summary

- **Current**: ~0.5-1s per MCP call (mostly startup)
- **Target**: <0.5s per MCP call
- **Reality**: This is standard for stdio MCP servers
- **Alternative**: Use HTTP API for sub-100ms calls
