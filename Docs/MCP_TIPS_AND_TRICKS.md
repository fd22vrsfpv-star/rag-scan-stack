# MCP Tips & Tricks for Building AI-Integrated Security Tools

This document captures practical lessons learned from building a multi-agent security platform with MCP (Model Context Protocol) integration.

---

## Table of Contents

1. [Architecture Decisions](#1-architecture-decisions)
2. [MCP Server Patterns](#2-mcp-server-patterns)
3. [Tool Design Best Practices](#3-tool-design-best-practices)
4. [Error Handling](#4-error-handling)
5. [Async & Concurrency](#5-async--concurrency)
6. [Logging & Debugging](#6-logging--debugging)
7. [Security Considerations](#7-security-considerations)
8. [Performance Optimization](#8-performance-optimization)
9. [Testing Strategies](#9-testing-strategies)
10. [Common Pitfalls](#10-common-pitfalls)

---

## 1. Architecture Decisions

### Pattern: HTTP Services + Thin MCP Proxy

**Problem:** MCP servers run via stdio, making debugging difficult and causing issues with mixed stderr output.

**Solution:** Build your services as HTTP APIs first, then create a thin MCP proxy.

```
┌────────────────┐         ┌─────────────────┐         ┌───────────────┐
│ Claude Desktop │ ◄─MCP─► │ MCP Proxy       │ ◄─HTTP─► │ HTTP Services │
│                │         │ (17KB Python)   │          │ (Full Logic)  │
└────────────────┘         └─────────────────┘         └───────────────┘
```

**Benefits:**
- Test services independently via curl/Postman
- Hot reload services without restarting MCP
- Multiple consumers (MCP, web UI, scripts) share same backend
- Easier debugging (HTTP has better tooling)

**Example - HTTP MCP Proxy:**
```python
# mcp/autogen-http-mcp.py - Only ~200 lines
async def call_tool(name: str, arguments: dict):
    if name == "start_pentest_session":
        async with httpx.AsyncClient(timeout=300) as client:
            resp = await client.post(f"{API_URL}/pentest", json=arguments)
            return resp.json()
```

### Pattern: Dual Interface Support

Your services should support BOTH MCP and REST simultaneously:

```python
# autogen_service.py
app = FastAPI()

@app.post("/pentest")
async def start_pentest_http(request: PentestRequest):
    return await start_pentest_session(request.dict())

# mcp_server.py uses the same underlying function
@server.call_tool()
async def handle_tool(name, args):
    if name == "start_pentest_session":
        return await start_pentest_session(args)
```

---

## 2. MCP Server Patterns

### Suppress Logging in MCP Mode

MCP uses stdio for communication. Any stderr output breaks the protocol.

```python
# CRITICAL: Check MCP mode before importing logging libraries
MCP_MODE = os.environ.get("MCP_MODE", "false").lower() == "true"

if MCP_MODE:
    # Suppress ALL logging to stderr
    logging.getLogger().setLevel(logging.CRITICAL + 1)
    logging.getLogger("httpx").setLevel(logging.CRITICAL + 1)
    # ... suppress all noisy libraries
```

### Lazy Imports for Fast Startup

Claude Desktop has a short timeout for MCP server initialization. Defer heavy imports.

```python
# BAD: Import everything upfront
from autogen import AssistantAgent  # Takes 2+ seconds
from playwright.async_api import async_playwright  # Heavy

# GOOD: Lazy import when needed
def get_autogen():
    from autogen import AssistantAgent
    return AssistantAgent

async def handle_tool(name, args):
    if name == "start_agent":
        AssistantAgent = get_autogen()  # Import only when called
```

### Tool Registration with Rich Schemas

Good tool descriptions help the AI use them correctly:

```python
Tool(
    name="start_nmap_scan",
    description="""Start an Nmap port scan against a target.

Workflow:
1. Masscan performs fast initial port discovery
2. Nmap performs service version detection on discovered ports
3. Results stored in PostgreSQL for analysis

Returns a job_id - use get_nmap_job_status to monitor progress.""",
    inputSchema={
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "IP, hostname, or CIDR (e.g., 10.0.1.0/24)",
                "pattern": "^[a-zA-Z0-9./-]+$"  # Basic validation
            },
            "ports": {
                "type": "string",
                "description": "Port range (default: top 1000)",
                "default": "1-1000"
            },
            "scan_type": {
                "type": "string",
                "enum": ["quick", "full", "stealth"],
                "default": "quick"
            }
        },
        "required": ["target"]
    }
)
```

---

## 3. Tool Design Best Practices

### Return Structured Data, Not Raw Output

AI assistants work better with structured JSON than raw text:

```python
# BAD: Return raw Nmap output
return nmap_xml_output  # AI can't parse this reliably

# GOOD: Return structured summary
return {
    "hosts_found": 45,
    "open_ports": [22, 80, 443, 8080],
    "services": {
        "22": {"name": "ssh", "version": "OpenSSH 8.9"},
        "80": {"name": "http", "version": "Apache 2.4.18"}
    },
    "high_risk_findings": [
        {"port": 80, "service": "Apache 2.4.18", "cve": "CVE-2021-41773"}
    ]
}
```

### Provide Actionable Next Steps

Help the AI know what to do next:

```python
return {
    "status": "completed",
    "findings": [...],
    "next_steps": [
        "Run 'search_exploits' for discovered services",
        "Start web_scan on ports 80, 443",
        "Check for default credentials on SSH"
    ],
    "related_tools": ["search_exploits", "start_web_scan"]
}
```

### Use Job IDs for Long-Running Operations

Scans can take minutes. Don't block the AI:

```python
async def start_nmap_scan(target, ports):
    job_id = str(uuid4())

    # Queue the job, return immediately
    await job_queue.put({"id": job_id, "target": target, "ports": ports})

    return {
        "job_id": job_id,
        "status": "queued",
        "message": "Scan started. Use get_nmap_job_status to monitor progress.",
        "estimated_duration": "2-5 minutes for /24 network"
    }
```

---

## 4. Error Handling

### Format Errors for AI Consumption

```python
def format_tool_response(result_str: str) -> str:
    """Format responses to be readable in Claude Desktop."""
    try:
        result = json.loads(result_str)

        if isinstance(result, dict) and "error" in result:
            error_msg = f"❌ {result.get('operation', 'Operation')} failed\n\n"
            error_msg += f"**Error Type**: {result['error']}\n"

            if "HTTP" in result['error']:
                error_msg += f"**Status Code**: {result.get('status_code')}\n"

            if "suggestion" in result:
                error_msg += f"\n💡 **Suggestion**: {result['suggestion']}\n"

            return error_msg

        return json.dumps(result, indent=2)
    except:
        return result_str
```

### Check Service Health Before Operations

```python
async def check_scan_service_health(service_name: str, health_url: str):
    """Verify service is up before attempting scan."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(health_url)
            if resp.status_code == 200:
                return True, None
            return False, f"{service_name} unhealthy: HTTP {resp.status_code}"
    except httpx.ConnectError:
        return False, f"{service_name} unreachable: Connection refused"

# Usage
async def start_nmap_scan(target):
    healthy, error = await check_scan_service_health("nmap_scanner", f"{NMAP_URL}/health")
    if not healthy:
        return {"error": error, "suggestion": "Check if nmap_scanner container is running"}
```

### Graceful Degradation

```python
async def search_exploits(query):
    try:
        return await rag_service.search(query)
    except ServiceUnavailable:
        return {
            "error": "RAG service unavailable",
            "fallback": "Try searching ExploitDB directly: https://exploit-db.com",
            "suggestion": "Run 'docker compose restart scan-recommender'"
        }
```

---

## 5. Async & Concurrency

### Use Proper Timeouts

Different operations need different timeouts:

```python
# Configurable via environment
MCP_TIMEOUT_SCAN = float(os.environ.get("MCP_TIMEOUT_SCAN", "300"))   # 5 min
MCP_TIMEOUT_QUICK = float(os.environ.get("MCP_TIMEOUT_QUICK", "30"))  # 30 sec
MCP_TIMEOUT_STATUS = float(os.environ.get("MCP_TIMEOUT_STATUS", "15")) # 15 sec

async def handle_tool(name, args):
    if name in ["start_nmap_scan", "start_web_scan"]:
        timeout = MCP_TIMEOUT_SCAN
    elif name in ["query_assets", "search_exploits"]:
        timeout = MCP_TIMEOUT_QUICK
    else:
        timeout = MCP_TIMEOUT_STATUS

    async with httpx.AsyncClient(timeout=timeout) as client:
        ...
```

### Session Stall Detection

AI conversations can get stuck. Add a watchdog:

```python
class SessionWatchdog:
    def __init__(self, stall_timeout=300):  # 5 minutes
        self.stall_timeout = stall_timeout

    async def monitor(self, session_id):
        last_message_count = 0
        stall_start = None

        while True:
            await asyncio.sleep(30)

            current_count = await get_message_count(session_id)

            if current_count == last_message_count:
                if stall_start is None:
                    stall_start = time.time()
                elif time.time() - stall_start > self.stall_timeout:
                    await stop_session(session_id, reason="stalled")
                    break
            else:
                stall_start = None
                last_message_count = current_count
```

### Background Tasks with Progress Updates

```python
async def start_long_scan(target):
    job_id = str(uuid4())

    # Start background task
    asyncio.create_task(run_scan_with_updates(job_id, target))

    return {"job_id": job_id}

async def run_scan_with_updates(job_id, target):
    await update_job_status(job_id, "running", progress="masscan_starting")

    # Run Masscan
    await run_masscan(target)
    await update_job_status(job_id, "running", progress="masscan_completed")

    # Run Nmap
    await update_job_status(job_id, "running", progress="nmap_enrichment")
    await run_nmap(target)

    await update_job_status(job_id, "completed", progress="done")
```

---

## 6. Logging & Debugging

### Send Logs to a Central Viewer

MCP's stdio constraint makes debugging hard. Send logs via HTTP:

```python
async def send_log(level: str, message: str, request_id: str = None):
    """Send log to web viewer for real-time debugging."""
    formatted = f"[{request_id}] {message}" if request_id else message

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                f"{LOG_API_URL}/logs/ingest",
                json={"level": level, "message": formatted, "source": "mcp"}
            )
    except:
        # Fallback to stderr (visible in docker logs)
        print(f"[MCP-LOG] {level}: {formatted}", file=sys.stderr)
```

### Circular Log Buffers

Avoid filling disk with logs:

```python
from collections import deque

class CircularLogBuffer:
    def __init__(self, max_size=10000):
        self.buffer = deque(maxlen=max_size)

    def append(self, entry):
        self.buffer.append({
            "timestamp": datetime.now().isoformat(),
            **entry
        })

    def get_recent(self, n=100, level=None):
        logs = list(self.buffer)
        if level:
            logs = [l for l in logs if l["level"] == level]
        return logs[-n:]

# Expose via HTTP for web UI
@app.get("/logs/recent")
async def get_logs(limit: int = 100, level: str = None):
    return log_buffer.get_recent(limit, level)
```

### Request ID Correlation

Track requests across services:

```python
@server.call_tool()
async def handle_tool(name, args):
    request_id = f"mcp-{uuid4().hex[:8]}"

    await send_log("INFO", f"Tool called: {name}", request_id)

    try:
        result = await execute_tool(name, args, request_id)
        await send_log("INFO", f"Tool completed: {name}", request_id)
        return result
    except Exception as e:
        await send_log("ERROR", f"Tool failed: {name} - {e}", request_id)
        return {"error": str(e), "request_id": request_id}
```

---

## 7. Security Considerations

### Input Validation

Never trust AI-generated input:

```python
import re

def validate_target(target: str) -> tuple[bool, str]:
    """Validate target is a safe IP/hostname/CIDR."""
    # Reject obvious shell injection attempts
    if any(c in target for c in [';', '|', '&', '$', '`', '\n']):
        return False, "Invalid characters in target"

    # Only allow IP, hostname, or CIDR patterns
    ip_pattern = r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$'
    hostname_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z0-9]$'

    if re.match(ip_pattern, target) or re.match(hostname_pattern, target):
        return True, None

    return False, "Target must be IP, hostname, or CIDR"
```

### Parameterized Queries

Never interpolate SQL:

```python
# BAD: SQL injection vulnerability
cursor.execute(f"SELECT * FROM assets WHERE ip = '{ip}'")

# GOOD: Parameterized query
cursor.execute("SELECT * FROM assets WHERE ip = %s", (ip,))
```

### Secrets Management

```python
# Use environment variables, never hardcode
API_KEY = os.environ.get("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY environment variable required")

# Don't log secrets
async def send_log(level, message):
    # Redact potential secrets
    redacted = re.sub(r'(api_key|password|token)=[^\s&]+', r'\1=REDACTED', message)
    ...
```

### Scope Limitations

Consider adding guardrails:

```python
ALLOWED_TARGET_RANGES = [
    "10.0.0.0/8",      # Private
    "172.16.0.0/12",   # Private
    "192.168.0.0/16",  # Private
]

def is_target_allowed(target: str) -> bool:
    """Only allow scanning private networks by default."""
    import ipaddress
    try:
        target_net = ipaddress.ip_network(target, strict=False)
        for allowed in ALLOWED_TARGET_RANGES:
            if target_net.subnet_of(ipaddress.ip_network(allowed)):
                return True
        return False
    except:
        return False  # Hostname - would need DNS resolution
```

---

## 8. Performance Optimization

### Connection Pooling

Reuse HTTP connections:

```python
# BAD: New connection per request
async def call_api(endpoint):
    async with httpx.AsyncClient() as client:
        return await client.get(endpoint)

# GOOD: Shared client with connection pooling
http_client = httpx.AsyncClient(
    timeout=30,
    limits=httpx.Limits(max_connections=100, max_keepalive_connections=20)
)

async def call_api(endpoint):
    return await http_client.get(endpoint)
```

### Batch Database Operations

```python
# BAD: N+1 queries
for port in ports:
    await db.execute("INSERT INTO ports VALUES (%s)", (port,))

# GOOD: Batch insert
await db.executemany(
    "INSERT INTO ports VALUES (%s)",
    [(p,) for p in ports]
)
```

### Embedding Caching

```python
from functools import lru_cache

@lru_cache(maxsize=10000)
def get_embedding(text: str) -> list:
    """Cache embeddings to avoid recomputing."""
    return embedding_model.encode(text).tolist()
```

---

## 9. Testing Strategies

### Unit Test Tools Independently

```python
import pytest

@pytest.mark.asyncio
async def test_start_nmap_scan_validates_input():
    result = await start_nmap_scan(target="; rm -rf /")
    assert "error" in result
    assert "Invalid characters" in result["error"]

@pytest.mark.asyncio
async def test_start_nmap_scan_returns_job_id():
    result = await start_nmap_scan(target="192.168.1.1")
    assert "job_id" in result
    assert result["status"] == "queued"
```

### Mock External Services

```python
@pytest.fixture
def mock_nmap_service(httpx_mock):
    httpx_mock.add_response(
        url="http://nmap_scanner:8012/jobs/masscan-then-nmap",
        json={"job_id": "test-123", "status": "queued"}
    )
    return httpx_mock

async def test_scan_calls_nmap_service(mock_nmap_service):
    result = await start_nmap_scan("10.0.1.0/24")
    assert result["job_id"] == "test-123"
```

### Integration Test with Docker

```bash
# docker-compose.test.yml
services:
  test-runner:
    build: .
    command: pytest tests/ -v
    depends_on:
      - rag-postgres
      - nmap_scanner
    environment:
      - TEST_MODE=true
```

---

## 10. Common Pitfalls

### Pitfall 1: MCP Timeout on Startup

**Problem:** Claude Desktop gives up if MCP server takes too long to initialize.

**Solution:**
- Use lazy imports
- Initialize heavy resources in background
- Keep MCP server startup under 5 seconds

### Pitfall 2: Mixed Stdout/Stderr

**Problem:** Print statements break MCP protocol.

**Solution:**
- Never use `print()` in MCP mode
- Route all output through logging
- Suppress third-party library output

### Pitfall 3: AI Hallucinating Tool Names

**Problem:** AI tries to call tools that don't exist.

**Solution:**
- Use clear, unambiguous tool names
- Provide comprehensive descriptions
- Include examples in descriptions

### Pitfall 4: Blocking Event Loop

**Problem:** Synchronous operations freeze the server.

**Solution:**
```python
# BAD: Blocking call
result = requests.get(url)

# GOOD: Async call
async with httpx.AsyncClient() as client:
    result = await client.get(url)
```

### Pitfall 5: Memory Leaks in Long Sessions

**Problem:** Growing data structures exhaust memory.

**Solution:**
```python
# Use bounded collections
from collections import deque
logs = deque(maxlen=10000)

# Clean up old sessions
async def cleanup_old_sessions(older_than_hours=24):
    cutoff = datetime.now() - timedelta(hours=older_than_hours)
    await db.execute("DELETE FROM sessions WHERE created_at < %s", (cutoff,))
```

### Pitfall 6: Race Conditions in Job Status

**Problem:** Checking job status immediately after starting returns stale data.

**Solution:**
```python
async def start_scan(target):
    job_id = str(uuid4())

    # Insert job record BEFORE starting background task
    await db.execute(
        "INSERT INTO jobs (id, status) VALUES (%s, 'queued')",
        (job_id,)
    )

    # Now start background task
    asyncio.create_task(run_scan(job_id, target))

    return {"job_id": job_id, "status": "queued"}
```

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────────────┐
│                    MCP Development Checklist                      │
├─────────────────────────────────────────────────────────────────┤
│ □ HTTP services first, MCP proxy second                         │
│ □ Suppress stderr in MCP mode                                   │
│ □ Lazy import heavy dependencies                                │
│ □ Rich tool descriptions with examples                          │
│ □ Structured JSON responses, not raw output                     │
│ □ Job IDs for long operations                                   │
│ □ Health checks before operations                               │
│ □ Proper timeouts (quick/scan/status)                          │
│ □ Request ID correlation across services                        │
│ □ Input validation on all parameters                            │
│ □ Connection pooling for HTTP clients                           │
│ □ Bounded collections to prevent memory leaks                   │
│ □ Unit tests for tools, integration tests with Docker           │
└─────────────────────────────────────────────────────────────────┘
```

---

## IDE Integration: Continue Extension (VS Code)

### Step 1: Configure Local LLM

Create `.continue/config.yaml`:

```yaml
name: local-profile
version: 1.0.0
schema: v1
models:
  - name: Autodetect
    provider: ollama
    model: AUTODETECT
    apiBase: http://localhost:11434
    roles:
      - chat
      - autocomplete
      - edit
      - apply
```

### Step 2: Add MCP Server

Copy `mcp/continue-mcp-config.json` to `.continue/mcpServers/` or create your own.

**Windows + WSL** (`.continue/mcpServers/autogen-pentest.json`):
```json
{
  "mcpServers": {
    "autogen-pentest": {
      "command": "C:\\Windows\\System32\\wsl.exe",
      "args": [
        "-d", "Ubuntu-22.04", "--",
        "/usr/bin/python3",
        "/opt/rag-scan-stack/mcp/autogen-http-mcp.py"
      ],
      "description": "AI-powered penetration testing agents"
    }
  }
}
```

**Linux/Mac** (`.continue/mcpServers/autogen-pentest.json`):
```json
{
  "mcpServers": {
    "autogen-pentest": {
      "command": "/usr/bin/python3",
      "args": ["/opt/rag-scan-stack/mcp/autogen-http-mcp.py"],
      "description": "AI-powered penetration testing agents"
    }
  }
}
```

### Alternative: HTTP Transport

If your MCP server exposes an HTTP endpoint:

```json
{
  "mcpServers": {
    "autogen-pentest": {
      "type": "streamable-http",
      "url": "http://localhost:8015/mcp"
    }
  }
}
```

### Important Notes

- MCP only works in **Agent mode** in Continue
- Restart VS Code after adding/modifying config
- Check Continue settings to verify server detection
- Environment variables can be added via `env:` key in YAML

---

## Further Reading

- [MCP Specification](https://modelcontextprotocol.io)
- [Anthropic MCP Python SDK](https://github.com/anthropics/mcp-python)
- [Continue MCP Documentation](https://docs.continue.dev/customize/deep-dives/mcp)
- [Autogen Documentation](https://microsoft.github.io/autogen)
- [pgvector GitHub](https://github.com/pgvector/pgvector)
- [httpx Documentation](https://www.python-httpx.org)
