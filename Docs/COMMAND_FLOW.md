# Command Flow: "Start a nmap service scan of 10.252.30.206"

## Complete Journey from Claude Desktop to Scan Results

### Step-by-Step Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. USER INPUT (Windows Machine)                                         │
│    "Start a nmap service scan of 10.252.30.206"                        │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 2. CLAUDE DESKTOP (Windows Application)                                 │
│    • Receives user message                                              │
│    • Analyzes intent: "User wants to scan an IP with nmap"             │
│    • Decides to use MCP tool: start_nmap_scan()                         │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      │ Executes MCP Command via Docker:
                      │ $ docker exec -i autogen-agents python /app/mcp_server.py
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 3. MCP SERVER (Inside autogen-agents Container)                         │
│    Location: /app/mcp_server.py                                         │
│    • Receives function call request via stdio                           │
│    • Function: start_nmap_scan("10.252.30.206", "1-1000")              │
│    • Imports: from scan_tools import start_nmap_scan                    │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 4. SCAN_TOOLS.PY (Inside autogen-agents Container)                      │
│    Location: /app/scan_tools.py                                         │
│                                                                          │
│    Function wrapper (line 445):                                         │
│    def start_nmap_scan(ip_address: str, ports: str) -> str:            │
│        result = scan_tools.start_nmap_scan(ip_address, ports)          │
│        return json.dumps(result, indent=2)                              │
│                                                                          │
│    Calls ScanTools class method (line 134):                             │
│    def start_nmap_scan(self, ip_address, ports, service_detection):    │
│        # Prepare HTTP request                                           │
│        response = self.client.post(                                     │
│            f"{self.nmap_url}/jobs/masscan-then-nmap",                  │
│            json={                                                        │
│                "targets": ["10.252.30.206"],                            │
│                "ports": "1-1000",                                       │
│                "rate": 1000                                             │
│            }                                                             │
│        )                                                                 │
│                                                                          │
│    Environment variables:                                               │
│    • self.nmap_url = "http://nmap_scanner:8012"                        │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      │ HTTP POST Request
                      │ URL: http://nmap_scanner:8012/jobs/masscan-then-nmap
                      │ Body: {"targets": ["10.252.30.206"], "ports": "1-1000", ...}
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 5. DOCKER NETWORK ROUTING                                               │
│    • Docker's internal DNS resolves "nmap_scanner" → 172.20.0.X        │
│    • Request routes through agents_net bridge network                   │
│    • Arrives at nmap_scanner container on port 8012                     │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 6. NMAP_SCANNER CONTAINER (FastAPI Application)                         │
│    Location: /app/nmap-api.py                                           │
│    Port: 8012                                                            │
│                                                                          │
│    Endpoint Handler (line 62):                                          │
│    @app.post("/jobs/masscan-then-nmap")                                │
│    def masscan_then_nmap(body: MasscanBody):                           │
│        # Step 6a: Run Masscan                                           │
│        path = _run_masscan(                                             │
│            targets=["10.252.30.206"],                                   │
│            ports="1-1000",                                              │
│            rate=1000                                                     │
│        )                                                                 │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 7a. MASSCAN EXECUTION (Fast Port Discovery)                             │
│    Command executed:                                                     │
│    $ masscan --rate 1000 -oJ /app/nmap_out/masscan_<timestamp>.json \  │
│              -p 1-1000 10.252.30.206                                    │
│                                                                          │
│    • Scans all 1000 ports at 1000 packets/second                       │
│    • Typically completes in seconds                                     │
│    • Output: JSON file with open ports                                  │
│                                                                          │
│    Example output:                                                       │
│    [                                                                     │
│      { "ip": "10.252.30.206", "ports": [                               │
│          {"port": 22, "proto": "tcp", "status": "open"},               │
│          {"port": 80, "proto": "tcp", "status": "open"},               │
│          {"port": 443, "proto": "tcp", "status": "open"}               │
│      ]}                                                                  │
│    ]                                                                     │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 7b. INGEST MASSCAN RESULTS TO DATABASE                                  │
│    HTTP POST to rag-api:                                                │
│    POST http://rag-api:8000/ingest/masscan                             │
│    • Uploads masscan JSON file                                          │
│    • Creates job_id in database                                         │
│    • Inserts records into:                                              │
│      - assets table (10.252.30.206)                                     │
│      - port_observation table (ports 22, 80, 443)                      │
│      - ports table (open port records)                                  │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 7c. NMAP ENRICHMENT (Detailed Service Detection)                        │
│    From: /app/run_masscan_nmap.py                                      │
│                                                                          │
│    Queries database for open ports, then for each port runs:           │
│    $ nmap -Pn -sT -T4 -p 22,80,443 -sV --version-intensity 9 \        │
│           --script banner,http-title,ssl-cert,ssl-enum-ciphers,... \   │
│           -oA /app/nmap_out/nmap_<ip>_<batch>.xml 10.252.30.206       │
│                                                                          │
│    Nmap probes each port to determine:                                  │
│    • Service name (ssh, http, https)                                    │
│    • Service version (OpenSSH 8.2p1, Apache 2.4.41)                    │
│    • Banner information                                                  │
│    • SSL certificate details                                            │
│    • HTTP server headers and title                                      │
│                                                                          │
│    This takes longer (30 seconds to several minutes)                   │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 7d. PARSE AND STORE NMAP RESULTS                                        │
│    From: /app/etl/parse_nmap.py                                        │
│                                                                          │
│    • Parses Nmap XML output                                             │
│    • Updates database tables:                                           │
│      - ports table: Adds service, product, version, banner             │
│      - vulns table: Stores vulnerability findings from NSE scripts     │
│      - port_observation table: Updates with enriched data              │
│                                                                          │
│    Example database record:                                             │
│    ports table:                                                          │
│    - port: 22                                                           │
│    - service: "ssh"                                                     │
│    - product: "OpenSSH"                                                 │
│    - version: "8.2p1 Ubuntu 4ubuntu0.3"                                │
│    - banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3"                │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 8. NMAP_SCANNER RESPONSE                                                │
│    Returns JSON response:                                               │
│    {                                                                     │
│      "ok": true,                                                        │
│      "masscan_out": "/app/nmap_out/masscan_1760482842.json",          │
│      "ingest": {                                                        │
│        "ok": true,                                                      │
│        "job_id": "a1b2c3d4-...",                                       │
│        "ports_found": 3                                                 │
│      },                                                                  │
│      "stats": {                                                         │
│        "hosts_scanned": 1,                                              │
│        "ports_enriched": 3,                                             │
│        "vulns_found": 0                                                 │
│      }                                                                   │
│    }                                                                     │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      │ HTTP Response
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 9. SCAN_TOOLS.PY RECEIVES RESPONSE                                      │
│    • httpx.Client receives HTTP 200 OK                                  │
│    • Parses JSON response                                               │
│    • Converts to JSON string with json.dumps()                         │
│    • Returns to MCP server                                              │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 10. MCP SERVER RETURNS RESULT                                           │
│    • Formats response for Claude Desktop                                │
│    • Sends via stdio to Claude Desktop process                         │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 11. CLAUDE DESKTOP PROCESSES RESULT                                     │
│    • Receives JSON response from MCP server                             │
│    • Parses the results                                                 │
│    • Formats human-readable message                                     │
└─────────────────────┬───────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ 12. USER SEES RESPONSE                                                  │
│    "I've started an Nmap scan of 10.252.30.206. The scan found         │
│     3 open ports:                                                       │
│     - Port 22: SSH (OpenSSH 8.2p1)                                     │
│     - Port 80: HTTP (Apache 2.4.41)                                    │
│     - Port 443: HTTPS (Apache 2.4.41)                                  │
│                                                                          │
│     The results have been stored in the database."                     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Key Technical Details

### Why Internal DNS Works

```
Windows (Claude Desktop)
    ↓ docker exec -i autogen-agents ...
Docker Container (autogen-agents)
    ↓ Uses Docker's internal DNS
    ↓ "nmap_scanner" → 172.20.0.X
Docker Network (agents_net)
    ↓ Routes to correct container
nmap_scanner Container
```

**Windows never needs to resolve "nmap_scanner"** because the code runs inside Docker!

### Network Path

```
[Windows Host]
    ↓ Docker socket
[autogen-agents container] 172.20.0.5:random
    ↓ HTTP POST
[Docker Bridge: agents_net]
    ↓ DNS resolution + routing
[nmap_scanner container] 172.20.0.X:8012
    ↓ Executes masscan/nmap
[Target: 10.252.30.206]
```

### Database Flow

```
1. Masscan Results
   ↓
2. POST to rag-api:8000/ingest/masscan
   ↓
3. Write to PostgreSQL (rag-postgres:5432)
   Tables: assets, port_observation, ports
   ↓
4. Nmap queries database for open ports
   ↓
5. Nmap enriches with service details
   ↓
6. Parse Nmap XML
   ↓
7. Update PostgreSQL
   Tables: ports (update), vulns (insert)
```

### File Storage

```
/app/nmap_out/ (mounted volume)
├── masscan_1760482842.json    ← Masscan raw output
├── nmap_10_252_30_206_0.xml   ← Nmap XML
├── nmap_10_252_30_206_0.gnmap ← Nmap greppable
└── nmap_10_252_30_206_0.nmap  ← Nmap normal
```

## Timing Breakdown

```
User Input                           0s
↓
Claude Desktop Processing            1-2s
↓
MCP Server Initialization            0.5s
↓
HTTP Request to nmap_scanner         0.1s
↓
Masscan Scan (1000 ports @ 1000pps)  2-5s
↓
Database Ingest (Masscan)            1s
↓
Nmap Enrichment (3 ports)            15-30s
  - SSH probe                        5s
  - HTTP probe                       5s
  - HTTPS probe + SSL cert          5s
↓
Database Ingest (Nmap)               2s
↓
Response to Claude Desktop           0.5s
─────────────────────────────────────
Total: ~25-45 seconds
```

## Error Handling Flow

If something fails at any step:

```
Error in nmap_scanner
    ↓
Returns {"error": "...", "url": "..."}
    ↓
scan_tools.py catches exception
    ↓
Returns error JSON to MCP server
    ↓
MCP server returns to Claude Desktop
    ↓
Claude tells user: "The scan encountered an error: ..."
```

## Environment Variables Chain

```
docker-compose.yml:
  NMAP_URL: "http://nmap_scanner:8012"
    ↓
autogen-agents container environment
    ↓
scan_tools.py reads os.environ.get("NMAP_URL")
    ↓
self.nmap_url = "http://nmap_scanner:8012"
    ↓
HTTP request to that URL
```

## Container Communication

```
                 ┌─────────────────┐
                 │  Claude Desktop │
                 │   (Windows)     │
                 └────────┬────────┘
                          │ docker exec
                          ▼
    ┌────────────────────────────────────┐
    │     autogen-agents container       │
    │  • scan_tools.py                   │
    │  • httpx client                    │
    │  • Uses internal DNS               │
    └──────────┬─────────────────────────┘
               │ HTTP (agents_net)
               ▼
    ┌──────────────────────┐
    │  nmap_scanner:8012   │
    │  • FastAPI           │
    │  • Masscan           │
    │  • Nmap              │
    └──────────┬───────────┘
               │ HTTP
               ▼
    ┌──────────────────────┐
    │   rag-api:8000       │
    │  • Database writes   │
    │  • ETL processing    │
    └──────────┬───────────┘
               │ PostgreSQL
               ▼
    ┌──────────────────────┐
    │ rag-postgres:5432    │
    │  • scans database    │
    │  • All tables        │
    └──────────────────────┘
```

## Summary

1. **User speaks to Claude Desktop** (Windows)
2. **Claude Desktop executes** `docker exec -i autogen-agents python /app/mcp_server.py`
3. **MCP server calls** `scan_tools.start_nmap_scan("10.252.30.206")`
4. **scan_tools.py makes HTTP request** to `http://nmap_scanner:8012/jobs/masscan-then-nmap`
5. **nmap_scanner runs Masscan** for fast port discovery
6. **Results ingested to database** via rag-api
7. **nmap_scanner runs Nmap** for service version detection
8. **Detailed results stored** in PostgreSQL
9. **Response returns through chain** back to Claude Desktop
10. **User sees formatted results** in natural language

The key insight: **Everything after step 2 happens inside Docker**, so internal DNS names work perfectly!
