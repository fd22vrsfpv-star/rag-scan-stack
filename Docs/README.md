# RAG Scan Stack

Turnkey stack to ingest **Masscan** results, run **Nmap** enrichment (-sV + useful scripts), perform **web scans** (Gobuster + ZAP), **Nuclei**, and **Playwright browser security testing**, with **AI-powered multi-agent orchestration** via **Autogen**, storing normalized results in **Postgres (pgvector)**. Exposes FastAPI services for ingestion, queries, and autonomous pentesting.

## Quick Start (Single Command)

```bash
# Fresh machine — single command does everything:
# (Go tools, credentials, Docker build, start, DB schema)
./scripts/setup.sh

# Or with options:
./scripts/setup.sh --skip-go-tools   # skip Go compilation if binaries exist
./scripts/setup.sh --no-start        # build only, don’t start services
./scripts/setup.sh --force           # rebuild Go tools even if they exist
make setup                           # same thing via Makefile
```

### Step-by-step alternative
```bash
# 1. Build Go security tools (~10-15 min first time)
./scripts/build-go-tools.sh

# 2. Generate credentials
./generate-credentials.sh

# 3. Deploy (network, dirs, kong, optionally build+start)
./scripts/deploy.sh

# 4. Apply DB schema
./scripts/ensure_db_schema.sh
```

## Start the full stack
```bash
docker compose up -d --build

# Build a specific service:
docker compose up -d --build kong

# Build without rebuilding everything:
docker compose build specs kong
docker compose up -d --no-deps specs kong
```

### Health
```bash
curl -s http://localhost:8000/health | jq .        # API
curl -s http://localhost:8010/health | jq .        # web-scanner
curl -s http://localhost:8011/health | jq .        # nuclei-runner
curl -s http://localhost:8014/health | jq .        # playwright-scanner
curl -s http://localhost:8015/health | jq .        # autogen-agents
```

## Database build (current patched schema)

The DB is **auto-initialized** by Postgres on first startup from `db_init/setup_alldb.sql`.

If you need to (re)apply manually, run:
```bash
# into the Postgres container
docker exec -it rag-postgres bash -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /docker-entrypoint-initdb.d/setup_alldb.sql'
```

You can also verify extensions and tables:
```bash
docker exec -it rag-postgres psql -U app -d scans -c '\dx'
docker exec -it rag-postgres psql -U app -d scans -c '\dt'
```

## ⚠️ Database Migration (IMPORTANT for Existing Installations)

If you're **upgrading from an older version**, you need to run the database migration to add critical missing tables.

**Quick Migration:**
```bash
cd /utils/agents
./db_init/run_migration.sh
```

Or manually:
```bash
docker exec -i rag-postgres psql -U app -d scans < db_init/add_missing_tables.sql
```

**What's Added:**
- `web_findings` - **CRITICAL** for web_scanner.py (was missing!)
- `vulns` - **CRITICAL** for `/vulns` API endpoint (was missing!)
- `scan_recommendations` - For AI-powered scan suggestions
- `playwright_*` tables - For Phase 2 browser automation
- `zap_sessions` - Playwright-ZAP integration tracking

**Fresh installations** automatically include all tables via `setup_alldb.sql`.

**See:** `db_init/MIGRATION_GUIDE.md` for detailed instructions and troubleshooting.

## Typical flow
```bash 
1) run_masscan_nmap 
curl -X 'POST' \
  'http://localhost:8000/run_masscan_nmap?ports=1-65535&rate=1000&interface=eth0' \
  -H 'accept: application/json' \
  -H 'x-api-key: changeme' \
  -H 'Content-Type: multipart/form-data' \
  -F 'file=@targets.txt;type=text/plain'

2) check status that it submitted
curl -X 'GET' \
  'http://localhost:8000/jobs' \
  -H 'accept: application/json' \
  -H 'x-api-key: changeme'
  
 
# 1) Ingest Masscan (-oJ) JSON (single JSON or NDJSON)
curl -s -X POST http://localhost:8000/ingest/masscan   -H 'x-api-key: changeme'   | jq .

# 2) Enrich via Nmap (adds -sV; scripts set by env)
curl -s -X POST http://localhost:8000/jobs/nmap-from-masscan   -H 'x-api-key: changeme' | jq .

# 3) Query normalized open ports
curl -s http://localhost:8000/ports/open -H 'x-api-key: changeme' | jq .

# Optional web scans (Gobuster + ZAP)
curl -s -X POST http://localhost:8010/jobs/web-scan   -H 'content-type: application/json'   -d '{"do_gobuster": true, "do_zap": true, "limit": 25}' | jq .

# Optional Nuclei checks
curl -s -X POST http://localhost:8011/jobs/nuclei-scan   -H 'content-type: application/json'   -d '{"limit": 25, "severity": "medium,high,critical"}' | jq .

# Optional Playwright browser security scans
curl -s -X POST http://localhost:8014/scan   -H 'content-type: application/json'   -d '{"url": "https://example.com", "use_zap_proxy": true, "capture_screenshots": true}' | jq .
```
## searchsploit
How to load ExploitDB into the RAG database after rebuild:
- One-shot refresh (generate JSON + ingest):
  - POST [http://localhost:8013/rag/refresh](http://localhost:8013/rag/refresh) with body: {"output_path": "/var/lib/searchsploit/searchsploit.json", "exploit_root": "/opt/exploitdb"}

- Or separate steps:
  - POST /rag/update_json to generate the JSON from searchsploit
  - POST /rag/ingest to embed and insert into the database

- Verify:
  - GET /rag/ask?q=Your+question
  - Or check row count in the exploit_chunks table via your database client.

/rag/update_json


## Endpoints

### API Container (Port: 8000)

**Swagger Documentation:** [API Swagger](http://localhost:8000/docs)

- **Ingestion**
  - `POST /ingest/masscan`  (file upload JSON/NDJSON)
  - `POST /ingest/nmap`     (file upload XML)
  - `POST /ingest/nuclei`   (JSONL)

- **Jobs**
  - `POST /jobs/nmap-from-masscan`

- **Queries**
  - `GET  /ports/open`
  - `GET  /findings`

### Web Scanner Container (Port: 8010)

**Swagger Documentation:** [Web Scanner Swagger](http://localhost:8010/docs)

- **Jobs**
  - `POST /jobs/web-scan`   (Gobuster + ZAP)

### Nuclei Runner Container (Port: 8011)

**Swagger Documentation:** [Nuclei Runner Swagger](http://localhost:8011/docs)

- **Jobs**
  - `POST /jobs/nuclei-scan`

### Playwright Scanner Container (Port: 8014)

**Swagger Documentation:** [Playwright Scanner Swagger](http://localhost:8014/docs)

**Full Documentation:** [Playwright Scanner README](playwright_scanner/README.md)

- **Scanning**
  - `POST /scan` - Create browser security scan
  - `GET /scan/{scan_id}` - Get scan status and results
  - `GET /scan/{scan_id}/findings` - Get findings with optional severity filter

**Features:**
- Browser automation (Chromium, Firefox, WebKit)
- OWASP Top 10 security checks
- DOM analysis and screenshot capture
- ZAP proxy integration for passive/active scanning
- Clickjacking, CSRF, Mixed Content, Security Headers detection
- Cookie and storage security analysis

**Example:**
```bash
# Start a scan
curl -X POST http://localhost:8014/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "url": "https://example.com",
    "use_zap_proxy": true,
    "capture_screenshots": true,
    "run_security_checks": true,
    "zap_spider": false,
    "zap_active_scan": false
  }'

# Check status
curl http://localhost:8014/scan/550e8400-e29b-41d4-a716-446655440000

# Get findings
curl "http://localhost:8014/scan/550e8400-e29b-41d4-a716-446655440000/findings?severity=high"
```

### Autogen Multi-Agent System (Port: 8015)

**Swagger Documentation:** [Autogen Agents Swagger](http://localhost:8015/docs)

**Full Documentation:** [Autogen Agents README](autogen_agents/README.md)

**MCP Integration:** [MCP Guide](autogen_agents/MCP_GUIDE.md)

- **Sessions**
  - `POST /pentest` - Start AI-powered pentest session
  - `GET /pentest/{session_id}` - Get session status
  - `GET /pentest/{session_id}/messages` - Get agent conversation
  - `GET /pentest/{session_id}/report` - Get final report
  - `GET /sessions` - List all sessions
  - `POST /pentest/{session_id}/stop` - Stop active session

**Features:**
- Autonomous penetration testing with AI agents
- Specialized agents: Coordinator, Reconnaissance, Scanner, Analyzer, Reporter
- Natural language task planning and execution
- Integrates all scanning services (Nmap, Web, Nuclei, Playwright)
- RAG-powered exploit database queries
- Automated report generation
- **Model Context Protocol (MCP) support for Claude Desktop integration**

**Dual Interface Support:**
- **REST API**: Programmatic access via HTTP (port 8015)
- **MCP Protocol**: AI assistant integration via Claude Desktop (stdio)

**REST API Example:**
```bash
# Start autonomous pentest
curl -X POST http://localhost:8015/pentest \
  -H 'Content-Type: application/json' \
  -d '{
    "target_description": "10.0.1.0/24 web application subnet",
    "session_name": "Q1 2025 Internal Pentest",
    "initial_task": "Discover all services and test for high-severity vulnerabilities",
    "max_rounds": 200,
    "auto_execute_scans": true
  }'

# Monitor progress
curl http://localhost:8015/pentest/{session_id}
curl http://localhost:8015/pentest/{session_id}/messages

# Get final report
curl http://localhost:8015/pentest/{session_id}/report
```

**MCP (Claude Desktop) Example:**
> **You:** I need to assess the security of my internal network at 10.0.1.0/24. Can you run a comprehensive penetration test?

> **Claude:** I'll start an autonomous pentest session using the autogen agents...

*Claude uses MCP tools to control the pentest infrastructure, monitor progress, and deliver results.*

See [MCP_GUIDE.md](autogen_agents/MCP_GUIDE.md) for Claude Desktop setup and usage examples.

## Using n8n flows
```bash
curl -X POST "http://<your-api-host>:8000/jobs/masscan-nmap/upload" \
-H "x-api-key: changeme" \
-F "file=@targets.txt"
```
## Notes
- `findings` has `created_at` and `updated_at` (trigger updates on write).
- UUIDs generated using `gen_random_uuid()` (**pgcrypto**), enabled in `setup_alldb.sql`.
- `rag_documents.embedding` uses `vector(384)` (MiniLM L6). Index via IVFFLAT is included.
- Only scan assets you are authorized to test.

## add extra software
- Kong (3.6, Debian):

: apt-get install -y netcat-openbsd

- n8n (node, Debian)
: apt-get install -y netcat-openbsd

- Python slim (Debian):

: apt-get install -y netcat-openbsd

- nginx:alpine / swagger-ui:

: apk add --no-cache netcat-openbsd
