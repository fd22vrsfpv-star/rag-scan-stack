# Scanner Framework API Endpoints

This document provides the correct API endpoints for all services in the penetration testing framework.

## Service Status

All services are accessible from the host machine at `http://localhost:<port>` and from within the Docker network at `http://<service-name>:<port>`.

## Available Services

### 1. Nmap Scanner (Port 8012)
**Base URL**: `http://localhost:8012` (external) or `http://nmap_scanner:8012` (internal)

**Endpoints**:
- `GET /health` - Health check
- `GET /docs` - Interactive Swagger UI documentation
- `POST /jobs/masscan-only` - Run Masscan scan only
  ```json
  {
    "targets": ["10.0.0.0/24"],
    "ports": "1-65535",
    "rate": 1000,
    "interface": "eth0"  // optional
  }
  ```
- `POST /jobs/masscan-then-nmap` - Run Masscan followed by Nmap enrichment
  ```json
  {
    "targets": ["10.0.0.1"],
    "ports": "80,443,22",
    "rate": 1000
  }
  ```
- `POST /jobs/nmap-from-masscan` - Run Nmap enrichment on existing Masscan results

**Example Usage**:
```bash
curl -X POST http://localhost:8012/jobs/masscan-only \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.1.0/24"],
    "ports": "1-1000",
    "rate": 500
  }'
```

### 2. Web Scanner (Port 8010)
**Base URL**: `http://localhost:8010` (external) or `http://web-scanner:8010` (internal)

**Endpoints**:
- `GET /health` - Health check
- `GET /docs` - Interactive Swagger UI documentation
- Additional endpoints available (check `/docs`)

### 3. Nuclei Scanner (Port 8011)
**Base URL**: `http://localhost:8011` (external) or `http://nuclei-runner:8011` (internal)

**Endpoints**:
- `GET /health` - Health check
- `GET /docs` - Interactive Swagger UI documentation
- Additional endpoints available (check `/docs`)

### 4. Scan Recommender (Port 8013)
**Base URL**: `http://localhost:8013` (external) or `http://scan-recommender:8013` (internal)

**Endpoints**:
- `GET /health` - Health check
- `GET /docs` - Interactive Swagger UI documentation
- Additional endpoints available (check `/docs`)

### 5. Playwright Scanner (Port 8014)
**Base URL**: `http://localhost:8014` (external) or `http://playwright-scanner:8014` (internal)

**Endpoints**:
- `GET /health` - Health check
- `GET /docs` - Interactive Swagger UI documentation
- `POST /scan` - Create and start a new Playwright security scan
  ```json
  {
    "url": "https://example.com",
    "browser": "chromium",
    "viewport_width": 1920,
    "viewport_height": 1080,
    "capture_screenshots": true,
    "run_security_checks": true,
    "zap_spider": false,
    "zap_active_scan": false
  }
  ```
- `GET /scan/{scan_id}` - Get status and results of a scan
- `GET /scan/{scan_id}/findings` - Get findings for a specific scan

**Example Usage**:
```bash
curl -X POST http://localhost:8014/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://testphp.vulnweb.com",
    "browser": "chromium",
    "capture_screenshots": true,
    "run_security_checks": true
  }'
```

### 6. RAG API (Port 8000)
**Base URL**: `http://localhost:8000` (external) or `http://rag-api:8000` (internal)

**Endpoints**:
- `GET /health` - Health check
- `GET /docs` - Interactive Swagger UI documentation
- `POST /ingest/masscan` - Ingest Masscan results
- `POST /ingest/nmap` - Ingest Nmap results
- `POST /recommendations/generate?ip=<optional>` - Generate scan recommendations for all currently-detected open ports that don't have one yet (no time window). Populates `scan_recommendations` so suggested scans can be dispatched against targets scanned earlier (the reactive ingest trigger only covers ports seen in the last 10 minutes). Synchronous + local-LLM-backed; emits a `recommendations_generated` webhook. Idempotent.

**Tool-selection feedback loop (steers which tools the recommender picks):**
- `GET /api/kb/feedback` — list active feedback policies (BFF → recommender `/kb/feedback`).
- `POST /api/kb/feedback` — record a policy. Body: `{verdict, service?, scanner?, selector?, payload?, reason?, created_by?}`.
  - `verdict: "suppress"` — stop recommending `scanner` (optionally only when its module/script matches `selector` glob); `service: null` = all services. (e.g. suppress `metasploit` `*robots_txt`.)
  - `verdict: "add_tool"` — inject a tool rec for `service`; `payload: {name, action, command}`. (e.g. add `curl -s http://{target}:{port}/robots.txt`.)
  - `verdict: "add_overlap"` — tag matching recs into an overlap group; `payload: {group}` (collapsed to one via the OR-dedup).
- `DELETE /api/kb/feedback/{id}` — deactivate a policy.
  Stored in `scan_tool_feedback`; applied live by the recommender (no rebuild). Emits `scan_recommender_tool_feedback_recorded`.

**Attack vector map (MITRE ATT&CK prioritization):** maps findings → ATT&CK techniques + a unified risk score (severity, CVSS, CISA KEV, exploit availability, tactic position, asset criticality) for attack-path prioritization. Config-driven by `knowledge/mitre/attack_map.yaml` (git-tracked, reloads on restart). Stored in `attack_vectors`.
- `POST /attack-vectors/compute?engagement_id=` (BFF `/api/attack-vectors/compute`) — (re)compute from current findings; emits `attack_vectors_recomputed` webhook.
- `GET /attack-vectors?limit=&min_risk=` (BFF `/api/attack-vectors`) — ranked vectors, highest risk first. **The AI agents consume this** (and the MCP tool `get_attack_vectors`) to choose the next-best action.
- `GET /attack-vectors/graph` (BFF `/api/attack-vectors/graph`) — nodes+edges (target → technique → tactic) for the Attack Map UI.

**Dispatch note (BFF `POST /api/scan-recommendations/run`):** dispatching a `metasploit` recommendation does NOT auto-exploit. It creates a `pending_exploits` row (`source=metasploit`, RHOSTS/RPORT prefilled, `status=pending`, `requested_by=recommendations_ui`) that surfaces in the Exploit Manager (`/exploits/all`) for human approve/reject; approval runs it via exploit-runner `/execute/by-id`. The run response includes a `queued` count for these, and emits a `metasploit_queued_for_approval` webhook.
- Additional endpoints available (check `/docs`)

> **Note:** internal service-to-service URLs use **HTTPS** (e.g. `https://rag-api:8000`, `https://scan-recommender:8013`). The recommender in particular must be reached over `https://` — `SCAN_RECOMMENDER_URL` is set accordingly in `.env` and the install scripts.

### 7. Autogen Agents (Port 8015)
**Base URL**: `http://localhost:8015` (external) or `http://autogen-agents:8015` (internal)

**Endpoints**:
- `GET /health` - Health check
- `GET /docs` - Interactive Swagger UI documentation
- `POST /pentest` - Start a multi-agent penetration testing session
- `GET /pentest/{session_id}` - Get pentest session status
- `GET /pentest/{session_id}/messages` - Get conversation messages
- `GET /sessions` - List all pentest sessions

**🎉 NEW: Diagnostic Log Viewing**:
- `GET /logs/ui` - **Web interface for viewing diagnostic logs** (recommended)
- `GET /logs` - Query logs with filtering (level, search, request_id)
- `GET /logs/stats` - Get logging statistics
- `GET /logs/export` - Export all logs as JSON file
- `DELETE /logs` - Clear all logs from buffer

**Example Usage - Web Interface**:
```
Open in browser: http://localhost:8015/logs/ui
```

**Example Usage - API**:
```bash
# View recent errors
curl "http://localhost:8015/logs?level=ERROR&limit=50"

# Search for specific IP
curl "http://localhost:8015/logs?search=192.168.1.1"

# Get statistics
curl http://localhost:8015/logs/stats
```

## Common Issues

### Error: 404 Not Found on `/scan`
**Problem**: The `/scan` endpoint doesn't exist on nmap_scanner.

**Solution**: Use the correct endpoint:
- For Nmap: `POST /jobs/masscan-only` or `POST /jobs/masscan-then-nmap`
- For Playwright: `POST /scan` (this service DOES have a /scan endpoint)

### Error: Database table doesn't exist
**Problem**: Database schema is incomplete.

**Solution**: The database has been migrated to include all necessary tables including:
- `agent_sessions`
- `agent_messages`
- `playwright_scans`
- `playwright_findings`
- `scan_recommendations`
- And more...

If you still see database errors, the database may need to be reinitialized.

## Viewing API Documentation

All services provide interactive Swagger UI documentation at the `/docs` endpoint:
- Nmap Scanner: http://localhost:8012/docs
- Web Scanner: http://localhost:8010/docs
- Nuclei: http://localhost:8011/docs
- Scan Recommender: http://localhost:8013/docs
- Playwright: http://localhost:8014/docs
- RAG API: http://localhost:8000/docs
- Autogen Agents: http://localhost:8015/docs

## Testing Connectivity

```bash
# Test all services
curl http://localhost:8000/health  # RAG API
curl http://localhost:8010/health  # Web Scanner
curl http://localhost:8011/health  # Nuclei
curl http://localhost:8012/health  # Nmap Scanner
curl http://localhost:8013/health  # Scan Recommender
curl http://localhost:8014/health  # Playwright Scanner
curl http://localhost:8015/health  # Autogen Agents
```

## Network Access

### From Host Machine (Your Computer)
Use `http://localhost:<port>`

### From Claude Desktop or External Tools
Use `http://localhost:<port>` if running on the same machine as Docker

### From Inside Docker Network
Use `http://<service-name>:<port>` (e.g., `http://nmap_scanner:8012`)

### From Another Container
Services can communicate using their container names via the `agents_net` Docker network.
