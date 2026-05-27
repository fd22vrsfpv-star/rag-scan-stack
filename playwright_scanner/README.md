# Playwright Security Scanner

Browser-based security testing service using Playwright for automated browser interaction and OWASP ZAP integration for comprehensive vulnerability scanning.

## Features

### Security Checks
- **Clickjacking Protection**: Detects missing X-Frame-Options and CSP frame-ancestors headers
- **Mixed Content**: Identifies HTTP resources loaded on HTTPS pages
- **CSRF Protection**: Validates CSRF token presence in forms
- **Security Headers**: Checks for CSP, HSTS, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy
- **Sensitive Data Exposure**: Analyzes cookies, localStorage, and sessionStorage for insecure data storage
- **CORS Misconfiguration**: Detects dangerous CORS policies (e.g., Access-Control-Allow-Origin: *)

### DOM Analysis
- **Forms Extraction**: Captures all forms with fields, methods, actions, and input types
- **Cookie Analysis**: Extracts cookies with security attributes (Secure, HttpOnly, SameSite)
- **Storage Analysis**: Reads localStorage and sessionStorage contents
- **JavaScript Detection**: Identifies frameworks (React, Vue, Angular, jQuery) and external scripts
- **WebSocket Detection**: Finds WebSocket connections
- **PostMessage Usage**: Detects postMessage API usage
- **DOM Snapshots**: Captures full HTML structure (limited to 1MB)

### Screenshot Capabilities
- **Full Page Screenshots**: Captures entire page including scroll areas
- **Viewport Screenshots**: Captures visible area only
- **Element Screenshots**: Targets specific CSS selectors
- **Form Screenshots**: Automatically captures all forms
- **Multi-Viewport**: Tests responsive designs at different sizes
- **Annotated Screenshots**: Adds visual overlays highlighting findings

### ZAP Integration
- **Proxy Mode**: Routes all browser traffic through ZAP for passive scanning
- **Spider Scan**: Optional ZAP spider after Playwright exploration
- **Active Scan**: Optional ZAP active scanning for deep vulnerability testing
- **Alert Import**: Automatically imports ZAP findings into database

## Architecture

```
┌─────────────┐
│   Browser   │ (Chromium/Firefox/WebKit)
│  (Headless) │
└──────┬──────┘
       │
       │ HTTP(S)
       ├──────────────┐
       │              │
       v              v
┌──────────┐   ┌──────────┐
│  Target  │   │   ZAP    │
│   Site   │   │  Proxy   │
└──────────┘   └────┬─────┘
                    │
              ┌─────v──────┐
              │  Passive   │
              │  Scanning  │
              └────┬───────┘
                   │
              ┌────v───────┐
              │  Spider/   │
              │  Active    │
              └────┬───────┘
                   │
              ┌────v───────┐
              │ PostgreSQL │
              │  Database  │
              └────────────┘
```

## API Endpoints

### Health Check
```bash
GET /health
```

**Response:**
```json
{
  "ok": true,
  "service": "playwright-scanner",
  "browser_type": "chromium",
  "zap_enabled": true
}
```

### Create Scan
```bash
POST /scan
```

**Request Body:**
```json
{
  "url": "https://example.com",
  "browser": "chromium",
  "viewport_width": 1920,
  "viewport_height": 1080,
  "user_agent": "Mozilla/5.0 (Playwright Security Scanner)",
  "use_zap_proxy": true,
  "capture_screenshots": true,
  "capture_dom": true,
  "run_security_checks": true,
  "zap_spider": false,
  "zap_active_scan": false,
  "timeout": 30
}
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "running",
  "message": "Scan started successfully"
}
```

### Get Scan Status
```bash
GET /scan/{scan_id}
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "url": "https://example.com",
  "status": "completed",
  "browser": "chromium",
  "start_time": "2025-01-15T10:30:00Z",
  "end_time": "2025-01-15T10:32:15Z",
  "screenshots": 3,
  "findings_count": 5,
  "console_logs_count": 12,
  "errors_count": 0
}
```

### Get Scan Findings
```bash
GET /scan/{scan_id}/findings?severity=high
```

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "findings": [
    {
      "id": "...",
      "finding_type": "clickjacking",
      "title": "Missing Clickjacking Protection",
      "severity": "medium",
      "description": "...",
      "evidence": "...",
      "cwe": ["CWE-1021"],
      "owasp_category": "A01:2021-Broken Access Control",
      "remediation": "...",
      "confidence": 0.9,
      "created_at": "2025-01-15T10:31:45Z"
    }
  ]
}
```

## Usage Examples

### Basic Scan via Kong Gateway
```bash
curl -X POST http://localhost:7080/playwright/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "capture_screenshots": true,
    "run_security_checks": true
  }'
```

### Scan with ZAP Spider
```bash
curl -X POST http://localhost:7080/playwright/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "use_zap_proxy": true,
    "zap_spider": true,
    "zap_active_scan": false
  }'
```

### Check Scan Status
```bash
curl http://localhost:7080/playwright/scan/550e8400-e29b-41d4-a716-446655440000
```

### Get High Severity Findings
```bash
curl "http://localhost:7080/playwright/scan/550e8400-e29b-41d4-a716-446655440000/findings?severity=high"
```

### Direct Service Access (Development)
```bash
curl -X POST http://localhost:8014/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_DSN` | `postgresql://app:app@rag-postgres:5432/scans` | Database connection string |
| `BROWSER_TYPE` | `chromium` | Browser to use: chromium, firefox, or webkit |
| `VIEWPORT_WIDTH` | `1920` | Browser viewport width in pixels |
| `VIEWPORT_HEIGHT` | `1080` | Browser viewport height in pixels |
| `USER_AGENT` | `Mozilla/5.0 (Playwright Security Scanner)` | Custom user agent string |
| `USE_ZAP` | `true` | Enable ZAP integration |
| `ZAP_ADDR` | `zap` | ZAP container hostname |
| `ZAP_PORT` | `8090` | ZAP API/proxy port |
| `ZAP_API_KEY` | `changeme` | ZAP API key |
| `HEADLESS` | `true` | Run browser in headless mode |
| `SCREENSHOT_FORMAT` | `png` | Screenshot format: png, jpeg, or webp |

## Database Schema

### playwright_scans
Stores scan metadata and results.

```sql
CREATE TABLE playwright_scans (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    url text NOT NULL,
    status text DEFAULT 'pending',
    browser text DEFAULT 'chromium',
    viewport jsonb,
    user_agent text,
    start_time timestamptz,
    end_time timestamptz,
    screenshots integer DEFAULT 0,
    dom_snapshot boolean DEFAULT false,
    console_logs jsonb,
    network_logs jsonb,
    errors jsonb,
    metadata jsonb,
    created_at timestamptz DEFAULT now()
);
```

### playwright_findings
Stores security findings from scans.

```sql
CREATE TABLE playwright_findings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id uuid REFERENCES playwright_scans(id) ON DELETE CASCADE,
    asset_id uuid REFERENCES assets(id) ON DELETE CASCADE,
    url text NOT NULL,
    finding_type text NOT NULL,
    title text NOT NULL,
    severity text CHECK (severity IN ('info','low','medium','high','critical')),
    description text,
    evidence text,
    location text,
    remediation text,
    cwe text[],
    owasp_category text,
    screenshot_id uuid,
    confidence real,
    created_at timestamptz DEFAULT now()
);
```

### playwright_screenshots
Stores screenshots with deduplication.

```sql
CREATE TABLE playwright_screenshots (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id uuid REFERENCES playwright_scans(id) ON DELETE CASCADE,
    url text NOT NULL,
    image_data bytea NOT NULL,
    image_hash text NOT NULL UNIQUE,
    viewport jsonb,
    format text DEFAULT 'png',
    full_page boolean DEFAULT false,
    selector text,
    metadata jsonb,
    captured_at timestamptz DEFAULT now()
);
```

### dom_analysis
Stores detailed DOM analysis results.

```sql
CREATE TABLE dom_analysis (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id uuid REFERENCES playwright_scans(id) ON DELETE CASCADE,
    asset_id uuid REFERENCES assets(id) ON DELETE CASCADE,
    url text NOT NULL,
    forms jsonb,
    cookies jsonb,
    local_storage jsonb,
    session_storage jsonb,
    javascript_libs jsonb,
    external_scripts jsonb,
    websockets jsonb,
    postmessage_usage boolean,
    csp_header text,
    cors_enabled boolean,
    cors_config jsonb,
    security_headers jsonb,
    mixed_content jsonb,
    dom_snapshot text,
    analyzed_at timestamptz DEFAULT now()
);
```

## Modules

### playwright_scanner.py
Main FastAPI application orchestrating all scanning operations.

### security_checks.py
**SecurityChecker** class implementing OWASP security checks:
- `check_clickjacking()` - X-Frame-Options and CSP frame-ancestors
- `check_mixed_content()` - HTTP resources on HTTPS
- `check_csrf_protection()` - CSRF token validation
- `check_security_headers()` - Comprehensive header analysis
- `check_sensitive_data_exposure()` - Storage and cookie analysis
- `check_cors_misconfiguration()` - CORS policy validation

### dom_analyzer.py
**DOMAnalyzer** class for DOM inspection:
- `extract_forms()` - Form structure and fields
- `get_cookies()` - Cookie extraction with security flags
- `get_local_storage()` / `get_session_storage()` - Storage contents
- `detect_javascript_libraries()` - Framework detection
- `get_external_scripts()` - External script sources
- `detect_websockets()` / `detect_postmessage()` - API usage detection
- `get_dom_snapshot()` - Full HTML capture
- `analyze_security_headers()` - Header extraction
- `check_mixed_content()` - Mixed content detection

### screenshot_handler.py
**ScreenshotHandler** class for screenshot capture:
- `capture_full_page()` - Full page screenshot
- `capture_viewport()` - Visible area only
- `capture_element()` - Specific element by selector
- `capture_all_forms()` - All forms on page
- `capture_multiple_viewports()` - Responsive testing
- `capture_with_annotations()` - Visual finding overlays

### zap_bridge.py
**ZAPBridge** class for Playwright-ZAP integration:
- `get_proxy_config()` - Proxy settings for Playwright
- `is_zap_ready()` - Health check with timeout
- `create_context()` - ZAP context creation
- `spider_url()` / `wait_for_spider()` - Spider scanning
- `active_scan()` / `wait_for_active_scan()` - Active scanning
- `get_alerts()` / `export_alerts_to_db_format()` - Alert retrieval
- `scan_with_playwright_session()` - Integrated scan orchestration

### db_utils.py
Database interaction functions:
- `get_or_create_asset()` - Asset management
- `create_playwright_scan()` - Scan record creation
- `update_playwright_scan()` - Scan status updates
- `create_playwright_finding()` - Finding persistence
- `save_screenshot()` - Screenshot storage with deduplication
- `save_dom_analysis()` - DOM data persistence
- `create_zap_session()` / `update_zap_session()` - ZAP session tracking

## Docker Configuration

### Shared Memory
Chromium requires significant shared memory. The service is configured with:
```yaml
shm_size: '2gb'
```

### Volumes
- `/screenshots` - Screenshot storage directory
- `/reports` - Scan report output directory

### Health Check
The service provides a health check endpoint polled every 20 seconds:
```yaml
healthcheck:
  test: ["CMD-SHELL", "wget -qO- http://127.0.0.1:8014/health || exit 1"]
  interval: 20s
  timeout: 5s
  retries: 15
```

## Security Considerations

1. **API Key Authentication**: All requests through Kong require valid x-api-key header
2. **ZAP Proxy Security**: ZAP API key should be changed from default
3. **Screenshot Storage**: Screenshots are stored in database with SHA256 deduplication
4. **Browser Isolation**: Each scan runs in isolated browser context
5. **SSL/TLS**: `ignore_https_errors: True` is set for testing self-signed certificates

## Performance

- **Scan Duration**: Typical scan takes 30-60 seconds without ZAP active scan
- **With ZAP Spider**: Add 1-3 minutes depending on site complexity
- **With ZAP Active Scan**: Add 5-15 minutes for comprehensive testing
- **Concurrent Scans**: Multiple background scans can run simultaneously
- **Memory Usage**: ~500MB per browser instance, ~2GB shared memory for Chromium

## Troubleshooting

### Browser Launch Failures
```bash
# Check shared memory allocation
docker exec playwright-scanner df -h /dev/shm

# Should show 2GB available
```

### ZAP Connection Issues
```bash
# Verify ZAP is running
curl http://localhost:8090/JSON/core/view/version/

# Check ZAP logs
docker logs zap
```

### Database Connection
```bash
# Test database connectivity
docker exec playwright-scanner psql postgresql://app:app@rag-postgres:5432/scans -c "SELECT 1;"
```

### Screenshot Capture Failures
```bash
# Check screenshot directory permissions
docker exec playwright-scanner ls -la /screenshots

# View service logs
docker logs playwright-scanner
```

## OWASP Mapping

Findings are categorized using OWASP Top 10 2021:

| Finding Type | OWASP Category | CWE |
|--------------|----------------|-----|
| Clickjacking | A01:2021-Broken Access Control | CWE-1021 |
| Mixed Content | A02:2021-Cryptographic Failures | CWE-311 |
| CSRF | A01:2021-Broken Access Control | CWE-352 |
| Missing Security Headers | A05:2021-Security Misconfiguration | CWE-16 |
| Sensitive Data in Storage | A02:2021-Cryptographic Failures | CWE-922 |
| CORS Misconfiguration | A05:2021-Security Misconfiguration | CWE-942 |

## Integration with Other Services

### RAG API
Findings are stored in the same database as RAG API scan results, enabling:
- Unified vulnerability queries
- Cross-service correlation
- LLM-based recommendation generation

### Web Scanner
Playwright complements the web-scanner service by:
- Testing JavaScript-heavy sites
- Validating client-side security controls
- Capturing visual evidence

### ZAP
Bi-directional integration:
- Playwright routes traffic through ZAP proxy
- ZAP performs passive scanning on all traffic
- ZAP spider and active scan enhance coverage
- ZAP findings imported into unified database

### Kong Gateway
All API access routed through Kong:
- `/playwright/scan` - Create scan
- `/playwright/scan/{id}` - Get status
- `/playwright/scan/{id}/findings` - Get findings
- `/playwright/health` - Health check

## Future Enhancements

- **Authentication Testing**: Form-based and OAuth2 login flows
- **Cookie Manipulation**: Automated session testing
- **JavaScript Injection**: Custom security test injections
- **HAR Export**: Network traffic capture in HAR format
- **PDF Reports**: Automated security assessment reports
- **Selenium Grid**: Distributed browser execution
- **CI/CD Integration**: GitHub Actions and GitLab CI pipelines
