---
name: zap-integration
description: >
  ZAP (OWASP Zed Attack Proxy) integration for launching scans, ingesting alerts,
  exporting findings, and querying results. Use when starting ZAP spider/active scans,
  importing ZAP alerts or XML reports, exporting URLs for ZAP import, or searching
  ZAP-sourced findings.
license: Proprietary
compatibility: Requires network access to web-scanner and rag-api services. ZAP instance managed by web-scanner.
metadata:
  author: rag-scan-stack
  version: "1.0"
  mcp-server: mcp-zap.py
  mcp-port: "9023"
  tool-count: "10"
---

# ZAP Integration Tools

MCP server providing 10 tools for ZAP scan management and bidirectional data exchange.

## Tools

### Scan Management
- **start_zap_scan** — Launch ZAP spider + active scan on a target URL. Results auto-ingested via ETL.
- **start_full_web_scan** — Gobuster directory brute-force + ZAP scan combined for maximum coverage.
- **start_content_recon** — Lighter pipeline: Gobuster -> Playwright -> ZAP checkpoint for content discovery.
- **get_zap_scan_status** — Check progress and status of a running ZAP scan job.

### Import (ZAP -> Platform)
- **ingest_zap_alerts** — Pull current alerts from the running ZAP instance into the platform. Use after manual browsing/scanning through ZAP.
- **import_zap_xml_report** — Import a ZAP XML report file export into the platform.

### Export (Platform -> ZAP)
- **export_findings_for_zap** — Export discovered URLs as plain text for ZAP's "Import URLs" add-on or spider seeding.
- **get_zap_xml_report** — Download the most recent ZAP XML report from the web-scanner.

### Query
- **search_zap_findings** — Search ZAP findings by severity, URL pattern, or CWE. Returns JSON results filtered to source='zap'.

## Workflow Examples

### Full scan workflow
```
1. start_zap_scan(target_url="http://10.0.0.5")
2. get_zap_scan_status(job_id="<returned_id>")  # poll until complete
3. search_zap_findings(severity="high")          # review high findings
```

### Manual browsing workflow
```
1. (Browse target manually through ZAP proxy)
2. ingest_zap_alerts()                           # capture findings
3. search_zap_findings()                         # review all findings
```

### Cross-tool workflow
```
1. export_findings_for_zap()                     # get URLs from other tools
2. (Import URL list into ZAP)
3. start_zap_scan(target_url="http://10.0.0.5")  # scan with full URL coverage
```

## Examples

```
User: "run a ZAP scan on the target"
Action: start_zap_scan(target_url="http://10.0.0.5")

User: "pull in the ZAP findings"
Action: ingest_zap_alerts()

User: "show me high severity ZAP results"
Action: search_zap_findings(severity="high")

User: "export URLs for ZAP"
Action: export_findings_for_zap()
```
