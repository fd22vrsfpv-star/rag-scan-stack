# RAG Scan Stack — Burp Suite Bridge Extension

Bidirectional finding sync between RAG Scan Stack and Burp Suite Professional.

## Install

1. Download [Jython standalone JAR](https://www.jython.org/download) (2.7.x)
2. Burp Suite > Extensions > Extension Settings > Python Environment > Select Jython JAR
3. Extensions > Add > Extension Type: **Python** > Select `RagScanBridge.py`
4. A new **RAG Scan Bridge** tab appears in Burp

## Setup

1. Go to the **RAG Scan Bridge** tab
2. Enter your RAG API URL (e.g., `https://192.168.1.100:8000`)
3. Enter your API key (from `.env` file)
4. Click **Test Connection** — green dot = connected, shows DB table count

## Features

### Preview Count
Before importing, click **Preview Count** to see:
- Total findings matching your filters
- Breakdown by severity (critical, high, medium, low, info) with color coding
- Breakdown by source tool (ZAP, nuclei, nmap, ssh-audit, sslscan, etc.)

### Filter by Scope / Engagement
- **Scope dropdown** — filter to in-scope targets (shows target count per scope)
- **Engagement dropdown** — filter to a specific project (includes findings for IPs in the engagement's scope, not just directly linked findings)
- **Target IP/Host** — filter by specific host
- **Severity** — filter by severity level
- **Source checkboxes** — select which tools to include (ZAP, Nikto, Nuclei, Nmap, Playwright, ssh-audit, Burp)

### Import to Burp
Pulls findings from RAG Scan Stack into Burp's Scanner results:
- Uses `/export/findings-exchange` which includes **real HTTP request/response** data (from ZAP scans, etc.)
- Falls back to synthetic request/response for tools without HTTP data (ssh-audit, nmap, etc.)
- Findings appear in **Target > Issues** tab with `[RAG]` prefix
- Includes evidence, CVEs, severity, description, remediation
- Click **Import Filtered** for current filters, or **Import All**
- Status label shows count of imported findings
- **Import Filtered uses the same filters as Preview Count** — what you preview is what you get

### Export from Burp
Pushes Burp Scanner findings to RAG Scan Stack:
- Toggle **In-scope only** to limit export
- Deduplicates against existing findings
- Includes request/response data
- Status label shows export result

### Bidirectional Sync
Click **Sync Both Ways** to export Burp issues then import RAG findings.

## Debug Logging

Every API call is logged in the Activity Log with `[DEBUG]` prefix showing the full URL:
```
[DEBUG] GET https://localhost:8000/findings/search?ip=192.168.1.150&source=zap&limit=500
```
Use this to diagnose filter issues or connection problems.

## Connection Status

The extension shows a colored status indicator:
- **Green dot** — Connected successfully (auto-loads scope + engagement lists, shows table count)
- **Red dot** — Connection failed (check URL, API key, TLS)
- **Gray dot** — Not tested yet

Import/export operations show inline status labels (green = success, red = error).

## API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Connection test (checks `ok` or `status` field) |
| `GET /findings/search` | Preview count with aggregations |
| `GET /export/findings-exchange` | Fetch findings with real request/response for import |
| `POST /import/findings-exchange` | Send Burp findings to RAG |
| `GET /scope/names` | Load scope names for dropdown |
| `GET /scope?name=X` | Load scope targets for IP resolution |
| `GET /engagements` | Load engagements for dropdown |

## Severity Mapping

| RAG Scan Stack | Burp Suite |
|---------------|------------|
| critical | High |
| high | High |
| medium | Medium |
| low | Low |
| info | Information |

## Source Tools

Findings are correctly attributed to their source tool:

| Tool | Source Label | Type |
|------|-------------|------|
| nmap | nmap | Network scan |
| nuclei | nuclei | Template scan |
| ZAP | zap | Web scan (includes real request/response) |
| ssh-audit | ssh-audit | SSH configuration audit |
| sslscan | sslscan | TLS/SSL audit |
| testssl | testssl | TLS testing |
| nikto | nikto | Web server scan |
| Burp Suite | burpsuite | Manual testing |

## Troubleshooting

- **500 error on import**: Check the Activity Log for the exact URL. Common cause: engagement ID truncation (fixed in current version)
- **Preview shows findings but import gets 0**: The import now uses `/export/findings-exchange` which supports target, severity, and source filters. Engagement filtering resolves scope targets to IPs.
- **Scopes dropdown empty**: Make sure you've created scopes in the dashboard under Settings > Scope
- **Connection test shows "unknown"**: The API returns `{"ok": true}` — the extension handles both `ok` and `status` field formats
