---
name: scan-pipelines
description: >
  Run composite multi-stage scan pipelines that chain multiple tools together automatically.
  Includes a full port scan pipeline (Masscan to Nmap to SMB vuln scan) and a web scan pipeline
  (Gobuster to Playwright to ZAP to Nuclei). Use when performing comprehensive scans that require
  multiple tools in sequence, or when the user asks for a "full scan" or "complete web assessment".
license: Proprietary
compatibility: Requires network access to nmap-scanner (port 8012) and web-scanner (port 8010) services.
metadata:
  author: rag-scan-stack
  version: "1.0"
  mcp-server: mcp-pipelines.py
  mcp-port: "9021"
  tool-count: "3"
---

# Composite Scan Pipelines

MCP server providing 3 tools for multi-stage automated scan pipelines.

## Tools

- **start_full_port_scan** — Complete port scan pipeline that runs: Masscan (ports 1-1000) then Nmap service detection, then Masscan (ports 1001-65535) then Nmap, then SMB vulnerability scan. Use for comprehensive network reconnaissance of a target.
- **start_web_pipeline** — Complete web application scan pipeline that runs: Gobuster (directory brute-force) then Playwright (browser crawling) then ZAP (proxy scanning) then Nuclei (vulnerability templates). Each stage feeds discovered URLs to the next.
- **get_pipeline_status** — Check status of a running pipeline scan. Specify pipeline type as 'port' or 'web'.

## When to Use Pipelines vs Individual Tools

Use **pipelines** when:
- The user asks for a "full scan" or "complete assessment"
- You want comprehensive coverage without manually chaining tools
- Time is not a constraint (pipelines run all stages sequentially)

Use **individual tools** (from pentest-scanning) when:
- You need results from a specific tool only
- You want to control which ports or parameters each tool uses
- You need to run scans in a custom order

## Examples

```
User: "full scan 192.168.1.150"
Action: start_full_port_scan(target="192.168.1.150")

User: "comprehensive web scan on http://10.0.0.5"
Action: start_web_pipeline(target_url="http://10.0.0.5")

User: "check pipeline status abc-123"
Action: get_pipeline_status(job_id="abc-123", pipeline_type="port")
```
