---
name: burp-integration
description: >
  Bidirectional Burp Suite integration for importing/exporting findings, sitemap data, and
  request/response pairs. Use when working with Burp Scanner results, sitemap exports,
  building Intruder payloads, syncing findings between Burp and the platform, or querying
  scope and discovered parameters.
license: Proprietary
compatibility: Requires network access to rag-api service. Burp extensions connect via HTTP to port 9022.
metadata:
  author: rag-scan-stack
  version: "1.0"
  mcp-server: mcp-burp.py
  mcp-port: "9022"
  tool-count: "10"
---

# Burp Suite Integration Tools

MCP server providing 10 tools for bidirectional data exchange with Burp Suite.

## Tools

### Import (Burp -> Platform)
- **import_burp_xml** — Import Burp Scanner issues or sitemap XML exports. Supports both `<issues>` (vulnerability findings) and `<items>` (sitemap) root formats. Deduplicates by fingerprint.
- **import_burp_sitemap** — Import Burp sitemap XML and extract URLs for content intelligence enrichment (parameter discovery, login detection, etc.).
- **import_burp_requests** — Import request/response pairs as JSON array. Synthesizes Burp sitemap XML internally. Useful for Burp extensions that export selected items as JSON.

### Export (Platform -> Burp)
- **export_findings_burp_xml** — Export platform findings as Burp Scanner-compatible XML. Filterable by severity, source, IP, and search term. Import into Burp via extensions or "Import scanner results".
- **export_sitemap_burp_xml** — Export the platform's discovered sitemap as Burp items XML for import into Burp's site map.
- **export_urls_txt** — Export discovered URLs as plain text (one per line) for Burp's URL paste, Intruder, or other tools.

### Query
- **search_findings** — Search findings by severity, source, CVE, or URL pattern. Returns JSON results.
- **get_sitemap** — Get discovered sitemap for a domain (pages, forms, parameters, technologies).
- **get_discovered_params** — Get parameters found in URLs, forms, and JS files. Useful for building Intruder payloads.
- **get_scope** — Get current engagement scope (target IPs, domains, networks) for configuring Burp's target scope.

## Connection Methods

### From Burp Extensions (HTTP)
Every tool is callable via HTTP POST to `http://<host>:9022/mcp` using the MCP JSON-RPC protocol.

### From MCPO Proxy (REST/OpenAPI)
Tools are also available as REST endpoints at `http://<host>:8080/burp/` via the MCPO OpenAPI proxy.

### From AI Clients (MCP)
Claude and other MCP-compatible clients connect natively to the MCP server.

## Examples

```
User: "import this Burp scan into the platform"
Action: import_burp_xml(xml_content="<issues>...</issues>")

User: "export high severity findings for Burp"
Action: export_findings_burp_xml(severity="high")

User: "what parameters have we found on example.com?"
Action: get_discovered_params(domain="example.com")

User: "get the scope targets for Burp"
Action: get_scope()

User: "export all URLs we've found"
Action: export_urls_txt()
```
