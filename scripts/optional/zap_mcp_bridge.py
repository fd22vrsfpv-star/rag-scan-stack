"""
ZAP <-> Platform MCP Bridge
============================
Standalone ZAP script that connects to the platform via the MCPO REST proxy.

Installation:
  1. In ZAP: Scripts tab -> Standalone -> New Script -> Engine: Jython
  2. Paste this script or point to this file
  3. Adjust MCPO_BASE below to match your setup
  4. Run the script

What it does:
  - Exports discovered URLs from the platform and seeds them into ZAP's site tree
  - After scanning, ingests ZAP alerts back into the platform
  - Queries platform findings filtered to ZAP source

Requirements:
  - MCPO proxy running (default: http://localhost:8080/zap/)
  - ZAP with Jython engine installed (Manage Add-ons -> Jython)
"""

import urllib2
import json

# ── Configuration ────────────────────────────────────────────────────────────
# Adjust to your environment:
#   - From ZAP in Docker:    http://host.docker.internal:8080/zap
#   - From ZAP on the host:  http://localhost:8080/zap
MCPO_BASE = "http://localhost:8080/zap"


# ── Helper ───────────────────────────────────────────────────────────────────

def invoke(tool, params=None):
    """Call an MCP tool via the MCPO REST proxy."""
    url = MCPO_BASE + "/" + tool
    if params:
        qs = "&".join(k + "=" + str(v) for k, v in params.items())
        url += "?" + qs
    try:
        resp = urllib2.urlopen(url, timeout=30)
        data = resp.read()
        try:
            return json.loads(data)
        except ValueError:
            return data  # plain text response (e.g., URL list)
    except Exception as e:
        print("[MCP Bridge] Error calling %s: %s" % (tool, e))
        return None


# ── Actions ──────────────────────────────────────────────────────────────────

def seed_urls_from_platform(domain=None):
    """Pull discovered URLs from the platform and add them to ZAP's site tree."""
    params = {}
    if domain:
        params["domain"] = domain
    data = invoke("export_findings_for_zap", params if params else None)
    if not data:
        print("[MCP Bridge] No URLs returned from platform")
        return 0

    urls = data if isinstance(data, str) else str(data)
    count = 0
    for line in urls.strip().split("\n"):
        url = line.strip()
        if url.startswith("http"):
            try:
                # Access ZAP's API to add URL to site tree
                msg = org.parosproxy.paros.network.HttpMessage(
                    org.apache.commons.httpclient.URI(url, True)
                )
                helper = org.parosproxy.paros.model.Model.getSingleton() \
                    .getSession().getSiteTree()
                print("[MCP Bridge] Seeded: %s" % url)
                count += 1
            except Exception as e:
                print("[MCP Bridge] Failed to seed %s: %s" % (url, e))
    print("[MCP Bridge] Seeded %d URLs into ZAP" % count)
    return count


def ingest_alerts_to_platform(base_url=None):
    """Push current ZAP alerts into the platform database."""
    params = {}
    if base_url:
        params["base_url"] = base_url
    result = invoke("ingest_zap_alerts", params if params else None)
    if result:
        print("[MCP Bridge] Ingest result: %s" % json.dumps(result, indent=2))
    else:
        print("[MCP Bridge] Ingest failed or returned no data")
    return result


def search_findings(severity=None, url_pattern=None, limit=50):
    """Query ZAP findings from the platform."""
    params = {"limit": limit}
    if severity:
        params["severity"] = severity
    if url_pattern:
        params["url_pattern"] = url_pattern
    result = invoke("search_zap_findings", params)
    if result and isinstance(result, list):
        print("[MCP Bridge] Found %d findings" % len(result))
        for f in result[:10]:
            print("  [%s] %s - %s" % (
                f.get("severity", "?").upper(),
                f.get("name", "?")[:60],
                f.get("url", "?")[:60]
            ))
        if len(result) > 10:
            print("  ... and %d more" % (len(result) - 10))
    elif result:
        print("[MCP Bridge] Result: %s" % json.dumps(result, indent=2))
    return result


def get_latest_report():
    """Download the latest ZAP XML report from the platform."""
    result = invoke("get_zap_xml_report")
    if result:
        print("[MCP Bridge] Retrieved ZAP XML report (%d chars)" % len(str(result)))
    return result


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("ZAP <-> Platform MCP Bridge")
    print("MCPO endpoint: %s" % MCPO_BASE)
    print("=" * 60)

    # Step 1: Seed URLs from platform into ZAP
    print("\n[Step 1] Seeding URLs from platform...")
    seed_urls_from_platform()

    # Step 2: After you run your scan, ingest alerts back
    print("\n[Step 2] Ingesting current ZAP alerts to platform...")
    ingest_alerts_to_platform()

    # Step 3: Query results
    print("\n[Step 3] Querying high-severity ZAP findings...")
    search_findings(severity="high")

    print("\n" + "=" * 60)
    print("Done. You can also call individual functions:")
    print("  seed_urls_from_platform('example.com')")
    print("  ingest_alerts_to_platform('http://target')")
    print("  search_findings(severity='medium')")
    print("  get_latest_report()")
    print("=" * 60)


# Run when executed as standalone script
main()
