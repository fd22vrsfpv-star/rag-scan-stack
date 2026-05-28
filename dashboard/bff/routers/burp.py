"""Burp Suite Professional REST API integration + Burp Follow-Up Queue."""

import httpx
from fastapi import APIRouter, HTTPException, Query, Request
from config import get_settings
from engagement import engagement_headers
from utils import safe_json

router = APIRouter()


def _burp_url() -> str:
    s = get_settings()
    if not s.burp_api_url:
        raise HTTPException(503, "Burp API URL not configured. Set BURP_API_URL in environment.")
    return s.burp_api_url.rstrip("/")


def _burp_headers() -> dict:
    s = get_settings()
    h = {"Content-Type": "application/json"}
    if s.burp_api_key:
        h["Authorization"] = f"Bearer {s.burp_api_key}"
    return h


@router.get("/api/burp/status")
async def burp_status():
    try:
        base = _burp_url()
    except HTTPException:
        return {"connected": False, "error": "BURP_API_URL not configured"}
    try:
        async with httpx.AsyncClient(verify=False, timeout=5) as c:
            resp = await c.get(f"{base}/v0.1/scan", headers=_burp_headers())
            return {"connected": True, "url": base, "status_code": resp.status_code,
                    "scans": resp.json() if resp.status_code == 200 else None}
    except Exception as e:
        return {"connected": False, "url": base, "error": str(e)}


@router.post("/api/burp/scan")
async def start_burp_scan(request: Request):
    base = _burp_url()
    body = await request.json()
    urls = body.get("urls", [])
    if not urls:
        raise HTTPException(400, "urls is required")

    scan_body: dict = {"urls": urls}
    scope = body.get("scope")
    if scope:
        scan_body["scope"] = scope
    else:
        from urllib.parse import urlparse
        scan_body["scope"] = {"include": [{"rule": f"{urlparse(u).scheme}://{urlparse(u).netloc}/"} for u in urls], "exclude": []}

    scan_config = body.get("scan_config", "default")
    config_map = {
        "fast": [{"type": "NamedConfiguration", "name": "Crawl strategy - fastest"}],
        "deep": [{"type": "NamedConfiguration", "name": "Audit checks - all except time-based detection methods"}],
        "default": [{"type": "NamedConfiguration", "name": "Crawl and audit - lightweight"}],
    }
    scan_body["scan_configurations"] = config_map.get(scan_config, config_map["default"])
    if body.get("credentials"):
        scan_body["application_logins"] = body["credentials"]

    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as c:
            resp = await c.post(f"{base}/v0.1/scan", json=scan_body, headers=_burp_headers())
            if resp.status_code in (200, 201):
                location = resp.headers.get("Location", "")
                task_id = location.split("/")[-1] if location else ""
                return {"ok": True, "task_id": task_id, "message": f"Burp scan started for {len(urls)} URL(s)", "status_url": f"/api/burp/scan/{task_id}"}
            return {"ok": False, "error": f"Burp returned {resp.status_code}: {resp.text[:500]}"}
    except Exception as e:
        raise HTTPException(502, f"Failed to connect to Burp API: {e}")


@router.get("/api/burp/scan/{task_id}")
async def burp_scan_status(task_id: str):
    base = _burp_url()
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            resp = await c.get(f"{base}/v0.1/scan/{task_id}", headers=_burp_headers())
            if resp.status_code == 200:
                data = resp.json()
                return {"task_id": task_id, "status": data.get("scan_status"), "metrics": data.get("scan_metrics"),
                        "issue_events": data.get("issue_events", []), "audit_items_count": len(data.get("issue_events", []))}
            return {"task_id": task_id, "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        raise HTTPException(502, f"Failed to query Burp scan: {e}")


@router.get("/api/burp/scans")
async def list_burp_scans():
    base = _burp_url()
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            resp = await c.get(f"{base}/v0.1/scan", headers=_burp_headers())
            return {"scans": resp.json()} if resp.status_code == 200 else {"scans": [], "error": f"HTTP {resp.status_code}"}
    except Exception as e:
        return {"scans": [], "error": str(e)}


@router.delete("/api/burp/scan/{task_id}")
async def cancel_burp_scan(task_id: str):
    base = _burp_url()
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            resp = await c.delete(f"{base}/v0.1/scan/{task_id}", headers=_burp_headers())
            return {"ok": resp.status_code in (200, 204), "status_code": resp.status_code}
    except Exception as e:
        raise HTTPException(502, f"Failed to cancel Burp scan: {e}")


@router.get("/api/burp/scan/{task_id}/issues")
async def burp_scan_issues(task_id: str):
    base = _burp_url()
    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as c:
            resp = await c.get(f"{base}/v0.1/scan/{task_id}", headers=_burp_headers())
            if resp.status_code != 200:
                return {"issues": [], "error": f"HTTP {resp.status_code}"}
            data = resp.json()
            return {"task_id": task_id, "count": len(data.get("issue_events", [])),
                    "issues": data.get("issue_events", []), "scan_status": data.get("scan_status")}
    except Exception as e:
        raise HTTPException(502, f"Failed to get Burp issues: {e}")


@router.post("/api/burp/scan/{task_id}/import")
async def import_burp_results(task_id: str):
    base = _burp_url()
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as c:
            resp = await c.get(f"{base}/v0.1/scan/{task_id}", headers=_burp_headers())
            if resp.status_code != 200:
                raise HTTPException(502, f"Burp returned {resp.status_code}")
            issues = resp.json().get("issue_events", [])
        if not issues:
            return {"ok": True, "imported": 0, "message": "No issues to import"}
        findings = []
        for event in issues:
            issue = event.get("issue", {})
            findings.append({
                "url": issue.get("origin", "") + issue.get("path", ""),
                "name": issue.get("name", ""), "severity": (issue.get("severity") or "info").lower(),
                "confidence": (issue.get("confidence") or "tentative").lower(),
                "evidence": issue.get("detail", "")[:2000], "description": issue.get("description", ""),
                "solution": issue.get("remediation", ""), "source": "burp",
                "issue_type": f"burp-{issue.get('type_index', 'unknown')}",
            })
        imported = 0
        async with httpx.AsyncClient(verify=False, timeout=60) as c:
            for finding in findings:
                try:
                    resp = await c.post(f"{s.rag_api_url}/findings/web", json=finding, headers={"x-api-key": s.api_key, **engagement_headers()})
                    if resp.status_code < 300:
                        imported += 1
                except Exception:
                    pass
        return {"ok": True, "imported": imported, "total": len(findings), "task_id": task_id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(502, f"Failed to import Burp results: {e}")


async def _get_burp_proxy_url() -> str:
    """Get Burp proxy URL from DB setting or fall back to env config."""
    s = get_settings()
    try:
        async with httpx.AsyncClient(verify=False, timeout=3) as c:
            resp = await c.get(f"{s.rag_api_url}/settings/config/burp_proxy_url", headers={"x-api-key": s.api_key, **engagement_headers()})
            if resp.status_code == 200:
                return safe_json(resp).get("value") or s.burp_proxy_url
    except Exception:
        pass
    return s.burp_proxy_url


@router.post("/api/burp/test-proxy")
async def test_burp_proxy():
    """Test Burp proxy connectivity and get external IP through Burp's proxy."""
    proxy_url = await _get_burp_proxy_url()
    if not proxy_url:
        return {"ok": False, "error": "Burp proxy URL not configured"}

    import time
    start = time.time()
    try:
        # Test connectivity through Burp proxy → httpbin to get external IP
        async with httpx.AsyncClient(proxy=proxy_url, verify=False, timeout=10) as c:
            resp = await c.get("https://httpbin.org/ip")
            elapsed = round((time.time() - start) * 1000)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ok": True,
                    "proxy_url": proxy_url,
                    "external_ip": data.get("origin", "unknown"),
                    "elapsed_ms": elapsed,
                    "message": f"Burp proxy reachable — external IP: {data.get('origin', '?')}",
                }
            return {"ok": False, "proxy_url": proxy_url, "error": f"HTTP {resp.status_code}", "elapsed_ms": elapsed}
    except httpx.ConnectError:
        elapsed = round((time.time() - start) * 1000)
        return {"ok": False, "proxy_url": proxy_url, "error": f"Cannot connect to Burp proxy at {proxy_url} — is Burp running?", "elapsed_ms": elapsed}
    except Exception as e:
        elapsed = round((time.time() - start) * 1000)
        return {"ok": False, "proxy_url": proxy_url, "error": str(e), "elapsed_ms": elapsed}


@router.post("/api/burp/configure-proxy")
async def configure_burp_proxy(request: Request):
    """Configure Burp's upstream SOCKS proxy.

    Body: { proxy_host, proxy_port, socks_version, enabled }
    Or: { node_id: "uuid" } — auto-lookup node's SOCKS port from node-manager
    """
    s = get_settings()
    body = await request.json()

    proxy_host = body.get("proxy_host", "")
    proxy_port = body.get("proxy_port", 1080)
    socks_version = body.get("socks_version", 5)

    # Auto-lookup from node if node_id is provided
    node_id = body.get("node_id")
    if node_id:
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as c:
                resp = await c.get(f"{s.tunnel_manager_url}/nodes/{node_id}", headers={"x-api-key": s.api_key, **engagement_headers()})
                if resp.status_code == 200:
                    node = resp.json()
                    # For external Burp: use docker_host_ip from request or DB setting
                    # This is the IP that Burp's machine can reach to access SOCKS ports
                    docker_host_ip = body.get("docker_host_ip")
                    if not docker_host_ip:
                        try:
                            async with httpx.AsyncClient(verify=False, timeout=3) as c2:
                                r2 = await c2.get(f"{s.rag_api_url}/settings/config/docker_host_ip", headers={"x-api-key": s.api_key, **engagement_headers()})
                                if r2.status_code == 200:
                                    docker_host_ip = r2.json().get("value")
                        except Exception:
                            pass
                    proxy_host = docker_host_ip or "node-manager"
                    proxy_port = node.get("proxy_port", 1080)
                    socks_version = 5 if node.get("proxy_type") == "socks5" else 4
        except Exception as e:
            return {"ok": False, "error": f"Failed to lookup node: {e}"}

    if not proxy_host:
        return {"ok": False, "error": "proxy_host is required (or provide node_id)"}

    # Try to set via Burp REST API
    try:
        base = _burp_url()
    except HTTPException:
        return {
            "ok": False,
            "error": "Burp API not configured",
            "manual_config": f"Set SOCKS{socks_version} proxy to {proxy_host}:{proxy_port} in Burp > Project options > Connections > SOCKS proxy",
        }

    config = {"project_options": {"connections": {"socks_proxy": {
        "use_proxy": body.get("enabled", True), "host": proxy_host,
        "port": proxy_port, "version": socks_version,
    }}}}
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as c:
            resp = await c.put(f"{base}/v0.1/configuration", json=config, headers=_burp_headers())
            if resp.status_code in (200, 204):
                return {"ok": True, "message": f"Burp SOCKS{socks_version} proxy set to {proxy_host}:{proxy_port}",
                        "proxy_host": proxy_host, "proxy_port": proxy_port}
            return {"ok": False,
                    "message": f"Burp API returned {resp.status_code}. Set manually: Project options > Connections > SOCKS proxy > {proxy_host}:{proxy_port}",
                    "manual_config": f"SOCKS{socks_version} → {proxy_host}:{proxy_port}",
                    "config": config}
    except Exception as e:
        return {"ok": False, "error": str(e),
                "manual_config": f"SOCKS{socks_version} → {proxy_host}:{proxy_port}",
                "config": config}


# ── Burp Follow-Up Queue ─────────────────────────────────────────────
# Proxy to rag-api's /burp-queue endpoints for queueing follow-up
# findings to the RagScanBridge Burp extension.

@router.post("/api/burp/queue")
async def add_to_burp_queue(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/burp-queue",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/burp/queue")
async def list_burp_queue(
    status: str = Query("pending"),
    limit: int = Query(200),
):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.get(
            f"{s.rag_api_url}/burp-queue",
            params={"status": status, "limit": limit},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.get("/api/burp/queue/stats")
async def burp_queue_stats():
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.get(
            f"{s.rag_api_url}/burp-queue/stats",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.patch("/api/burp/queue/{item_id}")
async def update_burp_queue_item(item_id: str, status: str = Query(...)):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.patch(
            f"{s.rag_api_url}/burp-queue/{item_id}",
            params={"status": status},
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.post("/api/burp/queue/mark-imported")
async def bulk_mark_imported(request: Request):
    s = get_settings()
    body = await request.json()
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        resp = await c.post(
            f"{s.rag_api_url}/burp-queue/mark-imported",
            json=body,
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)


@router.delete("/api/burp/queue/{item_id}")
async def delete_burp_queue_item(item_id: str):
    s = get_settings()
    async with httpx.AsyncClient(verify=False, timeout=10) as c:
        resp = await c.delete(
            f"{s.rag_api_url}/burp-queue/{item_id}",
            headers={"x-api-key": s.api_key, **engagement_headers()},
        )
        return safe_json(resp)
