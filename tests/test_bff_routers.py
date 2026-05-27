"""BFF router tests — verify proxy routes work with mocked upstream services."""
import sys, os, pytest
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import Response

# Add BFF source to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dashboard", "bff"))

from fastapi.testclient import TestClient


# Patch polling before importing app to prevent background task startup
with patch("main.poll_loop", new_callable=lambda: lambda: AsyncMock()):
    from main import app

client = TestClient(app, raise_server_exceptions=False)


def _mock_response(json_data, status_code=200):
    """Create a mock httpx.Response."""
    resp = MagicMock(spec=Response)
    resp.status_code = status_code
    resp.json.return_value = json_data
    resp.text = str(json_data)
    resp.headers = {"content-type": "application/json"}
    return resp


def _mock_async_client(response):
    """Create a mock httpx.AsyncClient context manager."""
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=response)
    mock_client.post = AsyncMock(return_value=response)
    mock_client.patch = AsyncMock(return_value=response)
    mock_client.put = AsyncMock(return_value=response)
    mock_client.request = AsyncMock(return_value=response)

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=False)
    return mock_cm, mock_client


# ── Test 1: GET /api/assets ──────────────────────────────────────────────────
class TestAssetsRouter:
    def test_list_assets(self):
        data = {"count": 2, "assets": [
            {"ip": "10.0.0.1", "hostname": "web1", "os": "Linux", "open_ports_count": 3},
            {"ip": "10.0.0.2", "hostname": "db1", "os": "Windows", "open_ports_count": 1},
        ]}
        mock_resp = _mock_response(data)
        mock_cm, mock_client = _mock_async_client(mock_resp)

        with patch("routers.assets.httpx.AsyncClient", return_value=mock_cm):
            resp = client.get("/api/assets?limit=100")
            assert resp.status_code == 200
            body = resp.json()
            assert body["count"] == 2
            assert len(body["assets"]) == 2
            assert body["assets"][0]["ip"] == "10.0.0.1"

    def test_asset_ports(self):
        data = {"count": 2, "items": [
            {"port": 80, "proto": "tcp", "service": "http", "product": "nginx"},
            {"port": 443, "proto": "tcp", "service": "https", "product": "nginx"},
        ]}
        mock_resp = _mock_response(data)
        mock_cm, mock_client = _mock_async_client(mock_resp)

        with patch("routers.assets.httpx.AsyncClient", return_value=mock_cm):
            resp = client.get("/api/assets/10.0.0.1/ports")
            assert resp.status_code == 200
            body = resp.json()
            assert body["count"] == 2

    def test_asset_credentials(self):
        data = {"credentials": [
            {"id": "abc", "ip": "10.0.0.1", "port": 22, "protocol": "ssh",
             "username": "root", "status": "valid", "source": "brutus"}
        ]}
        mock_resp = _mock_response(data)
        mock_cm, mock_client = _mock_async_client(mock_resp)

        with patch("routers.assets.httpx.AsyncClient", return_value=mock_cm):
            resp = client.get("/api/assets/10.0.0.1/credentials")
            assert resp.status_code == 200
            body = resp.json()
            assert len(body["credentials"]) == 1
            assert body["credentials"][0]["username"] == "root"


# ── Test 2: GET /api/findings ────────────────────────────────────────────────
class TestFindingsRouter:
    def test_list_findings(self):
        data = {"vulns": [
            {"id": "v1", "script": "heartbleed", "severity": "high", "ip": "10.0.0.1"}
        ]}
        mock_resp = _mock_response(data)
        mock_cm, mock_client = _mock_async_client(mock_resp)

        with patch("routers.findings.httpx.AsyncClient", return_value=mock_cm):
            resp = client.get("/api/findings?limit=50")
            assert resp.status_code == 200


# ── Test 3: Delta / Scan Runs ────────────────────────────────────────────────
class TestDeltaRouter:
    def test_list_scan_runs(self):
        data = {"runs": [
            {"id": "r1", "tool": "nmap", "target": "10.0.0.0/24", "started_at": "2026-03-10T00:00:00Z"}
        ]}
        mock_resp = _mock_response(data)
        mock_cm, mock_client = _mock_async_client(mock_resp)

        with patch("routers.delta.httpx.AsyncClient", return_value=mock_cm):
            resp = client.get("/api/delta/scan-runs")
            assert resp.status_code == 200
            body = resp.json()
            assert len(body["runs"]) == 1

    def test_dedup_report(self):
        data = {"duplicates": [], "total_findings": 100, "unique_fingerprints": 80}
        mock_resp = _mock_response(data)
        mock_cm, mock_client = _mock_async_client(mock_resp)

        with patch("routers.delta.httpx.AsyncClient", return_value=mock_cm):
            resp = client.get("/api/delta/dedup-report")
            assert resp.status_code == 200


# ── Test 4: Reports / SARIF ──────────────────────────────────────────────────
class TestReportsRouter:
    def test_sarif_export(self):
        import json as _json
        sarif = {"version": "2.1.0", "$schema": "https://sarif.example", "runs": []}
        mock_resp = _mock_response(sarif)
        mock_resp.content = _json.dumps(sarif).encode()
        mock_cm, mock_client = _mock_async_client(mock_resp)

        with patch("routers.reports.httpx.AsyncClient", return_value=mock_cm):
            resp = client.get("/sarif-export")
            assert resp.status_code == 200
            body = resp.json()
            assert body["version"] == "2.1.0"


# ── Test 5: Health endpoint ───────────────────────────────────────────────────
class TestHealthRouter:
    def test_health_returns_ok(self):
        """BFF /api/health should respond even if upstream services are down."""
        # Health checks upstream services with short timeouts; all will fail in test
        # but the endpoint should still return 200 with statuses
        mock_resp = _mock_response({"status": "ok"})
        mock_cm, mock_client = _mock_async_client(mock_resp)

        with patch("routers.health.httpx.AsyncClient", return_value=mock_cm):
            resp = client.get("/api/health")
            assert resp.status_code == 200
