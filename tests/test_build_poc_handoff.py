"""Verify the build-poc operator-handoff surfaces:
  - /software/cves-without-poc lists asset-software CVEs lacking a stored PoC
  - BuildPocBody accepts target_url and resolves it into ip/port/hint
  - _resolve_target_url: explicit ip/port win over URL-parsed values
"""
import subprocess
import pytest


def _rag_api_up():
    try:
        r = subprocess.run(
            ["docker", "exec", "rag-api", "sh", "-lc",
             "curl -sk https://localhost:8000/health -o /dev/null -w '%{http_code}'"],
            capture_output=True, text=True, timeout=6,
        )
        return r.returncode == 0 and r.stdout.strip() == "200"
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _rag_api_up(), reason="rag-api container not reachable")


def _in_container(py_snippet):
    r = subprocess.run(
        ["docker", "exec", "rag-api", "python3", "-c", py_snippet],
        capture_output=True, text=True, timeout=15,
    )
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def test_resolve_target_url_parses_full_url():
    py = """
import sys; sys.path.insert(0,'/app')
from api import _resolve_target_url
ip, port, hint = _resolve_target_url('http://172.18.0.35:9090/wp-json/wp/v2/users/1',
                                      None, None, None, None)
assert ip == '172.18.0.35'
assert port == 9090
assert '/wp-json/wp/v2/users/1' in hint
assert 'OPERATOR-SUPPLIED TARGET ENDPOINT' in hint
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_resolve_target_url_explicit_wins():
    py = """
import sys; sys.path.insert(0,'/app')
from api import _resolve_target_url
# Explicit ip + port must override the URL
ip, port, _ = _resolve_target_url('http://url-host/path', '10.0.0.1', 8443, None, None)
assert ip == '10.0.0.1', ip
assert port == 8443, port
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_resolve_target_url_https_default_port():
    py = """
import sys; sys.path.insert(0,'/app')
from api import _resolve_target_url
_, port, _ = _resolve_target_url('https://host/x', None, None, None, None)
assert port == 443
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, f"stderr: {err}"


def test_cves_without_poc_endpoint_shape():
    """Live endpoint smoke: returns the shape the UI needs. Allowed to be
    empty (zero rows is a real state); only the SHAPE is pinned."""
    r = subprocess.run(
        ["docker", "exec", "rag-api", "sh", "-lc",
         'curl -sk -H "x-api-key: $API_KEY" '
         '"https://localhost:8000/software/cves-without-poc?limit=3"'],
        capture_output=True, text=True, timeout=12,
    )
    assert r.returncode == 0, r.stderr
    import json
    d = json.loads(r.stdout)
    assert "count" in d and "total_candidates" in d and "items" in d
    for item in d["items"]:
        # Each item carries the fields the frontend needs to call /software/build-poc
        for k in ("cve", "ip", "severity", "build_poc_payload"):
            assert k in item, f"missing key {k}: {item}"
        assert item["cve"].startswith("CVE-")
        assert item["build_poc_payload"]["cve"] == item["cve"]
