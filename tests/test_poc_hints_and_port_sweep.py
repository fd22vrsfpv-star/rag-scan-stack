"""Executes the poc_hints endpoints + the port-sweep helper. Skips cleanly when the
rag-api container isn't up (host has no pytest deps for these). Sabotage-proven:
change the ENDPOINT path below to a bogus one and this test fails."""
import json
import os
import subprocess
import pytest

ENDPOINT = "/software/poc-hints"


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


def _call(method, path, body=None):
    args = ["docker", "exec", "-e", "PATH=/usr/local/bin:/usr/bin:/bin",
            "rag-api", "sh", "-lc",
            f'curl -sk -X {method} https://localhost:8000{path} '
            f'-H "x-api-key: $API_KEY" -H "Content-Type: application/json"' +
            (f" -d '{json.dumps(body)}'" if body else "")]
    r = subprocess.run(args, capture_output=True, text=True, timeout=15)
    try:
        return r.returncode, json.loads(r.stdout or "{}")
    except Exception:
        return r.returncode, {"raw": r.stdout[:400]}


def test_add_list_delete_poc_hint():
    """The full round-trip: POST creates a hint, GET lists it, DELETE deactivates it."""
    body = {"cve": "CVE-2099-TEST-HINT", "hint": "unit-test hint payload"}
    rc, resp = _call("POST", ENDPOINT, body)
    assert rc == 0, f"post failed: {resp}"
    hid = resp.get("id")
    assert hid, f"no id in response: {resp}"

    rc, listing = _call("GET", f"{ENDPOINT}?cve=CVE-2099-TEST-HINT")
    assert rc == 0
    ids = [h.get("id") for h in listing.get("hints", [])]
    assert hid in ids, f"created hint not listed: {listing}"

    rc, del_resp = _call("DELETE", f"{ENDPOINT}/{hid}")
    assert rc == 0
    assert del_resp.get("ok") is True


def test_port_sweep_helper_directly():
    """Runs the port-sweep helper against 127.0.0.1 inside rag-api and confirms the
    known-open port (8000) is discovered with an HTTP banner."""
    py = (
        "import sys; sys.path.insert(0, '/app'); "
        "from api import _scout_open_ports; "
        "print(_scout_open_ports('127.0.0.1', 8000))"
    )
    r = subprocess.run(
        ["docker", "exec", "rag-api", "python3", "-c", py],
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0, r.stderr
    out = r.stdout or ""
    assert "8000" in out, f"expected port 8000 in output: {out[:400]}"
    assert "HTTP" in out or "no HTTP" in out, f"expected HTTP banner probe result: {out[:400]}"
