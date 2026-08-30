"""Live: a security test exports to Burp and pushes into the Burp queue.

Two runtime-only failures this guards (both passed import + ast + healthy
container and only 500'd on execution):
  * send-to-burp inserted status='queued' — rejected by the queue's status CHECK
    ('pending','imported','dismissed');
  * it called emit_webhook without the local `from webhooks import` the rest of
    api.py uses -> NameError after the row was already inserted.

Skips cleanly without a stack.
    ST_URL=https://localhost:8000 pytest tests/test_security_tests_burp.py
"""
import json
import os
import re
import pathlib

import pytest

requests = pytest.importorskip("requests")
BASE = os.environ.get("ST_URL", "https://localhost:8000")


def _key():
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def _h():
    return {"x-api-key": _key(), "content-type": "application/json"}


def _post(path, body=None):
    try:
        return requests.post(f"{BASE}{path}", headers=_h(),
                             data=json.dumps(body) if body is not None else None,
                             timeout=25, verify=False)
    except Exception as e:
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


@pytest.fixture
def a_test():
    r = _post("/security-tests", {
        "name": "pytest-burp", "tier": "safe", "category": "lfi_read",
        "target_ip": "10.0.0.9", "target_port": 80, "tool": "curl",
        "command": "curl -sk http://10.0.0.9/x?file=/etc/passwd",
        "assertion": {"expect_substring": ["root:x:0:0"]}})
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, r.text[:200]
    tid = r.json()["id"]
    yield tid
    requests.request("DELETE", f"{BASE}/security-tests/{tid}", headers=_h(),
                     timeout=10, verify=False)  # best-effort; may 404 if no route


def test_export_burp_returns_har(a_test):
    r = _post(f"/security-tests/{a_test}/export-burp", {"format": "har"})
    assert r.status_code == 200, r.text[:200]
    d = r.json()
    assert d["filename"].endswith(".har")
    entry = json.loads(d["data"])["log"]["entries"][0]
    assert "file=/etc/passwd" in entry["request"]["url"]


def test_send_to_burp_queues(a_test):
    r = _post(f"/security-tests/{a_test}/send-to-burp")
    assert r.status_code == 200, f"send-to-burp {r.status_code}: {r.text[:200]}"
    d = r.json()
    assert d.get("ok") is True and d.get("queue_id")
    assert d.get("url", "").endswith("/x?file=/etc/passwd")
