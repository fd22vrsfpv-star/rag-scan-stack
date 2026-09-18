"""Token/header auth (bearer/JWT/API-key) + OAuth2 client-credentials persistence."""
import os, re
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
def _r(rel):
    p=os.path.join(REPO,rel)
    if not os.path.exists(p): pytest.skip(f"{rel} missing")
    return open(p,encoding="utf-8").read()

def test_zap_injects_session_headers():
    s=_r("playwright_scanner/zap_bridge.py")
    assert "def apply_session_headers" in s and "replacer.add_rule" in s
    # scan path injects headers (token-only profiles, no login form)
    assert "apply_session_headers(_sess_headers)" in s

def test_auth_capture_persists_token():
    s=_r("playwright_scanner/playwright_scanner.py")
    assert "persist_host" in s and "def _persist_session_headers" in s
    m=re.search(r"async def _capture_client_credentials\(.*?(?=\nasync def |\n@app\.)", s, re.S)
    assert m and "_persist_session_headers" in m.group(0)
    # persisted as a session-only token profile
    assert "'token'" in _r("playwright_scanner/playwright_scanner.py")
