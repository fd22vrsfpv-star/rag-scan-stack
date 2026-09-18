"""Headless-SSO deep end: ROPC + device-code + OIDC discovery + refresh + multi-step login."""
import os, re
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
def _r(rel):
    p=os.path.join(REPO,rel)
    if not os.path.exists(p): pytest.skip(f"{rel} missing")
    return open(p,encoding="utf-8").read()

def test_capture_modes():
    s=_r("playwright_scanner/playwright_scanner.py")
    assert 'req.mode == "password"' in s and 'req.mode == "device_code"' in s
    assert "def _capture_password" in s and 'grant_type": "password"' in s
    assert "def _capture_device_start" in s and '@app.post("/auth/device-poll")' in s
    assert "urn:ietf:params:oauth:grant-type:device_code" in s
    assert "def _oidc_discover" in s and "device_authorization_endpoint" in s

def test_auto_refresh_wired():
    s=_r("playwright_scanner/playwright_scanner.py")
    assert "def _maybe_refresh_session" in s
    assert "_maybe_refresh_session(host" in s  # called in _resolve_web_auth
    assert "needs_refresh" in s and "apply_refresh" in s

def test_multistep_login():
    s=_r("playwright_scanner/playwright_scanner.py")
    m=re.search(r"async def _drive_login\([\s\S]*?(?=\nasync def |\n@app)", s)
    assert m and "for step in range(4)" in m.group(0)
    assert "identifierId" in s and "kc-login" in s  # provider selectors

def test_bff_proxies():
    s=_r("dashboard/bff/routers/auth_profiles.py")
    assert "/api/auth-profiles/device-poll" in s and "/auth/device-poll" in s
    assert "/api/auth-profiles/oauth-capture" in s  # carries password/device modes
