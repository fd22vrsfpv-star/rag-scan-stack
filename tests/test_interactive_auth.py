"""Interactive auth breadth: import-session, assisted interactive login (+OTP
resume), scripted OAuth2 authorization-code — endpoints + bff proxies exist."""
import os, re
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
def _r(rel):
    p=os.path.join(REPO,rel)
    if not os.path.exists(p): pytest.skip(f"{rel} missing")
    return open(p,encoding="utf-8").read()

def test_playwright_endpoints():
    s=_r("playwright_scanner/playwright_scanner.py")
    for route in ('@app.post("/auth/import-session")',
                  '@app.post("/auth/interactive-login")',
                  '@app.post("/auth/interactive-login/{login_session_id}/otp")'):
        assert route in s, f"missing {route}"
    assert "def _capture_authorization_code" in s
    assert 'authorization_code' in s and "def _persist_session(" in s
    # captures the browser session (cookies + storage token) and persists it
    assert "session_from_storage_state" in s and "storage_state()" in s

def test_mfa_pause_resume():
    s=_r("playwright_scanner/playwright_scanner.py")
    # out-of-band OTP holds the browser and returns a resume id; TOTP computed inline
    assert "mfa_required" in s and "login_session_id" in s
    assert "totp_now(" in s

def test_bff_proxies():
    s=_r("dashboard/bff/routers/auth_profiles.py")
    for route in ('/api/auth-profiles/import-session',
                  '/api/auth-profiles/interactive-login',
                  '/api/auth-profiles/oauth-capture'):
        assert route in s, f"missing bff {route}"
