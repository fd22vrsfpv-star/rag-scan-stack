"""BFF Auth Profiles router proxies to the right upstreams and is registered."""
import os, re
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def _read(rel):
    p = os.path.join(REPO, rel)
    if not os.path.exists(p): pytest.skip(f"{rel} missing")
    return open(p, encoding="utf-8").read()

def test_router_defines_and_proxies():
    src = _read("dashboard/bff/routers/auth_profiles.py")
    for route in ('@router.get("/api/auth-profiles")',
                  '@router.post("/api/auth-profiles")',
                  '@router.delete("/api/auth-profiles/{host}")',
                  '@router.post("/api/auth-profiles/auto-populate")',
                  '@router.get("/api/auth-profiles/burp-bundle")'):
        assert route in src, f"missing route {route}"
    assert "/web-auth" in src  # -> playwright-scanner store
    assert "/auth-profiles/auto-populate" in src and "/auth-profiles/burp-bundle" in src  # -> rag-api

def test_router_registered():
    m = _read("dashboard/bff/main.py")
    assert "auth_profiles_router" in m and "include_router(auth_profiles_router)" in m

def test_playwright_url_configured():
    assert "playwright_scanner_url" in _read("dashboard/bff/config.py")
