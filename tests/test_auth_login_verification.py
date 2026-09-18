"""Login verification (Playwright path) + CSRF unification (pipeline path)."""
import os, re
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
def _r(rel):
    p=os.path.join(REPO,rel)
    if not os.path.exists(p): pytest.skip(f"{rel} missing")
    return open(p,encoding="utf-8").read()

def test_playwright_path_verifies_login():
    s=_r("playwright_scanner/zap_bridge.py")
    assert "def verify_authentication" in s
    assert "authenticate_as_user" in s and "get_authentication_state" in s
    # scan path must use the verification, not bare bool(user_id)
    m=re.search(r"user_id = self.configure_authentication[\s\S]{0,800}", s)
    assert m and "verify_authentication(context_id, user_id)" in m.group(0)

def test_pipeline_path_supports_csrf():
    s=_r("web_scanner/web_scan.py")
    assert "csrf_field: Optional[str]" in s  # ScanAuth field
    assert "def _ensure_csrf_auth_script" in s
    m=re.search(r"def configure_zap_auth\([\s\S]*?zap.sessionManagement", s)
    assert m and "scriptBasedAuthentication" in m.group(0) and "auth.csrf_field" in m.group(0)
