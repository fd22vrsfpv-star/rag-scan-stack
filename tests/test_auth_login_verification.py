"""Login verification (Playwright path) + CSRF unification (pipeline path)."""
import os, re
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ast_assert import calls, call_order, defines, function_source  # noqa: E402

def _r(rel):
    p=os.path.join(REPO,rel)
    if not os.path.exists(p): pytest.skip(f"{rel} missing")
    return open(p,encoding="utf-8").read()

def test_playwright_path_verifies_login():
    """The scan path must CONFIRM the login, not infer it from a user object
    existing (a ZAP user is not a session).

    Asked structurally. The previous version searched an 800-character window
    after `user_id = self.configure_authentication`, which went red the moment the
    second-identity (access-control) block was inserted between the two calls —
    the verification was still there, just further down.
    """
    s=_r("playwright_scanner/zap_bridge.py")
    assert defines(s, "verify_authentication")
    assert calls(s, "authenticate_as_user") and calls(s, "get_authentication_state"), \
        "verification must drive ZAP's own auth state, not re-implement a login check"
    scan = function_source(s, "scan_with_playwright_session")
    assert scan, "scan_with_playwright_session not found — guard would pass vacuously"
    assert calls(scan, "verify_authentication"), \
        "the scan path must verify the login, not settle for bool(user_id)"
    assert call_order(s, "configure_authentication", "verify_authentication",
                      within="scan_with_playwright_session"), \
        "verification must follow the auth configuration it checks"

def test_pipeline_path_supports_csrf():
    s=_r("web_scanner/web_scan.py")
    assert "csrf_field: Optional[str]" in s  # ScanAuth field
    assert "def _ensure_csrf_auth_script" in s
    m=re.search(r"def configure_zap_auth\([\s\S]*?zap.sessionManagement", s)
    assert m and "scriptBasedAuthentication" in m.group(0) and "auth.csrf_field" in m.group(0)
