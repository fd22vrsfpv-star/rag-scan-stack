"""Guard: ZAP Access Control (broken access control / IDOR) wiring.

Covers the accessControl add-on integration added to the authenticated scan:
  - zap_bridge.ZAPBridge.access_control_scan builds the correct ZAP API call and
    polls getScanStatus to completion.
  - zap_bridge.ZAPBridge.add_context_user creates + enables a second context user.
  - scan_with_playwright_session threads second_auth/do_access_control.
  - playwright_scanner exposes ScanRequest.zap_access_control/second_auth and a
    _resolve_second_web_auth resolver, and passes do_access_control to the bridge.
  - default_cred_check reads the zap.access_control setting and passes it on.
  - knowledge/default_cred_check.yaml enables it in authenticated_rescan.

Sabotage-proven: flip any wired line (drop the userid join, the setting read, the
yaml key) and the matching assertion fails.

Runs standalone; the functional part stubs zapv2/requests so it needs no ZAP.
"""
import ast
import os
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PW = ROOT / "playwright_scanner"


def _load_zap_bridge():
    """Import zap_bridge with zapv2/requests stubbed (no live ZAP needed)."""
    zapv2 = types.ModuleType("zapv2")

    class _FakeZAPv2:
        def __init__(self, *a, **k):
            pass

    zapv2.ZAPv2 = _FakeZAPv2
    sys.modules["zapv2"] = zapv2
    sys.modules.setdefault("requests", types.ModuleType("requests"))
    sys.path.insert(0, str(PW))
    import importlib
    if "zap_bridge" in sys.modules:
        del sys.modules["zap_bridge"]
    return importlib.import_module("zap_bridge")


class _Recorder:
    """Records the kwargs of the last call to each attribute accessed as a method."""
    def __init__(self, calls):
        self._calls = calls

    def __getattr__(self, name):
        def _fn(*a, **k):
            self._calls.append((name, a, k))
            # get_scan_status → return "100" (completed) so the poll ends fast
            if name == "get_scan_status":
                return "100"
            if name == "new_user":
                return "11"
            return "OK"
        return _fn


def _make_bridge():
    zb = _load_zap_bridge()
    b = zb.ZAPBridge(zap_addr="127.0.0.1", zap_port=8090, zap_api_key="x")
    calls = []

    class _Zap:
        def __init__(self):
            self.accessControl = _Recorder(calls)
            self.users = _Recorder(calls)
    b.zap = _Zap()
    return b, calls


def test_access_control_scan_builds_correct_call():
    b, calls = _make_bridge()
    out = b.access_control_scan("7", ["10", "11"], unauth=True)
    scan_calls = [c for c in calls if c[0] == "scan"]
    assert scan_calls, "accessControl.scan was never called"
    _, _, kw = scan_calls[0]
    assert kw.get("contextid") == "7"
    # both users must be joined for the horizontal-IDOR comparison
    assert kw.get("userid") == "10,11"
    assert kw.get("scanasunauthuser") == "true"
    assert kw.get("raisealert") == "true"
    assert out.get("ran") is True
    assert out.get("completed") is True


def test_access_control_scan_needs_context_and_users():
    b, _ = _make_bridge()
    assert b.access_control_scan("", ["10"]).get("ran") is False
    assert b.access_control_scan("7", []).get("ran") is False


def test_ajax_spider_bounds_are_container_safe():
    """The ajax spider MUST be bounded (1 browser, capped states) or it OOMs —
    ZAP's default is 32 browsers / unlimited states (measured 1GiB->14GiB in
    seconds). Guard the setters are called with safe values."""
    b, calls = _make_bridge()
    # give the fake zap an ajaxSpider recorder
    b.zap.ajaxSpider = _Recorder(calls)
    out = b.configure_ajax_spider_bounds()
    nb = out.get("set_option_number_of_browsers")
    # must be a small, bounded browser count — NOT ZAP's default 32 (which OOMs)
    assert isinstance(nb, int) and 0 < nb <= 8, f"browser count must be bounded and small, got {nb}"
    assert 0 < out.get("set_option_max_crawl_states", 0) <= 1000, "must cap crawl states (>0, not unlimited)"
    names = [c[0] for c in calls]
    assert "set_option_number_of_browsers" in names
    assert "set_option_max_crawl_states" in names


def test_scan_bounds_ajax_before_running_it():
    """The scan must bound the ajax spider before launching it, and call the
    ajax crawl with the USERNAME (not the numeric user id)."""
    s = _src("playwright_scanner/zap_bridge.py")
    assert "configure_ajax_spider_bounds(" in s
    # bounds set before the scan_as_user/scan call
    i_bounds = s.index("configure_ajax_spider_bounds(")
    i_scan = s.index("ajaxSpider.scan_as_user(")
    assert i_bounds < i_scan, "must bound the ajax spider before starting it"
    # scan_as_user must be passed the username, not the numeric id
    assert "_ajax_user" in s


def test_add_context_user_enables_user():
    b, calls = _make_bridge()
    uid = b.add_context_user("7", "jdoe", "demo1234")
    assert uid == "11"
    names = [c[0] for c in calls]
    assert "new_user" in names
    assert "set_authentication_credentials" in names
    assert "set_user_enabled" in names


# ─── source/AST wiring guards (no heavy imports) ──────────────────────────────

def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_scan_signature_threads_access_control():
    s = _src("playwright_scanner/zap_bridge.py")
    assert "def access_control_scan(" in s
    assert "def add_context_user(" in s
    # scan_with_playwright_session must accept + use the new params
    assert "second_auth" in s and "do_access_control" in s
    assert "self.access_control_scan(" in s


def test_playwright_scanner_exposes_fields_and_resolver():
    s = _src("playwright_scanner/playwright_scanner.py")
    assert "zap_access_control" in s
    assert "second_auth" in s
    assert "def _resolve_second_web_auth(" in s
    # the scan call must forward both to the bridge
    assert "do_access_control=" in s
    assert "second_auth=" in s


def test_default_cred_check_reads_setting_and_forwards():
    s = _src("etl/default_cred_check.py")
    assert "zap.access_control" in s
    assert "access_control" in s
    assert "zap_access_control" in s


def test_yaml_enables_access_control():
    import yaml
    y = yaml.safe_load(_src("knowledge/default_cred_check.yaml"))
    rescan = y["default_cred_check"]["authenticated_rescan"]
    assert rescan.get("zap_access_control") is True


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
