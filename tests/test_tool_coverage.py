"""Unit tests for the Kali allowlist reconciliation (registry-driven, minus MSF).

The kali-listener gate is security-critical: it must allow the recommender's
tool universe but NEVER Metasploit, and must fail closed to a known-good set
when the registry is unreachable.  Loaded by file path because kali_listener/
isn't a package and its sibling `from log_manager import ...` needs the dir on
sys.path.
"""
import importlib.util
import pathlib
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

KL_DIR = Path(__file__).parent.parent / "kali_listener"
sys.path.insert(0, str(KL_DIR))  # for the module's `from log_manager import ...`

_spec = importlib.util.spec_from_file_location("kl_listener", KL_DIR / "listener_service.py")
kl = importlib.util.module_from_spec(_spec)
# listener_service mkdir's /reports at import (read-only in the test env) — no-op it.
_orig_mkdir = pathlib.Path.mkdir
pathlib.Path.mkdir = lambda self, *a, **k: None
try:
    _spec.loader.exec_module(kl)
finally:
    pathlib.Path.mkdir = _orig_mkdir
# kali_listener/ and scan_recommender/ both ship a `log_manager` module; drop the
# cached one so a sibling test re-imports its own copy cleanly (test isolation).
sys.modules.pop("log_manager", None)
if str(KL_DIR) in sys.path:
    sys.path.remove(str(KL_DIR))


@pytest.fixture(autouse=True)
def _reset_registry_cache():
    kl._TOOL_REGISTRY = None
    yield
    kl._TOOL_REGISTRY = None


def _fake_registry_response(names):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "ok": True, "count": len(names),
        "tools": {n: {"check": f"which {n}", "verify": None, "install": f"apt-get install -y {n}"} for n in names},
        "names": names,
    }
    return resp


@pytest.mark.unit
class TestAllowlistReconciliation:
    def test_registry_union_minus_msf(self, monkeypatch):
        import requests
        names = ["nmap", "enum4linux", "sslscan", "dnsrecon", "metasploit", "msfconsole"]
        monkeypatch.setattr(requests, "get", lambda *a, **k: _fake_registry_response(names))
        allowed = kl.get_allowed_tools()
        # Registry tools present
        assert "sslscan" in allowed and "dnsrecon" in allowed and "enum4linux" in allowed
        # MSF excluded
        assert "metasploit" not in allowed
        assert "msfconsole" not in allowed
        # Fallback union preserved (e.g. medusa was in the hardcoded set)
        assert "medusa" in allowed

    def test_fallback_when_registry_unreachable(self, monkeypatch):
        import requests
        def boom(*a, **k):
            raise ConnectionError("node-manager down")
        monkeypatch.setattr(requests, "get", boom)
        allowed = kl.get_allowed_tools()
        # Falls back to the known-good hardcoded set
        assert allowed == set(kl._FALLBACK_ALLOWED_TOOLS)
        # which still excludes MSF (the fallback never contained it)
        assert "metasploit" not in allowed

    def test_cache_is_used(self, monkeypatch):
        import requests
        calls = {"n": 0}
        def counting_get(*a, **k):
            calls["n"] += 1
            return _fake_registry_response(["nmap", "sslscan"])
        monkeypatch.setattr(requests, "get", counting_get)
        kl.get_allowed_tools()
        kl.get_allowed_tools()
        assert calls["n"] == 1  # second call served from cache

    def test_msf_deny_constant(self):
        assert "metasploit" in kl._MSF_DENY
        assert "msfvenom" in kl._MSF_DENY
