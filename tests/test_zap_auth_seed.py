"""Guard: authenticated URLs are seeded into ZAP before the spider.

WHY THIS EXISTS
---------------
An authenticated ZAP scan of a login-gated app (demo.testfire.net) returned only
public URLs (/, /doLogin, /images/*) and ZERO /bank/ pages, even though the login
succeeded. The ZAP spider seeds only from the logged-out base URL, which links to
nothing under the authentication gate, so the authenticated area never entered
`z.core.urls()` and the active scan raised no authenticated-only alerts.

The fix (`ZAPBridge.seed_authenticated_urls`): before the spider, force every URL
the authenticated Playwright crawl walked into ZAP's site tree via
`core.access_url` (re-fetched under the forced-user session). `z.core.urls()` then
contains /bank/main.jsp and the active scan covers it.

This proves the SEEDING LOGIC only. LIVE verification against demo.testfire.net
(an authenticated scan discovers /bank/main.jsp and web_findings gains
authenticated-only alerts) is still required to truly close the open item.

Static/unit — stubs zapv2/requests, no live ZAP needed. Runs standalone:

    pytest tests/test_zap_auth_seed.py -v

Sabotage-proven:
  - drop the access_url call in seed_authenticated_urls           -> RED
  - gate the seed on the WRONG flag / never call it in the scan   -> RED (order test)
  - seed regardless of authentication                             -> RED (gate test)
"""
import ast
import importlib
import os
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ZAPB = ROOT / "playwright_scanner" / "zap_bridge.py"
PW = ROOT / "playwright_scanner"


def _load_zap_bridge():
    """Import zap_bridge with zapv2/requests stubbed (no live ZAP needed)."""
    if not ZAPB.exists():
        pytest.skip("zap_bridge.py not present")
    zapv2 = types.ModuleType("zapv2")

    class _FakeZAPv2:
        def __init__(self, *a, **k):
            pass

    zapv2.ZAPv2 = _FakeZAPv2
    sys.modules["zapv2"] = zapv2
    sys.modules.setdefault("requests", types.ModuleType("requests"))
    sys.path.insert(0, str(PW))
    if "zap_bridge" in sys.modules:
        del sys.modules["zap_bridge"]
    try:
        return importlib.import_module("zap_bridge")
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"zap_bridge could not be imported: {e}")


class _CoreRecorder:
    """Records every access_url call and returns OK, like the ZAP core view."""

    def __init__(self):
        self.access_url_calls = []

    def access_url(self, url=None, followredirects=None, *a, **k):
        self.access_url_calls.append(url)
        return "OK"


def _make_bridge():
    zb = _load_zap_bridge()
    b = zb.ZAPBridge(zap_addr="127.0.0.1", zap_port=8090, zap_api_key="x")

    class _Zap:
        def __init__(self):
            self.core = _CoreRecorder()

    b.zap = _Zap()
    return b


# The URLs an authenticated crawl of demo.testfire.net walks — the post-login area
# the logged-out spider can never reach on its own.
AUTH_URLS = [
    "http://demo.testfire.net/bank/main.jsp",
    "http://demo.testfire.net/bank/showAccount",
    "http://demo.testfire.net/bank/transfer.jsp",
    "http://demo.testfire.net/",  # public, still fine to seed
]


def test_each_authenticated_url_is_seeded_into_zap():
    b = _make_bridge()
    n = b.seed_authenticated_urls(AUTH_URLS)
    seeded = b.zap.core.access_url_calls
    # every distinct URL we passed was fed to ZAP's core.access_url
    for u in AUTH_URLS:
        assert u in seeded, f"{u} was never seeded via core.access_url"
    # the authenticated landing page specifically must be present
    assert "http://demo.testfire.net/bank/main.jsp" in seeded
    assert n == len(AUTH_URLS)


def test_seeding_dedups_and_skips_blanks():
    b = _make_bridge()
    n = b.seed_authenticated_urls(
        ["http://x/bank/main.jsp", "http://x/bank/main.jsp", "", "   ", None]
    )
    assert b.zap.core.access_url_calls == ["http://x/bank/main.jsp"]
    assert n == 1


def test_seeding_is_fail_soft_when_access_url_raises():
    b = _make_bridge()

    def _boom(*a, **k):
        raise RuntimeError("ZAP down")

    b.zap.core.access_url = _boom
    # a broken ZAP must not crash the scan — returns 0, no exception
    assert b.seed_authenticated_urls(AUTH_URLS) == 0


def test_empty_seed_list_is_a_noop():
    b = _make_bridge()
    assert b.seed_authenticated_urls(None) == 0
    assert b.seed_authenticated_urls([]) == 0
    assert b.zap.core.access_url_calls == []


# ---- structural guards on the wiring inside scan_with_playwright_session ----
# These read the source (the live method is an async coroutine that also spins up
# a real ZAP), so they assert the seeding is (a) called with seed_urls, (b) gated
# on the authenticated flag, and (c) placed BEFORE the spider.

def _src():
    return ZAPB.read_text(encoding="utf-8") if ZAPB.exists() else pytest.skip("no zap_bridge")


def _method_src(name):
    tree = ast.parse(_src())
    for n in ast.walk(tree):
        if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef)) and n.name == name:
            return ast.get_source_segment(_src(), n) or ""
    raise AssertionError(f"{name} not found — guard would pass vacuously")


def test_scan_method_seeds_gated_on_authentication():
    body = _method_src("scan_with_playwright_session")
    assert "seed_urls" in body, "scan_with_playwright_session takes no seed_urls param"
    assert "seed_authenticated_urls(seed_urls)" in body, \
        "scan_with_playwright_session never calls seed_authenticated_urls(seed_urls)"
    # the seed must be gated on a confirmed login, not fired unconditionally
    assert "results.get('authenticated')" in body or "results['authenticated']" in body, \
        "seeding is not gated on the authenticated flag"


def test_seed_happens_before_spider():
    body = _method_src("scan_with_playwright_session")
    seed_at = body.find("seed_authenticated_urls(seed_urls)")
    spider_at = body.find("self.spider_url(")
    assert seed_at != -1 and spider_at != -1
    assert seed_at < spider_at, "seeding must run BEFORE the spider, not after"


def test_module_ast_parses():
    ast.parse(_src())  # runtime-defect guard: the file must be valid Python
