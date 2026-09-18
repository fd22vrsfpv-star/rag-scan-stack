"""The ZAP-seeding crawl authenticates BEFORE crawling, so ZAP's authenticated
active scan attacks a post-login tree (previously the crawl was always
unauthenticated, undercutting authenticated scanning).

Guards without importing the heavy playwright-scanner service: source-level
checks + extract-and-exec of the pure `_login_fields` helper.

SABOTAGE PROOF
--------------
Remove the `req.auth or _resolve_web_auth` line from _perform_crawl and
test_crawl_resolves_and_logs_in fails; break _login_fields and
test_login_fields_parses_template fails.

Run:  pytest tests/test_authenticated_crawl.py -v
"""
import os
import re
import textwrap

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PS = os.path.join(REPO, "playwright_scanner", "playwright_scanner.py")


def _src():
    if not os.path.exists(PS):
        pytest.skip("playwright_scanner.py missing")
    return open(PS, encoding="utf-8").read()


def test_crawlrequest_has_auth_field():
    assert re.search(r"class CrawlRequest[\s\S]*?\n    auth: Optional\[Dict\]", _src())


def test_crawl_resolves_and_logs_in():
    src = _src()
    m = re.search(r"async def _perform_crawl\([\s\S]*?(?=\nasync def |\ndef |\Z)", src)
    assert m, "_perform_crawl not found"
    body = m.group(0)
    assert "req.auth or _resolve_web_auth(req.url" in body, "crawl must resolve an Auth Profile"
    assert "_browser_login(page, _crawl_auth)" in body, "crawl must log the browser in"


def test_browser_login_verifies_logged_in_regex():
    src = _src()
    m = re.search(r"async def _browser_login\([\s\S]*?(?=\nasync def |\ndef |\Z)", src)
    assert m, "_browser_login not found"
    assert "logged_in_regex" in m.group(0) and "re" in m.group(0)


def _extract_func(src, name):
    m = re.search(rf"^def {name}\(.*?(?=^def |^async def |\Z)", src, re.S | re.M)
    assert m, f"{name} not found"
    return textwrap.dedent(m.group(0))


def test_login_fields_parses_template():
    # exec ONLY the pure helper (stdlib deps) so we exercise the real code
    ns = {}
    exec(_extract_func(_src(), "_login_fields"), ns)
    fn = ns["_login_fields"]
    u, p = fn("user={%username%}&pass={%password%}&csrf={%csrf%}")
    assert u == "user" and p == "pass"
    u2, p2 = fn("email={%username%}&password={%password%}")
    assert u2 == "email" and p2 == "password"
    assert fn("") == (None, None)
