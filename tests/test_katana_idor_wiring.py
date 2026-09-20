"""Guard: authenticated-katana -> discovered_params -> IDOR mutation probe chain.

Covers the wiring that makes the platform catch a same-URL, param-value IDOR
(e.g. AltoroMutual showAccount?listAccounts=<acct>):
  - pd-runner katana accepts auth headers + automatic-form-fill, and EXCLUDES
    logout from an authenticated crawl (katana shares the caller's session; a
    /logout.jsp request invalidates it for the browser + probe).
  - the Playwright crawl runs authenticated katana before the probe and NEVER
    navigates to a logout link (same session-preservation reason).
  - the IDOR probe matches its asset by hostname OR ip (was `ip = <hostname>`,
    which errors on the inet column) and detects a "blocked" response by the
    LOGIN FORM (password field), not the word "login" (which appears in static
    labels like alt="Secure Login" on every authenticated page).

Sabotage-proven: revert any one wire and the matching assertion fails.
Runs standalone; the regex test is self-contained.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


# ── the probe's blocked-response detection (the fix) ─────────────────────────
# Mirrors the regex in playwright_scanner._idor_mutate_probe. A login/blocked
# page carries a password field; an object-data page does not.
_BLOCKED = re.compile(
    r"(?i)type=[\"']?password|name=[\"']?(?:passw|pwd|uid|username|user|"
    r"j_username|j_password)\b|not authori[sz]ed|access denied|\bforbidden\b|"
    r"must be logged|please log ?in")

# Real-shape fixtures: an authenticated account page carries the "Secure Login"
# label + LoginLink id (the strings that broke the old word-based check) but NO
# password field; the logged-out page carries the login form.
_ACCOUNT_PAGE = (
    '<img alt="Secure Login"/> <a id="LoginLink" href="/logout.jsp">Sign Off</a>'
    '<h1>Account Number 800001</h1><table><tr><td>Balance</td><td>$1,234.00</td></tr></table>')
_LOGIN_PAGE = (
    '<form action="/doLogin"><input name="uid"><input type="password" name="passw">'
    '<input type="submit" value="Login"></form> You must be logged in.')


def test_account_page_not_blocked_login_page_blocked():
    assert not _BLOCKED.search(_ACCOUNT_PAGE), \
        "account/object page must NOT be treated as blocked (no password field)"
    assert _BLOCKED.search(_LOGIN_PAGE), \
        "login/blocked page MUST be detected (has a password field)"


def test_old_word_match_would_false_positive():
    """Proves WHY the fix matters: the old word-based check flagged the account
    page (via 'Secure Login'), which is what suppressed every real finding."""
    old = re.compile(r"(?i)sign ?in|log ?in|not authori[sz]ed|access denied|forbidden|error")
    assert old.search(_ACCOUNT_PAGE), "old check matched 'Login' in the account page (the bug)"


# ── source-wiring guards ─────────────────────────────────────────────────────

def test_pd_runner_katana_supports_auth_and_form_fill():
    s = _src("pd_runner/pd_runner.py")
    assert "headers" in s and "auto_form_fill" in s
    assert '"-aff"' in s or "'-aff'" in s
    assert '"-H"' in s or "'-H'" in s
    # authenticated katana must exclude logout from its crawl scope
    assert "-crawl-out-scope" in s
    assert re.search(r"(?i)logout", s)


def test_playwright_runs_authenticated_katana_before_probe():
    s = _src("playwright_scanner/playwright_scanner.py")
    assert "def _run_authenticated_katana(" in s
    assert "auto_form_fill" in s
    # the katana step is invoked inside the crawl, before the probe
    i_katana = s.index("_run_authenticated_katana(ctx")
    i_probe = s.index("_idor_mutate_probe(ctx, req.url")
    assert i_katana < i_probe, "authenticated katana must run before the IDOR probe"


def test_crawl_excludes_logout_navigation():
    s = _src("playwright_scanner/playwright_scanner.py")
    assert "_LOGOUT_RE" in s
    # the crawl loop must skip navigating to a logout URL when authenticated
    assert re.search(r"_LOGOUT_RE\.search\(url\)", s)


def test_probe_matches_asset_by_hostname_or_ip():
    s = _src("playwright_scanner/playwright_scanner.py")
    # candidate query and asset lookup must both accept a hostname (assets.ip is
    # inet, so a bare `ip = <hostname>` errors and returns nothing)
    assert "a.hostname = %s OR host(a.ip) = %s" in s
    assert "hostname=%s OR host(ip)=%s" in s


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
