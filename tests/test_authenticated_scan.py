"""Authenticated scanning: credentials, and never a silent unauthenticated pass.

Run on demand:

    pytest tests/test_authenticated_scan.py -v

WHY THIS EXISTS
---------------
Nine WSTG tests (ATHN-01/03/05/07, SESS-03/06/07/09, IDNT-04) cannot be answered
without a session: fixation needs a pre- and post-login session to compare,
lockout needs repeated failures, timeout needs an idle authenticated session.

The dangerous failure here is not a crash — it is a scan that runs
UNAUTHENTICATED and is reported as authenticated. Every ATHN/SESS result would
then describe the login page, and the coverage number would go up while nothing
was tested. Three specific ways that happens, each pinned below:

  * a credential that is a HASH sent as a form password — the login fails, the
    scan proceeds, and it looks identical to success;
  * no logged-in/logged-out indicator, so ZAP cannot detect a dropped session and
    happily re-scans the login page;
  * authentication configured AFTER seeding/spidering, leaving the crawl
    unauthenticated.

Static checks — no ZAP, no DB, runs in CI.

Sabotage check: allow a non-plaintext credential_type -> RED.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
WEB_SCAN = os.path.join(REPO, "web_scanner", "web_scan.py")
PIPELINE = os.path.join(REPO, "web_scanner", "scan_pipeline.py")


def _src(path=WEB_SCAN):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    return open(path, encoding="utf-8").read()


def _func(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    raise AssertionError(f"{name} not found — this guard would pass vacuously")


def test_credentials_come_from_the_vault_or_inline():
    body = _func(_src(), "ScanAuth")
    assert "credential_vault_id" in body, "cannot select a stored credential"
    assert "username" in body and "password" in body, "cannot supply one inline"
    resolved = _func(_src(), "resolved") if "def resolved" in _src() else body
    assert "ValueError" in resolved or "ValueError" in body, (
        "an unusable credential must raise, not resolve to something empty"
    )


def test_a_hash_is_not_sent_as_a_form_password():
    """The failure that looks like success. An NTLM hash in a password field
    produces a failed login and a scan that reports normally."""
    src = _src()
    assert "_PLAINTEXT_CRED_TYPES" in src, "no allow-list of usable credential types"
    body = _func(src, "_credential_from_vault")
    assert "_PLAINTEXT_CRED_TYPES" in body, (
        "the vault lookup does not check credential_type, so a hash would be sent "
        "as a password and the scan would silently be unauthenticated"
    )
    assert "raise ValueError" in body, "a non-plaintext type must be refused"


def test_cracked_value_wins_over_the_stored_hash():
    body = _func(_src(), "_credential_from_vault")
    # Anchor on the PRECEDENCE expression, not on the SELECT list — the columns
    # are listed in table order there, which says nothing about which one wins.
    m = re.search(r"secret\s*=\s*\(row\.get\(\s*[\"']([a-z_]+)", body)
    assert m, "the secret is not chosen by an explicit precedence expression"
    assert m.group(1) == "cracked_value", (
        f"the first secret tried is {m.group(1)!r}; if a hash was cracked, the "
        "plaintext (cracked_value) is the thing that can actually log in"
    )


def test_an_indicator_is_required():
    """Without one ZAP cannot tell a live session from a logged-out one."""
    body = _func(_src(), "configure_zap_auth")
    assert re.search(r"logged_in_regex\s+or\s+.*logged_out_regex", body), (
        "no check that at least one indicator is set"
    )
    assert "raise ValueError" in body, "a missing indicator must refuse the scan"


def test_the_login_is_confirmed_not_assumed():
    body = _func(_src(), "configure_zap_auth")
    assert "get_authentication_state" in body, (
        "the login is never verified — the scan would proceed unauthenticated "
        "with no signal that it had"
    )
    assert "authenticated" in body, "the outcome is not reported to the caller"


def test_auth_is_configured_before_seeding_and_spidering():
    """Configured afterwards, the crawl itself is unauthenticated."""
    body = _func(_src(), "_zap_scan_with_urls_inner")
    cfg = body.find("configure_zap_auth")
    seed = body.find("zap.urlopen")
    spider = body.find("spider.scan")
    assert cfg != -1, "auth is never configured in the scan path"
    assert seed != -1 and spider != -1, "seeding/spidering not found — guard unreliable"
    assert cfg < seed and cfg < spider, (
        "authentication is configured after seeding or spidering, so those "
        "requests carry no session"
    )


def test_a_credential_error_is_not_swallowed():
    body = _func(_src(), "_zap_scan_with_urls_inner")
    seg = body[body.find("configure_zap_auth"):]
    seg = seg[:400]
    assert "raise" in seg, (
        "a ValueError from auth configuration is caught and dropped, which turns "
        "an operator's bad credential into an unauthenticated scan reported as fine"
    )


def test_the_outcome_reaches_the_pipeline_result():
    """An operator must be able to see that a scan ran unauthenticated."""
    src = _src(PIPELINE)
    assert 'zap_result.get("auth")' in src, (
        "the pipeline drops the auth outcome, so nothing downstream can tell an "
        "authenticated scan from an unauthenticated one"
    )


def test_the_secret_is_never_logged():
    src = _src()
    body = _func(src, "_credential_from_vault") + _func(src, "configure_zap_auth")
    for line in body.splitlines():
        if "logger." not in line:
            continue
        assert "password" not in line.lower() or "password}" not in line, (
            f"a log line may interpolate the secret: {line.strip()[:80]}"
        )
        assert "secret" not in line or "{secret" not in line, (
            f"a log line interpolates the secret: {line.strip()[:80]}"
        )
