"""Guard: gobuster runs authenticated by reusing the crawl's persisted session.

The crawl persists its live session cookies into the Auth Profile
(web_auth_configs.session.cookies); directory_followup reads them and passes
gobuster's -c so the dir brute runs as the logged-in user.

Structural assertions (tests/_ast_assert) rather than source substrings: the
previous version pinned strings like `f' -c "{cookie}"'` and
`_gobuster_command(dir_url, wordlist, cfg, cookie=`, which break on any
reformatting and are satisfied by a comment mentioning them.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).parent))
from _ast_assert import defines, calls, call_kwarg, string_constants  # noqa: E402

FOLLOWUP = ROOT / "etl/directory_followup.py"
SCANNER = ROOT / "playwright_scanner/playwright_scanner.py"


def test_followup_resolves_the_stored_session():
    assert defines(FOLLOWUP, "_resolve_session_cookie"), \
        "the followup must resolve the Auth Profile session"
    # it reads the profile's cookies, not some other store
    consts = string_constants(FOLLOWUP)
    assert any("web_auth_configs" in c for c in consts), "must read web_auth_configs"
    assert any("cookies" in c for c in consts), "must read session.cookies"


def test_gobuster_command_is_built_with_the_cookie():
    """The command builder takes a cookie and the caller passes one — asserted as
    a signature + keyword, so renaming a local or reflowing the call is fine."""
    assert defines(FOLLOWUP, "_gobuster_command")
    assert call_kwarg(FOLLOWUP, "_gobuster_command", "cookie"), \
        "the followup must pass cookie= into the gobuster command builder"
    # gobuster's own flag for a cookie is -c; it must appear as a real literal
    assert any("-c " in c for c in string_constants(FOLLOWUP)), \
        "gobuster needs -c to send the session cookie"


def test_crawl_persists_session_cookies():
    assert defines(SCANNER, "_persist_session_cookies"), \
        "the crawl must persist its session for other tools"
    assert calls(SCANNER, "_persist_session_cookies"), \
        "defining it is not enough — the crawl has to call it"
    # merges into the session blob rather than clobbering login_page
    assert any("jsonb_build_object" in c and "cookies" in c
               for c in string_constants(SCANNER)), \
        "cookies must be merged into the existing session jsonb"
    assert calls(SCANNER, "cookies"), "must read the live browser cookies"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
