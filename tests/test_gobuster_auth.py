"""Guard: gobuster runs authenticated by reusing the crawl's persisted session.

The crawl persists its live session cookies into the Auth Profile
(web_auth_configs.session.cookies); directory_followup reads them and adds
gobuster's -c so the dir brute runs as the logged-in user. Source-wiring guards.
"""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_directory_followup_adds_cookie():
    s = _src("etl/directory_followup.py")
    assert "def _resolve_session_cookie(" in s
    assert "web_auth_configs" in s and "cookies" in s
    # gobuster -c gets the cookie; command builder takes it
    assert 'f\' -c "{cookie}"\'' in s or '-c "{cookie}"' in s
    assert "_gobuster_command(dir_url, wordlist, cfg, cookie=" in s


def test_crawl_persists_session_cookies():
    s = _src("playwright_scanner/playwright_scanner.py")
    assert "def _persist_session_cookies(" in s
    assert "_persist_session_cookies(" in s
    # merges cookies into the session jsonb without clobbering login_page
    assert "jsonb_build_object('cookies'" in s
    assert "await ctx.cookies()" in s


if __name__ == "__main__":
    import pytest, sys
    sys.exit(pytest.main([__file__, "-v"]))
