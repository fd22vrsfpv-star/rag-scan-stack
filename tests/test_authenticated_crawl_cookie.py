"""A session the build already mined must reach the crawler.

`CrawlRequest` accepted a login RECIPE (login_url / login_data / username /
password) but no session, and the sender forwarded only those four keys. So a
cookie the build had already established (`_auto_cookie`) was dropped on the
way out: the crawler re-authenticated from scratch, or crawled anonymously.

Every CVE-Bench target grants a user account, so an anonymous crawl never sees
the vulnerable surface, gather cannot find the endpoint, and the refine loop
exhausts its iterations on the paths it CAN reach.

The reporting was worse than the bug. The trace note keyed on a LOCAL variable
rather than on what was forwarded, so it printed "authenticated crawl" while
the cookie was being discarded — the open item's own verification signal was
satisfiable by a crawl that was not authenticated.

    docker run --rm -v /opt/rag-scan-stack:/repo -w /repo python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=.:tests \
      python -m pytest tests/test_authenticated_crawl_cookie.py -v'
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCANNER = REPO / "playwright_scanner" / "playwright_scanner.py"
API = REPO / "app" / "rag-api" / "api.py"


class TestTheRequestCanCarryASession:
    def test_crawl_request_declares_a_cookie_field(self):
        tree = ast.parse(SCANNER.read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef) and n.name == "CrawlRequest":
                fields = {a.target.id for a in n.body
                          if isinstance(a, ast.AnnAssign)
                          and isinstance(a.target, ast.Name)}
                assert "cookie_header" in fields, (
                    "CrawlRequest cannot carry an established session; the "
                    f"build's mined cookie has nowhere to go. fields={sorted(fields)}")
                return
        pytest.fail("CrawlRequest not found")

    def test_the_cookie_is_installed_in_the_browser(self):
        src = SCANNER.read_text(encoding="utf-8")
        assert re.search(r"add_cookies\s*\(", src), (
            "a cookie field that is never installed via add_cookies() is "
            "decoration")

    def test_a_supplied_session_is_not_overwritten_by_a_fresh_login(self):
        """A second login can invalidate the first on single-session apps."""
        src = SCANNER.read_text(encoding="utf-8")
        assert re.search(r"if\s+not\s+_supplied_cookie\s+and", src), (
            "the login branch must be skipped when a session was supplied")

    def test_a_rejected_cookie_is_not_reported_as_authenticated(self):
        """Three outcomes: installed, rejected, none supplied."""
        src = SCANNER.read_text(encoding="utf-8")
        assert re.search(r"supplied_cookie_failed", src), (
            "a cookie that failed to install must be distinguishable from one "
            "that worked, or a broken session reads as an authenticated crawl")


class TestTheSenderForwardsIt:
    def test_the_cookie_is_put_on_the_wire(self):
        src = API.read_text(encoding="utf-8")
        assert re.search(r'body\[\s*["\']cookie_header["\']\s*\]', src), (
            "the sender still forwards only the login recipe, so a mined "
            "session is dropped before it reaches the crawler")

    def test_the_note_reports_what_was_sent_not_what_was_held(self):
        """The bug that made the gap invisible."""
        src = API.read_text(encoding="utf-8")
        assert re.search(r"_sent_auth\s*=", src), (
            "the authenticated/unauthenticated note must be derived from what "
            "was forwarded; keyed on a local variable it claimed an "
            "authenticated crawl while the cookie was being discarded")
