"""The portable auth bridge: Auth Profile <-> Burp.

Platform -> Burp: an Auth Profile renders into Burp `application_logins` and a
one-entry session HAR (for POST /api/burp/scan and Proxy>Import).
Burp -> platform: a Burp sitemap import captures the authenticated session
headers back into a session-only Auth Profile.

SABOTAGE PROOF
--------------
Make auth_profile_to_burp_logins emit a login for a session-only profile and
test_logins_empty_for_session_only fails; stop _capture_burp_session from
INSERTing on a Cookie header and test_capture_inserts_session fails.

Run:  pytest tests/test_burp_auth_bridge.py -v
"""
import os
import re
import sys
import json
import textwrap

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "app", "rag-api"))

be = pytest.importorskip("burp_export")


# ── platform -> Burp mappers ─────────────────────────────────────────────────
def test_logins_from_profile():
    logins = be.auth_profile_to_burp_logins(
        {"host": "app.example", "username": "admin", "password": "pw"})
    assert logins == [{"label": "app.example", "username": "admin", "password": "pw"}]


def test_logins_empty_for_session_only():
    assert be.auth_profile_to_burp_logins({"host": "x", "session": {"cookies": []}}) == []
    assert be.auth_profile_to_burp_logins({"username": "u"}) == []  # no password


def test_session_har_headers_and_har():
    sess = {"headers": {"Authorization": "Bearer T"},
            "cookies": [{"name": "sid", "value": "abc"}]}
    hdrs = {h["name"]: h["value"] for h in be.session_har_headers(sess)}
    assert hdrs["Authorization"] == "Bearer T"
    assert hdrs["Cookie"] == "sid=abc"
    har = be.build_session_har("http://app.example/", sess)
    assert har["log"]["version"] == "1.2"
    entry_hdrs = {h["name"] for h in har["log"]["entries"][0]["request"]["headers"]}
    assert "Authorization" in entry_hdrs and "Cookie" in entry_hdrs


# ── Burp -> platform capture (extract-and-exec the pure-ish helper) ──────────
class _FakeCur:
    def __init__(self):
        self.execs = []

    def execute(self, sql, params=None):
        self.execs.append((re.sub(r"\s+", " ", sql).strip(), params))


def _capture_fn():
    src = open(os.path.join(REPO, "etl", "parse_burp.py"), encoding="utf-8").read()
    m = re.search(r"^def _capture_burp_session\(.*?(?=^def )", src, re.S | re.M)
    assert m, "_capture_burp_session not found"
    ns = {"json": json, "logger": type("L", (), {"debug": staticmethod(lambda *a, **k: None)})()}
    exec(textwrap.dedent(m.group(0)), ns)
    return ns["_capture_burp_session"]


def test_capture_inserts_session():
    fn = _capture_fn()
    cur = _FakeCur()
    captured = set()
    req = ("GET /dashboard HTTP/1.1\r\nHost: app.example\r\n"
           "Cookie: session=abc123\r\nAuthorization: Bearer XYZ\r\n\r\n")
    fn(cur, "app.example", req, captured)
    inserts = [(s, p) for (s, p) in cur.execs if "INSERT INTO web_auth_configs" in s]
    assert inserts, "no session INSERT issued"
    sess = json.loads(inserts[0][1][1])
    assert sess["headers"]["Cookie"] == "session=abc123"
    assert sess["headers"]["Authorization"] == "Bearer XYZ"
    assert "app.example" in captured


def test_bff_start_scan_autosources_from_auth_profile():
    src = open(os.path.join(REPO, "dashboard", "bff", "routers", "burp.py"),
               encoding="utf-8").read()
    m = re.search(r"async def start_burp_scan\([\s\S]*?(?=\n@router\.|\Z)", src)
    assert m, "start_burp_scan not found"
    body = m.group(0)
    # when no explicit credentials, fetch the Auth Profile's application_logins
    assert "/auth-profiles/burp-bundle" in body
    assert "application_logins" in body


def test_capture_skips_when_no_auth_headers_or_already_seen():
    fn = _capture_fn()
    cur = _FakeCur()
    fn(cur, "app.example", "GET / HTTP/1.1\r\nHost: app.example\r\n\r\n", set())
    assert not any("INSERT INTO web_auth_configs" in s for s, _ in cur.execs)
    # already-captured host -> no work
    cur2 = _FakeCur()
    fn(cur2, "app.example", "Cookie: x=y", {"app.example"})
    assert cur2.execs == []
