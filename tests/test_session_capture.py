"""Pure session-capture helpers: build a replayable session from cookies / HAR /
Playwright storage_state, and RFC 6238 TOTP for assisted MFA."""
import os, sys
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "playwright_scanner"))
sc = pytest.importorskip("session_capture")

def test_build_session_derives_cookie_header():
    s = sc.build_session(cookies=[{"name": "sid", "value": "abc"}, {"name": "x", "value": "1"}])
    assert s["headers"]["Cookie"] == "sid=abc; x=1"
    assert s["cookies"][0]["name"] == "sid"

def test_storage_state_extracts_bearer_and_cookies():
    st = {"cookies": [{"name": "sid", "value": "c1", "domain": "app"}],
          "origins": [{"origin": "https://app",
                       "localStorage": [{"name": "access_token", "value": "eyJhbGci.eyJz.sig"}]}]}
    s = sc.session_from_storage_state(st)
    assert s["headers"]["Authorization"] == "Bearer eyJhbGci.eyJz.sig"
    assert s["headers"]["Cookie"] == "sid=c1"
    assert s["storage"] == st

def test_storage_state_bearer_from_json_value():
    st = {"origins": [{"localStorage": [{"name": "auth", "value": '{"access_token":"tok123"}'}]}]}
    assert sc.bearer_from_storage_state(st) == "tok123"

def test_session_from_har():
    har = {"log": {"entries": [
        {"request": {"headers": [{"name": "Cookie", "value": "s=1"},
                                 {"name": "Authorization", "value": "Bearer T"}]}}]}}
    s = sc.session_from_har(har)
    assert s["headers"]["Cookie"] == "s=1" and s["headers"]["Authorization"] == "Bearer T"

def test_totp_rfc6238_vector():
    # RFC 6238 appendix B: ASCII "12345678901234567890" at T=59 -> 287082 (SHA1, 6 digits)
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert sc.totp_now(secret, at=59) == "287082"
    assert sc.totp_now("not valid base32!!") is None
