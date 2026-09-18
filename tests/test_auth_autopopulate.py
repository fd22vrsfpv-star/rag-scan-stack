"""Auto-populate: parse a login page into an Auth Profile macro (deterministic)."""
import os, sys
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "app", "rag-api"))
ap = pytest.importorskip("auth_autopopulate")

_FORM = '''<html><body>
<form action="/do_login" method="post">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="text" name="username">
  <input type="password" name="password">
  <input type="hidden" name="return" value="/home">
  <button type="submit">Go</button>
</form></body></html>'''

def test_parse_login_form():
    f = ap.parse_login_form(_FORM)
    assert f and f["user_field"] == "username" and f["pass_field"] == "password"
    assert f["csrf_field"] == "csrf_token" and f["extras"] == {"return": "/home"}

def test_build_login_data():
    f = ap.parse_login_form(_FORM)
    ld = ap.build_login_data(f)
    assert "username={%username%}" in ld and "password={%password%}" in ld
    assert "csrf_token={%csrf%}" in ld and "return=/home" in ld

def test_synthesize_profile_resolves_action_and_csrf():
    prof = ap.synthesize_profile(_FORM, "http://app.example/login")
    assert prof["login_url"] == "http://app.example/do_login"
    assert prof["auth_type"] == "csrf" and prof["csrf_field"] == "csrf_token"

def test_no_password_form_returns_none():
    assert ap.parse_login_form("<form><input name=q></form>") is None
    assert ap.synthesize_profile("<html>no form</html>", "http://x/") is None
