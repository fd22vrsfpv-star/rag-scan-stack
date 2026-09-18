"""Pure OIDC/token helpers: discovery URL, token->session, expiry, refresh."""
import os, sys, time
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "playwright_scanner"))
of = pytest.importorskip("oidc_flows")

def test_discovery_url():
    assert of.discovery_url("https://idp.example/") == "https://idp.example/.well-known/openid-configuration"
    already = "https://idp.example/.well-known/openid-configuration"
    assert of.discovery_url(already) == already

def test_session_from_token_response():
    s = of.session_from_token_response(
        {"access_token": "AT", "token_type": "Bearer", "refresh_token": "RT", "expires_in": 3600},
        token_url="https://idp/token", client_id="cid", now=1000)
    assert s["headers"]["Authorization"] == "Bearer AT"
    assert s["refresh"]["refresh_token"] == "RT" and s["refresh"]["token_url"] == "https://idp/token"
    assert s["refresh"]["expires_at"] == 4600

def test_session_none_without_token():
    assert of.session_from_token_response({"error": "invalid_grant"}) is None

def test_needs_refresh():
    s = {"refresh": {"refresh_token": "RT", "token_url": "u", "expires_at": 1000}}
    assert of.needs_refresh(s, now=900) is False        # 100s left
    assert of.needs_refresh(s, now=980) is True         # within skew
    assert of.needs_refresh(s, now=2000) is True        # expired
    assert of.needs_refresh({"refresh": {"refresh_token": "RT", "token_url": "u"}}, now=0) is False  # no expiry
    assert of.needs_refresh({}, now=0) is False

def test_refresh_form_and_apply():
    s = {"headers": {"Authorization": "Bearer OLD"},
         "refresh": {"refresh_token": "RT", "token_url": "https://idp/token", "client_id": "cid"}}
    form = of.refresh_form(s)
    assert form["url"] == "https://idp/token" and form["data"]["grant_type"] == "refresh_token"
    assert form["data"]["refresh_token"] == "RT" and form["data"]["client_id"] == "cid"
    # apply a response that omits a new refresh_token -> keep the old one
    out = of.apply_refresh(s, {"access_token": "NEW", "expires_in": 100}, now=500)
    assert out["headers"]["Authorization"] == "Bearer NEW"
    assert out["refresh"]["refresh_token"] == "RT" and out["refresh"]["expires_at"] == 600
