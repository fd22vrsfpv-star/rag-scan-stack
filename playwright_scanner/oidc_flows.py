"""Fully-headless OIDC/OAuth2 token flows and helpers.

Pure (no network / no Playwright) parts of headless SSO so they are unit-testable:
building the discovery URL, turning a token-endpoint response into a replayable
Auth Profile session, computing token expiry, and deciding when a refresh is due.
The endpoints in playwright_scanner.py do the I/O and call these.

Session shape produced here (stored in web_auth_configs.session, replayed by the
ZAP Replacer / Burp bundle):

    {"headers": {"Authorization": "Bearer <access_token>"},
     "refresh": {"refresh_token", "token_url", "client_id", "client_secret"?,
                 "scope"?, "expires_at": <epoch>},
     "captured_from": "ropc|device_code|authorization_code|refresh"}
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

WELL_KNOWN = "/.well-known/openid-configuration"


def discovery_url(issuer: str) -> str:
    """OIDC discovery document URL for an issuer (idempotent if already given)."""
    issuer = (issuer or "").strip()
    if issuer.endswith(WELL_KNOWN):
        return issuer
    return issuer.rstrip("/") + WELL_KNOWN


def session_from_token_response(body: Dict[str, Any], *, token_url: Optional[str] = None,
                                client_id: Optional[str] = None,
                                client_secret: Optional[str] = None,
                                scope: Optional[str] = None,
                                captured_from: str = "oidc",
                                now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """Map a token-endpoint response to a session. Returns None if there is no
    access_token. Carries a `refresh` block (refresh_token + how to redeem it +
    expiry) so a long scan can auto-refresh."""
    if not isinstance(body, dict):
        return None
    token = body.get("access_token")
    if not token:
        return None
    ttype = body.get("token_type") or "Bearer"
    sess: Dict[str, Any] = {
        "headers": {"Authorization": f"{ttype} {token}"},
        "captured_from": captured_from,
    }
    now = time.time() if now is None else now
    expires_in = body.get("expires_in")
    refresh_token = body.get("refresh_token")
    if refresh_token or expires_in:
        ref: Dict[str, Any] = {}
        if refresh_token:
            ref["refresh_token"] = refresh_token
        if token_url:
            ref["token_url"] = token_url
        if client_id:
            ref["client_id"] = client_id
        if client_secret:
            ref["client_secret"] = client_secret
        if scope:
            ref["scope"] = scope
        if expires_in:
            try:
                ref["expires_at"] = now + int(expires_in)
            except (TypeError, ValueError):
                pass
        sess["refresh"] = ref
    return sess


def needs_refresh(session: Dict[str, Any], *, skew: int = 60,
                  now: Optional[float] = None) -> bool:
    """True when the session has a refresh_token+token_url and the access token
    is expired or within `skew` seconds of expiring. No expiry recorded => assume
    not due (a token with unknown lifetime is refreshed only on a 401 elsewhere)."""
    ref = (session or {}).get("refresh") or {}
    if not (ref.get("refresh_token") and ref.get("token_url")):
        return False
    exp = ref.get("expires_at")
    if not exp:
        return False
    now = time.time() if now is None else now
    return now >= (float(exp) - skew)


def refresh_form(session: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The (url, form-data) to POST for a refresh_token grant, or None if the
    session cannot be refreshed."""
    ref = (session or {}).get("refresh") or {}
    if not (ref.get("refresh_token") and ref.get("token_url")):
        return None
    data = {"grant_type": "refresh_token", "refresh_token": ref["refresh_token"]}
    if ref.get("client_id"):
        data["client_id"] = ref["client_id"]
    if ref.get("client_secret"):
        data["client_secret"] = ref["client_secret"]
    if ref.get("scope"):
        data["scope"] = ref["scope"]
    return {"url": ref["token_url"], "data": data}


def apply_refresh(session: Dict[str, Any], body: Dict[str, Any],
                  now: Optional[float] = None) -> Dict[str, Any]:
    """Merge a refresh_token grant response back into the session: new
    Authorization header + expiry, keeping the refresh block (some IdPs rotate
    the refresh_token, so take the new one when present)."""
    ref = dict((session or {}).get("refresh") or {})
    fresh = session_from_token_response(
        body, token_url=ref.get("token_url"), client_id=ref.get("client_id"),
        client_secret=ref.get("client_secret"), scope=ref.get("scope"),
        captured_from="refresh", now=now)
    if not fresh:
        return session
    # preserve the old refresh_token if the response omitted a new one
    new_ref = fresh.get("refresh", {})
    if not new_ref.get("refresh_token") and ref.get("refresh_token"):
        new_ref["refresh_token"] = ref["refresh_token"]
        fresh["refresh"] = new_ref
    out = dict(session or {})
    out["headers"] = {**(out.get("headers") or {}), **fresh["headers"]}
    out["refresh"] = fresh.get("refresh", ref)
    return out
