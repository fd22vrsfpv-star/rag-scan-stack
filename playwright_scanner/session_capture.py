"""Pure helpers for capturing/normalizing an authenticated web session into the
replayable shape the Auth Profile stores and ZAP/Burp injection consumes:

    {"cookies": [{"name","value","domain"?}], "headers": {Cookie|Authorization|
     X-API-Key}, "storage": {origin: {localStorage:{...}}}, "captured_from": ...}

Interactive/SSO/OAuth/SAML/MFA logins can't be scripted universally, so the
platform captures the RESULT of a real (possibly human-completed) login and
replays it. These functions build that session from the artifacts a browser or
an operator can provide (cookies, Playwright storage_state, a HAR, raw headers),
independent of Playwright so they are unit-testable.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import time
from typing import Any, Dict, List, Optional

# localStorage/sessionStorage keys that commonly hold a bearer token.
_TOKEN_KEY_HINTS = ("token", "jwt", "access_token", "id_token", "auth", "bearer")


def _cookie_header(cookies: List[Dict[str, Any]]) -> str:
    return "; ".join(f"{c.get('name')}={c.get('value')}"
                     for c in cookies if isinstance(c, dict) and c.get("name"))


def build_session(*, cookies: Optional[List[Dict[str, Any]]] = None,
                  headers: Optional[Dict[str, str]] = None,
                  storage: Optional[Dict[str, Any]] = None,
                  captured_from: str = "manual") -> Dict[str, Any]:
    """Assemble a session dict; derive a `Cookie` header from cookies if one is
    not already present so ZAP/Burp injection works from cookies alone."""
    cookies = [c for c in (cookies or []) if isinstance(c, dict) and c.get("name")]
    headers = {k: v for k, v in (headers or {}).items() if v}
    if cookies and not any(k.lower() == "cookie" for k in headers):
        ch = _cookie_header(cookies)
        if ch:
            headers["Cookie"] = ch
    sess: Dict[str, Any] = {"cookies": cookies, "headers": headers,
                            "captured_from": captured_from}
    if storage:
        sess["storage"] = storage
    return sess


def bearer_from_storage_state(storage_state: Dict[str, Any]) -> Optional[str]:
    """Find a bearer/JWT token in a Playwright storage_state's localStorage
    (SPAs/OIDC keep tokens there, not in cookies). Returns the raw token, or None."""
    for origin in (storage_state or {}).get("origins", []) or []:
        for item in origin.get("localStorage", []) or []:
            name = str(item.get("name", "")).lower()
            val = str(item.get("value", ""))
            if not val:
                continue
            if any(h in name for h in _TOKEN_KEY_HINTS):
                # value may be a bare JWT, or JSON wrapping one
                if val.count(".") == 2 and val[:4] == "eyJ0" or val[:3] == "eyJ":
                    return val
                try:
                    obj = json.loads(val)
                    for k in ("access_token", "id_token", "token", "jwt"):
                        if isinstance(obj, dict) and obj.get(k):
                            return str(obj[k])
                except Exception:  # noqa: BLE001
                    if val[:3] == "eyJ":
                        return val
    return None


def session_from_storage_state(storage_state: Dict[str, Any],
                               captured_from: str = "browser") -> Dict[str, Any]:
    """Build a session from a Playwright `storage_state()` (cookies + origins/
    localStorage). Adds an Authorization: Bearer header when a token is found."""
    cookies = [{"name": c.get("name"), "value": c.get("value"),
                "domain": c.get("domain")} for c in (storage_state or {}).get("cookies", [])
               if isinstance(c, dict) and c.get("name")]
    headers: Dict[str, str] = {}
    tok = bearer_from_storage_state(storage_state)
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    return build_session(cookies=cookies, headers=headers,
                         storage=storage_state, captured_from=captured_from)


def session_from_har(har: Any, captured_from: str = "har") -> Dict[str, Any]:
    """Pull the authenticated session out of a HAR: the last Cookie and the last
    Authorization/X-API-Key request headers seen (a logged-in request carries
    them). Accepts a HAR dict or its JSON string."""
    if isinstance(har, str):
        try:
            har = json.loads(har)
        except Exception:  # noqa: BLE001
            return build_session(captured_from=captured_from)
    headers: Dict[str, str] = {}
    for entry in ((har or {}).get("log", {}) or {}).get("entries", []) or []:
        for h in (entry.get("request", {}) or {}).get("headers", []) or []:
            name = str(h.get("name", "")).lower()
            val = h.get("value")
            if not val:
                continue
            if name == "cookie":
                headers["Cookie"] = val
            elif name == "authorization":
                headers["Authorization"] = val
            elif name in ("x-api-key", "apikey"):
                headers["X-API-Key"] = val
    return build_session(headers=headers, captured_from=captured_from)


def totp_now(secret: str, *, digits: int = 6, period: int = 30,
             at: Optional[int] = None) -> Optional[str]:
    """RFC 6238 TOTP from a base32 secret (stdlib only — no pyotp dependency), so
    the assisted browser login can answer a TOTP MFA prompt when the operator
    supplies the seed. Returns the current code, or None on a bad secret."""
    try:
        key = base64.b32decode(re_pad(secret.strip().replace(" ", "").upper()))
        counter = int((at if at is not None else time.time()) // period)
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
        return str(code).zfill(digits)
    except Exception:  # noqa: BLE001
        return None


def re_pad(b32: str) -> str:
    """Pad a base32 string to a multiple of 8 chars (many TOTP seeds are unpadded)."""
    return b32 + "=" * ((-len(b32)) % 8)
