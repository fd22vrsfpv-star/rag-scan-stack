"""Auto-populate a web Auth Profile from a discovered credential + a login page.

A discovered HTTP(S) credential in credential_findings has the username/secret and
the engagement, but NOT the app-shaped bits an Auth Profile needs — the login
form's action URL, the field names, and any CSRF token. Those come from the login
PAGE. This module parses a login form deterministically (stdlib html.parser) into
the `login_data` template + csrf field, so a profile can be assembled that
references the credential by id (secret resolved at scan time, never stored here).

Pure and dependency-free so it is unit-testable; the LLM is only a fallback for a
form the deterministic parser cannot read (wired in api.py via the router).
"""
from __future__ import annotations

from html.parser import HTMLParser
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

_USER_HINTS = ("user", "email", "login", "uname", "account", "name")
_CSRF_HINTS = ("csrf", "token", "authenticity", "xsrf", "nonce", "_token")


class _FormParser(HTMLParser):
    """Collects the FIRST <form> that contains a password input."""

    def __init__(self):
        super().__init__()
        self._forms: List[Dict[str, Any]] = []
        self._cur: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method") or "post").lower(),
                         "inputs": []}
        elif tag in ("input", "select", "textarea") and self._cur is not None:
            self._cur["inputs"].append({
                "name": a.get("name", ""), "type": (a.get("type") or "text").lower(),
                "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self._forms.append(self._cur)
            self._cur = None

    def best(self) -> Optional[Dict[str, Any]]:
        # a login form has a password input
        for f in self._forms:
            if any(i["type"] == "password" and i["name"] for i in f["inputs"]):
                return f
        return None


def parse_login_form(html: str) -> Optional[Dict[str, Any]]:
    """Return {action, method, user_field, pass_field, csrf_field, extras:{name:value}}
    for the first form with a password input, or None."""
    if not html:
        return None
    p = _FormParser()
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001
        return None
    form = p.best()
    if not form:
        return None
    user_field = pass_field = csrf_field = None
    extras: Dict[str, str] = {}
    for i in form["inputs"]:
        name, typ = i["name"], i["type"]
        if not name:
            continue
        low = name.lower()
        if typ == "password" and not pass_field:
            pass_field = name
        elif typ in ("text", "email") and not user_field and any(h in low for h in _USER_HINTS):
            user_field = name
        elif typ == "hidden" and any(h in low for h in _CSRF_HINTS) and not csrf_field:
            csrf_field = name
        elif typ == "hidden":
            extras[name] = i["value"]
    # fall back to the first text/email field as the username if none matched a hint
    if not user_field:
        for i in form["inputs"]:
            if i["type"] in ("text", "email") and i["name"]:
                user_field = i["name"]
                break
    if not pass_field:
        return None
    return {"action": form["action"], "method": form["method"],
            "user_field": user_field, "pass_field": pass_field,
            "csrf_field": csrf_field, "extras": extras}


def build_login_data(form: Dict[str, Any]) -> str:
    """`login_data` template with {%username%}/{%password%}/{%csrf%} placeholders
    and any hidden extras carried through literally."""
    parts = []
    if form.get("user_field"):
        parts.append(f"{form['user_field']}={{%username%}}")
    if form.get("pass_field"):
        parts.append(f"{form['pass_field']}={{%password%}}")
    if form.get("csrf_field"):
        parts.append(f"{form['csrf_field']}={{%csrf%}}")
    for k, v in (form.get("extras") or {}).items():
        parts.append(f"{k}={v}")
    return "&".join(parts)


def synthesize_profile(html: str, page_url: str,
                       login_url_hint: str = "") -> Optional[Dict[str, Any]]:
    """Turn a login page into the Auth Profile macro fields, or None if no login
    form is found. `login_url` is the form's action resolved against the page."""
    form = parse_login_form(html)
    if not form:
        return None
    action = form.get("action") or ""
    login_url = urljoin(page_url or login_url_hint or "", action) if action else (page_url or login_url_hint)
    login_data = build_login_data(form)
    if "{%username%}" not in login_data or "{%password%}" not in login_data:
        return None
    return {"login_url": login_url, "login_data": login_data,
            "csrf_field": form.get("csrf_field"),
            "auth_type": "csrf" if form.get("csrf_field") else "form"}
