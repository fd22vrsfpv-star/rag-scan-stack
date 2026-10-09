"""2026-10-09: supplied credentials must become a session using the login form
the run's own recon fingerprinted.

Six CVE-Bench runs (2624, 3234, 32964, 34070, 36858, 4320) resolved the exploit
path and then halted on `auth = "exploit needs authentication; no session
cookie in hand"` — with username/password supplied in the request and the
login form sitting in `recon:basic` (`Form POST /index.php?mainmenu=home
fields=['token','loginfunction','tz','username','password']`). The hard-coded
field-variant list did not match, the attempt was never traced, and a failed
attempt came back as a session_info with an empty cookie_header.

Dynamic for `_login_from_discovered_form` (httpx.MockTransport); structural
for the wiring.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest httpx && PYTHONPATH=. python -m pytest tests/test_build_poc_auth_from_recon.py -v'
"""
from __future__ import annotations

import ast as _ast
import logging
from pathlib import Path

import pytest

httpx = pytest.importorskip("httpx")

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"


def _func_src(name: str, path=API) -> str | None:
    src = path.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


def _load(names) -> dict:
    src = API.read_text()
    tree = _ast.parse(src)
    ns: dict = {"logging": logging}
    for n in names:
        node = next(x for x in _ast.walk(tree) if isinstance(x, _ast.FunctionDef) and x.name == n)
        exec(_ast.get_source_segment(src, node), ns)
    return ns


# A Dolibarr-shaped target: "/" renders the login form with hidden token/tz,
# POST /index.php logs in only when token + username + password are right.
LOGIN_PAGE = """<html><body>
<form id="login" action="/index.php?mainmenu=home" method="post">
<input type="hidden" name="token" value="tok123">
<input type="hidden" name="loginfunction" value="loginfunction">
<input type="hidden" name="tz" value="-4">
<input type="text" name="username"><input type="password" name="password">
</form></body></html>"""

FORM_5314 = {"path": "/index.php", "method": "POST",
             "fields": ["token", "loginfunction", "tz", "username", "password"],
             "raw_action": "/index.php?mainmenu=home"}


def _mock_target(expected_user="admin", expected_pass="s3cret"):
    seen = {"posts": []}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path in ("/", "/index.php"):
            return httpx.Response(200, text=LOGIN_PAGE, headers={"set-cookie": "DOLSESSID_x=pre; Path=/"})
        if request.method == "POST" and request.url.path == "/index.php":
            form = dict(x.split("=", 1) for x in request.content.decode().split("&") if "=" in x)
            seen["posts"].append(form)
            if form.get("token") == "tok123" and form.get("username") == expected_user and form.get("password") == expected_pass:
                return httpx.Response(302, headers={"set-cookie": "DOLSESSID_x=LOGGEDIN; Path=/", "location": "/"})
            return httpx.Response(200, text="bad login")
        return httpx.Response(404)
    return handler, seen


@pytest.fixture()
def login(monkeypatch):
    ns = _load(["_login_from_discovered_form"])
    handler, seen = _mock_target()
    real_client = httpx.Client

    class _PatchedClient(real_client):
        def __init__(self, *a, **kw):
            kw.pop("verify", None)
            super().__init__(*a, transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(httpx, "Client", _PatchedClient)
    return ns["_login_from_discovered_form"], seen


def test_discovered_form_login_submits_hidden_token_and_sets_session(login):
    fn, seen = login
    r = fn("10.0.0.5", 80, "admin", "s3cret", [FORM_5314])
    assert r["ok"] is True, r
    assert "DOLSESSID_x=LOGGEDIN" in r["cookie_header"]
    assert r["u_field"] == "username" and r["p_field"] == "password"
    assert r["login_url"].endswith("/index.php?mainmenu=home")
    posted = seen["posts"][-1]
    # hidden inputs harvested from the page, not invented
    assert posted["token"] == "tok123" and posted["tz"] == "-4" and posted["loginfunction"] == "loginfunction"


def test_wrong_credentials_do_not_claim_a_session(login):
    fn, seen = login
    r = fn("10.0.0.5", 80, "admin", "WRONG", [FORM_5314])
    # the pre-login cookie is NOT a logged-in session; caller validates with
    # _probe_session_valid, but the helper must at least not fabricate LOGGEDIN
    assert "LOGGEDIN" not in r.get("cookie_header", "")


def test_forms_without_a_password_field_are_ignored(login):
    fn, _ = login
    r = fn("10.0.0.5", 80, "admin", "s3cret", [{"path": "/search", "method": "GET", "fields": ["q"], "raw_action": "/search"}])
    assert r["ok"] is False and "no login-shaped form" in r["note"]


def test_no_forms_is_total(login):
    fn, _ = login
    assert fn("10.0.0.5", 80, "admin", "s3cret", [])["ok"] is False
    assert fn("10.0.0.5", 80, "admin", "s3cret", None)["ok"] is False


# ── wiring (structural, sabotage-provable) ──────────────────────────────────

def test_establish_session_falls_back_to_the_discovered_form():
    src = _func_src("_establish_session_for_build")
    assert src and "segments=None" in src.split(":", 1)[0]
    assert "_login_from_discovered_form(" in src and '"supplied_form"' in src
    assert "_parse_recon_segments(" in src


def test_wordpress_field_variant_present():
    src = _func_src("_login_field_variants")
    assert src and '("log", "pwd"' in src and "/wp-login.php" in src


def test_auth_establish_node_traces_and_never_returns_an_empty_session():
    src = _func_src("node_auth_establish", GRAPH)
    assert src and '"recon:auth_establish"' in src
    assert "session_info = None" in src and "segments=state.get(\"segments\")" in src


# ── fix #2: supplied creds are the first auto-login hint (authenticated recon) ──

def test_initial_state_seeds_supplied_creds_as_first_cred_hint():
    src = _func_src("initial_state", GRAPH)
    assert src and "f\"{auth['username']}:{auth['password']}\"" in src
    assert '"cred_hints": _supplied' in src


def test_response_mine_keeps_supplied_hint_ahead_of_mined_ones():
    src = _func_src("node_response_mine", GRAPH)
    assert src and 'list(state.get("cred_hints") or []) + cred_hints' in src


def test_auto_login_paths_and_pairs_cover_dolibarr_wordpress_zabbix():
    src = _func_src("_try_mined_credentials")
    assert src
    for p in ('"/index.php"', '"/wp-login.php"'):
        assert p in src, p
    for pair in ('("log", "pwd")', '("name", "password")', '("j_username", "j_password")'):
        assert pair in src, pair


def test_initial_state_executes_and_orders_hints(tmp_path):
    # exec the real initial_state source: supplied pair first, nothing when absent
    import ast as _a, time as _t
    src = GRAPH.read_text(); tree = _a.parse(src)
    node = next(x for x in _a.walk(tree) if isinstance(x, _a.FunctionDef) and x.name == "initial_state")
    ns: dict = {"time": _t, "Optional": object, "List": list, "BuildPocState": dict}
    exec(_a.get_source_segment(src, node), ns)
    st = ns["initial_state"]("CVE-2024-5314", "10.0.0.5", 9090, auth={"username": "user", "password": "pw"})
    assert st["cred_hints"] == ["user:pw"]
    st2 = ns["initial_state"]("CVE-2024-5314", "10.0.0.5", 9090, auth={"username": "user"})
    assert st2["cred_hints"] == []
    assert ns["initial_state"]("CVE-2024-5314", "10.0.0.5", 9090)["cred_hints"] == []
