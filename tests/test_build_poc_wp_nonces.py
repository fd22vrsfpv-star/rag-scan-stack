"""2026-10-09: WordPress nonces are harvested WITH the session and mapped to the
`wp_localize_script` object that owns them.

Five CVE-Bench WordPress runs resolved `/wp-admin/admin-ajax.php` correctly and
then fought the nonce for up to 15 refine iterations. `_fetch_preconditions`
scraped anonymously (WP nonces are per-user) and dropped the object name that
says which `action=` a nonce belongs to.

Dynamic (httpx monkeypatched) on a real captured WordPress page plus a
synthetic localize block; structural for the gather wiring.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest httpx && PYTHONPATH=. python -m pytest tests/test_build_poc_wp_nonces.py -v'
"""
from __future__ import annotations

import ast as _ast
from pathlib import Path

import pytest

httpx = pytest.importorskip("httpx")

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
FIXTURE = REPO / "tests" / "fixtures" / "wp_admin_page.html"


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
    ns: dict = {}
    for n in names:
        node = next(x for x in _ast.walk(tree) if isinstance(x, _ast.FunctionDef) and x.name == n)
        exec(_ast.get_source_segment(src, node), ns)
    return ns


# Real page captured from a CVE-Bench WordPress target (web_findings.response_data,
# 2026-09-27); carries `name="_wpnonce" value="240c8d3aa3"`.
REAL_WP_PAGE = FIXTURE.read_text(errors="replace") if FIXTURE.exists() else ""

# The shape wp_localize_script emits for a plugin's admin-ajax nonce.
LOCALIZED_ADMIN = """<html><head><script>
var htmega_ajax = {"ajax_url":"http://target:9090/wp-admin/admin-ajax.php","nonce":"a1b2c3d4e5","i18n":{"x":"y"}};
var wholesalex = {"ajaxUrl":"\\/wp-admin\\/admin-ajax.php","security":"ffeeddccbb"};
</script></head><body><a href="/wp-admin/users.php?action=remove&_wpnonce=0123456789">x</a></body></html>"""


@pytest.fixture()
def fetch(monkeypatch):
    ns = _load(["_fetch_preconditions"])
    calls = []

    def fake_get(url, timeout=8, verify=False, follow_redirects=True, headers=None):
        calls.append((url, dict(headers or {})))
        path = url.split("//", 1)[1].split("/", 1)[1] if "/" in url.split("//", 1)[1] else ""
        path = "/" + path
        if path.startswith("/wp-admin/") and (headers or {}).get("Cookie"):
            return httpx.Response(200, text=LOCALIZED_ADMIN, request=httpx.Request("GET", url))
        if path.startswith("/wp-admin/"):
            return httpx.Response(302, headers={"location": "/wp-login.php"}, request=httpx.Request("GET", url))
        return httpx.Response(200, text=REAL_WP_PAGE or "<html></html>", request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", fake_get)
    return ns["_fetch_preconditions"], calls


@pytest.mark.skipif(not REAL_WP_PAGE, reason="fixture tests/fixtures/wp_admin_page.html missing")
def test_anonymous_scan_still_finds_the_form_nonce_and_short_circuits(fetch):
    fn, calls = fetch
    r = fn("10.0.0.9", 9090)
    assert "_wpnonce=240c8d3aa3" in r["tokens"], r
    assert r["by_object"] == {}
    # first page hit → stop (unchanged behaviour); no Cookie header sent
    assert len(calls) == 1 and "Cookie" not in calls[0][1]


def test_with_session_reads_admin_pages_and_maps_localized_objects(fetch):
    fn, calls = fetch
    r = fn("10.0.0.9", 9090, cookie_header="wordpress_logged_in_x=abc")
    assert all(h.get("Cookie") == "wordpress_logged_in_x=abc" for _, h in calls)
    # admin pages were included and read as the user
    assert any(u.endswith("/wp-admin/profile.php") for u, _ in calls)
    assert r["by_object"]["htmega_ajax"] == "a1b2c3d4e5"
    assert r["by_object"]["wholesalex"] == "ffeeddccbb"
    assert "htmega_ajax.nonce=a1b2c3d4e5" in r["tokens"]
    assert "_wpnonce=0123456789" in r["tokens"]          # from a _wpnonce= link
    # does not short-circuit when a cookie is given
    assert len(calls) > 1


def test_explicit_paths_only(fetch):
    fn, calls = fetch
    r = fn("10.0.0.9", 9090, cookie_header="c=1", paths=["/wp-admin/admin.php"])
    assert [u.rsplit("/", 1)[1] for u, _ in calls] == ["admin.php"]
    assert "htmega_ajax" in r["by_object"]


# ── wiring (structural, sabotage-provable) ──────────────────────────────────

def test_gather_harvests_wp_nonces_with_the_session_only():
    src = _func_src("_gather_manifest")
    assert src and "_fetch_preconditions(ip, port, timeout=timeout, cookie_header=cookie)" in src
    assert 'facts["wp_nonces"]' in src and "if _is_wp and cookie:" in src


def test_manifest_text_renders_known_wp_nonces():
    src = _func_src("_gather_manifest_text")
    assert src and "KNOWN WP NONCES" in src
