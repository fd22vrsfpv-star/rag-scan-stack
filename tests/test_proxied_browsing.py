"""Browsing a discovered host through an exit node, not from the operator's IP.

Run on demand:

    pytest tests/test_proxied_browsing.py -v

WHY THIS EXISTS
---------------
Recon Intel lists HTTP services but gave no way to look at one. The obvious fix —
an `<a href>` — is the wrong one: the operator's own browser would fetch it from
the operator's own address, which is exactly what the exit nodes exist to
prevent, and in the UI it would look identical to a proxied fetch.

So there is no plain link. Instead:
  * `POST /api/recon/preview` renders the page headless AT THE NODE and returns
    a screenshot, status, title and headers.
  * Copy URL / Copy curl give the Burp path.
  * `GET /api/recon/proxy-endpoints` returns BOTH forms of each proxy, because
    they are not interchangeable and look equally plausible:
      internal  socks5://node-manager:PORT   what this stack's containers dial
      operator  socks5://127.0.0.1:PORT      what Burp or a browser on the HOST dials

    Only the second works from Burp, and only because docker-compose now
    publishes the SSH proxy range on localhost.

MEASURED, NOT ASSUMED
---------------------
    host, direct                        -> 199.168.198.186
    via socks5://127.0.0.1:10120        -> 3.15.200.93
    via socks5://127.0.0.1:10121        -> 54.165.76.119

And the negative control, which is the one that matters — a DEAD proxy must fail
rather than quietly going direct:

    proxy socks5://127.0.0.1:9          -> net::ERR_PROXY_CONNECTION_FAILED

That is the failure `tests/test_scan_proxy_forwarding.py` exists for: a proxy
parameter that is accepted, ignored, and reported as used.

THE BIND ADDRESS IS SECURITY, NOT PREFERENCE
--------------------------------------------
The published range is `127.0.0.1:10120-10149`. A `0.0.0.0` bind would expose an
open SOCKS relay into the engagement's tunnels to anything that can reach this
host. `test_socks_ports_are_localhost_only` fails if that bind ever widens.

SABOTAGE PROOF
--------------
Change the compose bind to `10120-10149:10120-10149` and
`test_socks_ports_are_localhost_only` fails. Delete the `_scope_refusal_for_url`
call from `preview_page` and `test_preview_is_scope_gated` fails.
"""
import ast
import os
import re

import pytest

from _container import container_exec

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
COMPOSE = os.path.join(REPO, "docker-compose.yml")
PW = os.path.join(REPO, "playwright_scanner", "playwright_scanner.py")
BFF = os.path.join(REPO, "dashboard", "bff", "routers", "findings.py")
UI_AB = os.path.join(REPO, "dashboard", "frontend", "src", "pages", "AssetBrowser.tsx")
UI_NODES = os.path.join(REPO, "dashboard", "frontend", "src", "pages", "Nodes.tsx")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _func_source(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


# ── The bind address ───────────────────────────────────────────────────────

def test_socks_ports_are_localhost_only():
    """A 0.0.0.0 bind publishes an open SOCKS relay into the engagement."""
    src = _read(COMPOSE)
    # Match PORT MAPPINGS only. A looser regex also caught the example
    # `--proxy-server="socks5://127.0.0.1:10120"` inside the explanatory
    # comment, which is a string in a comment and not a bind at all.
    binds = [m.group(1) for m in re.finditer(
        r'^\s*-\s*"((?:[\d.]+:)?\d{4,5}(?:-\d{4,5})?:\d{4,5}(?:-\d{4,5})?)"\s*$',
        src, re.M) if "1012" in m.group(1)]
    assert binds, "the SOCKS proxy range is no longer published at all"
    for b in binds:
        assert b.startswith("127.0.0.1:"), (
            f"SOCKS range published as {b!r} — it MUST bind 127.0.0.1 only, or "
            "anything that can reach this host gets an open relay into the "
            "engagement's tunnels")


# ── The gate ───────────────────────────────────────────────────────────────

def test_preview_is_scope_gated():
    """A preview is traffic to a host, so it is gated like a scan."""
    fn = _func_source(_read(PW), "preview_page")
    assert fn, "playwright /preview is gone"
    assert "_scope_refusal_for_url" in fn, (
        "the preview no longer passes the scope gate — it would fetch any host "
        "the operator can name")
    gate = fn.index("_scope_refusal_for_url")
    launch = fn.index("chromium.launch")
    assert gate < launch, "the gate must run BEFORE the browser opens a socket"


def test_bff_preview_fails_closed():
    fn = _func_source(_read(BFF), "proxied_preview")
    assert fn, "the BFF preview route is gone"
    assert "503" in fn and "refusing to browse" in fn, (
        "an unavailable scope gate must refuse, not fall through to browsing")
    assert "403" in fn, "an out-of-scope host must be refused with a reason"


def test_proxy_is_set_at_launch_not_on_the_context():
    """Chromium ignores a context-level socks5 proxy. Setting it there would
    send the request from this container while the UI claimed it was proxied —
    silent, and indistinguishable from success."""
    fn = _func_source(_read(PW), "preview_page")
    assert 'launch_kwargs["proxy"]' in fn, (
        "the proxy is no longer applied at launch; a context-level socks proxy "
        "is silently ignored by Chromium")


# ── Both proxy forms are offered ───────────────────────────────────────────

def test_endpoint_returns_both_proxy_forms():
    fn = _func_source(_read(BFF), "proxy_endpoints")
    assert fn, "the proxy-endpoints route is gone"
    assert '"internal"' in fn and '"operator"' in fn, (
        "both forms must be returned: node-manager:PORT is unreachable from "
        "Burp, 127.0.0.1:PORT is unreachable from the containers, and they look "
        "equally plausible")
    assert "127.0.0.1" in fn and "node-manager" in fn


def test_only_online_nodes_are_offered():
    fn = _func_source(_read(BFF), "proxy_endpoints")
    assert 'status") != "online"' in fn, (
        "offline nodes are offered as proxies; their tunnel is down, so every "
        "preview through one would just time out")


# ── The UI ─────────────────────────────────────────────────────────────────

def test_recon_intel_has_no_plain_link():
    """An <a href> to a target is the bug this feature exists to avoid."""
    src = _read(UI_AB)
    comp = src[src.index("function UrlProxyActions("):]
    comp = comp[:comp.index("\nfunction ")]
    assert "<a " not in comp and "window.open" not in comp, (
        "the preview grew a direct link — it would be fetched by the operator's "
        "browser from the operator's address")
    for control in ("Open via proxy", "Copy URL", "Copy curl"):
        assert control in comp, f"the {control!r} control is gone"


def test_recon_intel_names_the_exit_node():
    src = _read(UI_AB)
    assert "browsing via" in src, (
        "the UI no longer says which node it browses through; 'Open via proxy' "
        "with no named exit is indistinguishable from going direct")
    assert "no online exit node" in src, (
        "the UI must say when there is NO node, rather than quietly previewing "
        "from the scanner container")


def test_nodes_page_offers_burp_host_and_port_separately():
    """Burp's SOCKS settings are two fields, not a URI."""
    src = _read(UI_NODES)
    assert "function BurpProxyBlock(" in src, "the Burp proxy block is gone"
    comp = src[src.index("function BurpProxyBlock("):]
    comp = comp[:comp.index("\nfunction ")]
    assert 'label="host"' in comp and 'label="port"' in comp, (
        "Burp takes host and port in separate fields; offering only a URI makes "
        "the operator split it by hand")
    assert "127.0.0.1" in comp, "the Burp host must be 127.0.0.1, not node-manager"
    assert "DNS lookups over SOCKS" in comp, (
        "the DNS-over-SOCKS hint is gone — without it Burp resolves the target "
        "from the operator's own resolver, leaking the lookup")


# ── Live ───────────────────────────────────────────────────────────────────

_LIVE = r"""
import json, os, urllib3, requests
urllib3.disable_warnings()
H = {"x-api-key": os.environ.get("API_KEY", "changeme")}
B = "https://localhost:8000"
out = {}
# An out-of-scope host must be refused BEFORE any socket opens.
r = requests.post("https://playwright-scanner:8014/preview",
                  json={"url": "https://example.com/", "timeout": 10},
                  headers=H, verify=False, timeout=60)
out["oos_status"] = r.status_code
out["oos_detail"] = (r.json() or {}).get("detail", "")[:120] if r.status_code >= 400 else None
print(json.dumps(out))
"""


@pytest.fixture(scope="module")
def live():
    out = container_exec(_LIVE, timeout=180)
    if out is None:
        pytest.skip("rag-api container unreachable")
    if out.startswith("__ERR__"):
        pytest.fail(f"preview round-trip failed: {out}")
    import json
    return json.loads(out.strip().splitlines()[-1])


def test_out_of_scope_preview_is_refused(live):
    assert live["oos_status"] == 403, (
        f"an out-of-scope preview returned {live['oos_status']}, not 403 — the "
        "gate is not holding")
    assert "scope" in (live["oos_detail"] or "").lower(), (
        f"the refusal does not explain itself: {live['oos_detail']!r}")
