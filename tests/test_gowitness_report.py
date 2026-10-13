"""One combined GoWitness view, instead of a grid of unlabelled thumbnails.

WHY THIS EXISTS
---------------
The GoWitness data was always complete and always stored. Every `recon_findings`
row from gowitness carries url, final_url, status_code, title, server,
technologies, TLS and the screenshot path — 669 of them for examplecorp alone,
every one with a screenshot. What was missing was a way to LOOK at it: the
Screenshots tab renders thumbnails with no status code and no title, so triaging
a scope meant opening each image to find out whether it was a live app, a 403,
or a parked GoDaddy holder.

`GET /recon/gowitness-report` answers in three shapes from one query:
`fmt=json` for the UI, `csv` and `html` as downloads.

The unit cases run anywhere. The live cases need the stack and SKIP cleanly
without it (CLAUDE.md: a skip says "cannot run here", an error says "broken").

    pytest tests/test_gowitness_report.py
"""
from __future__ import annotations

import ast
import csv
import io
import os
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
MOD = REPO / "app" / "rag-api" / "gowitness_report.py"
API = REPO / "app" / "rag-api" / "api.py"


def _mod():
    if not MOD.exists():
        pytest.skip(f"{MOD} not present")
    sys.path.insert(0, str(MOD.parent))
    import importlib
    import gowitness_report as g  # noqa: E402
    return importlib.reload(g)


@pytest.fixture(scope="module")
def g():
    return _mod()


# Shaped like a real gowitness record — these are the keys _ingest_gowitness_jsonl
# actually writes into recon_findings.data.
REC = ({
    "url": "https://altrucommunity.examplecorp.com:443",
    "final_url": "https://altrucommunity.examplecorp.com/",
    "status_code": 200,
    "title": "ExampleCorp",
    "server": "cloudflare",
    "content_length": 51234,
    "protocol": "h2",
    "technologies": ["HSTS", "Cloudflare", "WordPress"],
    "redirect_to": "https://altrucommunity.examplecorp.com/",
    "tls": {"issuer": "Amazon RSA 2048 M04", "protocol": "TLS 1.3"},
    "screenshot": "passive_b8347924/https---altrucommunity.examplecorp.com-443.png",
}, "altrucommunity.examplecorp.com", None, "2026-08-25 14:59:36+00")


def test_rows_carry_every_field_the_operator_triages_on(g):
    r = g.rows_from_records([REC])[0]
    assert r["status_code"] == 200
    assert r["title"] == "ExampleCorp"
    assert r["technologies"] == "HSTS, Cloudflare, WordPress"
    assert r["tls_issuer"] == "Amazon RSA 2048 M04"
    assert r["screenshot"].endswith(".png")
    assert r["url"].startswith("https://")


def test_unparseable_status_is_kept_not_dropped(g):
    """A screenshot we took and cannot classify is still evidence. Dropping it
    would make this report disagree with the Screenshots tab, and a count that
    disagrees with another view is worse than a blank cell."""
    rec = (dict(REC[0], status_code="weird"), "h", None, "")
    rows = g.rows_from_records([rec])
    assert len(rows) == 1 and rows[0]["status_code"] == ""


def test_status_filter_selects(g):
    recs = [(dict(REC[0], status_code=c), "h", None, "") for c in (200, 403, 404)]
    assert len(g.rows_from_records(recs, statuses={403})) == 1
    assert len(g.rows_from_records(recs, statuses={200, 404})) == 2
    assert len(g.rows_from_records(recs, statuses=None)) == 3


@pytest.mark.parametrize("code,cls", [
    (200, "ok"), (204, "ok"), (301, "redir"), (403, "client"), (404, "client"),
    (500, "server"), (522, "server"), ("", "unk"), (None, "unk"), ("x", "unk"),
])
def test_badge_is_by_class_not_exact_code(g, code, cls):
    assert g.badge(code) == cls


def test_csv_round_trips(g):
    rows = g.rows_from_records([REC])
    out = g.to_csv(rows)
    back = list(csv.DictReader(io.StringIO(out)))
    assert len(back) == 1
    assert back[0]["status_code"] == "200"
    assert back[0]["title"] == "ExampleCorp"
    assert "screenshot" in back[0]


def test_html_is_self_describing_and_escaped(g):
    marker = "<script>XSSMARKER</script>"
    rows = g.rows_from_records([(dict(REC[0], title=marker), "h", None, "")])
    doc = g.to_html(rows, "examplecorp")
    assert doc.startswith("<!doctype html>")
    assert "<title>" in doc
    assert "examplecorp" in doc
    assert marker not in doc, "a hostile page title was not escaped"
    assert "&lt;script&gt;XSSMARKER" in doc
    # the two things the operator asked for: the code and the thumbnail
    assert 'class="badge' in doc, "no status badge"
    assert "<img" in doc, "no thumbnail"


def test_html_links_screenshots_rather_than_embedding(g):
    """The examplecorp set alone is 59 MB of PNG; base64 would make a ~79 MB
    file. The contact sheet references the dashboard proxy instead."""
    doc = g.to_html(g.rows_from_records([REC]), "examplecorp",
                    dashboard="https://dash.example:3002")
    assert "data:image" not in doc
    assert "https://dash.example:3002/api/screenshots/passive_b8347924/" in doc


def test_status_counts_summarise(g):
    recs = [(dict(REC[0], status_code=c), "h", None, "")
            for c in (200, 200, 403)]
    assert g.status_counts(g.rows_from_records(recs)) == {"200": 2, "403": 1}


def test_slug_is_filename_safe(g):
    assert g.slug("black/baud *2026") == "black_baud_2026"
    assert g.slug("") == "report"


# ── the endpoint's contract ────────────────────────────────────────────────

def test_endpoint_is_declared_and_engagement_filtered():
    """Per CLAUDE.md, a listing endpoint returning engagement-attributable data
    must honour X-Engagement-Id and offer an explicit all_engagements override."""
    src = API.read_text(encoding="utf-8")
    fn = None
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "gowitness_report":
            fn = node
    assert fn is not None, "/recon/gowitness-report handler is gone"
    args = [a.arg for a in fn.args.args] + [a.arg for a in fn.args.kwonlyargs]
    assert "engagement_id" in args and "all_engagements" in args
    body = ast.get_source_segment(src, fn) or ""
    assert "_resolve_engagement_id" in body, "the engagement header is never resolved"
    assert "engagement_id IS NULL" in body, (
        "NULL-engagement rows must stay visible — pre-attribution data is "
        "intentionally reachable in every engagement")


def test_endpoint_returns_a_download_for_file_formats():
    src = API.read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "gowitness_report":
            body = ast.get_source_segment(src, node) or ""
    assert "Content-Disposition" in body, (
        "csv/html must download, not render inline")


def test_bff_proxy_preserves_the_download_headers():
    """safe_json would discard Content-Disposition and hand the browser a JSON
    blob instead of a file — the same trap the scope CSV export hit."""
    bff = REPO / "dashboard" / "bff" / "routers" / "findings.py"
    if not bff.exists():
        pytest.skip(f"{bff} not present")
    src = bff.read_text(encoding="utf-8")
    fn = None
    for node in ast.parse(src).body:
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and \
                node.name == "gowitness_report":
            fn = ast.get_source_segment(src, node) or ""
    assert fn, "the BFF proxy is gone"
    assert "Content-Disposition" in fn
    assert "status_code" in fn, "a non-2xx upstream must not read as success"


# ── live ───────────────────────────────────────────────────────────────────

def _live():
    """Resolve the live rag-api base + key, or skip.

    Uses conftest's shared RAG_API rather than a literal: a hardcoded service
    URL drifts from the rest of the suite and is caught by
    test_no_new_hardcoded_service_urls. RAG_API_URL still wins when set, since
    that is the variable the container itself exports.
    """
    import urllib.request
    import ssl
    from conftest import RAG_API
    key = os.environ.get("API_KEY")
    base = os.environ.get("RAG_API_URL") or RAG_API
    if not key:
        pytest.skip("API_KEY not set — run inside rag-api for the live checks")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return base, key, ctx


def test_live_endpoint_executes():
    """ast.parse passing is not verification (CLAUDE.md). Execute it."""
    import json
    import urllib.request
    base, key, ctx = _live()
    req = urllib.request.Request(f"{base}/recon/gowitness-report?limit=5",
                                 headers={"x-api-key": key})
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as r:
            body = json.loads(r.read())
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"stack not reachable: {e}")
    assert body.get("ok") is True
    assert isinstance(body.get("rows"), list)
    assert isinstance(body.get("status_counts"), dict)


# ── SAST listing: attribution must be visible, scope must be filterable ────
# Four leftover test uploads keyed to 172.18.0.11 showed under a examplecorp
# scope on 2026-10-13 and read as a broken filter. The filter was correct —
# NULL-engagement rows are shown in EVERY engagement by design so
# pre-attribution data stays reachable — but nothing said so, and the scope
# selector had no effect on that tab at all.

def _sast_handler_src():
    src = API.read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "list_sast_findings":
            return node, (ast.get_source_segment(src, node) or "")
    pytest.fail("/sast/findings handler is gone")


def test_sast_listing_returns_engagement_id_so_the_ui_can_badge_it():
    """Without engagement_id on the row the UI cannot tell an unattributed
    finding from one that belongs to the selected engagement."""
    _, body = _sast_handler_src()
    select = body[body.find("SELECT id, scan_id"):body.find("FROM sast_findings")]
    assert "engagement_id" in select, (
        "the SELECT omits engagement_id — the unattributed badge has nothing "
        "to key on, which is how the test rows looked like examplecorp findings")


def test_sast_listing_keeps_null_engagement_rows_visible():
    """Deliberate, per the read-path invariant: pre-attribution data stays
    reachable in every engagement. The fix is to LABEL them, not hide them."""
    _, body = _sast_handler_src()
    assert "engagement_id IS NULL" in body


def test_sast_listing_offers_an_opt_in_scope_filter():
    node, body = _sast_handler_src()
    args = [a.arg for a in node.args.args] + [a.arg for a in node.args.kwonlyargs]
    assert "scope_only" in args, "no scope filter — the scope selector does nothing here"
    assert "all_engagements" in args
    assert "scope_targets" in body, "scope_only does not actually join scope_targets"
    # default must be OFF: out-of-scope collected data stays reviewable
    defaults = dict(zip(args[-len(node.args.defaults):], node.args.defaults)) if node.args.defaults else {}
    d = defaults.get("scope_only")
    assert isinstance(d, ast.Constant) and d.value is False, (
        "scope_only must default to False — the default is engagement-only, "
        "and a scope restriction is opt-in")


def test_frontend_sast_panel_badges_and_filters():
    tsx = REPO / "dashboard" / "frontend" / "src" / "pages" / "ExploitManager.tsx"
    if not tsx.exists():
        pytest.skip(f"{tsx} not present")
    src = tsx.read_text(encoding="utf-8")
    start = src.find("function SastFindingsPanel")
    assert start != -1, "SastFindingsPanel is gone"
    panel = src[start:start + 9000]
    assert "unattributed" in panel, "no unattributed badge"
    # the query string uses scope_only; the React state is scopeOnly, so this
    # cannot pass on the state variable alone
    assert "scope_only" in panel, "the panel never requests the scope filter"
    assert "engagement_id" in panel, "the panel never reads engagement_id"
    # the active mode must be stated, not inferred from a checkbox
    assert "in scope" in panel.lower(), "the active scope mode is not labelled"


# ── asset tags: the write path behind keyboard triage ──────────────────────

def _asset_tags_handler():
    src = API.read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "update_asset_tags":
            return node, (ast.get_source_segment(src, node) or "")
    pytest.fail("PATCH /assets/{asset_id}/tags is gone")


def test_asset_tags_uses_the_array_normaliser():
    """`assets.tags` is text[]. A bare string raises `malformed array literal`
    at runtime and nowhere earlier (CLAUDE.md: a column's TYPE matters as much
    as its name)."""
    _, body = _asset_tags_handler()
    assert "as_text_array" in body, "tag values are not normalised for a text[] column"


def test_asset_tags_supports_add_remove_not_only_set():
    """Triage toggles ONE tag. A set-only API would clobber tags written by a
    scan, an import, or an earlier pass."""
    node, body = _asset_tags_handler()
    for field in ("add", "remove", "set"):
        assert field in body, f"no {field} support"


def test_clearing_all_tags_is_distinguishable_from_omitting_the_field():
    """`set: []` means "clear everything". as_text_array returns None for an
    empty list, so truthiness collapses that into "not provided" and the call
    400s — which it did on first write."""
    _, body = _asset_tags_handler()
    assert "body.set is not None" in body, (
        "presence of the field, not truthiness of its value, must decide "
        "whether `set` was given")


def test_asset_tags_is_engagement_checked():
    """Tagging an asset that belongs to a different engagement must be refused,
    not silently applied."""
    _, body = _asset_tags_handler()
    assert "_resolve_engagement_id" in body
    assert "403" in body, "no engagement ownership check"


def test_asset_tags_bff_checks_the_status():
    """httpx does not raise on 4xx/5xx. Returning unconditionally would report
    a refused tag as success and leave the UI showing one the database never
    stored."""
    bff = REPO / "dashboard" / "bff" / "routers" / "agents.py"
    if not bff.exists():
        pytest.skip(f"{bff} not present")
    src = bff.read_text(encoding="utf-8")
    fn = None
    for node in ast.parse(src).body:
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == "update_asset_tags":
            fn = ast.get_source_segment(src, node) or ""
    assert fn, "the BFF proxy is gone"
    assert "status_code" in fn and "HTTPException" in fn


def test_keyboard_triage_is_suppressed_while_typing():
    """A global keydown handler that fires inside an input eats the operator's
    search term — 'interesting' would tag three assets and type nothing."""
    page = REPO / "dashboard" / "frontend" / "src" / "pages" / "AssetBrowser.tsx"
    if not page.exists():
        pytest.skip(f"{page} not present")
    src = page.read_text(encoding="utf-8")
    i = src.find("Keyboard triage")
    assert i != -1, "the keyboard triage handler is gone"
    block = src[i:i + 3000]
    for guard in ("input", "textarea", "isContentEditable"):
        assert guard in block, f"typing in a {guard} is not excluded"
    assert "ctrlKey" in block and "metaKey" in block, (
        "modifier combos are not excluded — the handler would eat real shortcuts")


def test_keyboard_tagging_toggles_rather_than_only_adding():
    """A pass that could only ADD makes the first mis-key permanent."""
    page = REPO / "dashboard" / "frontend" / "src" / "pages" / "AssetBrowser.tsx"
    if not page.exists():
        pytest.skip(f"{page} not present")
    src = page.read_text(encoding="utf-8")
    i = src.find("Keyboard triage")
    block = src[i:i + 3000]
    assert "remove:" in block and "add:" in block, (
        "the shortcut does not toggle — it can only add the tag")
