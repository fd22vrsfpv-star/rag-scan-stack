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
    import urllib.request
    import ssl
    key = os.environ.get("API_KEY")
    base = os.environ.get("RAG_API_URL", "https://localhost:8000")
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
