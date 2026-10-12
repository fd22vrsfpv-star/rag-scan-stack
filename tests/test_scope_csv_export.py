"""Scope targets export to CSV, with every field.

Operator ask 2026-10-12: "in the engagements and scope have an export for the
targets to a csv list with all the fields".

Two things this guards beyond "the endpoint exists":

  * It is a LISTING endpoint, so CLAUDE.md's read-path rule applies — it must
    honour the active X-Engagement-Id and offer the explicit
    `all_engagements` override, or an operator exports another engagement's
    targets under this engagement's header.
  * Exports must be DETERMINISTIC and documented. Ordering by `added_at` would
    make two exports of unchanged data differ whenever a row was re-touched,
    so the ORDER BY is on (name, target).

Run standalone:
  docker run --rm -v /opt/rag-scan-stack:/w -w /w python:3.12-slim \\
    sh -c "pip -q install pytest; python -m pytest tests/test_scope_csv_export.py -q"

The live leg additionally needs the stack:
  docker run --rm -v /opt/rag-scan-stack:/w -v /var/run/docker.sock:/var/run/docker.sock ...
"""
import ast
import csv
import io
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
BFF = REPO / "dashboard" / "bff" / "routers" / "scope.py"
APIFE = REPO / "dashboard" / "frontend" / "src" / "api" / "engagements.ts"
ENG = REPO / "dashboard" / "frontend" / "src" / "pages" / "Engagements.tsx"
SCOPE_PAGE = REPO / "dashboard" / "frontend" / "src" / "pages" / "ScopeIntelligence.tsx"


def _read(p):
    if not p.exists():
        pytest.skip(f"{p} not present")
    return p.read_text(encoding="utf-8", errors="replace")


def _func(src, name):
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        pytest.fail(f"does not parse: {e}")
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return ast.get_source_segment(src, n) or ""
    pytest.skip(f"{name} not found (renamed?)")


# ------------------------------------------------------------------ rag-api


def test_endpoint_is_declared():
    src = _read(API)
    assert '@app.get("/scope/export.csv"' in src, "the export route is gone"


def test_every_scope_column_is_exported():
    """'all the fields' — a CSV missing a column is the bug this prevents."""
    src = _read(API)
    m = re.search(r"SCOPE_EXPORT_COLUMNS = \[(.*?)\]", src, re.S)
    assert m, "SCOPE_EXPORT_COLUMNS not found"
    cols = set(re.findall(r'"([a-z_]+)"', m.group(1)))
    # Every column scope_targets actually has.
    for c in ("id", "name", "target", "target_type", "source", "added_at",
              "engagement_id"):
        assert c in cols, f"scope_targets.{c} is missing from the export"
    assert "engagement_name" in cols, (
        "the joined engagement name must be exported — a CSV keyed only by a "
        "uuid is not usable in a spreadsheet, which is the point of the format"
    )


def test_export_is_engagement_filtered():
    """CLAUDE.md: engagement + scope filters apply on READS, not just writes."""
    fn = _func(_read(API), "export_scope_csv")
    assert "_resolve_engagement_id" in fn, (
        "the export must read the active X-Engagement-Id like every other "
        "listing endpoint"
    )
    assert "engagement_id IS NULL" in fn, (
        "NULL-engagement rows are legacy/global and intentionally visible in "
        "every engagement"
    )
    assert "all_engagements" in fn, (
        "the cross-engagement audit override must exist and be explicit"
    )


def test_export_is_deterministic():
    fn = _func(_read(API), "export_scope_csv")
    assert "ORDER BY st.name, st.target" in fn, (
        "exports must be deterministic (CLAUDE.md). Ordering by added_at makes "
        "two exports of unchanged data differ."
    )


def test_placeholder_rows_are_excluded_by_default():
    """list_scope_names hides these; an export that includes them silently
    reports targets that match nothing."""
    fn = _func(_read(API), "export_scope_csv")
    assert "_SCOPE_PLACEHOLDER_SOURCE" in fn
    assert "include_placeholders" in fn, "there must be a way to see them deliberately"


def test_timestamps_are_iso_8601():
    fn = _func(_read(API), "export_scope_csv")
    assert "isoformat()" in fn, (
        "a spreadsheet and a diff must read the timestamp the same way"
    )


# ---------------------------------------------------------------------- BFF


def _code_only(src: str) -> str:
    """Strip the docstring and comments.

    A guard must assert on CODE. Three of these tests first passed/failed
    wrongly because the explanatory text names the very symbol being searched
    for ("NOT safe_json: the body is text/csv").
    """
    src = re.sub(r'"""(?:.|\n)*?"""', "", src, count=1)
    return "\n".join(line.split("#", 1)[0] for line in src.splitlines())


def test_bff_proxies_the_csv_without_json_parsing():
    fn = _func(_read(BFF), "export_scope_csv")
    assert "safe_json" not in _code_only(fn), (
        "the upstream body is text/csv; parsing it as JSON would corrupt it"
    )
    assert "text/csv" in fn
    assert "content-disposition" in fn.lower(), (
        "the filename must survive the proxy or the browser invents one"
    )


def test_bff_checks_the_upstream_status():
    """CLAUDE.md: an HTTP status is not an exception. httpx does not raise on
    4xx/5xx, so without this the operator downloads a file containing the error
    body and reads it as an empty scope."""
    fn = _func(_read(BFF), "export_scope_csv")
    assert "status_code" in fn and "HTTPException" in fn


# ----------------------------------------------------------------- frontend


def test_frontend_helper_does_not_use_apifetch():
    """apiFetch always calls resp.json(); this body is CSV."""
    fn = _read(APIFE)
    i = fn.find("export async function downloadScopeTargetsCsv")
    assert i != -1, "the download helper is gone"
    # Bound to THIS function: a fixed-size window overran into the next
    # export, which legitimately uses apiFetch.
    nxt = fn.find("\nexport ", i + 1)
    window = _code_only(fn[i:nxt if nxt != -1 else len(fn)])
    assert "apiFetch" not in window, "apiFetch would try to JSON-parse the CSV"
    assert "X-Engagement-Id" in window, (
        "the export must carry the active engagement, like every other read"
    )
    assert "content-disposition" in window.lower(), "use the server's filename"


def test_frontend_path_has_no_doubled_api_prefix():
    """apiUrl/apiFetch prepend /api — see tests/test_frontend_route_contracts."""
    src = _read(APIFE)
    assert "'/api/scope/export.csv'" not in src and '"/api/scope/export.csv"' not in src


@pytest.mark.parametrize("page,label", [(ENG, "Engagements"), (SCOPE_PAGE, "Scope Intel")])
def test_both_surfaces_offer_the_export(page, label):
    """The operator asked for it in BOTH places."""
    src = _read(page)
    assert "downloadScopeTargetsCsv" in src, f"{label} has no export control"
    assert "Export CSV" in src, f"{label}'s button has no visible label"
    assert "exportErr" in src, (
        f"{label} must surface a failed export — a silent failure looks "
        "identical to an empty scope"
    )


# --------------------------------------------------------------- round-trip


def test_writer_shape_round_trips():
    """The DictWriter contract: header order is the declared column order, and
    a row with every field survives a parse."""
    src = _read(API)
    m = re.search(r"SCOPE_EXPORT_COLUMNS = \[(.*?)\]", src, re.S)
    cols = re.findall(r'"([a-z_]+)"', m.group(1))
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    w.writerow({c: f"v_{c}" for c in cols})
    back = list(csv.DictReader(io.StringIO(buf.getvalue())))
    assert list(back[0].keys()) == cols, "header order must match the declared columns"
    assert back[0]["engagement_name"] == "v_engagement_name"
    # A target containing a comma must not split into two columns.
    buf2 = io.StringIO()
    w2 = csv.DictWriter(buf2, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
    w2.writeheader()
    w2.writerow({**{c: "" for c in cols}, "target": "10.0.0.1,10.0.0.2"})
    back2 = list(csv.DictReader(io.StringIO(buf2.getvalue())))
    assert back2[0]["target"] == "10.0.0.1,10.0.0.2", "csv quoting is doing its job"
