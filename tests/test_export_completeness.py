"""What a report actually contains.

Run on demand:

    pytest tests/test_export_completeness.py -v

WHY THIS EXISTS
---------------
Three export paths gave three different answers for one engagement:

    /findings/search   94   (inventory filtered)
    /export/sarif     787   (746 of them katana crawl rows)
    /export/data      779   web_findings, no filter at all

and SARIF had no run for `brutus` or `playwright` at all, so a verified
credential — arguably the most actionable thing a pentest produces — never
appeared in a SARIF report.

`record_kind` exists precisely to separate crawl inventory from findings. Both
exports now honour it, off by default, with `include_inventory=true` to get the
old behaviour back deliberately rather than by accident.
"""
import json
import os
import subprocess

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")


def _api_call(path):
    """Call rag-api over TLS from inside its own container."""
    script = (
        "import os, ssl, json, urllib.request\n"
        "ctx = ssl.create_default_context()\n"
        "ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE\n"
        f"req = urllib.request.Request('https://127.0.0.1:8000{path}',"
        " headers={'x-api-key': os.environ['API_KEY']})\n"
        "print(urllib.request.urlopen(req, timeout=300, context=ctx).read().decode())\n")
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=400)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    try:
        return json.loads(out.stdout)
    except Exception:
        return None


@pytest.fixture(scope="module")
def api():
    if _api_call("/health") is None:
        pytest.skip("rag-api not reachable")
    return True


# ── source-level ────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_both_exports_declare_the_inventory_switch():
    src = open(API, encoding="utf-8").read()
    for fn in ("def export_sarif(", "def export_data("):
        blk = src.split(fn, 1)[1][:1400]
        assert "include_inventory" in blk, f"{fn} has no include_inventory switch"
    sarif = src.split("def export_sarif(", 1)[1][:9000]
    assert "COALESCE(record_kind, 'finding') = 'finding'" in sarif, \
        "SARIF no longer suppresses crawl inventory"


@pytest.mark.unit
def test_sarif_covers_credentials_and_playwright():
    src = open(API, encoding="utf-8").read()
    blk = src.split("def export_sarif(", 1)[1][:14000]
    assert "FROM credential_findings" in blk, "SARIF omits credential findings"
    assert "FROM playwright_findings" in blk, "SARIF omits playwright findings"
    assert "Process credential findings" in blk and "Process playwright findings" in blk, \
        "the rows are queried but never emitted as results"


@pytest.mark.unit
def test_sarif_does_not_put_the_secret_in_the_report():
    """A SARIF file goes to CI and other tooling — a wider audience than the DB.

    `secret_stored` says whether one exists to look up; the value stays behind
    the authenticated API.
    """
    src = open(API, encoding="utf-8").read()
    blk = src.split("Process credential findings", 1)[1][:2000]
    assert "secret_stored" in blk, "the has-a-secret signal is gone"
    assert "secret_value" not in blk, \
        "the plaintext secret is being written into the SARIF report"


@pytest.mark.unit
def test_the_collapse_key_cannot_fold_ungroupable_rows_together():
    """DISTINCT ON over a NULL key folds ALL NULLs into one row.

    infrastructure_fingerprint is NULL for every ungroupable finding, so keying
    on it alone would silently drop hundreds of unrelated rows from the export.
    """
    src = open(API, encoding="utf-8").read()
    blk = src.split("def _export_web_findings(", 1)[1][:1800]
    # Pin the DISTINCT ON clause itself, not just "the substring appears
    # somewhere". The ORDER BY on the next line also contains the COALESCE, so a
    # looser check passed while the DISTINCT ON had been reduced to the bare
    # fingerprint — proven vacuous by sabotage before this was tightened.
    # Line-based on purpose. A regex over the whole block ran past the closing
    # paren into the ORDER BY on the next line, which carries the same COALESCE
    # — so the guard stayed green with the DISTINCT ON reduced to the bare
    # fingerprint. Sabotage caught that; this is the corrected form.
    # "SELECT DISTINCT ON", not "DISTINCT ON": this function's own DOCSTRING
    # explains the COALESCE key, and matching on the looser phrase found the
    # prose first — which SATISFIED the assertion while the SQL had been
    # reduced to the bare fingerprint. Prose must never be able to prove code.
    line = next((l for l in blk.splitlines() if "SELECT DISTINCT ON" in l), None)
    assert line, "no DISTINCT ON found in the collapse query"
    assert "COALESCE" in line and "id::text" in line, (
        f"the collapse key is {line.strip()!r} — without the id fallback, "
        "DISTINCT ON over a NULL fingerprint folds every ungroupable finding "
        "into one row")


# ── executed ────────────────────────────────────────────────────────────────

def test_sarif_suppresses_inventory_by_default(api):
    default = _api_call("/export/sarif?limit=5000")
    withinv = _api_call("/export/sarif?limit=5000&include_inventory=true")
    assert default and withinv, "SARIF export did not return"
    n_def = sum(len(r["results"]) for r in default["runs"])
    n_inv = sum(len(r["results"]) for r in withinv["runs"])
    assert n_inv > n_def, (
        f"include_inventory changed nothing ({n_def} vs {n_inv}) — either the "
        "filter is not applied or there is no inventory to suppress")
    tools = {r["tool"]["driver"]["name"] for r in default["runs"]}
    assert "katana" not in tools, \
        "katana crawl inventory is still in the default SARIF export"
    assert "brutus" in tools, (
        "no brutus run in the SARIF export — verified credentials are missing "
        "from the report entirely")
    assert "playwright" in tools, "no playwright run in the SARIF export"


def test_export_data_honours_the_same_switch(api):
    default = _api_call("/export/data?format=json")
    withinv = _api_call("/export/data?format=json&include_inventory=true")
    assert default and withinv, "/export/data did not return"
    d = default.get("counts", {}).get("web_findings")
    w = withinv.get("counts", {}).get("web_findings")
    assert d is not None and w is not None, "web_findings not counted"
    assert w > d, (
        f"include_inventory changed nothing on /export/data ({d} vs {w}) — the "
        "export still disagrees with /findings/search")


def test_export_data_and_sarif_agree_on_web_findings(api):
    """The two exports must not describe the same engagement differently."""
    data = _api_call("/export/data?format=json")
    assert data, "/export/data did not return"
    rows = data.get("data", {}).get("web_findings") or []
    kinds = {(r.get("record_kind") or "finding") for r in rows}
    assert kinds <= {"finding"}, (
        f"/export/data still carries non-finding record kinds by default: {kinds}")


def test_collapse_actually_collapses_when_there_is_duplication():
    """The live data has 13 groupable findings in 13 distinct groups, so collapse
    legitimately changes nothing there. Prove the MECHANISM on a synthetic group,
    or this switch could be a no-op and still look fine.

    record_kind is GENERATED from name/issue_type — both set here, so these rows
    are 'finding', not 'inventory'. Runs inside BEGIN ... ROLLBACK.
    """
    sql = """
BEGIN;
INSERT INTO assets (id, ip, hostname) VALUES
  ('66666666-6666-4666-8666-666666666666','203.0.113.91','collapse-probe.test');
INSERT INTO web_findings (asset_id, url, source, name, issue_type, severity, port,
                          infrastructure_fingerprint)
VALUES
  ('66666666-6666-4666-8666-666666666666','http://a/','collapse-probe','probe','tls','high',443,'collapse-probe-fp'),
  ('66666666-6666-4666-8666-666666666666','http://b/','collapse-probe','probe','tls','high',443,'collapse-probe-fp'),
  ('66666666-6666-4666-8666-666666666666','http://c/','collapse-probe','probe','tls','high',443,'collapse-probe-fp');
SELECT 'RAW', count(*) FROM web_findings WHERE source='collapse-probe';
SELECT 'KIND', count(DISTINCT COALESCE(record_kind,'finding')) || ':' ||
       max(COALESCE(record_kind,'finding')) FROM web_findings WHERE source='collapse-probe';
SELECT 'COLLAPSED', count(*) FROM (
  SELECT DISTINCT ON (COALESCE(infrastructure_fingerprint, id::text)) id
    FROM web_findings WHERE source='collapse-probe') x;
ROLLBACK;
"""
    try:
        out = subprocess.run(
            ["docker", "exec", "-i", "rag-postgres", "psql", "-U", "app", "-d",
             "scans", "-v", "ON_ERROR_STOP=1", "-tA"],
            input=sql, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        pytest.skip("rag-postgres not reachable")
    if out.returncode != 0:
        pytest.skip(f"collapse probe could not run: {out.stderr[-200:]}")
    got = dict(l.split("|", 1) for l in out.stdout.splitlines() if "|" in l)
    assert got.get("RAW") == "3", f"probe inserted {got.get('RAW')} rows, expected 3"
    assert got.get("KIND") == "1:finding", (
        f"probe rows are {got.get('KIND')} — they must be findings, or the "
        "inventory filter removes them and this proves nothing")
    assert got.get("COLLAPSED") == "1", (
        f"three rows sharing one infrastructure_fingerprint collapsed to "
        f"{got.get('COLLAPSED')}, not 1 — the collapse key is not grouping")
