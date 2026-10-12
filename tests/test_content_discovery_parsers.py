"""ffuf and feroxbuster output is PARSED, and lands in `web_findings`.

Run on demand:

    pytest tests/test_content_discovery_parsers.py -v

WHY THIS EXISTS
---------------
A live LangGraph session logged::

    post_enumeration: no parser for feroxbuster, ffuf

Both tools are on the kali-listener SAFE lane, both are named by
`knowledge/content_discovery.yaml` and `knowledge/service_tools.yaml`, and both
had run: 32 rows in `tool_executions`, up to 30 KB of output each, every one
with `parsed_results IS NULL`. `etl/parse_ffuf.py` existed the whole time — but
it takes a FILE PATH and writes rows itself (the `/ingest/ffuf` upload route),
so it could never be reached from `etl/tool_output_parsers.parse_for`, which
needs a pure text->dict function. "It has a parser" was true and beside the
point; the same trap the `_nuclei` entry in that module documents.

There are two registries and this file covers both:

  * `etl/tool_output_parsers.PARSERS` — pure text->dict, read by
    `autogen_agents/langgraph_engine._analyse_session_output` to fill
    `tool_executions.parsed_results`. A tool missing here is what produces the
    "no parser for" line.
  * `etl/parse_tool_output._TOOL_PARSERS` — Strategy 0 of
    `/ingest/tool-output`, the hook kali-listener calls after EVERY execution.
    A tool missing here falls through to the generic structurer, which turns 23
    discovered paths into one raw-text recon_finding.

FIXTURES ARE REAL
-----------------
`tests/fixtures/ffuf_*` and `tests/fixtures/feroxbuster_*` are byte-for-byte
`tool_executions.output` / `.error` columns from this stack (runs against the
172.18.0.32 lab target on 2026-09-28 / 2026-10-05), except the two machine
formats — `ffuf_json_output.json` (`-of json`) and
`feroxbuster_ndjson_output.jsonl` (`--json -o`) — which were captured by
running the real binaries inside `kali-listener` against a throwaway
`python -m http.server` on its own loopback. No shape here was invented.

SABOTAGE PROOF
--------------
* Remove `"ffuf"` or `"feroxbuster"` from `PARSERS` ->
  `test_both_tools_have_a_registry_parser` fails by name.
* Drop the URL check on feroxbuster's result line (so the auto-filter notice
  counts) -> `test_feroxbuster_autofilter_notice_is_not_a_result` fails.
* Remove `engagement_id` from the web_findings INSERT ->
  `test_writer_sets_engagement_and_asset` fails.
* Remove the `host_in_scope` call -> `test_writer_gates_out_of_scope_urls`
  fails.
"""
import ast
import json
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# The host inside these recordings. Deliberately a literal and NOT
# conftest.LAB_TARGET: the fixtures are recorded bytes, so the expected value
# moves only when the recording does (see conftest's FIXTURE_HOST note).
RECORDED_HOST = "172.18.0.32"


def _fixture(name):
    path = os.path.join(FIXTURES, name)
    if not os.path.exists(path):
        pytest.skip(f"fixture {name} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def reg():
    return pytest.importorskip("etl.tool_output_parsers")


# ── registry tier: parse_for / parse_status ────────────────────────────────

def test_both_tools_have_a_registry_parser(reg):
    """The exact gap the session reported: parse_for returned None for these."""
    for tool in ("ffuf", "feroxbuster"):
        st = reg.parse_status(tool)
        assert st["has_parser"] is True, f"{tool} has no parser — the session warning returns"
        assert st["kind"] == "registry", tool


def test_ffuf_text_output_yields_every_matched_path(reg):
    """Real `ffuf -u .../FUZZ -w common.txt` run: 8 hits on stdout, URL on stderr."""
    parsed = reg.parse_for("ffuf",
                           _fixture("ffuf_results.txt"),
                           _fixture("ffuf_results.stderr.txt"))
    assert parsed["tool"] == "ffuf"
    assert parsed["counts"]["results"] == 8
    assert reg.result_count(parsed) == 8
    assert parsed["productive"] is True
    # The URL template lives ONLY in the stderr banner; the hit lines carry the
    # matched word alone. Losing the banner loses every URL.
    assert parsed["base_url"] == f"http://{RECORDED_HOST}:9090/FUZZ"
    by_path = {p["path"]: p for p in parsed["paths"]}
    assert by_path["index.php"]["status"] == 200
    assert by_path["index.php"]["size"] == 2246
    assert by_path["index.php"]["url"] == f"http://{RECORDED_HOST}:9090/index.php"
    assert by_path[".htaccess"]["status"] == 403
    # ANSI erase sequences (`\r\x1b[2K`) prefix every line; left in they become
    # part of the matched word and every URL is wrong.
    assert all("\x1b" not in (p["path"] or "") for p in parsed["paths"])


def test_ffuf_json_output_is_preferred_when_present(reg):
    """`-of json` — the shape /ingest/tool-output gets when a run wrote a file."""
    parsed = reg.parse_for("ffuf", _fixture("ffuf_json_output.json"))
    assert parsed["counts"]["results"] == 3
    urls = {p["url"] for p in parsed["paths"]}
    assert "http://127.0.0.1:8765/index.php" in urls
    hit = next(p for p in parsed["paths"] if p["path"] == "admin")
    assert hit["status"] == 301 and hit["redirect"] == "/admin/"


def test_ffuf_that_matched_nothing_is_a_measured_zero(reg):
    """Empty stdout + a real banner on stderr: the tool RAN and found nothing.

    This must not be None. "Nobody wrote a parser" and "the parser found
    nothing" are different facts and the learner acts differently on each.
    """
    parsed = reg.parse_for("ffuf", "", _fixture("ffuf_no_results.stderr.txt"))
    assert parsed is not None
    assert parsed["counts"]["results"] == 0
    assert parsed["productive"] is False
    assert reg.result_count(parsed) == 0
    # Nothing at all on either stream stays unmeasured.
    assert reg.parse_for("ffuf", "", "") is None


def test_feroxbuster_text_output_yields_absolute_urls(reg):
    parsed = reg.parse_for("feroxbuster",
                           _fixture("feroxbuster_results.txt"),
                           _fixture("feroxbuster_results.stderr.txt"))
    assert parsed["tool"] == "feroxbuster"
    assert parsed["counts"]["results"] == 23
    assert parsed["base_url"] == f"http://{RECORDED_HOST}:9090/"
    urls = {p["url"] for p in parsed["paths"]}
    assert f"http://{RECORDED_HOST}:9090/index.php" in urls
    assert f"http://{RECORDED_HOST}:9090/custom" in urls
    redirect = next(p for p in parsed["paths"]
                    if p["url"] == f"http://{RECORDED_HOST}:9090/custom")
    assert redirect["status"] == 301
    assert redirect["redirect"] == f"http://{RECORDED_HOST}:9090/custom/"
    assert redirect["method"] == "GET"


def test_feroxbuster_autofilter_notice_is_not_a_result(reg):
    """`404 GET 9l 32w 315c Auto-filtering found 404-like response ...`

    wears the exact costume of a hit. Counting it means every run reports the
    calibration probes as discovered content.
    """
    parsed = reg.parse_for("feroxbuster",
                           _fixture("feroxbuster_results.txt"),
                           _fixture("feroxbuster_results.stderr.txt"))
    assert all(str(p["url"]).startswith("http") for p in parsed["paths"])
    assert not any("Auto-filtering" in str(p["url"]) for p in parsed["paths"])
    assert any("Auto-filtering" in n for n in parsed["notes"]), \
        "the notice must be KEPT as a note, not silently dropped"


def test_feroxbuster_ndjson_output(reg):
    """`--json -o file`: four record types, only `response` rows are hits."""
    parsed = reg.parse_for("feroxbuster",
                           _fixture("feroxbuster_ndjson_output.jsonl"))
    assert parsed["counts"]["results"] == 1
    hit = parsed["paths"][0]
    assert hit["url"] == "http://127.0.0.1:8765/index.php"
    assert hit["status"] == 200 and hit["size"] == 39
    assert parsed["base_url"] == "http://127.0.0.1:8765/"
    # `configuration` and `statistics` rows are not findings.
    assert len(parsed["paths"]) == 1


def test_feroxbuster_unreachable_target_reports_the_error(reg):
    """A target that refused every connection is zero results AND an error.

    Reporting it as a plain empty run is the "unreachable is not absent" bug:
    nothing distinguishes it from a host with no content.
    """
    parsed = reg.parse_for("feroxbuster",
                           _fixture("feroxbuster_unreachable.txt"),
                           _fixture("feroxbuster_unreachable.stderr.txt"))
    assert parsed["counts"]["results"] == 0
    assert parsed["productive"] is False
    assert any("Could not connect" in e for e in parsed["errors"])


def test_registry_emits_exactly_one_result_count_key(reg):
    """`result_count` SUMS every meaningful key it finds.

    A parser emitting two of them double-counts its own run — the reason the
    four earlier parsers all chose `results` and nothing else.
    """
    meaningful = {"credentials", "shares", "findings", "command_output_lines",
                  "hosts", "results", "items", "vulnerabilities", "ports"}
    for tool, out, err in (
            ("ffuf", _fixture("ffuf_results.txt"), _fixture("ffuf_results.stderr.txt")),
            ("feroxbuster", _fixture("feroxbuster_results.txt"),
             _fixture("feroxbuster_results.stderr.txt"))):
        counts = reg.parse_for(tool, out, err)["counts"]
        assert len(meaningful & set(counts)) == 1, (tool, sorted(counts))


# ── writer tier: /ingest/tool-output Strategy 0 -> web_findings ────────────

class _FakeCursor:
    """Just enough cursor to execute the writer without a database.

    Returns a RealDictCursor-shaped row for the INSERT ... RETURNING id, an
    empty scope table (so load_ingest_scope reports enforce=False) and no
    engagement. Each statement is recorded for assertion.
    """

    def __init__(self, scope_rows=None, engagement=None):
        self.statements = []
        self.inserts = []
        self._scope_rows = scope_rows or []
        self._engagement = engagement
        self._next = None

    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        s = " ".join(sql.split())
        if "FROM public.scope_targets" in s or "FROM scope_targets" in s:
            self._next = list(self._scope_rows)
            return
        if "FROM assets" in s and "engagement_id" in s:
            self._next = [{"engagement_id": self._engagement}] if self._engagement else []
            return
        if "INSERT INTO web_findings" in s:
            self.inserts.append(params)
            self._next = [{"id": params[0]}]
            return
        self._next = []

    def fetchone(self):
        rows = self._next or []
        self._next = []
        return rows[0] if rows else None

    def fetchall(self):
        rows = self._next or []
        self._next = []
        return rows


def _writer():
    pytest.importorskip("psycopg2",
                        reason="etl.parse_tool_output imports psycopg2 at module level")
    mod = pytest.importorskip("etl.parse_tool_output")
    return mod


def test_both_tools_are_registered_with_the_ingest_writer():
    mod = _writer()
    for tool in ("ffuf", "feroxbuster"):
        assert tool in mod._TOOL_PARSERS, (
            f"{tool} is not a Strategy 0 parser — /ingest/tool-output falls through "
            "to the generic structurer and 23 paths become one raw-text row")


def test_writer_stores_every_feroxbuster_path_as_a_web_finding():
    mod = _writer()
    cur = _FakeCursor()
    stats = mod._parse_content_discovery(
        _fixture("feroxbuster_results.txt"), RECORDED_HOST, 9090,
        "11111111-1111-1111-1111-111111111111", cur, tool_name="feroxbuster")
    assert stats["parse_method"] == "feroxbuster_content_discovery"
    assert stats["web_findings_inserted"] == 23, stats
    assert stats["records_seen"] == 23
    urls = [p[3] for p in cur.inserts]
    assert f"http://{RECORDED_HOST}:9090/index.php" in urls


def test_writer_builds_urls_for_ffuf_stdout_without_the_banner():
    """`/ingest/tool-output` receives `stdout` only — ffuf's URL is on stderr.

    The target+port the run was dispatched against supplies the base. That is
    the same host the command was built from, not a guess.
    """
    mod = _writer()
    cur = _FakeCursor()
    stats = mod._parse_content_discovery(
        _fixture("ffuf_results.txt"), RECORDED_HOST, 9090, None, cur,
        tool_name="ffuf")
    assert stats["web_findings_inserted"] == 8, stats
    urls = [p[3] for p in cur.inserts]
    assert f"http://{RECORDED_HOST}:9090/index.php" in urls
    assert all(u.startswith(f"http://{RECORDED_HOST}:9090/") for u in urls)


def test_writer_sets_engagement_and_asset():
    """Collected target data MUST carry the engagement (CLAUDE.md invariant)."""
    mod = _writer()
    eid = "22222222-2222-2222-2222-222222222222"
    aid = "11111111-1111-1111-1111-111111111111"
    cur = _FakeCursor(engagement=eid)
    mod._parse_content_discovery(_fixture("feroxbuster_results.txt"),
                                 RECORDED_HOST, 9090, aid, cur,
                                 tool_name="feroxbuster")
    sql = next(s for s, _ in cur.statements if "INSERT INTO web_findings" in s)
    cols = " ".join(sql.split())
    assert "engagement_id" in cols and "asset_id" in cols
    for params in cur.inserts:
        assert params[1] == aid, "asset_id not populated"
        assert params[2] == eid, "engagement_id not populated"


def test_writer_gates_out_of_scope_urls():
    """feroxbuster --extract-links follows what a page points AT.

    Scope is checked when the tool is pointed at a host; it must also be checked
    on what comes back, or a crawl stores third-party URLs as engagement data.
    """
    mod = _writer()
    # A scope table that covers ONLY an unrelated host => enforce=True and every
    # recorded URL is out of scope.
    cur = _FakeCursor(scope_rows=[{"target": "192.0.2.41", "target_type": "ip"}])
    stats = mod._parse_content_discovery(
        _fixture("feroxbuster_results.txt"), RECORDED_HOST, 9090, None, cur,
        tool_name="feroxbuster")
    assert stats["web_findings_inserted"] == 0
    assert stats["out_of_scope"] == 23, stats
    assert not cur.inserts


def test_writer_fingerprints_so_a_rescan_updates_rather_than_duplicates():
    mod = _writer()
    fp = pytest.importorskip("etl.fingerprint")
    cur = _FakeCursor()
    mod._parse_content_discovery(_fixture("feroxbuster_results.txt"),
                                 RECORDED_HOST, 9090, None, cur,
                                 tool_name="feroxbuster")
    sql = next(s for s, _ in cur.statements if "INSERT INTO web_findings" in s)
    flat = " ".join(sql.split())
    assert "ON CONFLICT (fingerprint)" in flat
    # The fingerprint must be computed from the values actually STORED, or a
    # later writer recomputing it from the row disagrees and the unique index
    # keeps both copies.
    url, name = cur.inserts[0][3], cur.inserts[0][5]
    assert cur.inserts[0][-1] == fp.web_fingerprint(url, "feroxbuster", name,
                                                    "discovered_path")
    # Stable across tools: the same URL found by ffuf is the SAME finding.
    assert fp.web_fingerprint(url, "ffuf", name, "discovered_path") == \
        fp.web_fingerprint(url, "feroxbuster", name, "discovered_path")


def test_writer_returns_none_for_unrecognisable_output():
    """Empty output must still reach the generic strategies, not be swallowed."""
    mod = _writer()
    assert mod._parse_content_discovery("", RECORDED_HOST, 9090, None,
                                        _FakeCursor(), tool_name="ffuf") is None


# ── source guard: both registries keep naming both tools ───────────────────
#
# AST, not import: it runs with no psycopg2 and no database, so the guard
# cannot quietly become a skip in the environment that matters most (CI).

def _module_source(rel):
    path = os.path.join(REPO, rel)
    if not os.path.exists(path):
        pytest.skip(f"{rel} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _dict_keys(src, name):
    tree = ast.parse(src)
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        for t in targets:
            if isinstance(t, ast.Name) and t.id == name and isinstance(node.value, ast.Dict):
                return {k.value for k in node.value.keys
                        if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    return set()


def test_registries_both_name_the_content_discovery_tools():
    reg_keys = _dict_keys(_module_source("etl/tool_output_parsers.py"), "PARSERS")
    ing_keys = _dict_keys(_module_source("etl/parse_tool_output.py"), "_TOOL_PARSERS")
    assert reg_keys, "PARSERS no longer parses as a literal dict — the guard is broken"
    assert ing_keys, "_TOOL_PARSERS no longer parses as a literal dict — the guard is broken"
    for tool in ("ffuf", "feroxbuster"):
        assert tool in reg_keys, (
            f"{tool} dropped from etl/tool_output_parsers.PARSERS — "
            "'post_enumeration: no parser for ...' returns")
        assert tool in ing_keys, (
            f"{tool} dropped from etl/parse_tool_output._TOOL_PARSERS — its output "
            "falls through to the generic structurer")


def test_ingest_dispatch_is_case_insensitive():
    """`_TOOL_PARSERS` keys are lower-case; an operator-typed `FFUF` must match."""
    src = _module_source("etl/parse_tool_output.py")
    assert "_TOOL_PARSERS.get((tool_name or \"\").strip().lower())" in src, \
        "Strategy 0 dispatch no longer lower-cases the tool name"
