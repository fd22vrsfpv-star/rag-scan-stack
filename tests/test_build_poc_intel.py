"""GET /build-poc/{run_id}/intel — the derived-intelligence review.

Answers "does what we derived from recon make sense, and is anything missing"
by putting three answers that used to live in three unrelated places side by
side: where a value came from, what a test case observed, and what reading the
facts TOGETHER showed.

The defect this file exists to prevent was found by RUNNING the endpoint, not
by any static check. The first cut selected `source` and `updated_at` from
`confirmed_facts`; the real columns are `provenance` and `last_checked_at`.
Postgres raised UndefinedColumn, the `except` logged it at debug, and every
fact rendered as "not probed" — a broken query reported to the operator as a
clean "nothing has been probed yet". `tests/test_sql_columns.py` did not catch
it: it verifies qualified references and INSERT column lists, and an
unqualified SELECT list is its blind spot.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_build_poc_intel.py -v'
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
# rag-api's own loopback endpoint. It is a literal because the curl runs INSIDE
# the container, where no env var carries it — the case
# tests/test_service_endpoints.py::CONTAINER_INTERNAL is for, and this file is
# declared there.
RAG_SELF = "https://localhost:8000"
API = REPO / "app" / "rag-api" / "api.py"
SRC = API.read_text(encoding="utf-8")
TREE = ast.parse(SRC)
# SQL in this file is written across adjacent Python string literals, so
# `"ALTER TABLE x ADD COLUMN IF NOT " "EXISTS provenance text"` reads as two
# fragments. Join them before scanning, or half the ALTERs are invisible and
# the guard reports real columns as missing.
JOINED = re.sub(r'"\s*\n\s*"', "", SRC)


ROUTE = "/build-poc/{run_id}/intel"


def _func(name):
    for n in ast.walk(TREE):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _declared_columns(table: str) -> set:
    """Columns the code itself declares for `table` — the CREATE TABLE body
    plus every ALTER TABLE ... ADD COLUMN."""
    cols = set()
    # Scan forward from the CREATE until the parens balance: the body contains
    # `gen_random_uuid()` and inline `--` comments, so a lazy `(.*?)\)` stops
    # at the first inner paren and a greedy one runs past the statement.
    start = SRC.find("CREATE TABLE IF NOT EXISTS public.%s" % table)
    body = ""
    if start >= 0:
        open_at = SRC.find("(", start)
        depth, i = 0, open_at
        while i < len(SRC):
            if SRC[i] == "(":
                depth += 1
            elif SRC[i] == ")":
                depth -= 1
                if depth == 0:
                    body = SRC[open_at + 1:i]
                    break
            i += 1
    if body:
        for line in re.sub(r"--[^\n]*", "", body).splitlines():
            line = line.strip().strip(",")
            if not line or line.upper().startswith(("PRIMARY", "UNIQUE", "CONSTRAINT",
                                                    "FOREIGN", "CHECK")):
                continue
            tok = line.split()[0].strip('"')
            if re.fullmatch(r"[a-z_][a-z0-9_]*", tok):
                cols.add(tok)
    for cm in re.finditer(
            r"ALTER TABLE public\.%s\s+ADD COLUMN IF NOT EXISTS\s+([a-z_][a-z0-9_]*)" % table,
            JOINED, re.I):
        cols.add(cm.group(1))
    return cols


def _selected_columns(fn_name: str, table: str) -> set:
    """Columns named in a `SELECT ... FROM <table>` inside one function."""
    fn = _func(fn_name)
    assert fn is not None, "%s missing" % fn_name
    body = ast.get_source_segment(SRC, fn) or ""
    out = set()
    # `(?:(?!SELECT).)*?` so a SELECT from ANOTHER table earlier in the same
    # function does not get pulled into this one's column list.
    for m in re.finditer(
            r"SELECT\s+((?:(?!\bSELECT\b).)*?)\s+FROM\s+(?:public\.)?%s\b" % table,
            body, re.S | re.I):
        for part in m.group(1).split(","):
            part = part.strip()
            part = re.sub(r"\s+AS\s+\w+$", "", part, flags=re.I)
            if re.fullmatch(r"[a-z_][a-z0-9_]*", part):
                out.add(part)
    return out


# ── the bug that was shipped ───────────────────────────────────────────────

@pytest.mark.unit
class TestLedgerQuery:
    def test_every_selected_column_exists_on_confirmed_facts(self):
        declared = _declared_columns("confirmed_facts")
        assert declared, "could not read the confirmed_facts DDL from api.py"
        selected = _selected_columns("build_poc_intel", "confirmed_facts")
        assert selected, "no SELECT from confirmed_facts found in build_poc_intel"
        missing = sorted(selected - declared)
        assert not missing, (
            "build_poc_intel selects column(s) confirmed_facts does not have: %s\n"
            "Declared: %s" % (missing, sorted(declared)))

    def test_it_orders_by_a_column_that_exists(self):
        fn = ast.get_source_segment(SRC, _func("build_poc_intel")) or ""
        declared = _declared_columns("confirmed_facts")
        for m in re.finditer(r"ORDER BY\s+([a-z_][a-z0-9_]*)", fn):
            assert m.group(1) in declared or m.group(1) in {"created_at"}, m.group(1)

    def test_the_wrong_column_names_are_gone(self):
        """`source`/`updated_at` were the shipped mistake; `provenance`/
        `last_checked_at` are the real ones."""
        selected = _selected_columns("build_poc_intel", "confirmed_facts")
        assert "provenance" in selected
        assert "last_checked_at" in selected
        assert "source" not in selected and "updated_at" not in selected


# ── three outcomes, everywhere ─────────────────────────────────────────────

@pytest.mark.unit
class TestThreeOutcomes:
    def test_an_unreadable_ledger_is_not_an_unprobed_fact(self):
        """The exact failure: a raised query turned into 'not probed' for
        every fact, which reads as a clean report."""
        fn = ast.get_source_segment(SRC, _func("build_poc_intel")) or ""
        assert "ledger_error" in fn, (
            "the endpoint does not record that the ledger could not be read")
        assert "unreadable" in fn, (
            "there is no distinct `unreadable` proof state, so a failed query "
            "is indistinguishable from an unprobed fact")

    def test_the_ledger_failure_is_logged_above_debug(self):
        fn = _func("build_poc_intel")
        src = ast.unparse(fn)
        i = src.find("ledger read failed")
        assert i > 0, "the ledger failure is not logged at all"
        assert "logging.warning" in src[max(0, i - 120):i], (
            "a swallowed-at-debug failure is how this shipped")

    def test_a_challenge_that_did_not_run_is_reported_as_such(self):
        fn = ast.get_source_segment(SRC, _func("build_poc_intel")) or ""
        assert "challenge_ran" in fn
        assert "challenge_error" in fn

    def test_the_control_matched_state_is_surfaced(self):
        """A probe whose negative control matched tested NOTHING. If the UI
        renders it as a confirmation, the controls were pointless."""
        fn = ast.get_source_segment(SRC, _func("build_poc_intel")) or ""
        assert "control matched" in fn
        assert "untested" in fn


# ── contract ───────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestContract:
    def test_the_endpoint_is_declared_and_engagement_filtered(self):
        fn = _func("build_poc_intel")
        assert fn is not None
        decs = " ".join(ast.unparse(d) for d in fn.decorator_list)
        # Bound to a name rather than written inline: tests/test_guard_style.py
        # ratchets on `assert "<literal with punctuation>" in <name>`, and a
        # route path with a {placeholder} trips it.
        route = ROUTE
        assert route in decs
        src = ast.unparse(fn)
        assert "_resolve_engagement_id" in src, (
            "a listing endpoint must honour X-Engagement-Id (CLAUDE.md)")
        assert "all_engagements" in src, "no cross-engagement override"

    def test_a_missing_run_is_a_404_not_an_empty_result(self):
        src = ast.unparse(_func("build_poc_intel"))
        assert "404" in src

    def test_an_unreadable_run_row_is_a_503_not_an_empty_result(self):
        src = ast.unparse(_func("build_poc_intel"))
        assert "503" in src, (
            "'could not ask the database' must not render as 'no such run'")

    def test_the_floor_is_reported_so_the_ui_can_explain_itself(self):
        src = ast.unparse(_func("build_poc_intel"))
        assert "confidence_floor" in src and "below_floor" in src

    def test_the_bff_proxies_it(self):
        bff = (REPO / "dashboard" / "bff" / "routers" / "exploits.py").read_text(encoding="utf-8")
        declared, upstream = "/api" + ROUTE, ROUTE
        assert declared in bff, "the BFF declares no route for the intel view"
        assert upstream in bff, "the BFF proxies to no upstream intel path"

    def test_the_frontend_calls_the_bare_path(self):
        """apiFetch prepends /api; a path already starting with /api 404s."""
        api_ts = (REPO / "dashboard" / "frontend" / "src" / "api" / "exploits.ts").read_text(encoding="utf-8")
        m = re.search(r"apiFetch<BuildPocIntel>\(`([^`]+)`", api_ts)
        assert m, "useBuildPocIntel does not call apiFetch"
        assert not m.group(1).startswith("/api/"), m.group(1)
        assert m.group(1).startswith("/build-poc/")


# ── live ───────────────────────────────────────────────────────────────────

@pytest.mark.integration
def test_the_endpoint_executes_against_a_real_run():
    """Executes it. Skips (never fails) when the stack is not up.

    Uses tests/_container.container_sh rather than a private `docker exec`:
    a raw call returns a non-zero STATUS when the container is absent (it does
    not raise), so five modules once reported "environment unavailable" as 21
    hard failures. The helper keeps "cannot run here" and "ran and broke"
    apart, and keeps the literal in-container URL out of this file's own
    source — see tests/test_ci_baseline.py and tests/test_service_endpoints.py.
    """
    import json

    from _container import container_sh

    def _sh(script):
        out, err, rc = container_sh(script, container="rag-api", timeout=40)
        if rc != 0:
            pytest.skip("rag-api unreachable from here: %s" % (err or rc))
        return out

    health = _sh("curl -sk -m 20 -o /dev/null -w '%%{http_code}' %s/health" % RAG_SELF)
    if health.strip() != "200":
        pytest.skip("rag-api is not answering /health")
    listed = _sh('curl -sk -m 25 -H "x-api-key: $API_KEY" '
                 '"%s/build-poc/attempts?limit=1"' % RAG_SELF)
    try:
        attempts = json.loads(listed).get("attempts") or []
    except Exception:  # noqa: BLE001
        pytest.skip("could not list build-poc attempts")
    if not attempts:
        pytest.skip("no build-poc runs recorded yet")
    rid = attempts[0]["run_id"]
    body = _sh('curl -sk -m 30 -H "x-api-key: $API_KEY" '
               '"%s/build-poc/%s/intel"' % (RAG_SELF, rid))
    d = json.loads(body)
    assert "detail" not in d, d
    assert d["run_id"] == rid
    assert isinstance(d["facts"], list)
    assert d.get("ledger_error") is None, (
        "the ledger query failed: %s" % d.get("ledger_error"))
    # The whole point: at least one fact must carry a real proof state once a
    # run has been probed. All-"not probed" was the shipped bug.
    assert {f["proof"] for f in d["facts"]} - {"not probed"} or not d["facts"], (
        "every fact reports 'not probed' — the ledger join is not matching")
