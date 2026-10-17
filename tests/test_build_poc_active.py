"""An in-flight Build-PoC run must be visible WHILE it runs.

`build_poc_endpoint` is a synchronous `def`: it blocks for the whole build —
10 to 25 minutes observed — and the UI awaits that single response. So the
first evidence a run existed was the attempt row written at the END, the Scan
Monitor's `bpc-` row could not be opened, and the live trace was a file inside
the container. Pressing Build PoC produced nothing to look at.

That is not cosmetic. On 2026-10-16 an operator submitted the same CVE twice
95 seconds apart because the form gave no sign the first had started, and both
ran to completion against a third-party host before anyone noticed.

Pinned here:

  1. the run is recorded BEFORE the graph runs, not after — a row that only
     appears at the end cannot answer "did it start?";
  2. the start record upserts on run_id, so the end-of-run record updates it
     rather than racing or duplicating;
  3. "in flight" means `stop_reason IS NULL` — the same column the end-of-run
     record fills, so a finished run leaves the list by itself;
  4. a database error is a 503, never an empty list: "could not ask" is not
     "nothing is running" (this repo's recurring "unreachable is not absent");
  5. a registered run whose trace file does not exist yet is still REPORTED,
     with `phase: None` — hiding it would recreate the very gap this closes.

Sabotage check: move the start record after `graph.invoke` and
`test_the_run_is_recorded_before_the_graph_runs` fails; return `{"runs": []}`
on a database error and `test_a_database_error_is_not_an_empty_list` fails.

    pytest tests/test_build_poc_active.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"


def _tree(path):
    if not path.exists():
        pytest.skip(f"{path} not found")
    return ast.parse(path.read_text(encoding="utf-8"))


def _func(path, name):
    fn = next((n for n in ast.walk(_tree(path))
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == name), None)
    assert fn, f"{name} not found in {path.name}"
    return fn


# -- 1 + 2. recorded at the START -------------------------------------------

def test_the_run_is_recorded_before_the_graph_runs():
    """Ordering is the whole point — after the graph, it answers nothing."""
    fn = _func(GRAPH, "invoke_build_poc")
    rec = [n.lineno for n in ast.walk(fn)
           if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
           and n.func.id == "_record_build_poc_attempt"]
    # Whatever RUNS the graph — `.invoke()` directly, or the traced runner
    # that streams it. Pinning the literal `graph.invoke` made this test fail
    # when the run moved to `stream_mode=["debug","values"]`, though the
    # ordering it guards was never violated.
    inv = [n.lineno for n in ast.walk(fn)
           if isinstance(n, ast.Call)
           and (getattr(n.func, "attr", None) in ("invoke", "stream")
                or getattr(n.func, "id", None) == "_run_graph_traced")]
    assert rec, "invoke_build_poc never records the run's start"
    assert inv, "nothing in invoke_build_poc runs the graph"
    assert min(rec) < min(inv), (
        f"the start record (line {min(rec)}) happens AFTER the graph runs "
        f"(line {min(inv)}) — it cannot answer 'did it start?'")


def test_the_start_record_says_running():
    src = ast.get_source_segment(GRAPH.read_text(encoding="utf-8"),
                                 _func(GRAPH, "invoke_build_poc")) or ""
    assert '"running"' in src or "'running'" in src, (
        "the start record does not set stage_reached='running', so an "
        "in-flight run is indistinguishable from one that never began")


def test_the_start_record_cannot_fail_the_build():
    """A status row is not worth failing a build over."""
    fn = _func(GRAPH, "invoke_build_poc")
    for n in ast.walk(fn):
        if not isinstance(n, ast.Try):
            continue
        calls = [c for c in ast.walk(n) if isinstance(c, ast.Call)
                 and isinstance(c.func, ast.Name)
                 and c.func.id == "_record_build_poc_attempt"]
        if calls and n.handlers:
            return
    pytest.fail("the start record is not wrapped in try/except — a database "
                "hiccup would abort a build that was about to run fine")


def test_the_upsert_targets_run_id():
    """Start then finish must be ONE row, or the list fills with ghosts."""
    import re
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func(API, "_record_build_poc_attempt")) or ""
    assert re.search(r"ON\s+CONFLICT\s*\(\s*run_id\s*\)", src, re.I), (
        "the attempt upsert does not key on run_id, so the start record and "
        "the end-of-run record become two rows for one build")


# -- 3 + 4 + 5. the endpoint ------------------------------------------------

def test_the_endpoint_exists_and_is_authed():
    fn = _func(API, "build_poc_active")
    routes = [d for d in fn.decorator_list
              if isinstance(d, ast.Call) and d.args
              and getattr(d.args[0], "value", "") == "/build-poc/active"]
    assert routes, "no @app.get('/build-poc/active') decorator"
    assert any(a.arg == "_" for a in fn.args.args) or fn.args.defaults, (
        "the endpoint takes no auth dependency")


def test_in_flight_means_no_stop_reason():
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func(API, "build_poc_active")) or ""
    assert "stop_reason IS NULL" in src, (
        "in-flight is not defined as stop_reason IS NULL, so a finished run "
        "either lingers in the list or never appears in it")


def test_a_database_error_is_not_an_empty_list():
    """'Could not ask' must not read as 'nothing is running'."""
    fn = _func(API, "build_poc_active")
    raises = [n for n in ast.walk(fn) if isinstance(n, ast.Raise)]
    assert raises, (
        "a database failure returns normally — an empty list would tell the "
        "operator nothing is running when the truth is we could not look")
    src = ast.unparse(fn)
    assert "503" in src, f"the failure is not a 503: {src[:200]}"


def test_a_missing_trace_file_still_reports_the_run():
    """Registered but no trace yet is the FIRST second of every run."""
    fn = _func(API, "build_poc_active")
    handlers = [h for n in ast.walk(fn) if isinstance(n, ast.Try)
                for h in n.handlers]
    names = []
    for h in handlers:
        if isinstance(h.type, ast.Name):
            names.append(h.type.id)
        elif isinstance(h.type, ast.Tuple):
            names += [e.id for e in h.type.elts if isinstance(e, ast.Name)]
    assert "FileNotFoundError" in names, (
        "a run whose trace file does not exist yet is not handled — it would "
        "either vanish from the list or raise, in the first seconds of every "
        "single build")


def test_the_phase_comes_from_the_trace_not_a_guess():
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func(API, "build_poc_active")) or ""
    assert '"phase"' in src and "poc_log_path" in src, (
        "the reported phase is not read from the run's own trace")


def test_the_listing_is_engagement_filtered():
    """CLAUDE.md: engagement filters apply on READS, not just writes.

    Without this an operator working in one engagement sees another's
    in-flight runs under their own header — the defect /exploit-store had.
    """
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func(API, "build_poc_active")) or ""
    assert "_resolve_engagement_id" in src, (
        "the in-flight listing does not read X-Engagement-Id, so it returns "
        "every engagement's runs under whichever one the operator is in")
    import re
    assert re.search(r"engagement_id\s*=\s*%s\s+OR\s+engagement_id\s+IS\s+NULL",
                     src, re.I), (
        "the standard `engagement_id = %s OR engagement_id IS NULL` filter is "
        "missing — legacy NULL rows must stay visible, everything else must not")


def test_the_cross_engagement_override_is_labelled():
    """?all_engagements=true is allowed, but the UI must be able to say so."""
    fn = _func(API, "build_poc_active")
    args = [a.arg for a in fn.args.args]
    assert "all_engagements" in args, "no cross-engagement override"
    src = ast.unparse(fn)
    assert "'all_engagements'" in src or '"all_engagements"' in src, (
        "the response does not report which mode it is in, so the UI cannot "
        "label it and 'all engagements' reads as 'this engagement'")


# -- the frontend half ------------------------------------------------------

PAGE = REPO / "dashboard" / "frontend" / "src" / "pages" / "ExploitManager.tsx"


def test_the_form_polls_only_while_a_build_is_outstanding():
    """An idle workbench must not poll."""
    if not PAGE.exists():
        pytest.skip("ExploitManager.tsx not found")
    src = PAGE.read_text(encoding="utf-8")
    # Find the CALL, not the first mention: the first occurrence of the path
    # in this file is the comment above the effect, and a window search
    # anchored there tested the wrong thing (caught 2026-10-16, by this test
    # failing on code that was correct).
    i = src.find("apiFetch<", src.find("'/build-poc/active'") - 400) \
        if "'/build-poc/active'" in src else -1
    assert "'/build-poc/active'" in src, "the form never polls /build-poc/active"
    # The effect that contains the call must be gated on buildInFlight, and
    # must list it as a dependency, or it never re-arms.
    j = src.index("'/build-poc/active'")
    effect_start = src.rfind("useEffect(", 0, j)
    assert effect_start > 0, "the poll is not inside a useEffect"
    import re
    effect = src[effect_start:j]
    assert re.search(r"if\s*\(\s*!\s*buildInFlight\s*\)\s*return", effect), (
        "the poll is not gated on a build being in flight — an idle page "
        "would hit the endpoint every few seconds forever")


def test_the_poll_stops_however_the_build_ends():
    if not PAGE.exists():
        pytest.skip("ExploitManager.tsx not found")
    src = PAGE.read_text(encoding="utf-8")
    i = src.find("setBuildInFlight(false)")
    assert i > 0, "nothing ever clears the in-flight flag"
    assert "finally" in src[max(0, i - 220):i], (
        "the flag is cleared on the success path only, so a failed build "
        "leaves the form claiming a run is still going")
