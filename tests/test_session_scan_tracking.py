"""A session must know about the scans it started, and analyse their results.

Run on demand:

    pytest tests/test_session_scan_tracking.py -v

WHY THIS EXISTS
---------------
A LangGraph run against 192.168.1.150 reported "no assets, no ports, no
findings" and queued nothing. It looked like a total failure. It was not: both
scans dispatched fine (HTTP 200 to nmap_scanner /jobs/full-scan) and the host
ended up with 20 ports, 13 vulns and 6 pending exploits. Three defects made a
working run look like a broken one.

1. **The scans were never recorded against the session.**
   `SessionScanTracker.track_scan` resolved the session from `threading.local()`.
   LangGraph runs its nodes on executor threads, which inherit neither the
   thread-local nor a contextvar, so `get_current_session()` returned None,
   track_scan returned early, and the scan vanished — logged at **DEBUG**, so
   nothing above debug ever said so. The registry stayed empty, `persist_to_db`
   wrote nothing, `cleanup_session` deleted the empty entry, and `/scans`
   reported `total_scans: 0`. `session_scan_metrics` held ONE row for the entire
   table, dated three weeks earlier.

   Fixed with three lookups — thread-local, contextvar, then the single active
   run. The third is what covers executor threads. With TWO concurrent runs the
   attribution is genuinely ambiguous, so it refuses rather than filing one
   session's scans under another.

2. **The graph never came back to look at the results.** `scan → analyze` are
   wired directly and the scan node returns as soon as it has dispatched, so
   analyze reads the database as it was BEFORE the scan. The session declared
   itself complete 102 seconds after dispatch, with the scan still running.
   Rather than block for the length of a 65535-port sweep, the run finishes and
   a background watcher re-runs the analysis when the scans finish.

3. **SurfaceTester skipped a target it had.** `surface_plan` fell back from
   `surface_target_request` to the top-ranked attack vector and then gave up —
   never to `state["target"]`, which held the target all along. With an empty
   database there are no ranked vectors, so it skipped every time.

SABOTAGE PROOF
--------------
Drop `register_run` from the engine and
`test_executor_thread_resolves_the_session` fails (it reproduces the original
None). Put the track_scan miss back to `logger.debug` and
`test_a_dropped_scan_is_not_silent` fails. Remove the `state["target"]` fallback
and `test_surface_falls_back_to_the_session_target` fails.
"""
import ast
import os
import re

import pytest

from _container import container_exec

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
TOOLS = os.path.join(REPO, "autogen_agents", "scan_tools.py")
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _func(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


# ── 1. The session must be resolvable off the graph's own thread ───────────

def test_tracker_has_all_three_lookups():
    src = _read(TOOLS)
    fn = _func(src, "get_current_session")
    assert fn, "get_current_session() is gone"
    assert "_local" in fn, "the thread-local lookup is gone"
    assert "_ctx_session" in fn, "the contextvar lookup is gone"
    assert "_active_runs" in fn, (
        "the active-run lookup is gone — executor threads inherit neither the "
        "thread-local nor the contextvar, so every LangGraph scan goes untracked")


def test_ambiguous_attribution_is_refused():
    """Two concurrent runs must not have one session's scans filed under the
    other. Guessing is worse than not recording."""
    fn = _func(_read(TOOLS), "get_current_session")
    assert "len(cls._active_runs) == 1" in fn, (
        "the single-active-run guard is gone; with two runs active this would "
        "attribute scans to whichever happened to be first")


def test_a_dropped_scan_is_not_silent():
    fn = _func(_read(TOOLS), "track_scan")
    assert fn, "track_scan() is gone"
    assert "logger.warning" in fn, (
        "a scan that cannot be attributed is logged below WARNING again — that "
        "is how this went unnoticed for three weeks")


def test_engine_registers_and_unregisters_the_run():
    src = _read(ENGINE)
    assert src.count("scan_tracker.register_run(sid)") >= 2, (
        "both the start and resume paths must register the run")
    assert src.count("scan_tracker.unregister_run(sid)") >= 2, (
        "a finished run left registered becomes the 'single active run' that a "
        "LATER session's scans get attributed to")


# ── 2. The run comes back to analyse what its scans produced ───────────────

def test_rescan_analysis_exists_and_is_bounded():
    src = _read(ENGINE)
    fn = _func(src, "_rerun_analysis_when_scans_finish")
    assert fn, "the post-scan re-analysis is gone"
    assert "RESCAN_ANALYSIS_MAX_WAIT_S" in fn, "the wait is unbounded"
    assert "analyze(state)" in fn, "it no longer re-runs the analysis"


def test_rescan_reports_a_timeout_rather_than_going_quiet():
    fn = _func(_read(ENGINE), "_rerun_analysis_when_scans_finish")
    assert "timeout" in fn.lower(), (
        "giving up after the deadline must SAY so; silently doing nothing is "
        "indistinguishable from the bug this fixes")


def test_rescan_is_scheduled_from_teardown():
    """From _teardown, not from the success path.

    A live run caught this: the graph never returned, the watchdog marked the
    session `stalled`, and teardown ran — but the scheduler sat after _finish()
    in the success branch and never did. A session whose scans outlive it is
    exactly the case that needs the re-analysis, and a stalled run is one of the
    likeliest ways to get there. _teardown is where all four exit paths meet.
    """
    src = _read(ENGINE)
    fn = _func(src, "_teardown")
    assert fn, "_teardown() is gone"
    assert "_maybe_schedule_rescan_analysis" in fn, (
        "the re-analysis is not scheduled from _teardown, so a run that stalls "
        "or raises never gets one")
    # And it must come after _finalize_session, which persists the scans the
    # watcher then restores to poll.
    assert fn.index("_finalize_session") < fn.index("_maybe_schedule_rescan_analysis"), (
        "scheduling before the scans are persisted leaves the watcher nothing "
        "to poll")


def test_rescan_state_is_read_back_from_the_session():
    """_teardown does not carry the graph state, so it reads what it needs."""
    fn = _func(_read(ENGINE), "_rescan_state_for")
    assert fn, "_rescan_state_for() is gone"
    for key in ("target", "task", "exploit_phase"):
        assert f'"{key}"' in fn, f"the rebuilt state is missing {key}"


def test_rescan_only_spawns_when_something_is_running():
    fn = _func(_read(ENGINE), "_maybe_schedule_rescan_analysis")
    assert fn, "the scheduler is gone"
    assert "if not running:" in fn and "return" in fn, (
        "a session whose scans all finished should not spawn a watcher thread "
        "just to discover that")
    assert "daemon=True" in fn, "the watcher must not hold the process open"


# ── 3. SurfaceTester uses the target it was given ──────────────────────────

def test_surface_falls_back_to_the_session_target():
    fn = _func(_read(ENGINE), "surface_plan")
    assert fn, "surface_plan() is gone"
    assert 'state.get("target")' in fn, (
        "surface_plan no longer falls back to the session's own target, so with "
        "an empty database it skips a host it was explicitly given")


# ── Live: the thread behaviour itself ──────────────────────────────────────

_LIVE = r"""
import sys, json, concurrent.futures as cf
sys.path.insert(0, "/app")
from scan_tools import scan_tracker as t

SID = "11111111-2222-3333-4444-555555555555"
OTHER = "99999999-8888-7777-6666-555555555555"
out = {}
try:
    t.set_session(SID)
    out["same_thread"] = t.get_current_session() == SID

    with cf.ThreadPoolExecutor(max_workers=1) as ex:
        out["executor_before_register"] = ex.submit(t.get_current_session).result()

    t.register_run(SID)
    with cf.ThreadPoolExecutor(max_workers=1) as ex:
        out["executor_after_register"] = ex.submit(t.get_current_session).result() == SID
        ex.submit(t.track_scan, "full_scan", "job-test-1", {"targets": ["192.0.2.1"]}).result()

    st = t.get_session_status(SID)
    out["tracked_from_executor"] = [s["job_id"] for s in (st.get("scans") or [])]

    # Ambiguity: two runs active, no thread context -> must refuse.
    t.register_run(OTHER)
    t._local.session_id = None
    t._ctx_session.set(None)
    with cf.ThreadPoolExecutor(max_workers=1) as ex:
        out["ambiguous"] = ex.submit(t.get_current_session).result()
finally:
    for s in (SID, OTHER):
        try:
            t.unregister_run(s); t.cleanup_session(s)
        except Exception:
            pass
print(json.dumps(out))
"""


@pytest.fixture(scope="module")
def live():
    out = container_exec(_LIVE, container="autogen-agents", timeout=180)
    if out is None:
        pytest.skip("autogen-agents container unreachable")
    if out.startswith("__ERR__"):
        pytest.fail(f"tracker thread round-trip failed: {out}")
    import json
    return json.loads(out.strip().splitlines()[-1])


def test_same_thread_still_resolves(live):
    assert live["same_thread"] is True


def test_executor_thread_reproduces_the_original_bug(live):
    """Without the run registered, an executor thread sees NO session — which is
    exactly why every LangGraph scan was dropped."""
    assert live["executor_before_register"] is None


def test_executor_thread_resolves_the_session(live):
    assert live["executor_after_register"] is True, (
        "an executor thread still cannot resolve the session; scans dispatched "
        "by graph nodes will go untracked")


def test_scan_dispatched_from_an_executor_thread_is_recorded(live):
    assert live["tracked_from_executor"] == ["job-test-1"], (
        f"expected the scan to be tracked, got {live['tracked_from_executor']}")


def test_two_active_runs_refuse_to_guess(live):
    assert live["ambiguous"] is None, (
        "with two runs active the tracker guessed instead of refusing — one "
        "session's scans would be filed under another")
