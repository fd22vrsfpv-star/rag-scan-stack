"""One build must be stoppable, and a second must not start by accident.

On 2026-10-16 two concurrent builds ran against the same third-party host.
The second was submitted 6m42s after the first because the Build PoC form
blocks for the whole run and showed no progress, so the operator reasonably
pressed it again. Neither problem had a fix:

  * there was NO cancel for a build — the only lever was restarting rag-api,
    which would have killed both, including the one worth keeping;
  * the submit path never checked whether that CVE+target was already running,
    even though `build_poc_attempts` now carries a `running` row for it.

Pinned here:

  1. cancel is checked at the LOOP BOUNDARY, before a dispatch, so stopping
     costs no further traffic to the target;
  2. it does not interrupt a dispatch already in flight — that would leave the
     listener running a command nobody reads;
  3. the flag is CLEARED when acted on, so the set cannot grow without bound;
  4. a duplicate is refused with 409 naming the run already going, not
     silently swallowed;
  5. `force_duplicate=true` is the deliberate override — a second run with
     different knobs is legitimate;
  6. a FAILED duplicate check does not block a legitimate build, and does not
     silently permit one either: it is logged.

Sabotage check: move the cancel check after the dispatch and
`test_cancel_is_checked_before_any_dispatch` fails; drop the 409 and
`test_a_duplicate_is_refused_by_default` fails.

    pytest tests/test_build_poc_cancel_and_duplicate.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"


def _tree():
    if not API.exists():
        pytest.skip("api.py not found")
    return ast.parse(API.read_text(encoding="utf-8"))


def _func(name):
    fn = next((n for n in ast.walk(_tree())
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == name), None)
    assert fn, f"{name} not found in api.py"
    return fn


def _src(name):
    return ast.get_source_segment(API.read_text(encoding="utf-8"), _func(name)) or ""


# -- 1-3. cancel -------------------------------------------------------------

def test_the_cancel_endpoint_exists():
    fn = _func("build_poc_cancel")
    routes = [d for d in fn.decorator_list
              if isinstance(d, ast.Call) and d.args
              and "cancel" in str(getattr(d.args[0], "value", ""))]
    assert routes, "no cancel route decorator on build_poc_cancel"


def test_cancel_is_checked_before_any_dispatch():
    """At the loop boundary, so a stop costs no further target traffic."""
    fn = _func("_run_refine_poc")
    loop = next((n for n in ast.walk(fn) if isinstance(n, ast.While)), None)
    assert loop, "the refine while-loop is gone"
    # The check must be in the first few statements of the loop body, and
    # before anything that dispatches.
    # The guard must be a LIVE condition, not merely present. `if False and
    # _build_poc_cancel_requested(run_id)` kept this test green while
    # disabling the cancel entirely — caught by sabotage.
    guard = None
    for stmt in loop.body[:3]:
        if isinstance(stmt, ast.If) and "_build_poc_cancel_requested" in ast.unparse(stmt.test):
            guard = stmt.test
            break
    assert guard is not None, (
        "the cancel flag is not checked at the top of the loop — a cancelled "
        "run would dispatch at least once more at the target")
    # Reject a constant that can short-circuit the call away.
    consts = [n for n in ast.walk(guard) if isinstance(n, ast.Constant)
              and isinstance(n.value, bool)]
    assert not consts, (
        f"the cancel condition contains a literal boolean ({ast.unparse(guard)}) "
        "— the check is present but cannot fire")
    assert isinstance(guard, ast.Call) or isinstance(guard, ast.UnaryOp), (
        f"the cancel condition is not a direct call: {ast.unparse(guard)}")
    body = ast.unparse(loop.body)
    i_cancel = body.find("_build_poc_cancel_requested")
    i_disp = body.find("_listener_vectors_run")
    if i_disp > 0:
        assert i_cancel < i_disp, (
            "the cancel check comes AFTER the dispatch in the loop body")


def test_cancelling_sets_a_stop_reason():
    src = _src("_run_refine_poc")
    i = src.find("_build_poc_cancel_requested")
    assert i > 0
    window = src[i:i + 400]
    assert "cancelled" in window, (
        "a cancelled run records no stop reason, so it is indistinguishable "
        "from one that finished on its own terms")


def test_the_flag_is_cleared_when_acted_on():
    """Otherwise the set grows forever and a reused id is pre-cancelled."""
    src = _src("_run_refine_poc")
    i = src.find("_build_poc_cancel_requested")
    assert "_build_poc_cancel_clear" in src[i:i + 400], (
        "the cancel flag is never cleared")


def test_cancel_is_thread_safe():
    """Set from an HTTP handler, read from a worker thread."""
    for name in ("request_build_poc_cancel", "_build_poc_cancel_requested"):
        src = _src(name)
        assert "_build_poc_cancel_lock" in src, (
            f"{name} touches the shared set without the lock")


def test_cancel_reports_whether_the_run_was_known():
    """A flag set on an unknown id is harmless but must not read as success."""
    src = _src("build_poc_cancel")
    assert "was_running" in src, (
        "the cancel response does not say whether the run was actually in "
        "flight, so a typo'd id looks identical to a real cancel")


# -- 4-6. the duplicate guard -----------------------------------------------

def test_a_duplicate_is_refused_by_default():
    src = _src("build_poc_endpoint")
    assert "stop_reason IS NULL" in src, (
        "the submit path does not look for an in-flight run of the same "
        "CVE+target, so pressing Build twice starts two builds")
    assert "409" in src, (
        "a duplicate submit is not refused with 409 — it either starts a "
        "second build or fails with a status that reads as a server error")


def test_the_refusal_names_the_run_already_going():
    src = _src("build_poc_endpoint")
    i = src.find("409")
    window = src[max(0, i - 200):i + 600]
    assert "run_id" in window, (
        "the refusal does not name the run already in flight, so the operator "
        "cannot watch or cancel it")
    assert "cancel" in window, (
        "the refusal does not tell the operator how to stop the existing run")


def test_the_override_exists_and_defaults_off():
    src = API.read_text(encoding="utf-8")
    cls = next((n for n in ast.walk(ast.parse(src))
                if isinstance(n, ast.ClassDef) and n.name == "BuildPocBody"), None)
    assert cls, "BuildPocBody not found"
    fields = {s.target.id: s for s in cls.body if isinstance(s, ast.AnnAssign)}
    assert "force_duplicate" in fields, "no force_duplicate override"
    default = fields["force_duplicate"].value
    assert isinstance(default, ast.Constant) and default.value is False, (
        "force_duplicate does not default to False — duplicates would be "
        "allowed by default, which is the behaviour this guards against")


def test_a_failed_check_does_not_block_a_legitimate_build():
    """'Could not check' must neither refuse nor silently permit."""
    src = _src("build_poc_endpoint")
    i = src.find("duplicate-build check failed")
    assert i > 0, (
        "a failure of the duplicate check is not logged — it would either "
        "abort a legitimate build or permit a duplicate with no trace")


def test_the_guard_only_looks_at_recent_runs():
    """A stale `running` row must not block builds forever."""
    src = _src("build_poc_endpoint")
    i = src.find("stop_reason IS NULL")
    window = src[max(0, i - 300):i + 300]
    assert "interval" in window, (
        "the in-flight lookup has no time bound, so one crashed run that "
        "never wrote a stop_reason blocks that CVE+target permanently")
