"""The refine loop must COUNT what it dispatches and SAY when it could not look.

Two defects, same shape — work happened (or didn't) and the record disagreed:

  * `_timing_confirmation_rerun` re-runs the command against the target with a
    scaled payload. It touched no counter, so every `latency_confirmed` /
    `latency_unconfirmed` verdict reported one fewer target run than it made.
  * `_inband_baseline_diff` computes a `reason` on all four of its bail-out
    paths. The caller traced only `checked=True`, so an absent `inband_diff`
    row meant BOTH "the responses matched" and "we never looked" — unreachable
    read as absent, which is this repo's recurring bug.

These are AST guards over the repo source, NOT the deployed container, so they
fail before a rebuild rather than after one.

    docker run --rm -v /opt/rag-scan-stack:/repo -w /repo python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=.:tests \
      python -m pytest tests/test_refine_loop_accounting.py -v'
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"


@pytest.fixture(scope="module")
def refine_fn():
    tree = ast.parse(API.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == "_run_refine_poc":
            return node
    pytest.fail("_run_refine_poc not found in api.py")


def _call_name(node):
    f = getattr(node, "func", None)
    return getattr(f, "id", None) or getattr(f, "attr", None)


def _owning_block(fn, predicate):
    """The statement LIST containing the statement matching `predicate`.

    Returns (list, index). Needed because both guards are about what sits
    NEXT TO a statement, which `ast.walk` alone cannot tell you.
    """
    for parent in ast.walk(fn):
        for field in ("body", "orelse", "finalbody"):
            stmts = getattr(parent, field, None)
            if not isinstance(stmts, list):
                continue
            for i, st in enumerate(stmts):
                if predicate(st):
                    return stmts, i
    return None, None


def _mentions(node, text):
    return text in ast.dump(node)


class TestTimingConfirmationIsCounted:
    def test_the_rerun_increments_target_runs(self, refine_fn):
        """A dispatch that is not counted makes the metric a lie."""
        def is_conf_assign(st):
            return (isinstance(st, ast.Assign)
                    and isinstance(st.value, ast.Call)
                    and _call_name(st.value) == "_timing_confirmation_rerun")

        stmts, i = _owning_block(refine_fn, is_conf_assign)
        assert stmts is not None, (
            "_run_refine_poc no longer assigns the result of "
            "_timing_confirmation_rerun")

        for st in stmts[i + 1:i + 6]:
            if _mentions(st, "target_runs"):
                return
        pytest.fail(
            "the _timing_confirmation_rerun call site does not touch "
            "metrics['target_runs'] — the confirmation dispatches a real "
            "request, so every confirmed latency verdict is short by one")

    def test_the_increment_is_guarded_on_an_actual_dispatch(self, refine_fn):
        """`pattern is None` means nothing was sent; counting it is as wrong
        as not counting a real run."""
        def is_conf_assign(st):
            return (isinstance(st, ast.Assign)
                    and isinstance(st.value, ast.Call)
                    and _call_name(st.value) == "_timing_confirmation_rerun")

        stmts, i = _owning_block(refine_fn, is_conf_assign)
        guarded = [st for st in stmts[i + 1:i + 6]
                   if isinstance(st, ast.If) and _mentions(st, "target_runs")
                   and _mentions(st.test, "pattern")]
        assert guarded, (
            "metrics['target_runs'] must be incremented only when the "
            "confirmation actually dispatched (guard on `pattern`)")


class TestInbandDiffReportsWhyItCouldNotRun:
    def test_the_trace_is_not_nested_under_checked(self, refine_fn):
        """The bail-out reasons exist; the caller must emit them.

        This is the whole bug: the trace sat INSIDE `if _ib.get("checked")`,
        so the three-outcome information the helper computed was discarded.
        """
        def is_ib_assign(st):
            return (isinstance(st, ast.Assign)
                    and isinstance(st.value, ast.Call)
                    and _call_name(st.value) == "_inband_baseline_diff")

        stmts, i = _owning_block(refine_fn, is_ib_assign)
        assert stmts is not None, "_inband_baseline_diff call site not found"

        for st in stmts[i + 1:]:
            # the trace must come FIRST, as a sibling of the checked-branch
            if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) \
                    and _call_name(st.value) == "_poc_trace" \
                    and _mentions(st.value, "inband_diff"):
                return
            if isinstance(st, ast.If) and _mentions(st.test, "checked"):
                pytest.fail(
                    "the inband_diff trace is still nested under "
                    "`if _ib.get('checked')` — a bail-out leaves no row, so "
                    "'never looked' is indistinguishable from 'no difference'")
        pytest.fail("no unconditional inband_diff trace found after the call")

    def test_the_helper_still_supplies_a_reason(self):
        """The guard above is only worth having while there is a reason to
        emit. If the helper stops producing one, this fails instead."""
        tree = ast.parse(API.read_text(encoding="utf-8"))
        fn = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef)
                   and n.name == "_inband_baseline_diff"), None)
        assert fn is not None, "_inband_baseline_diff not found"
        returns_with_reason = [
            n for n in ast.walk(fn)
            if isinstance(n, ast.Return) and n.value is not None
            and _mentions(n.value, "reason")]
        assert len(returns_with_reason) >= 3, (
            "_inband_baseline_diff should report a reason on each bail-out; "
            f"found {len(returns_with_reason)}")
