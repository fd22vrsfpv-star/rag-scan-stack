"""A failed iteration must say WHAT was tried and WHAT came back.

Why this exists
---------------
The build summary rendered its iterations as `#1 FAILED / #2 FAILED / #3
FAILED / #4 FAILED` and nothing else. That tells an operator an attempt
happened and neither of the two things they actually want to know: the command
that was dispatched, and the target's answer.

The `run` trace row has carried both all along — `extra.command`, plus the
verdict's own `reason`/`method`/`error_tier` — and `_summarize_build_trace`
simply dropped them, keeping a 200-char `output_head` whose first 400
characters of a curl run are HTTP headers.

Read with `ast`/text rather than importing api.py: that module needs fastapi
and psycopg2, absent on a bare checkout.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"

pytestmark = pytest.mark.skipif(not API.exists(), reason="rag-api source not present")


def _summary_fn() -> ast.FunctionDef:
    tree = ast.parse(API.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_summarize_build_trace":
            return node
    raise AssertionError("_summarize_build_trace not found")


def _iteration_append_keys() -> set[str]:
    """Keys of the dict appended to s['iterations_summary']."""
    for node in ast.walk(_summary_fn()):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        if not (isinstance(fn, ast.Attribute) and fn.attr == "append"):
            continue
        # s["iterations_summary"].append({...})
        tgt = fn.value
        if not (isinstance(tgt, ast.Subscript)
                and isinstance(tgt.slice, ast.Constant)
                and tgt.slice.value == "iterations_summary"):
            continue
        assert node.args and isinstance(node.args[0], ast.Dict), \
            "iterations_summary must be appended a dict literal"
        return {k.value for k in node.args[0].keys if isinstance(k, ast.Constant)}
    raise AssertionError("no append to iterations_summary found")


def test_iteration_carries_what_was_tried_and_what_came_back():
    keys = _iteration_append_keys()
    # What was tried.
    assert "command" in keys, "the dispatched command is the whole point of 'what was tried'"
    # What came back.
    assert "output_head" in keys
    # Why it was judged that way — usually the entire answer on one line.
    assert "reason" in keys
    assert "method" in keys
    # Which axis the outcome killed, so the next move is obvious.
    assert "error_tier" in keys
    # Still there.
    assert {"iter", "status"} <= keys


def test_output_head_is_not_truncated_below_its_own_slice():
    """`out` is sliced once when read and again when stored. If the first slice
    is the smaller of the two, the second is decorative and the stored head is
    silently shorter than it claims."""
    src = API.read_text(encoding="utf-8")
    i = src.index("def _summarize_build_trace")
    body = src[i:i + 12000]
    read_slice = body.index('out = str(e.get("run_output") or "")[:')
    read_cap = int(body[read_slice:].split("[:", 1)[1].split("]", 1)[0])
    store_cap = int(body.split('"output_head": out[:', 1)[1].split("]", 1)[0])
    assert read_cap >= store_cap, (
        f"run_output is read at {read_cap} chars but stored at {store_cap} — "
        "the stored head can never reach its own cap")


def test_iteration_fields_are_bounded():
    """Every iteration ships in the summary payload; an unbounded command or
    output would put a whole run's stdout in a page that renders 15 of them."""
    src = API.read_text(encoding="utf-8")
    seg = src.split('s["iterations_summary"].append(', 1)[1].split("})", 1)[0]
    for field in ("command", "reason", "output_head"):
        assert f'"{field}"' in seg, f"{field} missing from the appended dict"
    # Each of the three carries an explicit slice.
    assert seg.count("[:") >= 3, "command / reason / output_head must each be capped"


def test_truncated_command_is_labelled_not_silent():
    """A command cut mid-token shows unbalanced quotes and reads as "the
    generator emits broken shell". It does not — `_dry_parse_command` refuses
    malformed shell BEFORE dispatch (426 refusals on record as of
    2026-10-19). The cut was a display cap in the trace emit, at 600 chars,
    cutting tails like `slee` and `sleep`.

    So the true length travels with the slice, and the UI says it is a slice.
    Without it, a display cap is indistinguishable from a generator bug —
    which is exactly how it was reported."""
    src = API.read_text(encoding="utf-8")
    seg = src.split('s["iterations_summary"].append(', 1)[1].split("})", 1)[0]
    assert "command_len" in seg, (
        "the iteration must carry the command's TRUE length beside the slice")

    # And the trace emit must record it too, or there is nothing to carry.
    run_emit = src.split('_poc_trace(run_id, "run"', 1)[1].split("})", 1)[0]
    assert "command_len" in run_emit, \
        "the run trace row must record the command's true length"


def test_the_run_trace_keeps_more_of_the_command_than_the_summary():
    """The trace is the reviewer's primary artifact; the summary is a preview
    of it. A trace cap at or below the summary's cap makes the summary's own
    length figure a lie — it would report the trace's cut as the true length."""
    src = API.read_text(encoding="utf-8")
    run_emit = src.split('_poc_trace(run_id, "run"', 1)[1].split("})", 1)[0]
    trace_cap = int(run_emit.split('"command": (command or "")[:', 1)[1].split("]", 1)[0])
    seg = src.split('s["iterations_summary"].append(', 1)[1].split("})", 1)[0]
    summary_cap = int(seg.split('"command": str(extra.get("command") or "")[:', 1)[1].split("]", 1)[0])
    assert trace_cap > summary_cap, (
        f"trace keeps {trace_cap} chars but the summary keeps {summary_cap} — "
        "the trace must hold at least as much as its own preview")
