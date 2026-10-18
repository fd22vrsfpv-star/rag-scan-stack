"""An empty LLM reply ends a PoC build as `llm_unavailable`, never `max_iters`.

Run standalone:  pytest tests/test_refine_llm_unavailable.py -q

WHY THIS EXISTS
---------------
In `_run_refine_poc`, a refine reply with no usable command led to a bare
`break` that never set `_stop_reason`, so the build was recorded with the
default `max_iters`. On the 2026-10-18 CVE-Bench round, 4 of 11 builds stopped
after ONE iteration because the LLM path returned empty strings (a settings
outage routed every task to an uninstalled Ollama model), and every one of
them was reported as having exhausted its attempts. An outage read as an
exploit failure. Unreachable is not absent.

The guard is structural (AST over api.py), the same approach as
tests/test_refine_loop_escalation.py: the loop is too entangled to execute.
"""
import ast
import pathlib

import pytest

API = pathlib.Path(__file__).resolve().parents[1] / "app" / "rag-api" / "api.py"


def _refine_fn():
    if not API.exists():
        pytest.skip("api.py not present")
    tree = ast.parse(API.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_run_refine_poc":
            return node
    pytest.fail("_run_refine_poc not found in api.py")


def _mentions_command_get(test):
    """True for an `if` test that checks obj.get("command")."""
    for n in ast.walk(test):
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and n.func.attr == "get" and n.args
                and isinstance(n.args[0], ast.Constant)
                and n.args[0].value == "command"):
            return True
    return False


def _assigned_stop_reasons(stmts):
    """String values assigned to _stop_reason anywhere in `stmts`."""
    out = []
    for s in stmts:
        for n in ast.walk(s):
            if isinstance(n, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "_stop_reason"
                    for t in n.targets):
                for c in ast.walk(n.value):
                    if isinstance(c, ast.Constant) and isinstance(c.value, str):
                        out.append(c.value)
    return out


def _no_command_breaks(fn):
    """Every `if <no usable command>: ... break` block in the refine loop."""
    found = []
    for n in ast.walk(fn):
        if not isinstance(n, ast.If) or not _mentions_command_get(n.test):
            continue
        if any(isinstance(b, ast.Break) for b in ast.walk(ast.Module(n.body, []))):
            found.append(n)
    return found


def test_every_no_command_break_records_a_stop_reason():
    blocks = _no_command_breaks(_refine_fn())
    assert blocks, "no `obj.get('command')` break found -- has the loop moved?"
    silent = [b.lineno for b in blocks if not _assigned_stop_reasons(b.body)]
    assert not silent, (
        "api.py line(s) %s break out of the refine loop on a reply with no "
        "command without setting _stop_reason, so the build is recorded as "
        "max_iters -- an LLM outage reads as an exhausted exploit" % silent)


def test_empty_replies_stop_as_llm_unavailable():
    reasons = []
    for b in _no_command_breaks(_refine_fn()):
        reasons += _assigned_stop_reasons(b.body)
    assert "llm_unavailable" in reasons, (
        "no path sets _stop_reason='llm_unavailable' when the refine LLM "
        "returns empty; got %s" % sorted(set(reasons)))
    assert "unparseable_reply" in reasons, (
        "a non-empty but unusable reply must be distinguished from an empty "
        "one; got %s" % sorted(set(reasons)))


def test_empty_reply_is_reasked_after_a_backoff_before_giving_up():
    src = ast.get_source_segment(API.read_text(encoding="utf-8"), _refine_fn())
    assert "_REFINE_EMPTY_BACKOFF_SEC" in src, (
        "the empty-reply path no longer waits before re-asking; a 429's "
        "Retry-After is seconds, so stopping immediately wastes the build")


def test_the_detector_catches_a_planted_silent_break():
    """Sabotage-proof: a bare break on a missing command must be flagged."""
    planted = ast.parse(
        "def _run_refine_poc():\n"
        "    for it in range(3):\n"
        "        obj = {}\n"
        "        if not obj or not obj.get('command'):\n"
        "            break\n").body[0]
    blocks = _no_command_breaks(planted)
    assert len(blocks) == 1
    assert _assigned_stop_reasons(blocks[0].body) == []
