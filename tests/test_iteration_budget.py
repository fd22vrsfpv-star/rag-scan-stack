"""`max_iters` counts ATTEMPTS, not passes.

Why this exists
---------------
A pass that never produced exploit traffic must not spend an iteration, and
must not read as a failed attempt.

Two ways a pass produces nothing:

 * refused BEFORE dispatch — bad shell caught by the dry-parse, LLM refusal
   prose, a proven-fact violation, a failed prerun probe. `_dispatched_attempts`
   already skipped these, but the `run` row was still written with
   `assertion_passed=False` and every reader counted it. Worse,
   `it = _dispatched_attempts + 1`, so a refused pass and the real attempt
   after it SHARE an iteration number — CVE-2024-5452 wrote five rows all
   labelled `iter 3`.

 * rejected by the REMOTE shell — the listener ran, so `target_runs` moved and
   the attempt WAS charged, but the shell could not parse the command so none
   of it executed. **117 of 4,280 dispatched runs** in the trace archive are
   these, dominated by 86 x `"(" unexpected` (valid bash, invalid dash). Under
   a max_iters of 4 one of them is a quarter of the budget, spent on a quoting
   mistake and then filed as evidence the approach failed.

Read with `ast`/structure rather than importing api.py.
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _ast_assert import function_source  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"

pytestmark = pytest.mark.skipif(not API.exists(), reason="rag-api source not present")


def _src() -> str:
    return API.read_text(encoding="utf-8")


def _detector():
    """Execute just the detector so its behaviour, not its text, is tested."""
    src = _src()
    i = src.index("def _is_shell_syntax_failure")
    fn = src[i:src.index("_PRE_DISPATCH_MARKERS = (")]
    ns: dict = {}
    exec(compile(fn, "<detector>", "exec"), ns)  # noqa: S102
    return ns["_is_shell_syntax_failure"]


def test_detector_matches_every_real_shell_error_form():
    f = _detector()
    # All captured verbatim from /app/poc_logs.
    for text in (
        "/bin/sh: 1: Syntax error: Unterminated quoted string",
        '/bin/sh: 12: Syntax error: "(" unexpected',
        '/bin/sh: 3: Syntax error: "(" unexpected (expecting ")")',
        "/bin/sh: 7: Syntax error: redirection unexpected",
        "/bin/bash: line 3: syntax error near unexpected token",
    ):
        assert f(text), f"did not detect: {text!r}"


def test_detector_ignores_a_target_echoing_the_phrase():
    """A response body containing the words must not be read as the shell's
    own error — that would refund an attempt that really did run."""
    f = _detector()
    for text in (
        '{"detail":"Method Not Allowed"}',
        "HTTP/1.1 200 OK\nthe page says Syntax error: something",
        "EXPLOIT FAILED",
        "",
        None,
    ):
        assert not f(text), f"false positive on: {text!r}"


def _charge_branch() -> ast.If:
    """The `if <shell error> ... elif <target_runs moved> ...` chain, as AST."""
    fn = None
    for node in ast.walk(ast.parse(_src())):
        if isinstance(node, ast.FunctionDef) and "_run_refine_poc" in node.name:
            fn = node
    assert fn is not None, "_run_refine_poc not found"
    for node in ast.walk(fn):
        if (isinstance(node, ast.If)
                and any(isinstance(n, ast.Name) and n.id == "_remote_syntax"
                        for n in ast.walk(node.test))):
            return node
    raise AssertionError("no branch tests _remote_syntax")


def test_remote_syntax_failure_does_not_charge_an_attempt():
    """Structural: the shell-error branch must come FIRST and the charge must
    be its `elif`. A remote parse error DOES move target_runs, so an
    independent `if` would spend the attempt before the refund is considered —
    the ordering is the whole fix."""
    node = _charge_branch()
    # The refund branch must not itself charge.
    charged_in_refund = any(
        isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name)
        and n.target.id == "_dispatched_attempts"
        for n in ast.walk(ast.Module(body=node.body, type_ignores=[])))
    assert not charged_in_refund, "the refund branch must not spend an attempt"
    # ...and the charge lives in the else-chain below it.
    assert node.orelse, "the charge must be the elif of the syntax branch"
    charged_in_else = any(
        isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name)
        and n.target.id == "_dispatched_attempts"
        for n in ast.walk(ast.Module(body=node.orelse, type_ignores=[])))
    assert charged_in_else, "a dispatched pass must still be charged"


def test_a_refunded_pass_still_counts_toward_the_model_swap():
    """Refunding the budget must not make a model that cannot write shell loop
    forever: `_consecutive_syntax_fails` drives the fallback swap."""
    node = _charge_branch()
    body = ast.Module(body=node.body, type_ignores=[])
    assert any(isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name)
               and n.target.id == "_consecutive_syntax_fails"
               for n in ast.walk(body)), \
        "a refunded pass must still count toward the model-fallback swap"
    traced = {c.value for n in ast.walk(body) if isinstance(n, ast.Call)
              for c in n.args if isinstance(c, ast.Constant)}
    assert "iteration_not_charged" in traced, "the refund must be visible in the trace"


def test_summary_separates_repairs_from_attempts():
    seg = function_source(_src(), "_summarize_build_trace") or ""
    assert "pre_dispatch_refusals" in seg, \
        "passes that never reached the target need their own bucket"
    # The attempt list must be skipped for them.
    assert re.search(r"if not _disp:.*?continue", seg, re.S), \
        "a non-dispatched pass must not fall through into iterations_summary"


def test_older_traces_are_classified_by_their_refusal_markers():
    """Every trace on disk predates the `dispatched` flag, so the fallback is
    what classifies the archive. Each marker is a fixed prefix written by
    exactly one pre-dispatch branch."""
    markers = None
    for node in ast.walk(ast.parse(_src())):
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "_PRE_DISPATCH_MARKERS"
                        for t in node.targets)):
            markers = {c.value for c in ast.walk(node.value)
                       if isinstance(c, ast.Constant)}
    assert markers, "_PRE_DISPATCH_MARKERS not found"
    joined = " ".join(markers)
    for needed in ("pre-dispatch", "PRERUN_PROBE_FAIL", "[proxy] REFUSED"):
        assert needed in joined, f"{needed!r} missing from the marker table"
    seg = function_source(_src(), "_summarize_build_trace") or ""
    assert "_PRE_DISPATCH_MARKERS" in seg, "the fallback must consult the markers"


def test_bash_parse_check_is_advisory_not_a_refusal():
    """`bash -n` must NOT refuse a dispatch.

    Measured on the trace archive, replaying every COMPLETE stored command:
    23 of 1,368 commands that RAN FINE are rejected by bash (1.7%). They are
    the nested-quote `grep -oP` shapes that go down the PYTHON lane
    (`_curl_to_request` turns the curl into an HTTP request), where bash
    grammar never applies. And the classes do not separate — 15 of the 23 are
    `unexpected EOF while looking for matching`, the same class as a genuine
    unterminated quote — so no error type can be refused safely.

    Enforcing it would block ~1.7% of working builds to catch a class that is
    already near-zero: the remote shell errors stopped on 2026-10-15 when the
    executor switched to bash, and there have been none since.
    """
    seg = function_source(_src(), "_poc_shell_syntax_check") or ""
    assert '"bash", "-n", "-c"' in seg, "the shell's own parser must be consulted"
    # Find the return that carries the bash error; it must report ok=True.
    fn = None
    for node in ast.walk(ast.parse(_src())):
        if isinstance(node, ast.FunctionDef) and node.name == "_poc_shell_syntax_check":
            fn = node
    assert fn is not None
    bash_returns = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple)
        and "bash -n" in ast.dump(n.value)
    ]
    assert bash_returns, "no return carries the bash -n result"
    for r in bash_returns:
        first = r.value.elts[0]
        assert isinstance(first, ast.Constant) and first.value is True, (
            "the bash -n leg must return ok=True — refusing on it blocks "
            "working Python-lane commands")


def test_bash_parse_check_cannot_execute_the_command():
    """These are attack commands. The validator must PARSE them, never run
    them: `-n` plus an argv element, never shell=True or interpolation."""
    fn = None
    for node in ast.walk(ast.parse(_src())):
        if isinstance(node, ast.FunctionDef) and node.name == "_poc_shell_syntax_check":
            fn = node
    for call in ast.walk(fn):
        if not (isinstance(call, ast.Call) and "run" in ast.dump(call.func)):
            continue
        dumped = ast.dump(call)
        if "bash" not in dumped:
            continue
        assert "'-n'" in dumped or '"-n"' in dumped or "value='-n'" in dumped, \
            "bash must be invoked with -n (parse, do not execute)"
        for kw in call.keywords:
            assert kw.arg != "shell", "never shell=True around an attack command"
        assert any(kw.arg == "timeout" for kw in call.keywords), \
            "the validator must be bounded"


def test_bash_parse_check_fails_open():
    """A validator that cannot run must never read as 'the command is bad' —
    this repo's recurring unreachable-is-not-absent bug."""
    seg = function_source(_src(), "_poc_shell_syntax_check") or ""
    tail = seg[seg.index('"bash", "-n", "-c"'):]
    assert "except FileNotFoundError" in tail, "a missing bash must not block dispatch"
    assert tail.count("pass") >= 2, "both failure paths must fall through"
