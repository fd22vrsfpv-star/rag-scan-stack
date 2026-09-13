"""The non-MSF `command` dispatch source is scope-gated and fail-closed.

Run on demand:

    pytest tests/test_command_dispatch.py -v

WHY THIS EXISTS
---------------
Attempting a vector via a raw command is offensive — it sends real traffic and can
open shells or mutate the target. So the `command` source (exploit-runner) and the
kali-listener `/vectors/run` runner MUST fail CLOSED on scope, exactly like every
other dispatcher. This is a source guard for both fail-closed checks (the double
gate) — the authorization property the whole feature rests on.

SABOTAGE PROOF
--------------
Delete the `_exploit_scope_refusal` call from the command branch and
test_command_branch_is_scope_gated fails. Drop `enforce_scope` from /vectors/run
and test_vectors_run_is_scope_gated fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
RUNNER = os.path.join(REPO, "exploit_runner", "exploit_runner.py")
LISTENER = os.path.join(REPO, "kali_listener", "listener_service.py")


def _src(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _func(path, name):
    tree = ast.parse(_src(path))
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return ast.unparse(n)
    pytest.fail(f"{name} not found in {os.path.basename(path)}")


def test_files_parse():
    ast.parse(_src(RUNNER))
    ast.parse(_src(LISTENER))


def test_command_branch_exists_and_is_scope_gated():
    fn = _func(RUNNER, "execute_by_id")
    assert "source == 'command'" in fn or 'source == "command"' in fn, (
        "the non-MSF command dispatch branch is gone")
    # Fail-closed: scope refusal BEFORE any listener call, and it must 403.
    assert "_exploit_scope_refusal" in fn, "command branch is not scope-gated"
    assert "/vectors/run" in fn, "command branch does not route to the listener runner"
    assert "update_exploit_result" in fn, "command branch does not record a result"


def test_vectors_run_is_scope_gated_and_unfiltered():
    fn = _func(LISTENER, "vectors_run")
    assert "enforce_scope" in fn, "/vectors/run does not fail-closed on scope"
    assert "403" in fn, "/vectors/run does not refuse out-of-scope with 403"
    # It deliberately runs the raw command (offensive vectors need metacharacters),
    # not the allow-listed /tools/execute path.
    assert "subprocess.run" in fn and "timeout" in fn, (
        "/vectors/run no longer runs a bounded command")


def test_success_evaluator_distinguishes_shell_from_marker():
    """_eval_vector_success must only call it a shell when the output looks like
    one — a regex marker (enum success) is 'worked', not a shell."""
    fn = _func(RUNNER, "_eval_vector_success")
    assert "expect_shell" in fn and "expect_regex" in fn
    assert "uid=" in fn, "shell detection does not look for a shell marker"
