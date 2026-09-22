"""`/access/run` executes against a host, so it passes the scope gate.

WHY THIS EXISTS
---------------
`access_run` runs an arbitrary command through access the platform already holds
— a shell, a credential — and it called `check_dispatch` ZERO times. Its
docstring argued the access "was already obtained by an approved exploit or a
discovered credential", which is a real argument, and it is why the endpoint is
deliberately NOT bounded by the tool allow-list.

But holding access is not the same as being authorised to use it *now*. An
engagement can be purged, or a scope narrowed, after the shell was obtained; the
prior approval no longer describes current authorisation. CLAUDE.md admits no
exception: every code path that sends traffic to a host passes the gate, fail
closed.

THE EMPTY-TARGET HOLE. `check_dispatch("")` returns None — i.e. ALLOWED
(measured). So "no target" cannot be delegated to the gate; the endpoint must
refuse it itself, or a caller that simply omits `target` bypasses the check.

Sabotage: drop the enforce_scope call, or the empty-target refusal -> the
matching test fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
LISTENER = os.path.join(REPO, "kali_listener", "listener_service.py")


def _handler():
    if not os.path.exists(LISTENER):
        pytest.skip("listener_service.py not present")
    src = open(LISTENER, encoding="utf-8").read()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "access_run":
            return ast.get_source_segment(src, n), src
    pytest.fail("access_run not found")


def test_access_run_enforces_scope():
    body, _ = _handler()
    calls = {getattr(c.func, "id", None) or getattr(c.func, "attr", None)
             for c in ast.walk(ast.parse(body.lstrip())) if isinstance(c, ast.Call)}
    assert "enforce_scope" in calls, (
        "/access/run executes a command against a host without passing the scope "
        "gate — holding access is not the same as being authorised to use it now")


def test_an_unresolvable_target_is_refused_not_allowed():
    """check_dispatch("") returns None (allowed), so the endpoint must refuse."""
    body, _ = _handler()
    assert "no resolvable target" in body, (
        "/access/run does not refuse a request whose target cannot be resolved. "
        "check_dispatch('') returns None — allowed — so falling through to the "
        "gate is a silent bypass")
    # the refusal must come BEFORE the transport is invoked
    tree = ast.parse(body.lstrip())
    raise_lines = [n.lineno for n in ast.walk(tree) if isinstance(n, ast.Raise)]
    call_lines = [n.lineno for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "fn"]
    assert raise_lines, "no refusal path at all"
    if call_lines:
        assert min(raise_lines) < min(call_lines), (
            "the transport runs before the scope refusal — the command would "
            "already have executed")


def test_the_gate_is_the_shared_one():
    """Reuse, not a second implementation: a private copy is how the BFF and the
    listener drifted into three copies of the scope rules before."""
    body, src = _handler()
    assert "enforce_scope" in body
    assert "def enforce_scope(" in src, "the shared helper is gone"
    assert "check_dispatch" in src, "enforce_scope no longer delegates to the gate"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))


def test_only_host_port_handles_have_a_host_recovered():
    """An ssh_credential handle is `user:secret` and an msf_session handle is a
    session id. Splitting those would check a USERNAME as a hostname — observed
    live: handle "u:p" was gated as target "u", which would wrongly PASS if a
    username ever matched an in-scope host."""
    body, _ = _handler()
    assert "bind_shell" in body and "listener_callback" in body, (
        "the host-recovery fallback is not restricted to the kinds whose handle "
        "is host:port — a username would be treated as a hostname")
    # and the restriction must guard the split, not merely appear somewhere
    idx = body.find("rsplit")
    assert idx != -1, "no host recovery at all"
    assert "request.kind in" in body[:idx], (
        "the handle is split before the kind is checked")
