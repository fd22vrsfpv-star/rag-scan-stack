"""A command that drifted off the CVE's endpoint cannot verify itself.

`drifted` means the command attacked a DIFFERENT endpoint than the one the CVE
lives on. It was detected, traced, and then ignored — so a local regex match on
a drifted command counted as proof, and the PoC was stored as a security_test.

CVE-2024-31611 on 2026-10-14, from the run trace:

    drift   : command target ('172.19.125.116:80', '/search.php')
              != CVE endpoint ('172.19.125.116:80', '/admin_template.php')
    run     : PRERUN_PROBE_FAIL ... status=404 ... exploit will all_404
    output  : the canary, ten times, then MARKER_FOUND
    result  : success=True verified=True drifted=True
              security_test_id=acb4162b-7173-48a5-b5d5-540821ebb004

The canary appearing proves the command printed the canary. On the CVE's own
endpoint that is the agreed proof; on a different endpoint it is evidence of
nothing — and here the CVE's endpoint had already 404'd.

So a drifted command needs INDEPENDENT confirmation: the benchmark harness's
own verdict, or a method anchored by construction (timing measures the server's
behaviour, not our own output, so a drifted timing proof is still a measurement
of the target).

Static (`ast`) — no DB, no running stack.

Sabotage check: delete the `if verified and drifted` block, or add "regex" to
the methods that survive drift, and the matching case fails.

    pytest tests/test_drift_blocks_verification.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"

# Methods whose proof does not come from our own output.
SURVIVES_DRIFT = {"benchmark_oracle", "latency_confirmed", "latency_confirmed_anchored"}


def _drift_guard() -> ast.If:
    if not API.exists():
        pytest.skip(f"{API} not found")
    for node in ast.walk(ast.parse(API.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.If):
            continue
        names = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
        if {"verified", "drifted"} <= names:
            return node
    pytest.fail("no `if verified and drifted ...` guard found — a drifted "
                "command can still verify itself from its own output")


def test_drift_clears_verified():
    guard = _drift_guard()
    assigns = [n for n in ast.walk(guard) if isinstance(n, ast.Assign)]
    cleared = any(
        any(isinstance(t, ast.Name) and t.id == "verified" for t in a.targets)
        and isinstance(a.value, ast.Constant) and a.value.value is False
        for a in assigns)
    assert cleared, (
        "the drift guard does not set verified=False — drift is recorded and "
        "then ignored, which is how a 404'd endpoint produced a stored PoC")


def test_only_independent_methods_survive_drift():
    """Anything judged from our own output must not pass while drifted."""
    guard = _drift_guard()
    allowed = {n.value for n in ast.walk(guard.test)
               if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert allowed, "the guard exempts no method at all — even a harness-confirmed pass would be discarded"
    assert allowed <= SURVIVES_DRIFT, (
        f"methods exempted from the drift rule that judge our own output: "
        f"{sorted(allowed - SURVIVES_DRIFT)}. A marker we printed is not proof "
        "on an endpoint the CVE does not live on.")
    assert "regex" not in allowed, (
        "a plain regex match survives drift again — that is exactly the "
        "CVE-2024-31611 false positive")


def test_the_guard_runs_before_the_stop_reason_is_fixed():
    """Otherwise the row still reports success while verified is False."""
    guard = _drift_guard()
    stop = [n for n in ast.walk(guard)
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "_stop_reason" for t in n.targets)]
    assert stop, (
        "the drift guard does not set _stop_reason — the attempt row would "
        "still say 'success' for a run that is no longer verified")
