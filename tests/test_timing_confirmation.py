"""Blind-timing verdict confirmation.

PROJECT RULE: A latency-based verdict (blind SQLi SLEEP, pg_sleep, WAITFOR,
BENCHMARK) is ALWAYS re-run with a scaled payload. The second run's elapsed
MUST track the scaled payload within tolerance — otherwise the first run
was a false positive (target was just slow) and the verdict is downgraded
to latency_unconfirmed.

This matters because a target that takes 5s to respond on every request
looks identical to a verified blind SQLi SLEEP(5) when you only look at
one run. The sqlmap-style confirmation (run again with SLEEP(12), expect
~12s) is the industry-standard way to tell them apart.

Guards:
  _timing_payload_scale  — recognizes SLEEP / pg_sleep / WAITFOR / BENCHMARK
                            and scales N by +delta
  _timing_confirmation_rerun — runs the scaled command through the listener,
                                verdict based on whether elapsed scales with
                                the payload
  _run_refine_poc        — fires the confirmation after any latency verdict;
                            downgrades to latency_unconfirmed on failure,
                            upgrades to latency_confirmed on success
"""
import subprocess
import pytest

from _container import container_python, service_healthy


def _rag_api_up():
    # Shared probe — see tests/_container.py. Was a private
    # subprocess.run(['docker','exec',...]) copy in nine modules.
    return service_healthy("rag-api")


pytestmark = pytest.mark.skipif(not _rag_api_up(), reason="rag-api container not reachable")


def _in_container(py_snippet):
    # Shared runner — see tests/_container.py::container_python.
    return container_python(py_snippet)


def test_scale_recognizes_sleep():
    """SLEEP(5) → SLEEP(12) when delta=7. Preserves int-ness."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _timing_payload_scale
cmd = "curl -d 'x=1 AND SLEEP(5)-- -' http://t/"
new, pat, old, new_n = _timing_payload_scale(cmd, delta=7)
assert pat == 'SLEEP', pat
assert old == 5.0 and new_n == 12.0, (old, new_n)
assert 'SLEEP(12)' in new, new
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err


def test_scale_recognizes_pg_sleep():
    """pg_sleep is PostgreSQL — same scaling behavior as MySQL SLEEP."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _timing_payload_scale
cmd = "pg_sleep(5)"
new, pat, old, new_n = _timing_payload_scale(cmd, delta=7)
assert pat == 'pg_sleep', pat
assert 'pg_sleep(12)' in new, new
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err


def test_scale_recognizes_waitfor():
    """MSSQL WAITFOR DELAY '0:0:5' → '0:0:12'."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _timing_payload_scale
cmd = "'; WAITFOR DELAY '0:0:5'-- -"
new, pat, _, _ = _timing_payload_scale(cmd, delta=7)
assert pat == 'WAITFOR', pat
assert "WAITFOR DELAY '0:0:12'" in new, new
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err


def test_scale_recognizes_benchmark_doubles_iter():
    """BENCHMARK(N, expr) scales iteration count by 2 (linear timing)."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _timing_payload_scale
cmd = "AND BENCHMARK(5000000, MD5('x'))"
new, pat, old, new_n = _timing_payload_scale(cmd, delta=7)
assert pat == 'BENCHMARK', pat
assert new_n == old * 2, (old, new_n)
assert 'BENCHMARK(10000000' in new, new
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err


def test_scale_returns_none_when_no_timing_payload():
    """A plain curl without SLEEP/pg_sleep/WAITFOR is NOT scalable — caller
    must treat as 'cannot confirm' rather than crash."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _timing_payload_scale
cmd = "curl -d 'name=admin' http://t/"
new, pat, old, new_n = _timing_payload_scale(cmd, delta=7)
assert pat is None
assert old is None and new_n is None
assert new == cmd, 'command should be returned unchanged when nothing matched'
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err


def test_confirmation_rejects_no_min_seconds():
    """A non-timing assertion must not trigger the confirmation re-run."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _timing_confirmation_rerun
# Pass a bogus listener — if the function tries to run it, we'd see a
# different reason. 'no min_seconds' means it bailed before dispatching.
r = _timing_confirmation_rerun('curl -d x', {}, '127.0.0.1', 80,
                                'http://nowhere', 'k', 1)
assert r['confirmed'] is False
assert 'no min_seconds' in r['reason'].lower(), r
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err


def test_confirmation_rejects_no_timing_payload():
    """A command without a scalable payload must bail with
    confirmed=False / pattern=None — caller downgrades to
    latency_unconfirmable (NOT latency_confirmed)."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _timing_confirmation_rerun
r = _timing_confirmation_rerun('curl http://t/', {'min_seconds': 5},
                                '127.0.0.1', 80, 'http://nowhere', 'k', 1)
assert r['confirmed'] is False
assert r['pattern'] is None
assert 'no timing payload' in r['reason'].lower(), r
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err


def test_refine_loop_fires_confirmation_on_latency_verdict():
    """Sabotage-proof guard: the refine loop MUST call the confirmation
    helper when a latency / latency_anchored verdict passes. If a future
    refactor removes the call, this test fails — forcing the author to
    either keep the confirmation OR explicitly document its removal."""
    py = r"""
import sys, inspect, ast; sys.path.insert(0,'/app')
import api
src = inspect.getsource(api._run_refine_poc)
tree = ast.parse(src)
# Walk calls; look for _timing_confirmation_rerun somewhere in the function
calls = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        f = getattr(node.func, 'id', None) or getattr(node.func, 'attr', None)
        if f: calls.add(f)
assert '_timing_confirmation_rerun' in calls, (
    'refine loop no longer calls _timing_confirmation_rerun — latency '
    'verdicts can now false-positive on slow targets')
# Also assert the downgrade logic for unconfirmed verdicts
assert 'latency_unconfirmed' in src, (
    'refine loop no longer downgrades unconfirmed latency verdicts')
assert 'latency_confirmed' in src, (
    'refine loop no longer upgrades confirmed latency verdicts')
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err


def test_connection_timeout_rejects_latency_assertion():
    """curl exit code 28 (connection timeout) must NEVER pass a timing
    assertion. The server never received the payload — the delay is
    infrastructure failure, not SLEEP success.

    Why: CVE-2024-3408 passed min_seconds=5 because a 10s connection
    timeout looked like SLEEP(10) succeeding. The target was unreachable."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _poc_assertion_verdict

# Case 1: curl exit code 28 with a timing assertion
v = _poc_assertion_verdict(
    {"min_seconds": 5},
    "curl: (28) Connection timed out after 10002 milliseconds",
    exit_code=28, elapsed_seconds=10.0)
assert v["passed"] is False, f"connection timeout must not pass: {v}"
assert v["method"] == "latency_connection_error", v["method"]

# Case 2: "Failed to connect" in output (no exit code available)
v2 = _poc_assertion_verdict(
    {"min_seconds": 5},
    "curl: (28) Failed to connect to 172.19.0.16 port 9090 after 135s: Could not connect to server",
    exit_code=None, elapsed_seconds=135.0)
assert v2["passed"] is False, f"failed-to-connect must not pass: {v2}"
assert v2["method"] == "latency_connection_error", v2["method"]

# Case 3: "No route to host"
v3 = _poc_assertion_verdict(
    {"min_seconds": 5},
    "curl: (7) Failed to connect - No route to host",
    exit_code=7, elapsed_seconds=6.0)
assert v3["passed"] is False, f"no-route must not pass: {v3}"
assert v3["method"] == "latency_connection_error", v3["method"]

# Case 4: normal SLEEP(5) output should STILL pass
v4 = _poc_assertion_verdict(
    {"min_seconds": 5},
    "<!DOCTYPE html>\\n<html>slow response</html>",
    exit_code=0, elapsed_seconds=5.5)
assert v4["passed"] is True, f"real timing should pass: {v4}"
assert v4["method"] == "latency", v4["method"]

print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err


def test_default_max_seconds_cap():
    """When max_seconds is not set, a default cap of min_seconds * 4 applies.
    A 135s connection timeout must not pass a min_seconds=5 assertion even
    when there is no connection-error signature in the output."""
    py = """
import sys; sys.path.insert(0,'/app')
from api import _poc_assertion_verdict

# 135s elapsed with min_seconds=5, no max_seconds, clean output
v = _poc_assertion_verdict(
    {"min_seconds": 5},
    "server returned an empty response after a long time",
    exit_code=0, elapsed_seconds=135.0)
assert v["passed"] is False, f"135s should exceed default cap of 20s: {v}"
assert v["method"] == "latency_too_slow", v["method"]

# 18s elapsed with min_seconds=5 should still pass (within 4x)
v2 = _poc_assertion_verdict(
    {"min_seconds": 5},
    "server delayed response",
    exit_code=0, elapsed_seconds=18.0)
assert v2["passed"] is True, f"18s within 4x of 5s should pass: {v2}"

# Explicit max_seconds still works — 135s passes when max_seconds=200
v3 = _poc_assertion_verdict(
    {"min_seconds": 5, "max_seconds": 200},
    "server delayed response",
    exit_code=0, elapsed_seconds=135.0)
assert v3["passed"] is True, f"explicit max_seconds=200 should allow 135s: {v3}"

print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err


def test_refine_loop_has_target_unreachable_exit():
    """Sabotage-proof guard: the refine loop MUST contain the
    target-unreachable early exit logic. If removed, runs waste their full
    iteration budget (50 × 135s = 112 min) on dead targets.

    Why: 5 of 7 refine-blocked CVEs in the focused-10 batch failed purely
    because target containers were down — every iteration returned curl: (28).
    """
    py = r"""
import sys, inspect, ast; sys.path.insert(0,'/app')
import api
src = inspect.getsource(api._run_refine_poc)

# The refine loop must track consecutive connection failures
assert '_consecutive_conn_fails' in src, (
    'refine loop no longer tracks consecutive connection failures')
assert 'target_unreachable' in src, (
    'refine loop no longer has target_unreachable stop reason')
assert 'CONN_FAIL_EXIT_AT' in src, (
    'refine loop no longer has configurable connection-fail threshold')

# The connection-error detection must check the key signatures
for sig in ['curl: (28)', 'Failed to connect', 'No route to host', 'ConnectError']:
    assert sig in src, f'refine loop missing connection-error signature: {sig}'

print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and 'OK' in out, err
