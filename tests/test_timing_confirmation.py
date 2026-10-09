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


def _rag_api_up():
    try:
        r = subprocess.run(
            ["docker", "exec", "rag-api", "sh", "-lc",
             "curl -sk https://localhost:8000/health -o /dev/null -w '%{http_code}'"],
            capture_output=True, text=True, timeout=6)
        return r.returncode == 0 and r.stdout.strip() == "200"
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _rag_api_up(), reason="rag-api container not reachable")


def _in_container(py_snippet):
    r = subprocess.run(
        ["docker", "exec", "rag-api", "python3", "-c", py_snippet],
        capture_output=True, text=True, timeout=15)
    return r.stdout.strip(), r.stderr.strip(), r.returncode


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
