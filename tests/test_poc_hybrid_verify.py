"""Executes the hybrid regex+semantic verdict helper.

Verifies the four verification methods (regex / canary_loose / semantic /
rejected_error) + the canary-grounded safety check on semantic.
Skips cleanly when rag-api isn't up; sabotage-proven per CLAUDE.md.
"""
import json
import subprocess
import pytest


def _rag_api_up():
    try:
        r = subprocess.run(
            ["docker", "exec", "rag-api", "sh", "-lc",
             "curl -sk https://localhost:8000/health -o /dev/null -w '%{http_code}'"],
            capture_output=True, text=True, timeout=6,
        )
        return r.returncode == 0 and r.stdout.strip() == "200"
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _rag_api_up(), reason="rag-api container not reachable")


def _in_container(py_snippet, env=None):
    env_args = []
    for k, v in (env or {}).items():
        env_args.extend(["-e", f"{k}={v}"])
    r = subprocess.run(
        ["docker", "exec"] + env_args + ["rag-api", "python3", "-c", py_snippet],
        capture_output=True, text=True, timeout=15,
    )
    return r.stdout.strip(), r.stderr.strip(), r.returncode


def test_regex_match_tier():
    """Direct regex match returns method='regex' confidence=1.0."""
    py = """
import sys; sys.path.insert(0, '/app')
from api import _poc_assertion_verdict
v = _poc_assertion_verdict({'expect_regex': 'POCzABC', 'canary': 'POCzABC'},
                            'response contains POCzABC marker', 0)
print(v['method'], v['passed'], v['confidence'])
"""
    out, err, rc = _in_container(py)
    assert rc == 0, f"stderr: {err}"
    assert out.split() == ["regex", "True", "1.0"], f"got: {out!r}"


def test_canary_loose_tier_when_regex_misses_but_canary_present():
    """Regex missed; canary still in output -> method='canary_loose' confidence 0.85."""
    py = """
import sys; sys.path.insert(0, '/app')
from api import _poc_assertion_verdict
# Regex is specific but doesn't match; canary IS in output
v = _poc_assertion_verdict({'expect_regex': 'created user: POCzABC in db',
                             'canary': 'POCzABC'},
                            '{"username": "POCzABC", "created": true}', 0)
print(v['method'], v['passed'], v['confidence'])
"""
    out, err, rc = _in_container(py)
    assert rc == 0, f"stderr: {err}"
    assert out.split() == ["canary_loose", "True", "0.85"], f"got: {out!r}"


def test_regex_missed_canary_missing_refuses():
    """Canary missing from output -> method='regex_missed' and refuses to pass.
    Semantic verifier is NOT called (would be ungrounded hallucination risk)."""
    py = """
import sys; sys.path.insert(0, '/app')
from api import _poc_assertion_verdict
v = _poc_assertion_verdict({'expect_regex': 'POCzABC', 'canary': 'POCzABC'},
                            'response has no marker at all', 0)
print(v['method'], v['passed'])
"""
    out, err, rc = _in_container(py)
    assert rc == 0, f"stderr: {err}"
    assert out.split() == ["regex_missed", "False"], f"got: {out!r}"


def test_shell_error_marker_rejects():
    """Output containing /bin/sh: syntax error wins over any regex match."""
    py = """
import sys; sys.path.insert(0, '/app')
from api import _poc_assertion_verdict
v = _poc_assertion_verdict({'expect_regex': 'POCzABC', 'canary': 'POCzABC'},
                            '/bin/sh: 1: Syntax error: Unterminated quoted string POCzABC', 0)
print(v['method'], v['passed'])
"""
    out, err, rc = _in_container(py)
    assert rc == 0, f"stderr: {err}"
    assert out.split() == ["rejected_error", "False"], f"got: {out!r}"


def test_semantic_fallback_refuses_without_canary():
    """When canary isn't in output, the semantic fallback refuses — guarantees
    semantic doesn't invent passes on exploits that didn't inject their marker."""
    py = """
import sys; sys.path.insert(0, '/app')
from api import _poc_assertion_verdict_with_semantic
v = _poc_assertion_verdict_with_semantic(
    {'expect_regex': 'POCzABC', 'canary': 'POCzABC'},
    'response that mentions no canary at all', 0,
    rationale='test', model=None)
print(v['method'], v['passed'])
"""
    out, err, rc = _in_container(py)
    assert rc == 0, f"stderr: {err}"
    # Method is regex_missed; passed is False — semantic never fired
    assert out.split() == ["regex_missed", "False"], f"got: {out!r}"


def test_default_truthy_no_assertion():
    """No regex, no shell flag, no canary: non-empty output + exit 0 = default_truthy."""
    py = """
import sys; sys.path.insert(0, '/app')
from api import _poc_assertion_verdict
v = _poc_assertion_verdict({}, 'some response', 0)
print(v['method'], v['passed'], v['confidence'])
"""
    out, err, rc = _in_container(py)
    assert rc == 0, f"stderr: {err}"
    assert out.split() == ["default_truthy", "True", "0.5"], f"got: {out!r}"


def test_poc_assertion_passes_backward_compat():
    """Original boolean function still works for every pre-existing caller."""
    py = """
import sys; sys.path.insert(0, '/app')
from api import _poc_assertion_passes
# Regex match
assert _poc_assertion_passes({'expect_regex': 'ABC', 'canary': 'ABC'}, 'ABC here') is True
# Shell error dominates
assert _poc_assertion_passes({'expect_regex': 'ABC', 'canary': 'ABC'},
                              '/bin/sh: Syntax error ABC') is False
print('OK')
"""
    out, err, rc = _in_container(py)
    assert rc == 0 and "OK" in out, f"stderr: {err}"
