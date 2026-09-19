"""The offensive command lane (/vectors/run) must allow a multi-minute timeout.

Run on demand:

    pytest tests/test_vector_run_timeout.py -v

WHY THIS EXISTS
---------------
The impactful command lane (exploit-runner source='command' -> listener
/vectors/run) ran a confirmation command (e.g. a sqlmap deepen probe). The
runner sent timeout=60 and the listener hard-capped it at 180s
(`min(..., 180)`), which truncated sqlmap mid-run at higher --level/--risk. Both
sides are now configurable with minute-scale defaults (VECTOR_RUN_TIMEOUT) and a
higher, still-bounded ceiling (VECTOR_RUN_MAX_TIMEOUT).

SABOTAGE PROOF
--------------
Restore `min(int(request.timeout or 60), 180)` in vectors_run, or `"timeout": 60`
/ `timeout=90` in the runner's /vectors/run call, and the matching case fails.
"""
import os
import re

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LISTENER = os.path.join(REPO, "kali_listener", "listener_service.py")
RUNNER = os.path.join(REPO, "exploit_runner", "exploit_runner.py")


def _src(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} missing")
    return open(path, encoding="utf-8").read()


def test_listener_cap_is_raised_and_configurable():
    s = _src(LISTENER)
    assert "VECTOR_RUN_MAX_TIMEOUT" in s and "VECTOR_RUN_DEFAULT_TIMEOUT" in s, \
        "vector-run timeouts must be named constants"
    # the old 180s hard cap must be gone from the vectors_run clamp
    assert "min(int(request.timeout or 60), 180)" not in s, \
        "the 180s hard cap must be replaced by the configurable ceiling"
    assert "VECTOR_RUN_MAX_TIMEOUT" in s.split("def vectors_run")[1], \
        "vectors_run must clamp with VECTOR_RUN_MAX_TIMEOUT"
    # defaults are minute-scale, ceiling is well above the old 180s
    m = re.search(r'VECTOR_RUN_DEFAULT_TIMEOUT\s*=\s*int\(os\.environ\.get\("VECTOR_RUN_TIMEOUT",\s*"(\d+)"\)\)', s)
    mx = re.search(r'VECTOR_RUN_MAX_TIMEOUT\s*=\s*int\(os\.environ\.get\("VECTOR_RUN_MAX_TIMEOUT",\s*"(\d+)"\)\)', s)
    assert m and int(m.group(1)) >= 300, "default vector-run timeout should be >= 300s"
    assert mx and int(mx.group(1)) >= 900, "vector-run ceiling should be >= 900s"


def test_runner_sends_a_long_timeout():
    s = _src(RUNNER)
    # anchor on the actual httpx.post call, not the earlier comment mention
    anchor = "rstrip('/')}/vectors/run"
    assert anchor in s, "runner /vectors/run call not found"
    i = s.index(anchor)
    block = s[i - 400:i + 500]  # window spans the _vec_to assignment + the call
    assert '"timeout": 60' not in block, "runner must not send the old 60s timeout"
    assert "VECTOR_RUN_TIMEOUT" in block, "runner must send a configurable timeout"
    # the HTTP client wait must exceed the command timeout (was a fixed 90)
    assert "timeout=90" not in block, "runner HTTP client must not use the old 90s wait"
    assert "_vec_to + 60" in block, "runner HTTP wait must exceed the command timeout"
