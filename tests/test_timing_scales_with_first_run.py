"""The scaled timing run must be slower than the FIRST run by about the delta.

Run standalone:  pytest tests/test_timing_scales_with_first_run.py -q

CLAUDE.md: "verify the second run's elapsed scales with the payload (within a
2.5s tolerance)". The code only checked the second run against an absolute
floor (`elapsed >= min_seconds + delta - tolerance`) and never looked at the
first run. A target that is merely SLOW passes that:

  CVE-2023-37999, 2026-10-18 round 8 -- SLEEP(5) took 23.2s, SLEEP(12) took
  9.7s. The bigger sleep was 13.5s FASTER, and the build was stored as
  latency_confirmed because 9.7 >= 12 - 2.5.

  CVE-2023-51483, same round -- SLEEP(5) 6.6s, SLEEP(12) 13.4s: +6.8s for a
  +7s payload. That one is real and must stay confirmed.

EXECUTED: the function is compiled out of api.py with a stub listener and a
fake clock that replays the observed elapsed times.
"""
import ast
import pathlib
import types

import pytest

API = pathlib.Path(__file__).resolve().parents[1] / "app" / "rag-api" / "api.py"

CMD = ("curl -s -X POST -d 'reg_role=%27+OR+SLEEP%285%29--+-&reg_name=POCz1' "
       "'http://172.19.150.154:9090/wp-admin/admin-ajax.php?action=htmega_ajax_register'")
ASSERTION = {"min_seconds": 5, "max_seconds": 30}


def _run(first_s, second_s):
    import sys
    tree = ast.parse(API.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
              and n.name == "_timing_confirmation_rerun")
    clock = iter([100.0, 100.0 + second_s])

    class _Resp:
        status_code = 200

        def json(self):
            return {"output": "ok"}
    ns = {"_timing_payload_scale": lambda c, d: (c, "SLEEP", 5, 12),
          "_listener_vectors_run": lambda *a, **k: _Resp()}
    exec(compile(ast.Module([fn], []), "api.py", "exec"), ns)
    real_time = sys.modules["time"]
    real_httpx = sys.modules.get("httpx")
    sys.modules["time"] = types.SimpleNamespace(time=lambda: next(clock))
    sys.modules.setdefault("httpx", types.ModuleType("httpx"))
    try:
        return ns["_timing_confirmation_rerun"](CMD, ASSERTION, "t", 9090, "l", "k", 60,
                                                delta=7, tolerance=2.5, first_s=first_s)
    finally:
        sys.modules["time"] = real_time
        if real_httpx is not None:
            sys.modules["httpx"] = real_httpx


def test_a_slow_target_that_does_not_scale_is_not_confirmed():
    r = _run(first_s=23.166, second_s=9.74)            # CVE-2023-37999
    assert r["confirmed"] is False, (
        "SLEEP(12) ran 13.4s FASTER than SLEEP(5) and was still confirmed -- "
        "the check is not comparing against the first run")


def test_a_real_blind_injection_still_confirms():
    r = _run(first_s=6.598, second_s=13.41)            # CVE-2023-51483
    assert r["confirmed"] is True, r["reason"]


def test_without_a_first_run_the_absolute_floor_still_applies():
    assert _run(first_s=None, second_s=13.0)["confirmed"] is True
    assert _run(first_s=None, second_s=5.0)["confirmed"] is False


def test_the_refine_loop_passes_the_first_runs_elapsed():
    tree = ast.parse(API.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
              and n.name == "_run_refine_poc")
    calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call)
             and getattr(c.func, "id", "") == "_timing_confirmation_rerun"]
    assert calls, "the refine loop no longer confirms timing verdicts"
    for c in calls:
        assert any(k.arg == "first_s" for k in c.keywords), (
            "a confirmation call does not pass first_s, so it cannot check scaling")
