"""2026-10-22: advisory text could not stop the model re-proposing a dead proof.

`_failure_analysis_lines` puts an explicit instruction in the prompt —
"TIMING PROOF FAILED Nx ... DO NOT propose another `min_seconds` assertion
against this target" — and the model proposes one anyway. Measured:

  2026-10-21 solver, 3 rounds : warning present every round, min_seconds 28/73/58
  2026-10-22 top-20, CVE-2024-4443 : warning present 10x, min_seconds emitted 94x,
                                     13 latency_too_fast verdicts

Five independent builds. CLAUDE.md already settles the principle for the timing
confirmation and the unmeasurable-assertion repair: the model is what produced
the assertion, so it is not the thing to ask about fixing it. So the refusal is
deterministic and inline.

`_repair_dead_timing_mechanism` is the sibling of
`_repair_unmeasurable_timing_assertion`: that one handles min_seconds with NO
payload (nothing to measure), this one handles a payload that IS dispatched
while the target answers fast every time (the claim is refuted).

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_dead_timing_mechanism.py -v'
"""
from __future__ import annotations

import ast as _ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"

CANARY = "POCz1d6f99e623"


@pytest.fixture(scope="module")
def repair():
    src = API.read_text()
    tree = _ast.parse(src)
    fn = next(n for n in tree.body if isinstance(n, _ast.FunctionDef)
              and n.name == "_repair_dead_timing_mechanism")
    const = next((_ast.get_source_segment(src, n) for n in tree.body
                  if isinstance(n, _ast.Assign)
                  and any(getattr(t, "id", "") == "_TIMING_DEAD_AT" for t in n.targets)), None)
    assert const, "_TIMING_DEAD_AT is not a module-level constant"
    ns: dict = {"os": __import__("os")}
    exec(const + "\n\n" + _ast.get_source_segment(src, fn), ns)  # noqa: S102
    return ns["_repair_dead_timing_mechanism"], ns["_TIMING_DEAD_AT"]


def test_below_threshold_the_assertion_stands(repair):
    """One or two fast answers can be a slow-then-fast target, not a refutation."""
    fn, thr = repair
    a = {"min_seconds": 5}
    for n in range(thr):
        out, repaired = fn(dict(a), CANARY, n)
        assert not repaired, f"repaired at {n} fails, threshold is {thr}"
        assert out == a


def test_at_threshold_it_becomes_a_canary_assertion(repair):
    fn, thr = repair
    out, repaired = fn({"min_seconds": 5}, CANARY, thr)
    assert repaired
    assert out["expect_regex"] == CANARY
    assert out.get("min_seconds") is None, "the timing shape must be gone"
    assert out.get("cve_anchored") is True


def test_without_a_canary_nothing_is_invented(repair):
    """Never fabricate a proof: with nothing honest to assert, the timing
    assertion stands and latency_unconfirmable is the truthful verdict."""
    fn, thr = repair
    for empty in (None, ""):
        out, repaired = fn({"min_seconds": 5}, empty, thr + 10)
        assert not repaired
        assert out == {"min_seconds": 5}


def test_a_non_timing_assertion_is_untouched(repair):
    fn, thr = repair
    a = {"expect_regex": "root:x:0:0"}
    out, repaired = fn(dict(a), CANARY, thr + 5)
    assert not repaired and out == a


def test_garbage_inputs_fail_safe(repair):
    """An unusable count must not trigger a rewrite on a guess."""
    fn, thr = repair
    for bad in (None, "many", object()):
        out, repaired = fn({"min_seconds": 5}, CANARY, bad)
        assert not repaired, f"repaired on count={bad!r}"
    assert fn("not a dict", CANARY, 99)[1] is False


def test_the_rewrite_cannot_manufacture_a_pass(repair):
    """The replacement asserts the canary and nothing else — it succeeds only
    if the canary actually comes back."""
    fn, thr = repair
    out, _ = fn({"min_seconds": 5, "max_seconds": 30}, CANARY, thr)
    assert set(out) <= {"expect_regex", "canary", "cve_anchored"}, out
    assert out["expect_regex"] == CANARY


# --- wiring: the helper is worthless if the loop does not use it -------------

def _loop_src() -> str:
    src = API.read_text()
    fn = next(n for n in _ast.parse(src).body
              if isinstance(n, _ast.FunctionDef) and n.name == "_run_refine_poc")
    return _ast.get_source_segment(src, fn)


def test_the_loop_counts_timing_failures():
    seg = _loop_src()
    assert "_latency_fails" in seg, "the loop never counts timing failures"
    assert re.search(r"_latency_fails\s*\+=\s*1", seg), "the counter never increments"
    assert re.search(r"verification_method\s+in\s+_TIMING_FAIL_METHODS", seg), \
        "the counter is not driven by the timing verdict methods"


def test_the_loop_calls_the_repair():
    assert re.search(r"_repair_dead_timing_mechanism\(", _loop_src()), \
        "_run_refine_poc no longer calls _repair_dead_timing_mechanism"


def test_the_repair_clears_timing_mode():
    """The anti-drift rule keeps the latency shape while _timing_mode is set, so
    a repair that does not clear it is undone on the very next iteration."""
    seg = _loop_src()
    m = re.search(r"if\s+_dead\s*:(.{0,400})", seg, re.S)
    assert m, "the repair result is never branched on"
    assert re.search(r"_timing_mode\s*,?\s*.{0,20}=\s*", m.group(1)) and \
        "False" in m.group(1), "timing mode is not cleared when the mechanism is dead"


def test_dead_repair_runs_before_the_unmeasurable_one():
    """Order matters: the dead-mechanism rewrite must override the anti-drift
    decision just made, and the unmeasurable repair is a no-op afterwards."""
    seg = _loop_src()
    dead = seg.find("_repair_dead_timing_mechanism(")
    unmeasurable = seg.find("_repair_unmeasurable_timing_assertion(\n                _new_a")
    if unmeasurable < 0:
        unmeasurable = seg.find("_repair_unmeasurable_timing_assertion(", dead)
    assert dead >= 0 and unmeasurable > dead, \
        "the dead-mechanism repair must come first in the refine block"


def test_threshold_is_operator_tunable():
    src = API.read_text()
    m = re.search(r"_TIMING_DEAD_AT\s*=\s*(.+)", src)
    assert m and "REFINE_TIMING_DEAD_AT" in m.group(1), \
        "the threshold is not readable from the environment"
