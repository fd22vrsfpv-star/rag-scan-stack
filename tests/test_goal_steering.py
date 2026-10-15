"""On a graded target the ORACLE decides, not our endpoint check.

The goal ladder picked the cheapest scored goal and the prompt said "aim at the
goal, not at a textbook exploit for the CVE" — and nothing changed, across two
full focused-10 rounds. The cause was not prompting. It was mechanical, and it
was in direct opposition to the instruction:

    if _c2 and _c2 != _new_cmd and not (... _fam2[1] != orig[1]):
        accept
    else:
        refine_identical_rejected_drift
        _stop_reason = "identical_resend"; break

Any command whose path differed from the CVE's endpoint was refused AND THE
BUILD WAS STOPPED. But six of CVE-Bench's eight scored goals — outbound
request, unauthorized admin login, privilege escalation, database
modification, file access, database access — are reached somewhere OTHER than
the CVE's endpoint. So the loop structurally forbade the thing the goal block
asked for. `refine_identical_rejected_drift` fired 12 times across the
2026-10-15 focused-10, and every one of those builds ended `identical_resend`.

The anti-drift rules are RIGHT on a normal engagement: a PoC for CVE-X must
exercise CVE-X, and CVE-2024-31611 verified itself from its own echoed canary
on a different path. What changes on a graded target is that an INDEPENDENT
oracle exists — `GET :9091/done` — so drift can be adjudicated by something
other than our own canary.

Two halves, both tested here:

  1. a drifted re-ask is ACCEPTED when a harness is present, instead of ending
     the build;
  2. the oracle is polled AFTER EVERY ATTEMPT, which is what the benchmark's
     own instructions say to do ("Once verified, stop immediately"). Checking
     only at the end meant a run that won at iteration 2 kept attacking — the
     shape that overwrote CVE-2024-36412's only verified result with
     verified=False at iteration 19.

Fail-closed in the direction that matters: `_graded` comes from
`_benchmark_oracle(ip)` returning present=True. No harness, or one that did not
answer, leaves every drift rule exactly as it was.

Sabotage check: drop `_graded` from the re-ask condition and
`test_a_drifted_reask_is_allowed_on_a_graded_target` fails; delete the
per-attempt poll and `test_the_oracle_is_polled_after_every_attempt` fails;
let the poll flip a positive to negative and
`test_the_oracle_can_only_turn_a_negative_into_a_positive` fails.

    pytest tests/test_goal_steering.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"


def _src() -> str:
    if not API.exists():
        pytest.skip("api.py not found")
    return API.read_text(encoding="utf-8")


def _func(name):
    for n in ast.walk(ast.parse(_src())):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    pytest.fail(f"{name} is not defined in api.py")


def _fsrc(name) -> str:
    return ast.get_source_segment(_src(), _func(name)) or ""


# ── the graded flag ───────────────────────────────────────────────────────────

def test_graded_is_decided_from_the_oracle_not_a_guess():
    src = _fsrc("_run_refine_poc")
    assert "_graded" in src, "the refine loop cannot tell a graded target from a normal one"
    assert "_benchmark_oracle" in src, (
        "`_graded` is not derived from the harness probe, so it is an "
        "assumption rather than an observation")


def test_graded_fails_closed_to_the_old_behaviour():
    """No harness -> every drift rule unchanged."""
    src = _fsrc("_run_refine_poc")
    i = src.find("_graded")
    window = src[max(0, i - 300): i + 400]
    assert "except" in window, (
        "the harness probe has no exception handler; a probe that could not "
        "run would raise instead of leaving the strict rules in place")
    # Structural: an assignment of `_graded` to a literal False must exist.
    # Matching the source text broke on whitespace and on a reformat, and the
    # invariant is the FALLBACK, not its spelling.
    fn = _func("_run_refine_poc")
    falls_back = any(
        isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_graded" for t in n.targets)
        and isinstance(n.value, ast.Constant) and n.value.value is False
        for n in ast.walk(fn))
    assert falls_back, (
        "there is no explicit `_graded = False` fallback — an unreadable "
        "oracle must not relax the anti-drift rules")


# ── half 1: a drifted re-ask survives on a graded target ──────────────────────

def test_a_drifted_reask_is_allowed_on_a_graded_target():
    src = _fsrc("_run_refine_poc")
    assert "_drifted_reask" in src, (
        "the drift condition is still inline, so it cannot be relaxed for a "
        "graded target")
    assert "_graded or not _drifted_reask" in src, (
        "a drifted re-ask still ends the build regardless of whether a harness "
        "is scoring the target. Six of the eight scored goals live off the "
        "CVE's endpoint, so this is what made the goal ladder inert")
    assert "graded_drift_allowed" in src, (
        "the relaxation is not traced, so an operator cannot see why a command "
        "that would previously have been refused was dispatched")


def test_drift_is_still_refused_on_a_normal_engagement():
    """The rule that caught CVE-2024-31611 must survive."""
    src = _fsrc("_run_refine_poc")
    assert "refine_identical_rejected_drift" in src, (
        "the non-graded drift refusal was removed entirely — on a normal "
        "engagement a canary matched on a different endpoint proves nothing")


# ── half 2: the oracle is polled after every attempt ──────────────────────────

def test_the_oracle_is_polled_after_every_attempt():
    src = _fsrc("_run_refine_poc")
    assert "benchmark_oracle_win" in src, (
        "the harness is only consulted after the loop ends. A run that won at "
        "iteration 2 keeps attacking — the shape that overwrote "
        "CVE-2024-36412's only verified result at iteration 19")
    # it must sit INSIDE the loop, before the break
    i_poll = src.find("benchmark_oracle_win")
    i_break = src.find("if success or _dispatched_attempts >= max_iters:")
    assert 0 < i_poll < i_break, (
        "the per-attempt oracle check is not before the loop's break test, so "
        "it cannot stop the loop early")


def test_the_oracle_can_only_turn_a_negative_into_a_positive():
    """It must never downgrade a local success."""
    src = _fsrc("_run_refine_poc")
    i = src.find("benchmark_oracle_win")
    window = src[max(0, i - 900): i]
    assert "and not success" in window, (
        "the per-attempt poll runs even when the local verdict already passed, "
        "so a harness that answers oddly could overwrite a genuine success")
    assert "_bp and _bd" in window, (
        "the poll does not require BOTH that the harness is present AND that "
        "it reported done — an oracle that could not be read would pass")


def test_a_win_sets_the_oracle_as_the_verification_method():
    src = _fsrc("_run_refine_poc")
    # Structural: find the `if` whose body traces benchmark_oracle_win, and
    # check what that body ASSIGNS. Searching a character window around the
    # trace name matched assignments belonging to neighbouring blocks and
    # broke whenever the block moved.
    fn = _func("_run_refine_poc")
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        body = list(ast.walk(node))
        if not any(isinstance(n, ast.Constant) and n.value == "benchmark_oracle_win"
                   for n in body):
            continue
        assigned = {}
        for n in body:
            if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        assigned[t.id] = n.value.value
        assert assigned.get("verification_method") == "benchmark_oracle", (
            "a harness win is not labelled as such, so the stored result "
            f"claims the canary chain proved something it did not: {assigned}")
        assert assigned.get("drifted") is False, (
            "a harness-confirmed win is still marked drifted, so the drift "
            "guard downstream would strip the verification the oracle just "
            f"granted: {assigned}")
        assert assigned.get("success") is True, "the win does not set success"
        return
    pytest.fail("no block traces benchmark_oracle_win")


def test_the_drift_guard_still_requires_independent_confirmation():
    """The verification-side guard is unchanged and still allows only
    oracle/timing to bless a drifted command."""
    src = _src()
    i = src.find("if verified and drifted and verification_method not in")
    assert i > 0, "the drift verification guard is gone"
    window = src[i:i + 300]
    for method in ("benchmark_oracle", "latency_confirmed"):
        assert method in window, f"{method} is no longer an accepted independent proof"
