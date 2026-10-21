"""The persistent solver: work one CVE until solved, learning each round.

Why this exists
---------------
`max_iters` bounds attempts INSIDE one build — all of them sharing the recon,
the class decision and the plan that build started with. When the APPROACH is
wrong, more iterations refine the wrong approach, which is exactly what
`axis_exhausted` and `dup_exit` report. A new round re-runs recon and
re-decides, carrying forward only what the last round learned as a persisted
`poc_hint`.

The dangerous failure mode for any such loop is running forever against a
target while learning nothing, so the stopping rules are what this file is
mostly about. In particular the middle one: two identical outcomes in a row
means the hint changed nothing, and that is the round-level form of the
repeated-outcome rule CLAUDE.md already applies inside the refine loop —
"a repeated outcome is provably zero-information".
"""
from __future__ import annotations

import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "solve_cve.sh"

pytestmark = pytest.mark.skipif(not SCRIPT.exists(), reason="solve_cve.sh not present")


def _src() -> str:
    return SCRIPT.read_text(encoding="utf-8")


def _code() -> str:
    """Executable lines only.

    A comment explaining a behaviour is not that behaviour. Checking the whole
    file let a sabotage that changed the derive-hint URL pass, because the
    docstring above it still named it — the same "guard that cannot fail"
    shape as the _assert_template_for tests earlier today."""
    return "\n".join(l for l in _src().splitlines()
                      if not l.lstrip().startswith("#"))


def test_it_is_valid_shell():
    """Generated or hand-written, a driver that does not parse is a driver
    that fails at 3am rather than now."""
    import shutil
    import subprocess
    if not shutil.which("bash"):
        pytest.skip("bash not available")
    r = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True, text=True, timeout=20)
    assert r.returncode == 0, r.stderr.strip()[:300]


def test_it_stops_when_solved():
    s = _src()
    m = re.search(r'if \[ "\$VERIFIED" = "True" \]; then(.{0,400}?)fi', s, re.S)
    assert m, "nothing branches on the verified verdict"
    # ...and exits ZERO inside that branch, so a caller can branch on it.
    assert "exit 0" in m.group(1), "a solved CVE must exit 0"


def test_it_stops_when_the_hint_changes_nothing():
    """The rule that keeps this from being a target-hammering loop. Two
    identical (stage, stop_reason) outcomes means the learning is not landing;
    more rounds will not change that."""
    s = _src()
    assert "STALL_AT" in s, "no stall detector"
    # The signature must cover BOTH stage and stop_reason: either alone
    # repeats across genuinely different outcomes.
    assert re.search(r'sig=.*STAGE.*STOP', s), (
        "the outcome signature must cover both stage and stop_reason")
    assert re.search(r'if \[ "\$stall" -ge "\$STALL_AT" \]', s), "the stall is never acted on"


def test_the_round_budget_is_bounded():
    s = _src()
    assert re.search(r"for round in \$\(seq 1 \"\$ROUNDS\"\)", s), "unbounded round loop"
    assert re.search(r'ROUNDS=.*\$\{2:-\d+\}', s), "no default round budget"


def test_the_verdict_is_read_from_the_attempt_row_not_the_response():
    """The result file has reported a stale verdict before (2026-10-09):
    `derived_cve_specs.verified` is written BEFORE synth and never updated by
    the refine loop. The attempt row is the one the loop acts on."""
    s = _src()
    assert "from build_poc_attempts" in s
    i_build = s.index("runpoc.sh /tmp/solve_body.json")
    i_read = s.index("select verified, stage_reached")
    assert i_build < i_read, "the verdict is read before the build that produces it"


def test_each_round_learns_from_the_last():
    """Without the hint the loop is just a retry — same inputs, same build,
    same outcome. `derive-hint` reads that build's own trace and persists a
    poc_hint scoped to (cve, target), which the next round's synth reads."""
    s = _code()
    assert "derive-hint" in s, "nothing carries learning between rounds"
    i_stall = s.index("prev_sig=\"$sig\"")
    i_hint = s.index("derive-hint")
    assert i_stall < i_hint, (
        "the hint is derived before the stall check, so a stalled loop still "
        "pays for a hint it has already proven useless")


def test_it_does_not_widen_authorization():
    """It schedules work; it does not decide what may be touched. Every build
    goes through the same scope gate and MAX_CONCURRENT_SCANS bound as any
    other dispatch — so the script must not reach past the build endpoint."""
    s = _code()
    for forbidden in ("scope_targets", "INSERT INTO", "not_in_scope",
                      "vectors/run", "kali-listener"):
        assert forbidden not in s, (
            f"{forbidden!r} in the solver — it must dispatch only through the "
            "build endpoint, which is already gated")


def test_it_refuses_a_target_it_cannot_resolve():
    """Guessing an IP would be guessing what to attack."""
    s = _src()
    assert "no known target for" in s
    assert re.search(r'\[ -n "\$\{IP:-\}" \] \|\|.*exit', s), "a missing target does not stop it"
