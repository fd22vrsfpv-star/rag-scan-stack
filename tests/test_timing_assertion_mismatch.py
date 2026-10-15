"""A min_seconds assertion is meaningless without a timing payload to measure.

Two halves of one bug, found by analysing the 2026-10-12 focused-10 CVE-Bench
run (see Docs/CHANGES_MADE.md):

F2 — the verdict path emitted `latency_too_fast` ("timing payload did not block
     the server") for commands containing no timing payload at all. On
     CVE-2024-32511 — an auth-bypass CVE, correctly classified as auth-bypass —
     a 302 login-wall redirect was recorded as a timing failure, and the false
     reason was written into cross-run error memory as
     "302|latency_too_fast|location: {url}".

F1 — the refine prompt handed back a JSON assertion template shaped by the
     PREVIOUS assertion kind, with no path back to expect_regex. One wrong
     first guess therefore converted the entire build into a timing build:
     all 14 of CVE-2024-32511's runs were locked into timing.

The no-payload check already existed on the SUCCESS path (the
_timing_confirmation_rerun block, CLAUDE.md "Blind-timing verdicts must be
confirmed with a scaled payload"). It was simply never asked on the failure
path. These tests pin both paths.

Static (ast/regex) rather than importing api.py — that module is ~37k lines and
pulls the whole service graph on import. See CLAUDE.md "Running tests needs a
container" / the repo's existing guard-test convention.

Run standalone:
  docker run --rm -v /opt/rag-scan-stack:/w -w /w python:3.12-slim \
    sh -c "pip -q install pytest; python -m pytest tests/test_timing_assertion_mismatch.py -q"
"""
import ast
import os
import pathlib
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ast_assert import call_kwarg, calls_with  # noqa: E402

API = pathlib.Path(__file__).resolve().parents[1] / "app" / "rag-api" / "api.py"


def _src() -> str:
    if not API.exists():
        pytest.skip(f"{API} not present")
    return API.read_text(encoding="utf-8", errors="replace")


def _func(src: str, name: str) -> str:
    """Return the source of a top-level function, or skip if it is gone."""
    try:
        tree = ast.parse(src)
    except SyntaxError as e:  # a broken edit should fail loudly, not skip
        pytest.fail(f"api.py does not parse: {e}")
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    pytest.skip(f"{name} not found in api.py (renamed?)")


# ---------------------------------------------------------------- F2: verdict


def test_verdict_accepts_the_command():
    """The verdict cannot check for a timing payload it is never handed."""
    src = _src()
    fn = _func(src, "_poc_assertion_verdict")
    sig = fn.split("\n")[0] + fn.split("\n")[1] if fn.count("\n") else fn
    head = fn[: fn.index('"""')] if '"""' in fn else fn[:400]
    assert "command" in head, (
        "_poc_assertion_verdict must accept `command` — without it the "
        "min_seconds branch has nothing to inspect for a timing payload"
    )


def test_min_seconds_branch_checks_for_a_timing_payload():
    """F2: the failure path must consult the payload detector."""
    fn = _func(_src(), "_poc_assertion_verdict")
    assert "_timing_payload_scale" in fn, (
        "the min_seconds branch must call _timing_payload_scale(command) — "
        "otherwise a command with no SLEEP/pg_sleep/WAITFOR/BENCHMARK is still "
        "graded as a timing failure"
    )
    assert "latency_unconfirmable" in fn, (
        "a min_seconds assertion over a command with no timing payload must "
        "return latency_unconfirmable, not latency_too_fast "
        "(CLAUDE.md: 'cannot be confirmed -> latency_unconfirmable, advisory only')"
    )


def test_no_payload_check_precedes_the_too_fast_verdict():
    """Order matters: latency_too_fast must not win over the no-payload case."""
    fn = _func(_src(), "_poc_assertion_verdict")
    # Compare the RETURN SITES, not any mention — the explanatory comment above
    # the check names latency_too_fast while describing the bug it fixes, so a
    # naive substring search reports the wrong order.
    def _ret(method):
        m = re.search(r'"method"\s*:\s*"' + re.escape(method) + r'"', fn)
        assert m, f'no `"method": "{method}"` return in _poc_assertion_verdict'
        return m.start()

    assert _ret("latency_unconfirmable") < _ret("latency_too_fast"), (
        "the no-timing-payload check must run BEFORE the elapsed < min_seconds "
        "check, or a payload-free command still reports latency_too_fast"
    )


def test_unconfirmable_reason_blames_the_assertion_not_the_target():
    """The reason string is what the refine loop reads — it must redirect."""
    fn = _func(_src(), "_poc_assertion_verdict")
    i = fn.find("latency_unconfirmable")
    assert i != -1
    window = fn[i : i + 1400].lower()
    assert "expect_regex" in window, (
        "the latency_unconfirmable reason must name the assertion to switch to "
        "(expect_regex), or the loop has no way back to a reflected canary"
    )
    assert "time-based" in window or "blind" in window, (
        "the reason must state the one condition under which min_seconds is "
        "still correct (the advisory says time-based / blind)"
    )


def test_wrappers_thread_the_command_through():
    """A kwarg the wrappers drop is a kwarg the verdict never sees."""
    src = _src()
    for name in ("_poc_assertion_passes", "_poc_assertion_verdict_with_semantic"):
        fn = _func(src, name)
        assert "command=command" in fn.replace(" ", ""), (
            f"{name} must forward `command` to _poc_assertion_verdict; "
            "dropping it silently restores the old behaviour"
        )


def test_live_build_loop_supplies_the_command():
    """The fix is inert if the real caller never passes a command."""
    fn = _func(_src(), "_run_refine_poc")
    i = fn.find("_poc_assertion_verdict_with_semantic")
    assert i != -1, "_run_refine_poc no longer calls the semantic verdict"
    call = fn[i : i + 400]
    assert "command=" in call, (
        "_run_refine_poc must pass command= to the verdict — this is the call "
        "site that produced the CVE-2024-32511 misdiagnosis"
    )


# ------------------------------------------------------- F1: sticky template


def test_assertion_template_is_not_unconditionally_sticky():
    """F1: a timing template must be earned by an actual timing payload."""
    fn = _func(_src(), "_run_refine_poc")
    assert "_prev_had_latency" in fn, "the assertion-shape branch is gone"
    i = fn.index("_prev_had_latency")
    window = fn[i : i + 2500]
    assert "_timing_payload_scale" in window, (
        "the refine prompt must check the command carries a timing payload "
        "before re-offering the min_seconds template; without this one wrong "
        "first guess locks the whole build into timing"
    )


def test_switch_note_is_actually_rendered_into_the_prompt():
    """A note built and never interpolated changes nothing (CLAUDE.md:
    'a fallback leg is an endpoint. Verify every leg or delete it')."""
    fn = _func(_src(), "_run_refine_poc")
    assert "_assert_switch_note" in fn, "the switch note is gone"
    # It must appear at least twice: once assigned, once interpolated.
    assert fn.count("_assert_switch_note") >= 2, (
        "_assert_switch_note is built but never rendered into the prompt"
    )
    assert "{_assert_switch_note}" in fn, (
        "_assert_switch_note must be interpolated into the refine prompt "
        "f-string, or the LLM is never told the assertion kind was wrong"
    )


def test_switch_note_forbids_the_make_it_slower_reflex():
    """The failure mode is the model padding the command to beat the clock."""
    fn = _func(_src(), "_run_refine_poc")
    i = fn.find("_assert_switch_note = (")
    if i == -1:
        pytest.skip("switch note is not a literal assignment")
    window = fn[i : i + 1400].lower()
    assert "slower" in window or "do not" in window, (
        "the switch note must explicitly tell the model NOT to make the "
        "command slower to satisfy the clock"
    )


def test_fail_soft_on_detector_error():
    """A detector exception must not flip the shape or crash the build."""
    fn = _func(_src(), "_run_refine_poc")
    i = fn.find("_timing_payload_present")
    assert i != -1
    window = fn[i : i + 700]
    assert "except" in window, (
        "the _timing_payload_scale call in the refine path must be wrapped — "
        "a detector error must never fail a build"
    )
    assert re.search(r"_timing_payload_present\s*=\s*True", window), (
        "on detector failure the code must fall back to the legacy (sticky) "
        "shape rather than silently switching assertion kinds"
    )


# -------------------------------------- F2b: never dispatched != too fast
#
# Found while watching the 2026-10-12 run that shipped F1/F2: the no-payload
# check fixed one expression of the defect and missed the other. On
# CVE-2024-22120, two consecutive iterations were graded latency_too_fast for
# commands that never reached the target — iter 1 blocked by a missing runner
# program ("the command was NOT sent to the target", its own words), iter 2
# refused by the pre-dispatch canary check. Both carry elapsed = 0.0, and the
# no-payload check does not fire because the command genuinely does contain a
# SLEEP. The latency branch simply assumed `elapsed` was evidence.


def test_not_executed_helper_exists():
    src = _src()
    fn = _func(src, "_poc_command_not_executed")
    assert "pre-dispatch dry-parse refused to run" in fn, (
        "must recognise the pre-dispatch refusal marker"
    )
    assert "45" in fn and "NOT sent to the target" in fn, (
        "must recognise the prerun-tool-missing path (exit 45 + its marker)"
    )


def test_not_executed_does_not_key_on_elapsed_or_bare_exit_2():
    """A real request can legitimately return in 0.0s, and a genuinely
    dispatched command can exit 2 — neither proves it never ran."""
    fn = _func(_src(), "_poc_command_not_executed")
    assert "elapsed" not in fn.split('"""')[-1], (
        "must not infer 'not executed' from elapsed == 0"
    )
    assert "exit_code == 2" not in fn, (
        "must not treat a bare exit code 2 as 'not executed' — a dispatched "
        "command may exit 2 on its own"
    )


def test_latency_branch_checks_not_executed_first():
    fn = _func(_src(), "_poc_assertion_verdict")
    assert "_poc_command_not_executed" in fn, (
        "the min_seconds branch must ask whether the command ran at all"
    )

    def _ret(method):
        m = re.search(r'"method"\s*:\s*"' + re.escape(method) + r'"', fn)
        assert m, f'no `"method": "{method}"` return in _poc_assertion_verdict'
        return m.start()

    # It must precede EVERY other latency verdict - there is nothing to measure.
    for later in ("latency_missing", "latency_connection_error",
                  "latency_unconfirmable", "latency_too_fast"):
        assert _ret("latency_not_executed") < _ret(later), (
            f"latency_not_executed must be returned before {later}; a command "
            "that never ran has no elapsed time to interpret"
        )


def test_not_executed_reason_redirects_away_from_the_payload():
    fn = _func(_src(), "_poc_assertion_verdict")
    i = fn.find('"method": "latency_not_executed"')
    assert i != -1, "latency_not_executed return site not found"
    # Join adjacent string literals: the reason is wrapped across source lines,
    # so the sentence is not contiguous in the file even though it is at runtime.
    window = re.sub(r'"\s*\n\s*"', "", fn[i:i + 1200]).lower()
    assert "do not change the timing payload" in window, (
        "the reason must tell the loop to fix why the command did not run, "
        "not to re-shape the timing payload"
    )
    assert "measures nothing" in window, (
        "the reason must say plainly that the elapsed time is not evidence"
    )


# ------- F10: a confirmed timing proof is not invalidated by a stray echo
#
# CVE-2024-3552, 2026-10-12: latency_confirmed at 0.98 — the scaled-payload
# re-run passed, so the server demonstrably executed the SLEEP — and `verified`
# still flipped to False because the command happened to print its own canary
# into stdout. The reflection guard ran a control token, saw it echo too, and
# downgraded. It was right that the canary proved nothing; it was wrong that
# this mattered, because in a blind-timing proof the canary is a request TAG
# and the evidence is the timing. The same CVE verified in the three prior runs
# whose command happened not to echo it.
#
# This is the same SHAPE as the F6 regression: a correct rule applied where its
# premise does not hold.


def test_reflection_guard_has_a_confirmed_timing_exception():
    fn = _func(_src(), "_run_refine_poc")
    i = fn.find('"reflection_check"')
    assert i != -1, "the reflection guard is gone"
    window = fn[i:i + 4000]
    assert "latency_confirmed" in window, (
        "the reflection guard must not downgrade a CONFIRMED timing verdict — "
        "the canary is not the evidence in that mode"
    )


def test_exception_is_scoped_to_confirmed_methods_only():
    """Bare `latency` / `latency_anchored` are UNCONFIRMED and must keep the
    downgrade: there, a reflected canary may be the only thing that looked
    like proof."""
    fn = _func(_src(), "_run_refine_poc")
    i = fn.find('verification_method in (\n                    "latency_confirmed"')
    if i == -1:
        i = fn.find('"latency_confirmed", "latency_confirmed_anchored"')
    assert i != -1, "the exception's method tuple was not found"
    window = fn[max(0, i - 200):i + 200]
    assert '"latency"' not in window and '"latency_anchored"' not in window, (
        "an unconfirmed latency verdict must still be downgraded by reflection"
    )


def test_exception_runs_before_the_downgrade():
    fn = _func(_src(), "_run_refine_poc")
    exc = fn.find('"latency_confirmed", "latency_confirmed_anchored"')
    dow = fn.find("if reflection:\n                verified = False")
    assert exc != -1 and dow != -1
    assert exc < dow, (
        "the confirmed-timing exception must clear `reflection` BEFORE the "
        "downgrade, or it has no effect"
    )


# ---- F12: PoC commands must run under bash, not dash
#
# kali-listener executes with subprocess.run(shell=True), which on POSIX uses
# /bin/sh — a symlink to dash in this image. The model naturally writes bash:
# process substitution <(...), [[ ]], arrays. Those die before reaching the
# target. 37 trace files carry a shell syntax error ("redirection unexpected"
# x24, "end of file unexpected" x4, "word unexpected" x2), and the pre-dispatch
# shlex check cannot catch them — shlex parses tokens, not shell grammar.
# Measured on the runner: <(...) and [[ ]] and arrays all FAIL under /bin/sh
# and all pass under bash. bash 5.3.3 is already installed.


def _listener_src():
    p = pathlib.Path(__file__).resolve().parents[1] / "kali_listener" / "listener_service.py"
    if not p.exists():
        pytest.skip(f"{p} not present")
    return p.read_text(encoding="utf-8", errors="replace")


def test_vector_run_executes_under_bash():
    src = _listener_src()
    assert "_EXEC_SHELL" in src, "the exec shell must be resolved"
    assert calls_with(src, "shutil.which", args=["bash"]), (
        "resolve bash at import; a hardcoded path breaks on an image that "
        "installs it elsewhere"
    )
    assert calls_with(src, "subprocess.run", kwargs={"shell": True}), (
        "the shell=True exec site is gone"
    )
    assert call_kwarg(src, "subprocess.run", "executable"), (
        "shell=True without executable= uses /bin/sh (dash here), which "
        "rejects the bash syntax the model writes"
    )


def test_runner_reports_its_own_runtime():
    """The runner is the authority on its shell — same reasoning as
    /tools/capabilities. Hardcoding the executor fixes the symptom; REPORTING
    it is what lets the synthesiser write correct commands and lets the fact be
    embedded into RAG instead of compiled into one branch."""
    src = _listener_src()
    assert '"/runtime/profile"' in src, "the runtime profile endpoint is gone"
    for key in ("exec_shell", "sh_is_dash", "bash_available",
                "binaries_present", "binaries_missing"):
        assert f'"{key}"' in src, f"the profile must report {key}"


def test_bash_absence_falls_back_rather_than_failing():
    """shutil.which returns None when bash is absent; subprocess then behaves
    exactly as before. A hard failure would be worse than dash."""
    src = _listener_src()
    i = src.find("_BASH = ")
    assert i != -1
    window = src[max(0, i - 400):i + 120]
    assert "None" in window, (
        "the comment must record that None means the previous /bin/sh "
        "behaviour, not a crash"
    )
