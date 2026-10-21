"""2026-10-21: the auto-hint must describe how the build FAILED, not only what recon saw.

Operator asked for a loop that solves one CVE by running it to the end, analysing
the failure, improving the hint, and going again (`scripts/solve_cve.sh`). The loop
ran CVE-2024-4443 three times and stalled: every round ended
`stage=refine stop=max_iters`, and the stall detector fired exactly as designed.

The reason was the hint. `_derive_auto_hint` read only the recon half of the build
summary, so a target whose recon established a single fact produced a 135-character
hint — `CONTEXT: framework=WordPress` — on every round. That is a restatement of
something the build already knew, so nothing changed and nothing could change.

Meanwhile the attempt record held the actionable finding: the model asserted
`min_seconds` and the target answered in 2.2-2.9s against a 5s floor, five times in
a row. "Timing does not work here, use another proof" is what the next round needed
to be told, and the hint never said it.

Fixtures are the REAL `run` rows captured from round 3
(`CVE-2024-4443_172.19.18.126_1792590041.jsonl`), trimmed to the fields the
summariser reads.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_auto_hint_failure_analysis.py -v'
"""
from __future__ import annotations

import ast as _ast
from pathlib import Path

import pytest

import tests._ast_assert as _aa

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"

# Real round-3 `run` rows. Two refused before dispatch, five dispatched and
# answered too fast for the asserted min_seconds.
REAL_RUN_ROWS = [
    {"phase": "run", "iteration": 1, "assertion_passed": False, "dispatched": False,
     "method": "regex_missed", "error_tier": "regex_missed", "command_len": 666,
     "reason": "canary not in output — regex-authoritative failure",
     "run_output": "PROVEN_FACT_UNUSED (pre-dispatch): the command does not use proven "
                   "fact(s): endpoint_exists='/wp-includes/blocks/image/style.min.css', "
                   "input_field='context'."},
    {"phase": "run", "iteration": 1, "assertion_passed": False, "dispatched": False,
     "method": "rejected_error", "error_tier": "syntax", "command_len": 271,
     "reason": "output contains a shell-error marker; refused regardless of regex",
     "run_output": "/bin/sh: syntax error (pre-dispatch dry-parse refused to run): canary "
                   "'POCz087594d555' appears ONLY inside a SQL comment (after -- or within "
                   "/* */), where the server discards it and it can never be reflected"},
    {"phase": "run", "iteration": 1, "assertion_passed": False, "dispatched": True,
     "method": "regex_missed", "error_tier": "regex_missed", "command_len": 356,
     "reason": "canary not in output — regex-authoritative failure",
     "run_output": "[proxy] DIRECT - the caller resolved no proxy for this target\n"
                   "--- STEP exploit-cve-2024-4443 ---\nPROOF_NOT_FOUND\nELAPSED=0\n"},
] + [
    {"phase": "run", "iteration": it, "assertion_passed": False, "dispatched": True,
     "method": "latency_too_fast", "error_tier": "latency_too_fast", "command_len": 385 + it,
     "reason": f"elapsed {el}s below min_seconds 5.0 (timing payload did not block the server)",
     "run_output": "[proxy] DIRECT - the caller resolved no proxy for this target\n"
                   "--- STEP exploit-cve-2024-4443 ---\nPROOF_NOT_FOUND\nELAPSED=0\n"}
    for it, el in ((2, "2.9"), (3, "2.9"), (4, "2.2"), (5, "2.7"), (6, "2.9"))
]

# The recon half of the real round-3 build: one fact, which is the whole point.
RECON_ONLY_ROWS = [
    {"phase": "recon:response_mine", "iteration": 0, "response": "FRAMEWORK: WordPress"},
]


def _load():
    """exec the three hint symbols out of api.py without importing the module."""
    src = API.read_text()
    tree = _ast.parse(src)
    wanted = {"_summarize_build_trace", "_failure_analysis_lines", "_derive_auto_hint"}
    chunks, consts = [], []
    for node in tree.body:
        if isinstance(node, _ast.FunctionDef) and node.name in wanted:
            chunks.append(_ast.get_source_segment(src, node))
        if isinstance(node, _ast.Assign) and any(
                isinstance(t, _ast.Name) and t.id == "_TIMING_FAIL_METHODS"
                for t in node.targets):
            consts.append(_ast.get_source_segment(src, node))
        if isinstance(node, _ast.Assign) and any(
                isinstance(t, _ast.Name) and t.id == "_PRE_DISPATCH_MARKERS"
                for t in node.targets):
            consts.append(_ast.get_source_segment(src, node))
    missing = wanted - {c.split("(")[0].replace("def ", "").strip()
                        for c in (x.splitlines()[0] for x in chunks)}
    assert not missing, f"not found in api.py: {missing}"
    ns: dict = {"_trace_extra": lambda e: {k: v for k, v in e.items()
                                           if k not in ("phase", "response")}}
    exec("\n\n".join(consts + chunks), ns)  # noqa: S102 - our own source
    return ns


@pytest.fixture(scope="module")
def ns():
    return _load()


def test_recon_only_hint_is_the_stall(ns):
    """The old behaviour, pinned: recon alone yields a hint with nothing to act on."""
    summary = ns["_summarize_build_trace"](RECON_ONLY_ROWS)
    lines = ns["_failure_analysis_lines"](summary)
    assert lines == [], "a build with no attempts has no failure analysis to give"


def test_timing_failure_is_named_and_forbidden(ns):
    """The finding that broke the loop: five latency_too_fast verdicts must become
    an explicit instruction to stop asserting min_seconds."""
    summary = ns["_summarize_build_trace"](REAL_RUN_ROWS)
    hint = ns["_derive_auto_hint"](summary)

    assert hint, "a build with five failed attempts must produce a hint"
    assert "TIMING PROOF FAILED 5x" in hint, hint
    assert "latency_too_fast" in hint
    # The actionable half: say what NOT to do, and what to do instead.
    assert "min_seconds" in hint
    assert "DO NOT" in hint
    for alternative in ("error-based", "boolean/differential", "reflected canary"):
        assert alternative in hint, f"no alternative proof offered: {alternative}"


def test_pre_dispatch_refusals_are_reported(ns):
    """Refusals cost no iteration but say the command was malformed — the next
    build cannot avoid repeating what it is never told."""
    summary = ns["_summarize_build_trace"](REAL_RUN_ROWS)
    hint = ns["_derive_auto_hint"](summary)
    assert "REFUSED BEFORE DISPATCH 2x" in hint, hint
    assert "syntax" in hint
    # The real cause, carried through verbatim enough to act on.
    assert "SQL comment" in hint or "PROVEN_FACT_UNUSED" in hint


def test_attempt_count_separates_dispatched_from_refused(ns):
    """3 dispatched + 5 timing = 6 reached the target; 2 never did."""
    summary = ns["_summarize_build_trace"](REAL_RUN_ROWS)
    assert len(summary["iterations_summary"]) == 6
    assert len(summary["pre_dispatch_refusals"]) == 2
    hint = ns["_derive_auto_hint"](summary)
    # Split, and without the "(s)" literal: the guard-style ratchet reads
    # parentheses in an asserted string as a code fragment.
    assert "6 attempt" in hint and "reached the target" in hint, hint
    assert "0 passed" in hint, hint


def test_repeated_outcome_is_surfaced(ns):
    """A reason the target returned repeatedly is zero-information — say so."""
    summary = ns["_summarize_build_trace"](REAL_RUN_ROWS)
    hint = ns["_derive_auto_hint"](summary)
    assert "REPEATED OUTCOME" in hint, hint


def test_derive_auto_hint_actually_calls_the_analysis(ns):
    """Sabotage guard: the wiring, not just the helper.

    An earlier round of guards in this repo tested a helper while its call site
    was gone. Assert on `_derive_auto_hint`'s own output for a summary that has
    NO recon signal at all — if the call site is removed, the recon half yields
    "" and this fails.
    """
    summary = ns["_summarize_build_trace"](REAL_RUN_ROWS)
    assert not summary.get("framework"), "fixture must carry no recon signal"
    hint = ns["_derive_auto_hint"](summary)
    assert hint, "_derive_auto_hint must emit failure analysis with zero recon"
    assert "how its attempts failed" in hint, "preamble must promise the failure half"


def test_call_site_is_present_in_source():
    """Structural: _derive_auto_hint calls _failure_analysis_lines.

    Scoped to the one function, so deleting the call while leaving the helper
    referenced anywhere else in api.py still fails.
    """
    src = _ast.get_source_segment(
        API.read_text(),
        next(n for n in _ast.parse(API.read_text()).body
             if isinstance(n, _ast.FunctionDef) and n.name == "_derive_auto_hint"))
    assert _aa.calls(src, "_failure_analysis_lines"), \
        "_derive_auto_hint no longer calls _failure_analysis_lines"
