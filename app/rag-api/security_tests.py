"""Security-test persistence: the assertion evaluator + record_test_run.

A `security_tests` row is a reusable TEST DEFINITION (a command + the assertion
that proves it, tiered safe|impactful). Each execution appends a
`security_test_runs` row — the pass/fail HISTORY. This module owns the ONE place
an assertion is evaluated, so the agent lane and the API re-run path produce
identical verdicts.

It deliberately does NOT execute anything. Safe tests run via kali-listener
`/tools/execute` (→ tool_executions); impactful tests run via
execute_approved_exploit (→ exploit_results). record_test_run is called AFTER an
execution, with the evidence row it produced.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# ── the assertion evaluator (pure; no DB import, so tests run on a bare checkout) ──
#
# The assertion is a small structured spec stored on security_tests.assertion.
# Every clause present is ANDed. Evaluation is total and side-effect-free:
#   pass    — the run completed AND every clause held
#   fail    — the run completed but a clause failed
#   error   — the run never completed (no exit_code and no output/proof)
#   skipped — handled by the caller (disabled test / awaiting approval), not here
#
# Supported clauses:
#   expect_exit_code:      int        exit_code must equal this
#   expect_substring:      [str]      every listed substring must appear in output
#   expect_not_substring:  [str]      none may appear
#   expect_regex:          str        output must match (re.search)
#   expect_status:         int        parsed HTTP status must equal this
#   expect_shell:          true       a shell/session was obtained (impactful)
#   expect_screenshot:     true       a screenshot evidence row exists
#   min_output_bytes:      int        len(output) >= this
_CLAUSE_KEYS = {
    "expect_exit_code", "expect_substring", "expect_not_substring",
    "expect_regex", "expect_status", "expect_shell", "expect_screenshot",
    "min_output_bytes",
}


def evaluate_assertion(
    assertion: Optional[Dict[str, Any]],
    *,
    exit_code: Optional[int] = None,
    output: Optional[str] = None,
    http_status: Optional[int] = None,
    has_shell: bool = False,
    has_screenshot: bool = False,
) -> Tuple[str, Dict[str, Any], str]:
    """Return (status, per_clause_eval, one_line_summary).

    An empty/absent assertion means "the test is proven by executing without
    error" — so a clean completion is a pass. That keeps a bare probe useful
    without forcing the author to write a clause.
    """
    assertion = assertion or {}
    out = output or ""

    # Did the run complete at all? No exit code AND no output AND no proof => error.
    completed = (exit_code is not None) or bool(out) or has_shell or has_screenshot
    if not completed:
        return "error", {"_reason": "run did not complete (no exit code, output or proof)"}, \
               "run did not complete"

    clauses = {k: v for k, v in assertion.items() if k in _CLAUSE_KEYS}
    evald: Dict[str, Any] = {}
    fails: List[str] = []

    def record(key: str, ok: bool, detail: str) -> None:
        evald[key] = {"pass": ok, "detail": detail}
        if not ok:
            fails.append(f"{key}: {detail}")

    if "expect_exit_code" in clauses:
        want = clauses["expect_exit_code"]
        record("expect_exit_code", exit_code == want,
               f"exit_code={exit_code} want={want}")

    if "expect_substring" in clauses:
        want = clauses["expect_substring"]
        want = want if isinstance(want, list) else [want]
        missing = [w for w in want if str(w) not in out]
        record("expect_substring", not missing,
               "all present" if not missing else f"missing {missing}")

    if "expect_not_substring" in clauses:
        bad = clauses["expect_not_substring"]
        bad = bad if isinstance(bad, list) else [bad]
        present = [w for w in bad if str(w) in out]
        record("expect_not_substring", not present,
               "none present" if not present else f"present {present}")

    if "expect_regex" in clauses:
        pat = str(clauses["expect_regex"])
        try:
            ok = re.search(pat, out) is not None
            record("expect_regex", ok, f"/{pat}/ {'matched' if ok else 'no match'}")
        except re.error as e:
            record("expect_regex", False, f"bad regex: {e}")

    if "expect_status" in clauses:
        want = clauses["expect_status"]
        record("expect_status", http_status == want,
               f"status={http_status} want={want}")

    if "expect_shell" in clauses and clauses["expect_shell"]:
        record("expect_shell", bool(has_shell),
               "shell/session obtained" if has_shell else "no shell/session")

    if "expect_screenshot" in clauses and clauses["expect_screenshot"]:
        record("expect_screenshot", bool(has_screenshot),
               "screenshot captured" if has_screenshot else "no screenshot")

    if "min_output_bytes" in clauses:
        want = int(clauses["min_output_bytes"])
        record("min_output_bytes", len(out) >= want,
               f"{len(out)} bytes >= {want}")

    if not clauses:
        return "pass", {"_reason": "no assertion clauses; clean completion is a pass"}, \
               "completed (no assertion)"

    if fails:
        return "fail", evald, "; ".join(fails)[:400]
    return "pass", evald, f"all {len(clauses)} clause(s) held"


# ── record_test_run (needs a DB connection; caller owns the transaction) ──────
class TestRunError(ValueError):
    """A malformed record_test_run call — a safe run masquerading as impactful
    proof, or vice versa. Raised rather than silently mis-recording."""


def record_test_run(
    conn,
    *,
    test_id: str,
    lane: str,
    command_run: Optional[str] = None,
    exit_code: Optional[int] = None,
    output: Optional[str] = None,
    duration_ms: Optional[int] = None,
    tool_execution_id: Optional[str] = None,
    exploit_result_id: Optional[str] = None,
    http_status: Optional[int] = None,
    has_shell: bool = False,
    has_screenshot: bool = False,
    status_override: Optional[str] = None,
    triggered_by: str = "agent",
    triggered_by_session: Optional[str] = None,
    engagement_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Insert a security_test_runs row, evaluate the test's assertion, and update
    the rollup. Returns {run_id, status, assertion_eval, result_summary}.

    Invariant: exactly one evidence FK, and it must agree with `lane`
    (safe→tool_execution_id, impactful→exploit_result_id). Enforced here so a
    safe run can never be recorded as impactful proof.
    """
    # Validate args BEFORE importing the DB layer, so the invariant is testable
    # on a bare checkout and a malformed call never reaches a cursor.
    if lane not in ("safe", "impactful"):
        raise TestRunError(f"lane must be safe|impactful, got {lane!r}")
    if lane == "safe" and exploit_result_id is not None:
        raise TestRunError("a safe run cannot carry an exploit_result_id")
    if lane == "impactful" and tool_execution_id is not None:
        raise TestRunError("an impactful run cannot carry a tool_execution_id")
    if tool_execution_id is not None and exploit_result_id is not None:
        raise TestRunError("a run maps to exactly one evidence row, not both")

    from psycopg2.extras import Json, RealDictCursor
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT assertion, tier, engagement_id FROM public.security_tests WHERE id = %s::uuid",
            (test_id,),
        )
        row = cur.fetchone()
        if not row:
            raise TestRunError(f"security_test not found: {test_id}")
        eng = engagement_id or row.get("engagement_id")

        if status_override in ("pass", "fail", "error", "skipped"):
            status, assertion_eval, summary = status_override, \
                {"_reason": f"status set by caller: {status_override}"}, status_override
        else:
            status, assertion_eval, summary = evaluate_assertion(
                row.get("assertion"), exit_code=exit_code, output=output,
                http_status=http_status, has_shell=has_shell,
                has_screenshot=has_screenshot)

        cur.execute(
            """INSERT INTO public.security_test_runs
                 (test_id, completed_at, duration_ms, status, lane, command_run,
                  exit_code, result_summary, assertion_eval, tool_execution_id,
                  exploit_result_id, triggered_by, triggered_by_session,
                  engagement_id, output)
               VALUES (%s::uuid, now(), %s, %s, %s, %s, %s, %s, %s,
                       %s::uuid, %s::uuid, %s, %s::uuid, %s::uuid, %s)
               RETURNING id""",
            (test_id, duration_ms, status, lane, command_run, exit_code, summary,
             Json(assertion_eval), tool_execution_id, exploit_result_id,
             triggered_by, triggered_by_session, eng, (output or "")[:20000]),
        )
        run_id = cur.fetchone()["id"]

        # Rollup for cheap list rendering. A 'queued' impactful test is recorded
        # as 'skipped' until it actually runs, so the rollup never shows a stale
        # pass/fail for something that has not executed.
        cur.execute(
            """UPDATE public.security_tests
                  SET last_run_at = now(), last_run_status = %s,
                      run_count = run_count + 1
                WHERE id = %s::uuid""",
            (status, test_id),
        )

    return {"run_id": str(run_id), "status": status,
            "assertion_eval": assertion_eval, "result_summary": summary}
