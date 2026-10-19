"""Every knowledge retrieval that informs an attack must say what it returned.

Seven helpers in `app/rag-api/api.py` pulled prior knowledge into a PoC build —
cross-run error memory, review criteria, prior reviews, product lessons, scan
telemetry — and none of them recorded a single row about it. The trace could
not answer the first question asked of a failed build: *what did it know?*

Two properties are guarded here, and they are different in kind:

1. THREE OUTCOMES, not two. "The memory held nothing" and "the memory was never
   consulted" are opposite facts that both arrive as `[]`. This repo keeps
   filing the second as the first, and an unexplored approach then reads as a
   disproven one. Each traced helper must be able to emit `hit`, `empty`, and
   at least one could-not-run outcome — and the EMPTY case must still write a
   row, because an absent row is exactly the ambiguity being removed.
2. OBSERVING MUST NOT BREAK THE OBSERVED. A trace writer that raises would turn
   an instrumentation bug into a failed build.

The executable half `exec`s the REAL source of `_trace_retrieval` and
`_trace_rag_hits` out of api.py with a recording `_poc_trace`, so the behaviour
under test is the shipped code and not a re-typed copy. The structural half is
AST (`tests/_ast_assert.py`), not source substrings.

    pytest tests/test_retrieval_observability.py -q
"""
from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ast_assert import arg_default, call_kwarg, function_source  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"

if not API.exists():  # pragma: no cover - cannot run here, not a failure
    pytest.skip("app/rag-api/api.py not present", allow_module_level=True)

SRC = API.read_text(encoding="utf-8", errors="replace")
TREE = ast.parse(SRC)

# The helpers under guard, and the outcome classes each must be able to report.
# `_retrieve_review_criteria` / `_retrieve_prior_reviews` have no precondition
# they can fail on (an empty context still embeds), so their could-not-run
# outcome is only the failure one; the others can also decline to query.
TRACED = {
    "_similar_prior_errors": {"RETRIEVAL_HIT", "RETRIEVAL_EMPTY",
                              "RETRIEVAL_NOT_QUERIED", "RETRIEVAL_FAILED"},
    "_recall_lessons": {"RETRIEVAL_HIT", "RETRIEVAL_EMPTY",
                        "RETRIEVAL_NOT_QUERIED", "RETRIEVAL_FAILED"},
    "_scan_evidence_for_target": {"RETRIEVAL_HIT", "RETRIEVAL_EMPTY",
                                  "RETRIEVAL_NOT_QUERIED", "RETRIEVAL_FAILED"},
    "_retrieve_review_criteria": {"RETRIEVAL_HIT", "RETRIEVAL_EMPTY", "RETRIEVAL_FAILED"},
    "_retrieve_prior_reviews": {"RETRIEVAL_HIT", "RETRIEVAL_EMPTY", "RETRIEVAL_FAILED"},
}

# Where the run id each helper traces to comes from. A trace that can never
# fire is worse than none, so the wiring is guarded as explicitly as the body.
WIRING = [
    ("_gather_manifest", "_scan_evidence_for_target", "trace_run_id"),
    ("_post_run_review", "_retrieve_review_criteria", "trace_run_id"),
    ("_post_run_review", "_retrieve_prior_reviews", "trace_run_id"),
    ("_gather_manifest_text", "_recall_lessons", "trace_run_id"),
    ("_record_gather_manifest", "_gather_manifest_text", "run_id"),
]


# ── helpers ──────────────────────────────────────────────────────────────────

def _func(name: str):
    for n in ast.walk(TREE):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _callee(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _traced_outcomes(fn) -> set:
    """Outcome constants this function can report, delegation included."""
    out: set = set()
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        callee = _callee(n.func)
        if callee == "_trace_retrieval":
            out.update(s.id for s in ast.walk(n)
                       if isinstance(s, ast.Name) and s.id.startswith("RETRIEVAL_"))
        elif callee == "_trace_rag_hits":
            # the shared vector-search reporter decides hit vs empty itself
            out.update({"RETRIEVAL_HIT", "RETRIEVAL_EMPTY"})
    return out


def _module_constants() -> dict:
    vals = {}
    for node in TREE.body:
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            name = getattr(t, "id", "")
            if name.startswith("RETRIEVAL_") and isinstance(node.value, ast.Constant):
                vals[name] = node.value.value
    return vals


class _Recorder:
    """Stands in for `_poc_trace`, which otherwise writes to the run's JSONL."""

    def __init__(self, explode=False):
        self.rows = []
        self.explode = explode

    def __call__(self, run_id, phase, iteration=0, prompt=None, response=None,
                 run_output=None, assertion_passed=None, llm_model=None, extra=None):
        if self.explode:
            raise RuntimeError("trace sink is down")
        row = {"run_id": run_id, "phase": phase, "iteration": iteration,
               "response": response}
        row.update(extra or {})
        self.rows.append(row)


def _live(recorder):
    """Namespace holding the REAL trace writers from api.py, wired to `recorder`."""
    ns = {"logging": __import__("logging"), "_poc_trace": recorder}
    ns.update(_module_constants())
    for name in ("_trace_retrieval", "_trace_rag_hits"):
        src = function_source(SRC, name)
        assert src, f"{name} is not defined in api.py"
        exec(compile(ast.parse(src), "<api>", "exec"), ns)  # noqa: S102 - real source
    return ns


# ── the writers themselves (executed) ────────────────────────────────────────

def test_outcome_constants_exist_and_are_distinct():
    consts = _module_constants()
    assert set(consts) == {"RETRIEVAL_HIT", "RETRIEVAL_EMPTY",
                           "RETRIEVAL_NOT_QUERIED", "RETRIEVAL_FAILED"}, consts
    assert len(set(consts.values())) == 4, "outcomes must be distinguishable in the trace"


def test_trace_records_counts_and_identifiers_not_a_size():
    rec = _Recorder()
    ns = _live(rec)
    ns["_trace_retrieval"](
        "RUN-1", "recall_prior_errors", ns["RETRIEVAL_HIT"],
        items=[{"cve": "CVE-2024-4443", "sim": 0.78, "resolved": True},
               {"cve": "CVE-2024-36412", "sim": 0.61, "resolved": False}],
        note="2 prior errors, best sim 0.78",
        extra={"best_similarity": 0.78})
    assert len(rec.rows) == 1
    row = rec.rows[0]
    assert row["run_id"] == "RUN-1" and row["phase"] == "recall_prior_errors"
    assert row["outcome"] == ns["RETRIEVAL_HIT"]
    assert row["count"] == 2, "the count is the point; a character total is not"
    assert [i["cve"] for i in row["items"]] == ["CVE-2024-4443", "CVE-2024-36412"]
    assert row["best_similarity"] == 0.78, "the score that ranked the recall must survive"


def test_an_empty_result_still_emits_a_row():
    """The whole ambiguity being removed: absence of a row meant two things."""
    rec = _Recorder()
    ns = _live(rec)
    ns["_trace_rag_hits"]("RUN-2", "recall_review_criteria", [],
                          empty_note="queried and empty", id_keys=("criterion_id",))
    assert len(rec.rows) == 1, "an empty retrieval must still be recorded"
    assert rec.rows[0]["outcome"] == ns["RETRIEVAL_EMPTY"]
    assert rec.rows[0]["count"] == 0


def test_empty_and_could_not_run_are_different_rows():
    rec = _Recorder()
    ns = _live(rec)
    ns["_trace_rag_hits"]("RUN-3", "recall_review_criteria", [],
                          empty_note="queried and empty", id_keys=())
    ns["_trace_retrieval"]("RUN-3", "recall_review_criteria", ns["RETRIEVAL_FAILED"],
                           count=0, note="embedder unreachable")
    ns["_trace_retrieval"]("RUN-3", "recall_lessons", ns["RETRIEVAL_NOT_QUERIED"],
                           count=0, note="no product resolved")
    outcomes = [r["outcome"] for r in rec.rows]
    assert len(set(outcomes)) == 3, outcomes


def test_rag_hit_trace_carries_the_identifier_and_the_similarity():
    rec = _Recorder()
    ns = _live(rec)
    rows = [{"title": "gather manifest complete", "similarity": 0.91,
             "metadata": {"criterion_id": "gather_manifest_complete",
                          "category": "gather", "severity": "high"}},
            {"title": "iteration efficiency", "similarity": 0.44,
             "metadata": {"criterion_id": "iteration_efficiency"}}]
    ns["_trace_rag_hits"]("RUN-4", "recall_review_criteria", rows,
                          empty_note="n/a", id_keys=("criterion_id", "category", "severity"))
    row = rec.rows[0]
    assert row["count"] == 2
    assert row["items"][0]["criterion_id"] == "gather_manifest_complete"
    assert row["items"][0]["severity"] == "high"
    assert row["best_similarity"] == 0.91 and row["worst_similarity"] == 0.44
    assert "gather_manifest_complete" in row["response"], \
        "the readable line must name what was recalled"


def test_no_run_id_writes_nothing_rather_than_a_stray_log():
    rec = _Recorder()
    ns = _live(rec)
    for rid in (None, "", 0):
        ns["_trace_retrieval"](rid, "recall_lessons", ns["RETRIEVAL_EMPTY"], count=0)
        ns["_trace_rag_hits"](rid, "recall_lessons", [], empty_note="x")
    assert rec.rows == [], "a falsy run id must not write a row under that name"


def test_tracing_never_breaks_the_retrieval_it_observes():
    """A broken trace sink must not take the build down with it."""
    ns = _live(_Recorder(explode=True))
    ns["_trace_retrieval"]("RUN-5", "recall_prior_errors", ns["RETRIEVAL_HIT"],
                           items=[{"cve": "CVE-2024-4443"}])
    ns["_trace_rag_hits"]("RUN-5", "recall_review_criteria",
                          [{"title": "t", "similarity": 0.5, "metadata": {}}],
                          empty_note="n/a")
    # reaching here without an exception IS the assertion


def test_malformed_rows_do_not_raise():
    """Retrieval rows come from the database; a None similarity must not throw."""
    rec = _Recorder()
    ns = _live(rec)
    ns["_trace_rag_hits"]("RUN-6", "recall_prior_reviews",
                          [{"title": None, "similarity": None, "metadata": None}],
                          empty_note="n/a", id_keys=("cve",))
    assert len(rec.rows) == 1 and rec.rows[0]["count"] == 1


# ── the helpers under guard (structural) ─────────────────────────────────────

@pytest.mark.parametrize("name", sorted(TRACED))
def test_helper_is_traced(name):
    fn = _func(name)
    assert fn is not None, f"{name} is gone from api.py"
    assert _traced_outcomes(fn), f"{name} retrieves prior knowledge and records nothing"


@pytest.mark.parametrize("name", sorted(TRACED))
def test_helper_distinguishes_three_outcomes(name):
    """Returned-something, returned-nothing, and could-not-run."""
    fn = _func(name)
    assert fn is not None, f"{name} is gone from api.py"
    got = _traced_outcomes(fn)
    missing = sorted(TRACED[name] - got)
    assert not missing, (
        f"{name} cannot report {missing}. An outcome it cannot report is an "
        f"outcome a reviewer will read as one of the others.")
    assert got & {"RETRIEVAL_NOT_QUERIED", "RETRIEVAL_FAILED"}, \
        f"{name} conflates 'found nothing' with 'could not look'"


@pytest.mark.parametrize("name", sorted(TRACED))
def test_helper_takes_a_trace_run_id(name):
    """Without a run id the trace has nowhere to land."""
    assert arg_default(SRC, name, "trace_run_id") is None, \
        f"{name} must accept trace_run_id, defaulting to None"


@pytest.mark.parametrize("caller,callee,kw", WIRING)
def test_call_site_supplies_the_run_id(caller, callee, kw):
    src = function_source(SRC, caller)
    assert src, f"{caller} is gone from api.py"
    assert call_kwarg(src, callee, kw), (
        f"{caller} calls {callee} without {kw} — the trace inside it can never fire")


def test_similar_prior_errors_traces_to_the_asking_run():
    """Its two loop call sites name the asking run `exclude_run_id`; the trace
    falls back to it so the refine loop needs no call-site change to be
    observed, while the endpoint (which passes neither) writes nothing."""
    fn = _func("_similar_prior_errors")
    assert fn is not None
    found = False
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.IfExp):
            names = {s.id for s in ast.walk(n.value) if isinstance(s, ast.Name)}
            if {"trace_run_id", "exclude_run_id"} <= names:
                found = True
    assert found, "the trace run id must fall back to exclude_run_id"


def test_gather_manifest_text_traces_the_unqueried_case_too():
    """Its `if product:` guard short-circuits before the helper is called, so
    the not-queried row has to be emitted at the gate that made the decision."""
    fn = _func("_gather_manifest_text")
    assert fn is not None
    assert "RETRIEVAL_NOT_QUERIED" in _traced_outcomes(fn), \
        "a build with no product must record that lessons were never looked up"
