"""Operator feedback must actually change what retrieval returns.

Run on demand:

    pytest tests/test_rag_feedback_ranking.py -v

WHY THIS EXISTS
---------------
The RAG feedback loop was open. `/rag/feedback` wrote rows to `rag_feedback`,
and `exploits_rag._retrieve` went on ranking by pure cosine similarity forever —
the rows were read only by a stats endpoint, the training export and the eval
harness, none of which sit on the query path. Rating a chunk down changed
nothing: the next identical query returned it in the same position. An audit
found `rag_feedback` had 0 rows, which is what a loop nobody can see working
looks like.

`_apply_feedback_ranking` closes it. These are the properties that make it safe
to have on by default, each pinned below:

  1. **No feedback => byte-identical behaviour.** An install that has never
     rated anything must get exactly the old similarity order, or enabling this
     is a silent regression for every existing deployment.
  2. **Bounded.** A few votes must not drag an irrelevant chunk over a much
     better match. The adjustment is squashed through tanh and capped at
     _FEEDBACK_WEIGHT, so it can only reorder near-ties.
  3. **It genuinely reorders.** A chunk operators keep marking helpful must be
     able to overtake a marginally-better similarity match, or the loop is
     decorative.
  4. **Downvotes demote.**
  5. **Inspectable.** The adjustment rides on the row, so an operator can see
     why something moved rather than suspecting the search is broken.

Pure functions over plain dicts — no DB, no embedder, so this runs on a bare
checkout.

Sabotage proofs performed:
  * returned rows unsorted from _apply_feedback_ranking -> test_helpful_chunk_can_overtake RED
  * removed the tanh squash (raw net * weight)          -> test_feedback_cannot_override_a_far_better_match RED
  * unwired BOTH call sites in _retrieve                -> test_the_loop_is_wired_into_retrieval RED
"""
import os
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _load():
    """Import exploits_rag's ranking helpers without importing the service.

    The module pulls in fastapi/psycopg2 at import time, so the functions are
    extracted and exec'd on their own. That keeps this test runnable anywhere,
    which for a guard is the difference between running and existing.
    """
    src_path = REPO / "scan_recommender" / "exploits_rag.py"
    if not src_path.exists():
        pytest.skip("scan_recommender/exploits_rag.py not present")
    import ast
    tree = ast.parse(src_path.read_text(encoding="utf-8"))
    wanted_fns = {"_apply_feedback_ranking"}
    wanted_consts = {"_FEEDBACK_WEIGHT", "_FEEDBACK_SCALE"}
    ns: dict = {"Dict": dict, "math": __import__("math")}
    picked = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in wanted_fns:
            exec(compile(ast.Module([node], []), "<rank>", "exec"), ns)
            picked.add(node.name)
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Name) and t.id in wanted_consts:
                exec(compile(ast.Module([node], []), "<const>", "exec"), ns)
                picked.add(t.id)
    missing = (wanted_fns | wanted_consts) - picked
    assert not missing, (
        f"could not extract {sorted(missing)} from exploits_rag.py — the ranking "
        "helpers were renamed or removed, and this guard would pass vacuously")
    return ns


@pytest.fixture(scope="module")
def rank():
    return _load()


def _rows(*pairs):
    """[(id, sim), ...] already ordered by similarity, as _retrieve returns."""
    return [{"id": i, "sim": s, "chunk": f"chunk-{i}"} for i, s in pairs]


# ── 1. the safety property ──────────────────────────────────────────────────
def test_no_feedback_is_a_no_op(rank):
    """An install that never rated anything must see the old order exactly."""
    rows = _rows((1, 0.90), (2, 0.80), (3, 0.70), (4, 0.60))
    out = rank["_apply_feedback_ranking"](list(rows), {}, 3)
    assert [r["id"] for r in out] == [1, 2, 3]
    # and no scoring keys invented on the rows
    assert all("feedback_adj" not in r for r in out)


def test_empty_input_is_safe(rank):
    assert rank["_apply_feedback_ranking"]([], {5: 3}, 6) == []


def test_limit_is_respected(rank):
    rows = _rows((1, 0.9), (2, 0.8), (3, 0.7))
    assert len(rank["_apply_feedback_ranking"](rows, {1: 2}, 2)) == 2


# ── 2. bounded: feedback can only reorder near-ties ─────────────────────────
def test_feedback_cannot_override_a_far_better_match(rank):
    """A downvoted strong match must still beat an upvoted weak one.

    Without the squash+cap, enough votes would let operators pin an unrelated
    chunk to the top of every query — turning a retrieval system into a manual
    bookmark list, and doing it silently.
    """
    rows = _rows((1, 0.95), (2, 0.40))
    out = rank["_apply_feedback_ranking"](rows, {1: -50, 2: 50}, 2)
    assert [r["id"] for r in out] == [1, 2], (
        "feedback overrode a 0.55 similarity gap; the adjustment is not bounded")


def test_adjustment_never_exceeds_the_cap(rank):
    cap = rank["_FEEDBACK_WEIGHT"]
    rows = _rows((1, 0.5))
    out = rank["_apply_feedback_ranking"](rows, {1: 10_000}, 1)
    assert abs(out[0]["feedback_adj"]) <= cap + 1e-9


# ── 3/4. it actually learns ─────────────────────────────────────────────────
def test_helpful_chunk_can_overtake(rank):
    """The point of the loop: a repeatedly-helpful chunk beats a near-tie."""
    rows = _rows((1, 0.72), (2, 0.70))
    out = rank["_apply_feedback_ranking"](rows, {2: 5}, 2)
    assert [r["id"] for r in out] == [2, 1], (
        "an upvoted chunk did not overtake a chunk 0.02 better on similarity — "
        "operator feedback is not affecting the ranking")


def test_unhelpful_chunk_is_demoted(rank):
    rows = _rows((1, 0.72), (2, 0.70))
    out = rank["_apply_feedback_ranking"](rows, {1: -5}, 2)
    assert [r["id"] for r in out] == [2, 1]


# ── 5. inspectable ──────────────────────────────────────────────────────────
def test_rows_carry_why_they_moved(rank):
    rows = _rows((1, 0.72), (2, 0.70))
    out = rank["_apply_feedback_ranking"](rows, {2: 4}, 2)
    top = out[0]
    assert top["feedback_votes"] == 4
    assert top["feedback_adj"] > 0
    assert top["ranked_score"] == pytest.approx(top["sim"] + top["feedback_adj"], abs=1e-6)


def test_the_loop_is_wired_into_retrieval():
    """The helper existing is not enough — _retrieve must call it.

    A pure-function test passes just as happily when nothing uses the function,
    which is exactly how the old loop stayed open.
    """
    src = (REPO / "scan_recommender" / "exploits_rag.py").read_text(encoding="utf-8")
    i = src.index("def _retrieve(")
    body = src[i:src.index("\ndef ", i + 10)]
    assert "_apply_feedback_ranking" in body, (
        "_retrieve no longer applies feedback ranking — the loop is open again")
    assert "_chunk_feedback_scores" in body, (
        "_retrieve no longer reads feedback scores")
    # and writing feedback must invalidate the cache, or a rating appears to do
    # nothing for up to _FEEDBACK_TTL seconds
    assert "_invalidate_feedback_cache()" in src
