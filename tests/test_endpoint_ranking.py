"""The endpoint the refine loop attacks must be the BEST answering candidate.

Selection used to `break` on the first probe that was not a 404, so a 302 beat
a 200 that had not been tried yet, and the refine loop spent every iteration on
the wrong URL. In the 2026-10-17 baseline round, 7 of 10 builds exited at
`max_iters` — the signature of a loop working on a target it can never prove.

Worse, the answer already existed. `_run_one_building_block` records
`claim_type='endpoint_exists'` when the readiness gate PROBED a path and it
answered; 58 such rows were present and `_gather_manifest` read none of them.
The gate did the work, stored the result, and the selector re-derived an
endpoint from scratch.

    docker run --rm -v /opt/rag-scan-stack:/repo -w /repo python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=.:tests \
      python -m pytest tests/test_endpoint_ranking.py -v'
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"


@pytest.fixture(scope="module")
def gather():
    tree = ast.parse(API.read_text(encoding="utf-8"))
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and n.name == "_gather_manifest":
            return n
    pytest.fail("_gather_manifest not found")


def _strings(node):
    return {n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)}


class TestConfirmedEndpointsAreUsed:
    def test_it_reads_the_gates_confirmed_endpoints(self, gather):
        sql = " ".join(s for s in _strings(gather) if "confirmed_facts" in s)
        assert sql, (
            "_gather_manifest never queries confirmed_facts — the readiness "
            "gate's probe results are discarded and the endpoint is "
            "re-derived from scratch")
        assert "endpoint_exists" in sql, "must select the endpoint_exists claims"
        # Match the STATUS PREDICATE, not the word. The table is called
        # `confirmed_facts`, so a bare `"confirmed" in sql` is satisfied by
        # the FROM clause and passes with the filter deleted — a false pass
        # this guard's own sabotage run exposed.
        import re as _re
        assert _re.search(r"status\s*=\s*'confirmed'", sql), (
            "an UNVERIFIED claim is not evidence the path is real; only "
            f"status='confirmed' rows may seed the probe list. SQL was: {sql}")

    def test_the_lookup_cannot_break_the_build(self, gather):
        """An unreadable table is not evidence that no endpoint was
        confirmed — it must not change the outcome."""
        tries = [n for n in ast.walk(gather) if isinstance(n, ast.Try)
                 and any("confirmed_facts" in s
                         for s in _strings(n) if isinstance(s, str))]
        assert tries, "the confirmed-endpoint lookup must be fail-soft"


class TestItRanksRatherThanTakingTheFirst:
    def test_candidates_are_collected_and_sorted(self, gather):
        names = {t.id for n in ast.walk(gather) if isinstance(n, ast.Assign)
                 for t in n.targets if isinstance(t, ast.Name)}
        assert "_ranked" in names, (
            "answering candidates must be collected, not consumed by the "
            "first `break` — a 302 otherwise beats an unprobed 200")
        sorts = [n for n in ast.walk(gather) if isinstance(n, ast.Call)
                 and getattr(n.func, "attr", None) == "sort"]
        assert sorts, "the collected candidates are never ranked"

    def test_the_advisory_path_outranks_everything(self, gather):
        """Score 0 is the EXPLOIT WRITEUP's own URL, answering.

        A `confirmed_fact` says a path EXISTS; the advisory says where the
        BUG is. Ranking "exists" above "is vulnerable" points the refine loop
        at a path nobody claimed was exploitable — the first version of this
        fix got that backwards.
        """
        src = ast.get_source_segment(API.read_text(encoding="utf-8"), gather) or ""
        i = src.find("_score = 0")
        assert i > 0, "there must be a best-possible class"
        window = src[max(0, i - 260):i]
        assert "_adv" in window and "_2xx" in window, (
            "the top rank must be the advisory path answering 2xx; "
            f"context was: {window[-170:]!r}")

    def test_an_advisory_path_beats_a_confirmed_one(self, gather):
        """Explicit ordering check, not just the top slot."""
        src = ast.get_source_segment(API.read_text(encoding="utf-8"), gather) or ""
        adv_only = src.find("elif _adv:")
        conf_2xx = src.find("elif _conf and _2xx:")
        assert adv_only > 0 and conf_2xx > 0, "both branches must exist"
        assert adv_only < conf_2xx, (
            "a path named by the advisory must rank above a merely-confirmed "
            "one: a 3xx on the documented endpoint is a login redirect in "
            "front of the right path, which beats a 200 on an unrelated page")

    def test_only_the_best_class_short_circuits(self, gather):
        """Breaking on anything less than the best re-creates the bug."""
        src = ast.get_source_segment(API.read_text(encoding="utf-8"), gather) or ""
        i = src.find("if _score == 0:")
        assert i > 0, (
            "the probe loop must stop early ONLY on the unbeatable class; "
            "breaking on any lower rank is the original defect")

    def test_the_choice_is_traced(self, gather):
        """A silent choice between candidates cannot be reviewed."""
        assert "endpoint_ranked" in _strings(gather), (
            "when several candidates answer, the trace must record which was "
            "chosen and what it beat")
