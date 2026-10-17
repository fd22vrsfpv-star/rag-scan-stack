"""The challenge agent — a second opinion, from a DIFFERENT model, that can
only ever warn.

`etl/fact_contradictions.py` catches what exact comparison catches: a template,
another product's route, a parameter from the wrong class. It cannot catch the
semantic cases — an endpoint that is syntactically fine and implausible for
this product. So a model reviews the DERIVED facts.

Two properties make that safe rather than another way for a model to decide:

  * IT IS ROUTED SEPARATELY. A reviewer sharing the builder's model is the same
    model grading its own homework. Every LLM call already carried a `caller`
    tag, but nothing mapped a caller to a MODEL — the tag only reached the
    metrics table. `LLM_ROUTE_<CALLER>` pins one consumer; unset is today's
    behaviour exactly.

  * IT CAN ONLY WARN. Never clear, never downgrade, never confirm. CLAUDE.md:
    "RAG proposes; the gate disposes." A model must not be able to talk the
    deterministic gate into or out of anything.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest pyyaml && \
      PYTHONPATH=.:tests python -m pytest tests/test_challenge_agent.py -v'
"""
from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
API = REPO / "app" / "rag-api" / "api.py"
SRC = API.read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _func(name):
    for n in ast.walk(TREE):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _load(response=None, raises=False):
    """Exec the real review function with the LLM call stubbed."""
    calls = []

    def _llm(prompt, model=None, caller="llm", num_predict=1024, temperature=0.2):
        calls.append({"prompt": prompt, "model": model, "caller": caller,
                      "temperature": temperature})
        if raises:
            raise RuntimeError("backend down")
        return {"response": response or '{"concerns": []}', "model": "stub-model"}

    ns = {"chr": chr, "os": os, "logging": __import__("logging"),
          "_llm_for_model": _llm,
          "_poc_extract_json": lambda t: (json.loads(t) if t.strip().startswith("{") else None)}
    for name in ("_LLM_CHALLENGE_SOURCES", "_LLM_CHALLENGE_PROMPT"):
        node = next(n for n in TREE.body if isinstance(n, ast.Assign)
                    and any(getattr(t, "id", "") == name for t in n.targets))
        exec(compile(ast.Module([node], []), "<api>", "exec"), ns)
    exec(compile(ast.Module([_func("_llm_challenge_review")], []), "<api>", "exec"), ns)
    ns["_calls"] = calls
    return ns


INTEL = {
    "facts": {"endpoint": "/download/x", "input_field": "file",
              "target_reachable": "HTTP 200"},
    "fact_sources": {"endpoint": "llm_fallback", "input_field": "advisory_derived",
                     "target_reachable": "probe"},
    "vuln_class": "path-traversal",
}


# ── routing ────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestRouting:
    """The challenger is a TASK in the stack's own router, not a new mechanism.

    An earlier draft invented a per-CALLER env var, `LLM_ROUTE_<CALLER>`. That
    collided with `LLM_ROUTE_<TASK>` — the documented env fallback for
    `llm.route.<task>` — using the same prefix to mean something different. The
    stack already had a router: `app_settings` rows `llm.route.<task>` with
    `.fallback` siblings, DB over env over default, resolved by
    `common.llm_settings.get_route`.
    """

    def test_challenge_is_a_declared_task(self):
        from common.llm_settings import LLM_TASK_NAMES, LLM_TASKS
        assert "challenge" in LLM_TASK_NAMES, (
            "the challenger has no route, so it silently shares the builder's "
            "model — the thing having a separate reviewer is meant to avoid")
        desc = dict(LLM_TASKS)["challenge"]
        assert desc.strip(), "a task with no description does not reach the UI"

    def test_it_resolves_through_the_shared_router(self):
        """Not a private lookup: the same call every other task makes."""
        src = ast.unparse(_func("_llm_challenge_review"))
        assert "get_route" in src and "challenge" in src

    def test_no_parallel_per_caller_mechanism_survives(self):
        """`LLM_ROUTE_<CALLER>` and `LLM_ROUTE_<TASK>` cannot both exist — same
        prefix, different key space."""
        assert "_model_for_caller" not in SRC
        assert "_CALLER_ROUTE_PREFIX" not in SRC

    def test_an_explicit_model_is_never_overridden(self):
        """A caller that already decided must win over the route."""
        src = ast.unparse(_func("_llm_challenge_review"))
        i = src.index("get_route")
        assert "if model is None" in src[max(0, i - 200):i], (
            "the route is applied without checking the caller's own model")

    def test_an_unroutable_task_falls_back_rather_than_failing(self):
        """get_route never raises and never half-fills: an unset challenge
        route inherits route.default, which is today's behaviour."""
        from common.llm_settings import get_route
        r = get_route("challenge", settings={"routes": {}, "backend": "ollama",
                                             "ollama_model": "x"})
        assert isinstance(r, dict) and "model" in r

    def test_a_route_lookup_failure_does_not_stop_the_review(self):
        src = ast.unparse(_func("_llm_challenge_review"))
        i = src.index("get_route")
        assert "try:" in src[max(0, i - 200):i]


# ── the review ─────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestReview:
    def test_it_uses_its_own_caller_tag(self):
        ns = _load()
        ns["_llm_challenge_review"](INTEL, [], "CVE-X", "1.1.1.1", 443)
        assert ns["_calls"][0]["caller"] == "fact_challenge", (
            "without its own caller tag it cannot be routed to another model")

    def test_it_reviews_only_derived_facts(self):
        """A probe-established fact needs no second opinion, and reviewing it
        spends a call on something already measured."""
        ns = _load()
        ns["_llm_challenge_review"](INTEL, [], "CVE-X", "1.1.1.1", 443)
        p = ns["_calls"][0]["prompt"]
        assert "endpoint" in p and "input_field" in p
        assert "target_reachable" not in p

    def test_it_does_not_run_when_every_fact_was_probed(self):
        ns = _load()
        r = ns["_llm_challenge_review"](
            {"facts": {"endpoint": "/x"}, "fact_sources": {"endpoint": "probe"}},
            [], "CVE-X", "1.1.1.1", 443)
        assert r["ran"] is False
        assert "no derived facts" in r["reason"]
        assert ns["_calls"] == [], "it spent a call with nothing to review"

    def test_it_is_told_what_was_already_found(self):
        ns = _load()
        ns["_llm_challenge_review"](
            INTEL, [{"rule_id": "placeholder_unsubstituted", "message": "it is a template"}],
            "CVE-X", "1.1.1.1", 443)
        assert "placeholder_unsubstituted" in ns["_calls"][0]["prompt"]

    def test_concerns_become_warnings_and_nothing_else(self):
        """The safety property: a model cannot clear or downgrade a fact."""
        ns = _load(response=json.dumps({"concerns": [
            {"item": "endpoint", "concern": "implausible for this product",
             "why": "the vendor does not ship that route"}]}))
        r = ns["_llm_challenge_review"](INTEL, [], "CVE-X", "1.1.1.1", 443)
        assert r["ran"] is True and len(r["findings"]) == 1
        f = r["findings"][0]
        assert f["action"] == "warn"
        assert f["severity"] == "medium"
        assert f["source"] == "llm"

    def test_no_concern_can_be_high_severity(self):
        ns = _load(response=json.dumps({"concerns": [
            {"item": "endpoint", "concern": "x", "why": "y", "severity": "high",
             "action": "clear"}]}))
        r = ns["_llm_challenge_review"](INTEL, [], "CVE-X", "1.1.1.1", 443)
        assert r["findings"][0]["severity"] == "medium"
        assert r["findings"][0]["action"] == "warn"

    def test_an_opinion_about_a_fact_we_do_not_hold_is_dropped(self):
        ns = _load(response=json.dumps({"concerns": [
            {"item": "not_a_fact", "concern": "x", "why": "y"}]}))
        assert ns["_llm_challenge_review"](INTEL, [], "CVE-X", "1.1.1.1", 443)["findings"] == []

    def test_an_empty_concern_is_dropped(self):
        ns = _load(response=json.dumps({"concerns": [{"item": "endpoint"}, "nonsense"]}))
        assert ns["_llm_challenge_review"](INTEL, [], "CVE-X", "1.1.1.1", 443)["findings"] == []

    def test_it_is_bounded(self):
        many = {"concerns": [{"item": "endpoint", "concern": "c%d" % i, "why": "w"}
                             for i in range(40)]}
        ns = _load(response=json.dumps(many))
        assert len(ns["_llm_challenge_review"](INTEL, [], "CVE-X", "1.1.1.1", 443)["findings"]) <= 6

    def test_a_failed_review_is_reported_not_silent(self):
        """"the reviewer said nothing" and "the reviewer never spoke" are not
        the same, and a clean report must not be able to mean either."""
        ns = _load(raises=True)
        r = ns["_llm_challenge_review"](INTEL, [], "CVE-X", "1.1.1.1", 443)
        assert r["ran"] is False
        assert "did not run" in r["reason"]

    def test_unparseable_output_is_not_a_finding(self):
        ns = _load(response="I think the endpoint looks wrong, honestly")
        r = ns["_llm_challenge_review"](INTEL, [], "CVE-X", "1.1.1.1", 443)
        assert r["findings"] == []

    def test_it_asks_for_determinism(self):
        ns = _load()
        ns["_llm_challenge_review"](INTEL, [], "CVE-X", "1.1.1.1", 443)
        assert ns["_calls"][0]["temperature"] == 0.0


# ── wiring ─────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestWiring:
    def test_the_challenger_invokes_it(self):
        src = ast.unparse(_func("_challenge_derived_facts"))
        assert "_llm_challenge_review" in src

    def test_it_runs_after_the_actions_are_applied(self):
        """Appending before the apply loop would let an opinion reach code
        that clears and downgrades."""
        src = ast.unparse(_func("_challenge_derived_facts"))
        assert src.index("out['applied'].append") < src.index("_llm_challenge_review")

    def test_its_outcome_is_recorded_separately(self):
        src = ast.unparse(_func("_challenge_derived_facts"))
        assert "llm_review" in src

    def test_a_broken_review_cannot_fail_the_challenge(self):
        src = ast.unparse(_func("_challenge_derived_facts"))
        i = src.index("_llm_challenge_review")
        assert "try:" in src[max(0, i - 200):i]
