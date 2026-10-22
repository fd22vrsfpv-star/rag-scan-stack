"""Research-phase multi-model fanout (1-3 models, same prompt, compared at
post-review). Operator ask, 2026-10-18.

Run standalone:  pytest tests/test_research_multi_model.py -q

- `_dedup_models` caps the fanout at 3 and drops duplicates (case-insensitive).
- `_research_exploit_fanout` runs each model in parallel; a failed candidate
  becomes a row with analysis=None + error (unreachable is not absent).
- `_research_pick_best` picks a usable analysis without the comparison call.
- `_research_compare` only fires when more than one model answered, and never
  overrides the default picker on failure.
- `_research_exploit` lets the comparison's `picked_model` override the pick.

The helpers are compiled out of api.py and executed with stub LLM/intel calls.
"""
import ast
import json
import pathlib
import time

import pytest

API = pathlib.Path(__file__).resolve().parents[1] / "app" / "rag-api" / "api.py"


def _load(stubs):
    tree = ast.parse(API.read_text(encoding="utf-8"))
    want = {"_dedup_models", "_research_exploit_fanout", "_research_pick_best",
            "_research_compare", "_research_exploit"}
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in want]
    assert {n.name for n in body} == want, "helper(s) gone from api.py"
    # Pull the two constants the fanout reads so tests don't bake in literals.
    body += [n for n in tree.body if isinstance(n, ast.Assign) and any(
        getattr(t, "id", "") in ("_RESEARCH_FANOUT_MAX", "_RESEARCH_CALL_TIMEOUT_S")
        for t in n.targets)]
    import concurrent.futures
    import logging
    import os
    ns = {"concurrent": concurrent, "logging": logging, "os": os}
    ns.update(stubs)
    exec(compile(ast.Module(body=body, type_ignores=[]), "<api-sub>", "exec"), ns)
    return ns


# ------------------------------------------------------------------ dedup

def test_dedup_caps_at_three_and_drops_duplicates():
    ns = _load({})
    f = ns["_dedup_models"]
    assert f(["a", "A", "b", "a", "c", "d"], None) == ["a", "b", "c"]
    assert f(["x"], None) == ["x"]
    # None fallback becomes [None] (single, route-chosen).
    assert f([], None) == [None]
    assert f(None, "m") == ["m"]
    # Empty/whitespace names normalize to None (route-chosen).
    assert f(["", "   "], None) == [None]


# ------------------------------------------------------------------ fanout

def _ok(reply):
    return lambda prompt, model=None, caller=None: {"response": reply, "model": model or "r"}


def test_fanout_runs_each_model_and_captures_each_response():
    stubs = {
        "_poc_extract_json": lambda t: json.loads(t) if t.strip().startswith("{") else None,
        "_llm_for_model": _ok(json.dumps({"summary": "sample", "payload": "x",
                                           "seed_command": "curl /", "confidence": 0.7})),
    }
    ns = _load(stubs)
    out = ns["_research_exploit_fanout"]("prompt", ["m1", "m2", "m3"])
    assert [c["model"] for c in out] == ["m1", "m2", "m3"], "order must mirror the request"
    assert all(c["analysis"] and c["analysis"]["seed_command"] == "curl /" for c in out)
    assert all(c["error"] is None and c["duration_s"] >= 0 for c in out)


def test_a_failed_candidate_is_recorded_not_dropped():
    """Unreachable is not absent. A failed call becomes a row with the error,
    never a silent exclusion."""
    def _mixed(prompt, model=None, caller=None):
        if model == "bad":
            raise RuntimeError("provider blew up")
        if model == "empty":
            return {"response": "", "model": model}
        return {"response": json.dumps({"summary": "ok", "seed_command": "curl /",
                                        "confidence": 0.6}), "model": model}
    ns = _load({"_poc_extract_json": lambda t: json.loads(t) if t.strip().startswith("{") else None,
                "_llm_for_model": _mixed})
    out = ns["_research_exploit_fanout"]("p", ["good", "bad", "empty"])
    rows = {c["model"] or c["requested_model"]: c for c in out}
    assert rows["good"]["analysis"]["summary"] == "ok"
    assert rows["bad"]["analysis"] is None and "RuntimeError" in rows["bad"]["error"]
    assert rows["empty"]["analysis"] is None and "empty" in rows["empty"]["error"].lower()


def test_three_slow_models_run_in_parallel_not_serial():
    """The fanout must run its calls CONCURRENTLY.

    Measured by observed overlap, not by a wall-clock budget. The previous
    version asserted `elapsed < 2.5s` for three 1-second calls, which fails on
    a loaded CI runner for reasons that have nothing to do with the code --
    that whole suite run took 26m50s. A flaky red is worse than no test,
    because it trains everyone to ignore the colour.

    Each stub call registers itself as in-flight, holds briefly, then leaves.
    A serial implementation can never see more than one in flight at a time, so
    `peak > 1` is exactly the property under test and it does not care how
    slow the machine is.
    """
    import threading
    lock = threading.Lock()
    state = {"live": 0, "peak": 0}

    def _slow(prompt, model=None, caller=None):
        with lock:
            state["live"] += 1
            state["peak"] = max(state["peak"], state["live"])
        # Long enough that genuinely concurrent callers overlap, short enough
        # that the test stays quick even if they do not.
        time.sleep(0.3)
        with lock:
            state["live"] -= 1
        return {"response": json.dumps({"summary": model, "seed_command": "x",
                                        "confidence": 0.5}), "model": model}

    ns = _load({"_poc_extract_json": lambda t: json.loads(t) if t.strip().startswith("{") else None,
                "_llm_for_model": _slow})
    out = ns["_research_exploit_fanout"]("p", ["a", "b", "c"])
    assert len(out) == 3, "fanout dropped a candidate"
    assert state["peak"] > 1, (
        f"fanout ran serially: never more than {state['peak']} call in flight")


# ------------------------------------------------------------------ pick

def test_pick_best_prefers_seed_command_then_confidence():
    ns = _load({})
    candidates = [
        {"model": "a", "analysis": {"summary": "x", "confidence": 0.9}},
        {"model": "b", "analysis": {"summary": "y", "confidence": 0.6,
                                     "seed_command": "curl /x"}},
    ]
    assert ns["_research_pick_best"](candidates)["model"] == "b"


def test_pick_best_handles_a_failed_candidate_without_crashing():
    ns = _load({})
    assert ns["_research_pick_best"]([{"model": "a", "analysis": None,
                                         "error": "x"}])["model"] == "a"


# ------------------------------------------------------------------ compare

def test_compare_skipped_with_only_one_usable_candidate():
    ns = _load({"_llm_for_model": lambda *a, **k: pytest.fail("compare must not run")})
    assert ns["_research_compare"]([{"model": "a", "analysis": {"summary": "x"}}]) is None
    assert ns["_research_compare"]([{"model": "a", "analysis": {"summary": "x"}},
                                      {"model": "b", "analysis": None, "error": "oops"}]) is None


def test_compare_asks_the_llm_and_returns_structured_choice():
    reply = json.dumps({"picked_model": "b", "rationale": "b matches advisory",
                        "agreement": {"http_method": "POST"},
                        "disagreement": {"target_endpoint": {"a": "/x", "b": "/y"}}})
    ns = _load({"_llm_for_model": _ok(reply),
                "_poc_extract_json": lambda t: json.loads(t) if t.strip().startswith("{") else None})
    out = ns["_research_compare"](
        [{"model": "a", "analysis": {"summary": "sa", "target_endpoint": "/x"},
          "duration_s": 1},
         {"model": "b", "analysis": {"summary": "sb", "target_endpoint": "/y"},
          "duration_s": 1}])
    assert out["picked_model"] == "b" and out["candidates_compared"] == ["a", "b"]
    assert out["agreement"]["http_method"] == "POST"


def test_compare_failure_returns_an_error_not_a_crash():
    def _boom(*a, **k): raise RuntimeError("provider down")
    ns = _load({"_llm_for_model": _boom,
                "_poc_extract_json": lambda t: None})
    out = ns["_research_compare"]([{"model": "a", "analysis": {"summary": "x"}},
                                     {"model": "b", "analysis": {"summary": "y"}}])
    assert out and "compare call failed" in out["error"]
