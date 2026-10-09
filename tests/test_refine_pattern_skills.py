"""2026-10-09: the refine-pattern skills stop shouting and start learning.

Measured over all 473 build traces (2,917 iterations): `canary_reflection_risk`
was injected 1,531 times for 9 next-iteration passes, `method_not_allowed_405`
~27× per build for 0, and the learned-pattern miner had promoted nothing in
473 runs. Three changes, each pinned here:

  1. a per-build injection budget (`REFINE_PATTERN_MAX_INJECT`, default 2, or
     `triggers.max_per_build`) — past it the loop says "already applied N×
     without effect" once, then stays silent;
  2. trigger keys `min_iteration` and `error_signature` in
     `_match_refine_patterns` (context from the loop); the two noisy YAML
     entries carry `min_iteration` / `max_per_build`;
  3. the miner promotes pending patterns from `build_poc_error_memory`
     (resolved rows, ≥ min_hits distinct runs, dominant change_summary).

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest pyyaml && PYTHONPATH=. python -m pytest tests/test_refine_pattern_skills.py -v'
"""
from __future__ import annotations

import ast as _ast
import logging
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
YAML = REPO / "knowledge" / "refine_error_patterns.yaml"


def _func_src(name: str, path=API) -> str | None:
    src = path.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


@pytest.fixture(scope="module")
def patterns():
    return yaml.safe_load(YAML.read_text())["patterns"]


@pytest.fixture(scope="module")
def matcher(patterns):
    """_match_refine_patterns with _load_refine_patterns stubbed to the YAML rows."""
    ns = {"logging": logging, "_load_refine_patterns": lambda force=False: [
        {"id": p["id"], "title": p.get("title"), "guidance": p.get("guidance", ""),
         "triggers": p.get("triggers") or {}, "pending": False, "trial_count": 0, "success_count": 0}
        for p in patterns] + [
        {"id": "learned_em_abc", "title": "Learned (error memory)", "guidance": "do X",
         "triggers": {"error_signature": '-|latency_too_fast|"message":"attack unsuccessful."', "max_per_build": 2},
         "pending": True, "trial_count": 0, "success_count": 0}]}
    exec(_func_src("_match_refine_patterns"), ns)
    return ns["_match_refine_patterns"]


CANARY = "POCz0d38270d93"


def test_canary_reflection_risk_waits_for_iteration_3_and_is_budgeted(matcher, patterns):
    p = next(x for x in patterns if x["id"] == "canary_reflection_risk")
    assert p["triggers"]["min_iteration"] == 3 and p["triggers"]["max_per_build"] == 1
    cmd = f"curl -s 'http://h/x?q={CANARY}'"
    out = "HTTP/1.1 200 OK\n<html>nothing</html>"
    ids1 = {m["id"] for m in matcher(out, {"expect_regex": "x"}, CANARY, cmd, context={"iteration": 1})}
    ids2 = {m["id"] for m in matcher(out, {"expect_regex": "x"}, CANARY, cmd, context={"iteration": 2})}
    ids3 = {m["id"] for m in matcher(out, {"expect_regex": "x"}, CANARY, cmd, context={"iteration": 3})}
    assert "canary_reflection_risk" not in ids1 and "canary_reflection_risk" not in ids2
    assert "canary_reflection_risk" in ids3
    # no context (legacy caller) → fires as before; the budget is the loop's job
    assert "canary_reflection_risk" in {m["id"] for m in matcher(out, {"expect_regex": "x"}, CANARY, cmd)}
    m = next(x for x in matcher(out, {"expect_regex": "x"}, CANARY, cmd, context={"iteration": 5}) if x["id"] == "canary_reflection_risk")
    assert m["max_per_build"] == 1


def test_error_signature_trigger_matches_the_normalised_signature(matcher):
    sig = '-|latency_too_fast|"message":"attack unsuccessful."'
    hit = [m for m in matcher('{"message":"Attack unsuccessful."}', {}, None, "curl x",
                              context={"iteration": 4, "error_signature": sig})]
    assert any(m["id"] == "learned_em_abc" and m["pending"] and m["max_per_build"] == 2 for m in hit)
    miss = matcher('{"message":"Attack unsuccessful."}', {}, None, "curl x",
                   context={"iteration": 4, "error_signature": "-|other|something else"})
    assert not any(m["id"] == "learned_em_abc" for m in miss)
    assert not any(m["id"] == "learned_em_abc" for m in matcher("x", {}, None, "curl x"))   # no signature → no fire


def test_method_not_allowed_405_keeps_its_substring_trigger_with_a_budget(matcher, patterns):
    p = next(x for x in patterns if x["id"] == "method_not_allowed_405")
    assert p["triggers"]["max_per_build"] == 2
    hit = matcher("HTTP/1.1 405 Method Not Allowed", {}, None, "curl -X POST http://h/", context={"iteration": 1})
    assert any(m["id"] == "method_not_allowed_405" and m["max_per_build"] == 2 for m in hit)


def test_loop_applies_the_per_build_budget_and_passes_context():
    loop = _func_src("_run_refine_poc")
    assert loop
    assert '_REFINE_PATTERN_MAX_INJECT = int(os.environ.get("REFINE_PATTERN_MAX_INJECT", "2") or "2")' in loop
    assert "_pattern_inject_counts = {}" in loop
    assert 'context={"iteration": it,' in loop and '"error_signature": (_err_rows[-1]["signature"] if _err_rows else "")' in loop
    assert "if n_prev >= budget:" in loop and "ALREADY APPLIED" in loop and "WITHOUT EFFECT" in loop
    assert "if n_prev == budget:" in loop                       # the notice is given exactly once
    assert '"suppressed": _suppressed, "exhausted": _exhausted' in loop   # trace tells which were held back
    # the trial credit still only counts patterns that were actually injected
    i_cap = loop.index("if n_prev >= budget:")
    i_pending = loop.index("_pending_tried_this_iter.append(pid)")
    assert i_cap < i_pending


def test_miner_learns_from_the_error_memory():
    m = _func_src("_mine_refine_pattern_candidates")
    assert m and "FROM build_poc_error_memory" in m
    assert "WHERE resolved AND next_command IS NOT NULL" in m
    assert "distinct_runs = {h[\"run_id\"] for h in hits}" in m and "len(distinct_runs) < min_hits" in m
    assert '"learned_em_"' in m and 'triggers = {"error_signature": sig, "max_per_build": 2}' in m
    assert "VALUES (%s, %s, %s, %s::jsonb, 'learned')" in m          # still pending: operator approves
    assert "changes.most_common(1)[0]" in m                           # dominant change_summary
    # legacy trace-mining source is still there
    assert "SIGNAL_PATTERNS" in m


def test_matcher_docs_the_new_keys():
    src = _func_src("_match_refine_patterns")
    assert src and "min_iteration" in src and "error_signature" in src and "max_per_build" in src
    assert "context=None" in src
