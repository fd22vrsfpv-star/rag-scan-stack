"""2026-10-09: end-of-attempt failure analysis, built from the run's own trace.

Operator ask: "when an attempt fails at the end conduct an analysis and save
this information so that it can be added to the markdown file for manual
review, or viewed in the poc summary attempt". The deterministic analyzer is
exercised on a REAL trace (CVE-2024-5314, Dolibarr, halted at the gather gate on
input_field with arjun having found the params) — dynamic, AST-loaded.

Also pins two things the analysis depends on:
  * `_trace_extra` — `_poc_trace` flattens `extra` into the record; readers that
    did `rec.get("extra")` saw {} on every real trace (the review.md dossier
    shipped 2026-10-08 never rendered).
  * `get_derivation_intel`'s key_phases name only phases that are actually
    passed to `_poc_trace` somewhere (the 2026-10-08 list named phases that are
    never emitted, so the judge never reached the key trace).

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_build_poc_failure_analysis.py -v'
"""
from __future__ import annotations

import ast as _ast
import json
import logging
import os
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"
FIXTURE = REPO / "tests" / "fixtures" / "poc_trace_CVE-2024-5314.jsonl"

_CONSTS = ("_POC_TRACE_STD_KEYS", "_GATHER_FOLLOW_UP", "_GATHER_FIELD_REQUIRED_CLASSES",
           "_GATHER_OOB_CLASSES", "_RECON_STATIC_EXT", "_RECON_DYNAMIC_EXT", "_FA_STAGES")
_FUNCS = ("_trace_extra", "_summarize_build_trace", "_parse_recon_segments",
          "_read_trace_file", "_build_failure_analysis")


def _func_src(name: str, path=API) -> str | None:
    src = path.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


def _load(names=_FUNCS) -> dict:
    src = API.read_text()
    tree = _ast.parse(src)
    ns: dict = {"os": os, "logging": logging}
    for node in tree.body:
        if isinstance(node, _ast.Assign) and any(getattr(t, "id", "") in _CONSTS for t in node.targets):
            exec(_ast.get_source_segment(src, node), ns)
    for n in names:
        node = next(x for x in _ast.walk(tree) if isinstance(x, _ast.FunctionDef) and x.name == n)
        exec(_ast.get_source_segment(src, node), ns)
    return ns


@pytest.fixture(scope="module")
def ns():
    return _load()


@pytest.fixture(scope="module")
def entries(ns):
    assert FIXTURE.exists(), "fixture missing"
    e = ns["_read_trace_file"](str(FIXTURE))
    assert len(e) >= 20, "fixture should be the real 25-line 5314 trace"
    return e


# ── _trace_extra ────────────────────────────────────────────────────────────

def test_trace_extra_recovers_flattened_keys(ns, entries):
    gc = [e for e in entries if e.get("phase") == "gather_check"]
    assert gc, "no gather_check in fixture"
    # the flattened record has no "extra" key — the old readers saw nothing
    assert "extra" not in gc[-1]
    ex = ns["_trace_extra"](gc[-1])
    assert "gather_manifest" in ex and ex["gather_manifest"].get("missing") == ["input_field"]
    pv = [e for e in entries if e.get("phase") == "recon:plan_verified"][-1]
    assert ns["_trace_extra"](pv).get("verdicts") == {"PRIMARY": "FAKE", "ALT1": "FAKE", "ALT2": "FAKE"}


def test_summarize_build_trace_now_sees_plan_verdicts(ns, entries):
    s = ns["_summarize_build_trace"](entries)
    assert s["plan_verdicts"] == {"PRIMARY": "FAKE", "ALT1": "FAKE", "ALT2": "FAKE"}, s["plan_verdicts"]
    assert s["framework"] or s["open_ports"], s


def test_trace_extra_sabotage_old_reader_yields_nothing(entries):
    # Prove the guard: the pre-2026-10-09 expression returns {} on a real trace.
    pv = [e for e in entries if e.get("phase") == "recon:plan_verified"][-1]
    assert (pv.get("extra") or {}) == {}


# ── the analyzer on the real 5314 trace ─────────────────────────────────────

def test_analysis_of_a_gather_halt(ns, entries):
    gc = [e for e in entries if e.get("phase") == "gather_check"][-1]
    man = ns["_trace_extra"](gc)["gather_manifest"]
    result = {"ok": True, "success": False, "verified": False, "blocked": True,
              "verification_method": "gather_incomplete", "gather_manifest": man}
    segs = [e.get("response") or "" for e in entries if str(e.get("phase") or "").startswith("recon:")]
    fa = ns["_build_failure_analysis"]("RUN-5314", str(FIXTURE), result, gather_manifest=man,
                                        state_bits={"segments": segs, "auth": {"username": "user"}})
    assert fa["stage_reached"] == "gather"
    assert fa["stop_reason"] == "gather_incomplete:input_field"
    assert fa["missing"] == ["input_field"] and fa["endpoint"] == "/admin/dict.php"
    assert fa["blockers"] and fa["blockers"][0]["item"] == "input_field"
    b = fa["blockers"][0]
    assert b["suggested_manual_step"]
    assert fa["tried"] == []
    inv = fa["recon_inventory"]
    assert "/support/index.php" in inv["urls"] or "/user/passwordforgotten.php" in inv["urls"], inv["urls"][:10]
    # the supplied credentials DID produce a session on this run (auth gathered)
    assert inv["session"]["ok"] is True and inv["session"]["creds_supplied"] is True
    assert isinstance(fa["next_steps_deterministic"], list)
    assert fa["llm"]["judge"] == {} and fa["llm"]["fallback_errors"] == []
    # serialisable (goes into jsonb + a webhook)
    json.dumps(fa, default=str)


def test_analysis_of_a_crash_without_trace(ns, tmp_path):
    fa = ns["_build_failure_analysis"]("RUN-x", str(tmp_path / "missing.jsonl"),
                                        {"verified": False, "crash": True}, gather_manifest=None, state_bits={})
    assert fa["stage_reached"] == "crash" and fa["stop_reason"] == "crash"
    assert fa["blockers"] == [] and fa["tried"] == []


def test_analysis_marks_refine_stage_and_tried_from_runs(ns, tmp_path):
    p = tmp_path / "t.jsonl"
    rows = [
        {"phase": "synthesize", "iteration": 0, "response": '{"command": "curl -s http://t/x?id=1", "assertion": {}}'},
        {"phase": "run", "iteration": 1, "run_output": "HTTP/1.1 403 Forbidden\n", "reason": "waf"},
        {"phase": "refine", "iteration": 1, "response": '{"command": "curl -s http://t/x?id=1%27", "assertion": {}}'},
        {"phase": "run", "iteration": 2, "run_output": "HTTP/1.1 200 OK\nno canary", "reason": "no_canary"},
        {"phase": "result", "iteration": 2, "response": "success=False verified=False", "verified": False},
    ]
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    fa = ns["_build_failure_analysis"]("RUN-r", str(p), {"verified": False, "stop_reason": "max_iters", "iterations": 2})
    assert fa["stage_reached"] == "refine" and fa["stop_reason"] == "max_iters"
    assert [t["http_status"] for t in fa["tried"]] == [403, 200]
    assert fa["tried"][1]["command_head"].startswith("curl -s http://t/x?id=1%27")
    assert any("Last attempt (iter 2)" in s for s in fa["next_steps_deterministic"])


# ── key_phases ⊆ phases actually emitted (sabotage-provable) ────────────────

def _emitted_phase_literals() -> tuple[set, set]:
    lits, prefixes = set(), set()
    for path in (API, GRAPH):
        src = path.read_text()
        for m in re.finditer(r'_poc_trace\(\s*[^,]+,\s*"([^"]+)"', src):
            lits.add(m.group(1))
        for m in re.finditer(r'_poc_trace\(\s*[^,]+,\s*f"([^"{]+)\{', src):
            prefixes.add(m.group(1))
    return lits, prefixes


def _module_const(name: str):
    src = API.read_text()
    tree = _ast.parse(src)
    for node in tree.body:
        if isinstance(node, _ast.Assign) and any(getattr(t, "id", "") == name for t in node.targets):
            ns: dict = {}
            exec(_ast.get_source_segment(src, node), ns)
            return ns[name]
    return None


def test_key_phases_are_all_emitted():
    named = _module_const("_KEY_TRACE_PHASES")
    assert named, "_KEY_TRACE_PHASES missing"
    assert "_key_and_full_trace(" in (_func_src("get_derivation_intel") or ""), "intel must use the shared reader"
    lits, prefixes = _emitted_phase_literals()
    missing = sorted(p for p in named if p not in lits and not any(p.startswith(x) for x in prefixes))
    assert not missing, f"_KEY_TRACE_PHASES names phases nothing emits: {missing}"
    # and the phases this feature relies on are both named and emitted
    for must in ("failure_analysis", "failure_analysis_error", "gather_llm_fallback_error", "judge_near_miss", "recon:auth_establish"):
        assert must in named and must in lits, must


# ── wiring (structural) ──────────────────────────────────────────────────────

def test_failure_analysis_node_is_wired_before_save_store():
    src = GRAPH.read_text()
    assert '_add_node(g, "failure_analysis", node_failure_analysis)' in src
    assert '{"deep_recon": "deep_recon", "save_store": "failure_analysis"}' in src
    assert 'g.add_edge("failure_analysis", "save_store")' in src
    node = _func_src("node_failure_analysis", GRAPH)
    assert node and "_record_build_poc_attempt(" in node and '"failure_analysis"' in node
    assert "build_poc_failure_analysis" in node and "emit_webhook(" in node
    save = _func_src("node_save_store", GRAPH)
    assert save and '"failure_analysis": state.get("failure_analysis")' in save and "_link_attempt_to_store(" in save


def test_attempts_ddl_declared_in_both_places():
    sql = (REPO / "db_init" / "ensure_all_tables.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS public.build_poc_attempts" in sql
    assert _func_src("_ensure_build_poc_attempts_table")
    for col in ("run_id text NOT NULL UNIQUE", "failure_analysis jsonb", "live_recon jsonb", "missing text[]"):
        assert col in sql, col
    assert "build_poc_attempts" in (REPO / "scripts" / "post-install-check.sh").read_text()
    assert '"build_poc_attempts"' in (REPO / "scripts" / "ensure_db_schema.sh").read_text()
