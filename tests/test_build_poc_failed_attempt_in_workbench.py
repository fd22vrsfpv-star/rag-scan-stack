"""2026-10-10: a FAILED build-PoC run is stored in the exploit workbench too.

Operator: "at the end of failed runs, we should have it add the analysis of the
failed runs, this goes to the markdown file and should be stored with the
exploit workbench for review." The failure analysis already lands in
`build_poc_attempts` + the review markdown; the gap was the workbench itself:
`node_save_store` created an `exploit_store` row ONLY when the run produced a
`final_command`, so a fully-failed run (blocked / gather-incomplete / every
iteration unverified) never appeared in the Exploit workbench.

Now an unverified run with a failure analysis is stored as a `failed_poc` row
carrying the analysis in metadata, and the UI gains a "Failed" filter.

This is a behavior test: node_save_store is exec'd with stubbed `api`/`webhooks`
modules, and we assert what it writes to the store.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_build_poc_failed_attempt_in_workbench.py -v'
"""
from __future__ import annotations

import ast as _ast
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"
UI = REPO / "dashboard" / "frontend" / "src" / "pages" / "ExploitManager.tsx"


def _func_src(name: str) -> str:
    src = GRAPH.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    raise AssertionError(f"{name} not found")


def _run_node_save_store(state, final_command=None, verified=False):
    """exec node_save_store in a namespace with fake api/webhooks modules; return
    the list of _save_exploit_store kwargs it issued."""
    calls = []

    fake_api = types.ModuleType("api")
    fake_api._save_exploit_store = lambda **kw: (calls.append(kw) or f"store-{len(calls)}")
    fake_api._extract_credentials_from_poc_output = lambda *a, **k: []
    fake_api._store_captured_credentials = lambda *a, **k: 0
    fake_api._poc_trace = lambda *a, **k: None
    fake_api._link_attempt_to_store = lambda *a, **k: None
    fake_api._read_trace_entries = lambda *a, **k: []
    fake_api._derive_auto_hint = lambda *a, **k: None
    fake_api._auto_save_recon_hint = lambda *a, **k: None
    fake_api._summarize_build_trace = lambda *a, **k: {}
    fake_webhooks = types.ModuleType("webhooks")
    fake_webhooks.emit_webhook = lambda *a, **k: None

    ns = {"time": __import__("time"), "os": __import__("os"), "logging": __import__("logging")}
    saved = {k: sys.modules.get(k) for k in ("api", "webhooks")}
    sys.modules["api"] = fake_api
    sys.modules["webhooks"] = fake_webhooks
    try:
        exec(_func_src("node_save_store"), ns)
        ns["node_save_store"](state)
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return calls


def _base_state(result):
    return {"cve": "CVE-2024-99999", "ip": "10.0.0.5", "port": 8080, "t0": 0.0,
            "run_id": "CVE-2024-99999_10.0.0.5_1", "built": {"rationale": "r"},
            "result": result, "product": "p", "version": "1", "eid": None,
            "research_out": None, "recon_metrics": {}, "recon_source": None}


def test_failed_run_is_stored_as_a_failed_poc_with_the_analysis():
    fa = {"stage_reached": "gather", "stop_reason": "gather_incomplete",
          "missing": ["input_field"], "narrative": "never reached synth",
          "tried": [{"iteration": 1, "command_head": "curl -s http://h/x", "http_status": 404, "reason": "404"}]}
    state = _base_state({"ok": True, "success": False, "verified": False,
                         "final_command": None, "stop_reason": "gather_incomplete",
                         "iterations": 0, "log_path": "/app/poc_logs/x.jsonl"})
    state["failure_analysis"] = fa
    calls = _run_node_save_store(state)
    assert len(calls) == 1, "a failed run must still write ONE workbench row"
    kw = calls[0]
    assert kw["kind"] == "failed_poc" and kw["verified"] is False
    assert kw["cve"] == "CVE-2024-99999" and kw["target_host"] == "10.0.0.5"
    assert kw["metadata"]["failed_attempt"] is True
    assert kw["metadata"]["failure_analysis"] is fa
    assert kw["metadata"]["stage_reached"] == "gather" and kw["metadata"]["stop_reason"] == "gather_incomplete"
    assert kw["command"] == "curl -s http://h/x"            # the last attempted command, for context
    assert "failed" in kw["name"].lower()


def test_run_with_no_command_and_no_analysis_writes_nothing():
    state = _base_state({"ok": True, "success": False, "verified": False, "final_command": None})
    state["failure_analysis"] = {}
    assert _run_node_save_store(state) == []


def test_verified_run_still_uses_the_normal_row_not_failed_poc():
    state = _base_state({"ok": True, "success": True, "verified": True,
                         "final_command": "curl -s http://h/exploit", "final_assertion": {},
                         "iterations": 2, "log_path": "/app/poc_logs/v.jsonl"})
    state["failure_analysis"] = {}
    calls = _run_node_save_store(state)
    assert len(calls) == 1 and calls[0]["kind"] != "failed_poc" and calls[0]["verified"] is True


def test_ui_has_a_failed_filter():
    ui = UI.read_text()
    assert "filter === 'failed' ? { kind: 'failed_poc' }" in ui
    assert "'all' | 'verified' | 'tweaking' | 'failed'" in ui
    assert "Failed ({failedCount})" in ui
    assert "r.kind === 'failed_poc'" in ui
