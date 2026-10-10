"""2026-10-10: cross-round command dedup — round 2 must not re-run commands
that already failed in round 1.

The refine loop's `_cmd_signatures` list was local to `_run_refine_poc` and
reset between rounds. When the deep-recon go-around fired (run_refine →
deep_recon → gather_check → synth → run_refine), round 2 could re-synthesize
the exact same failing command from round 1 and burn the full iteration budget
on it again.

Fix: `prior_cmd_signatures` threads round 1's signatures through the graph
state into round 2's refine loop. A match against the prior set triggers
`cross_round_dup` immediately (iteration 1) instead of waiting for the
consecutive-dup threshold.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_build_poc_cross_round_dedup.py -v'
"""
from __future__ import annotations

import ast as _ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"


def _func_src(name: str, path=API) -> str | None:
    src = path.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


# ── 1. _refine_signature is a pure function we can exec ────────────────────
def _refine_signature(cmd):
    """Reimplementation of the normalizer for test — must match api.py's version."""
    import re
    s = (cmd or "").strip().lower()
    s = re.sub(r"poc[0-9a-f]{6,}", "{CANARY}", s)
    s = re.sub(r"\b\d{10,}\b", "{EPOCH}", s)
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"'[a-f0-9]{32,}'", "'{HEX}'", s)
    return s[:300]


def test_refine_signature_normalizes_canary_and_epoch():
    a = _refine_signature("curl -s http://h/x?c=poc1a2b3c4d -d 'ts=1718292739'")
    b = _refine_signature("curl -s http://h/x?c=pocFFEEDDCC -d 'ts=1718292999'")
    assert a == b


def test_refine_signature_matches_api_implementation():
    """The test's reimplementation must use the same regex patterns as api.py."""
    src = _func_src("_run_refine_poc")
    assert src
    assert '{CANARY}' in src and 'poc[0-9a-f]{6,}' in src
    assert '{EPOCH}' in src and r'\b\d{10,}\b' in src
    assert "{HEX}" in src and "[a-f0-9]{32,}" in src


# ── 2. prior_cmd_signatures pre-populates _cmd_signatures ─────────────────
def test_cmd_signatures_seeded_from_prior():
    src = _func_src("_run_refine_poc")
    assert src
    assert "prior_cmd_signatures=None" in src
    assert "_cmd_signatures = list(prior_cmd_signatures or [])" in src


def test_cross_round_dup_check_exists():
    src = _func_src("_run_refine_poc")
    assert src
    assert '"cross_round_dup"' in src
    assert "cross_round_dup_exit" in src
    assert "_sig in _cmd_signatures[:_prior_count]" in src


# ── 3. Graph threads signatures across rounds ─────────────────────────────
def test_graph_state_has_prior_cmd_signatures():
    src = GRAPH.read_text()
    assert "prior_cmd_signatures: List[str]" in src


def test_node_run_refine_passes_and_returns_signatures():
    src = _func_src("node_run_refine", GRAPH)
    assert src
    assert 'prior_cmd_signatures=state.get("prior_cmd_signatures")' in src
    assert '"prior_cmd_signatures": result.get("cmd_signatures")' in src


def test_result_includes_cmd_signatures():
    src = _func_src("_run_refine_poc")
    assert src
    assert '"cmd_signatures": _cmd_signatures' in src


# ── 4. _route_after_refine recognises the new stop reason ─────────────────
def test_route_after_refine_recognises_cross_round_dup():
    src = GRAPH.read_text()
    assert '"cross_round_dup"' in src
    assert '"cross_round_dup"' in src[src.index("_route_after_refine"):]


# ── 5. key trace includes the new phases ──────────────────────────────────
def test_key_trace_includes_cross_round_dup():
    src = API.read_text()
    kt = src[src.index("_KEY_TRACE_PHASES"):]
    kt = kt[:kt.index("}") + 1]
    assert '"cross_round_dup_exit"' in kt
    assert '"refine_dup_exit"' in kt
    assert '"refine_no_progress"' in kt
