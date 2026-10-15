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

from _ast_assert import arg_default, call_kwarg

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"



def _ast_func(path, name):
    """The ast node for `name` in `path` — for structural assertions."""
    src = path.read_text(encoding="utf-8") if hasattr(path, "read_text") else path
    for n in _ast.walk(_ast.parse(src)):
        if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and n.name == name:
            return n
    raise AssertionError(f"{name} not found")

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
    """The parameter exists and defaults to None, and the local list is SEEDED
    from it rather than starting empty.

    Asserted structurally: the substring form broke on whitespace, on a
    reordered signature, and matched the same text in a comment. What must hold
    is that `_cmd_signatures` is initialised from `prior_cmd_signatures` — if it
    starts as a bare `[]`, round 2 cannot see round 1's commands and the whole
    cross-round check is dead while every one of these tests still passes.
    """
    api = API.read_text()
    assert arg_default(api, "_run_refine_poc", "prior_cmd_signatures") is None, (
        "_run_refine_poc takes no prior_cmd_signatures parameter (or it does "
        "not default to None), so the caller cannot hand round 1's signatures in")
    fn = _ast_func(GRAPH if False else API, "_run_refine_poc")
    seeded = False
    for n in _ast.walk(fn):
        if not isinstance(n, _ast.Assign):
            continue
        if not any(isinstance(t, _ast.Name) and t.id == "_cmd_signatures" for t in n.targets):
            continue
        if any(isinstance(x, _ast.Name) and x.id == "prior_cmd_signatures"
               for x in _ast.walk(n.value)):
            seeded = True
    assert seeded, (
        "_cmd_signatures is not seeded from prior_cmd_signatures — round 2 "
        "starts blind and re-sends commands that already failed in round 1")


def test_cross_round_dup_check_exists():
    src = _func_src("_run_refine_poc")
    assert src
    assert '"cross_round_dup"' in src
    assert "cross_round_dup_exit" in src
    # The check itself, structurally: a membership test of the signature
    # against the PRIOR slice of the list. Pinning the exact expression text
    # broke on a rename of either local and on any reformat.
    fn = _ast_func(API, "_run_refine_poc")
    checks_prior_slice = any(
        isinstance(n, _ast.Compare)
        and any(isinstance(o, _ast.In) for o in n.ops)
        and any(isinstance(x, _ast.Subscript) and isinstance(x.slice, _ast.Slice)
                and isinstance(x.value, _ast.Name) and x.value.id == "_cmd_signatures"
                for x in n.comparators)
        for n in _ast.walk(fn))
    assert checks_prior_slice, (
        "nothing tests the new signature against the PRIOR slice of "
        "_cmd_signatures — without the slice the check also matches this "
        "round's own commands, so it fires on the first repeat instead of a "
        "genuine cross-round duplicate")


# ── 3. Graph threads signatures across rounds ─────────────────────────────
def test_graph_state_has_prior_cmd_signatures():
    """BuildPocState must carry the field, or LangGraph drops it between nodes."""
    tree = _ast.parse(GRAPH.read_text())
    fields = {n.target.id for cls in _ast.walk(tree)
              if isinstance(cls, _ast.ClassDef) and cls.name == "BuildPocState"
              for n in cls.body
              if isinstance(n, _ast.AnnAssign) and isinstance(n.target, _ast.Name)}
    assert "prior_cmd_signatures" in fields, (
        "BuildPocState has no prior_cmd_signatures field, so the signatures "
        "node_run_refine returns are discarded before the second round reads "
        f"them. Declared fields: {sorted(fields)}")


def test_node_run_refine_passes_and_returns_signatures():
    src = _func_src("node_run_refine", GRAPH)
    assert src
    assert call_kwarg(src, "_run_refine_poc", "prior_cmd_signatures"), (
        "node_run_refine does not pass prior_cmd_signatures into "
        "_run_refine_poc, so round 2 never receives round 1's commands")
    fn = _ast_func(GRAPH, "node_run_refine")
    returns_sigs = any(
        isinstance(n, _ast.Return) and isinstance(n.value, _ast.Dict)
        and any(isinstance(k, _ast.Constant) and k.value == "prior_cmd_signatures"
                for k in n.value.keys)
        for n in _ast.walk(fn))
    assert returns_sigs, (
        "node_run_refine does not return prior_cmd_signatures, so nothing is "
        "written back into the graph state and round 2 starts empty")


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
