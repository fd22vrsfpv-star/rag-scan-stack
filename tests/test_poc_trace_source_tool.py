"""The trace must say WHICH tool produced a deterministic row.

Why this exists
---------------
`_poc_trace(run_id, phase, response=...)` writes to a generic `response` slot.
The recon nodes put deterministic tool output there (an httpx fetch of
/openapi.json, a ZAP run, an Arjun run) and the LLM nodes put model output
there. The viewer labelled every one of them "llm response", so a 1,600-char
OpenAPI dump read as something a model had written, and there was no way to
tell which tool found a thing without grepping the phase string back to its
emit site in build_poc_graph.py.

`llm_model` already marks the model calls. `_poc_source_tool()` names the tool
behind the deterministic ones, and returning None is a real answer — the UI
then shows the phase name rather than a guess.

Read with `ast` rather than importing api.py: that module pulls fastapi,
psycopg2 and the rest, which are absent on a bare checkout (see
tests/test_langgraph_phases.py for the same approach).
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"

pytestmark = pytest.mark.skipif(
    not API.exists() or not GRAPH.exists(),
    reason="rag-api sources not present in this checkout",
)


def _module():
    return ast.parse(API.read_text(encoding="utf-8"))


def _assign(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == name:
                    return node.value
    return None


def _exact_table():
    val = _assign(_module(), "_POC_SOURCE_TOOL_EXACT")
    assert isinstance(val, ast.Dict), "_POC_SOURCE_TOOL_EXACT must be a dict literal"
    return {k.value: v.value for k, v in zip(val.keys, val.values)}


def _prefix_table():
    val = _assign(_module(), "_POC_SOURCE_TOOL_PREFIX")
    assert isinstance(val, ast.Tuple), "_POC_SOURCE_TOOL_PREFIX must be a tuple literal"
    return [(e.elts[0].value, e.elts[1].value) for e in val.elts]


def _resolve(phase: str):
    """Mirror of _poc_source_tool, driven by the real tables."""
    hit = _exact_table().get(phase)
    if hit:
        return hit
    for prefix, tool in _prefix_table():
        if phase.startswith(prefix):
            return tool
    return None


def _emitted_phases() -> set[str]:
    """Literal phase names passed to _poc_trace across the rag-api sources."""
    found = set()
    for path in (API, GRAPH):
        src = path.read_text(encoding="utf-8")
        for m in re.finditer(r'_poc_trace\(\s*[^,]+,\s*"([^"]+)"', src):
            found.add(m.group(1))
    return found


def test_tables_are_well_formed():
    exact, prefix = _exact_table(), _prefix_table()
    assert exact and prefix
    assert all(isinstance(k, str) and isinstance(v, str) for k, v in exact.items())
    assert all(isinstance(p, str) and isinstance(t, str) for p, t in prefix)


def test_prefix_table_is_ordered_most_specific_first():
    # A looser prefix listed above a tighter one silently swallows it:
    # "recon:zap" before "recon:zap_active" means an active scan is reported
    # as a passive one. Order is the whole contract of a prefix table.
    prefixes = [p for p, _ in _prefix_table()]
    for i, p in enumerate(prefixes):
        for later in prefixes[i + 1:]:
            assert not later.startswith(p), (
                f"{later!r} is shadowed by the earlier, looser prefix {p!r} — "
                "move the more specific entry up")


def test_known_recon_phases_resolve_to_their_real_tool():
    # Each pinned to what the node actually calls, verified at the emit site.
    cases = {
        "recon:openapi":    "OpenAPI",       # _openapi_discover: httpx GET of the spec
        "recon:arjun":      "Arjun",
        "recon:playwright": "Playwright",
        "recon:zap":        "ZAP",
        "recon:zap_active": "ZAP",
        "recon:port_sweep": "TCP-connect",   # socket scan, NOT nmap
        "run":              "kali-listener",
        "prerun_probe":     "httpx",
        "benchmark_oracle": "CVE-Bench",
    }
    for phase, needle in cases.items():
        got = _resolve(phase)
        assert got, f"{phase} resolves to no tool"
        assert needle in got, f"{phase} -> {got!r}, expected to mention {needle!r}"


def test_zap_active_is_not_reported_as_passive():
    assert "active" in (_resolve("recon:zap_active") or "")
    assert "active" not in (_resolve("recon:zap") or "")


def test_node_rows_say_ok_means_did_not_raise():
    # `node` rows are LangGraph task_result events. "failure_analysis ok in
    # 1.35s" says the node did not throw — not that it found anything. The
    # label has to carry that or the row is read as a result.
    got = _resolve("node") or ""
    assert "LangGraph" in got
    assert "raise" in got, "the `node` label must say ok = did not raise"


def test_unknown_phase_returns_none_rather_than_guessing():
    assert _resolve("some_phase_that_does_not_exist") is None
    assert _resolve("") is None


def test_every_recon_phase_emitted_in_the_code_is_named():
    # recon:* rows are the ones an operator asks "which tool found this?" of.
    # A new recon phase with no entry falls back to its bare phase name, so
    # this fails by name and the table stays complete.
    missing = sorted(p for p in _emitted_phases()
                     if p.startswith("recon:") and _resolve(p) is None)
    assert not missing, f"recon phases with no named source tool: {missing}"


def _assigns_source_tool_subscript(fn_name: str) -> bool:
    """True if `<something>["source_tool"] = ...` appears in that function.

    Structural rather than a substring match on the exact spelling: the local
    variable may be renamed without weakening the guarantee, while a comment
    quoting the line must not satisfy it."""
    for node in ast.walk(_func(fn_name)):
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            if (isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                    and t.slice.value == "source_tool"):
                return True
    return False


def _func(name: str) -> ast.FunctionDef:
    for node in ast.walk(_module()):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not found in api.py")


def test_poc_trace_stamps_the_row_on_write():
    # Written onto the row, so the JSONL on disk is self-describing.
    assert _assigns_source_tool_subscript("_poc_trace"), \
        "_poc_trace must stamp source_tool onto the entry it writes"


def test_the_reader_backfills_older_traces():
    # Derived again when serving, so traces that predate the stamp — which is
    # all of them — are labelled too.
    assert _assigns_source_tool_subscript("get_exploit_trace"), \
        "get_exploit_trace must backfill source_tool for rows written before the stamp"


def test_source_tool_is_a_standard_key_not_an_extra():
    """`_trace_extra` returns every NON-standard key, so leaving source_tool out
    of the standard set would surface it a second time as a generic key=value
    chip beside the label that already shows it — and hand it to every
    downstream consumer of the extras dict."""
    val = _assign(_module(), "_POC_TRACE_STD_KEYS")
    assert val is not None, "_POC_TRACE_STD_KEYS not found"
    names = {c.value for c in ast.walk(val) if isinstance(c, ast.Constant)}
    assert "source_tool" in names
    assert "llm_model" in names
