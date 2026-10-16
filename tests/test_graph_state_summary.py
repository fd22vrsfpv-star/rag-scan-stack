"""The graph's final state reaches the trace, bounded.

BuildPocState is the pipeline's entire memory — 69 fields carrying the recon,
the session, the manifest, the proven facts and the verdict — and at the end of
a run it was discarded. The trace recorded what each node SAID; nothing
recorded what the run ENDED UP KNOWING. So "did the manifest ever get a
product", or "was there a session when synthesis ran", could only be answered
by replaying node output and inferring.

The summary must be BOUNDED or it defeats itself. A real end-state carries
~15KB in `guidance` alone plus multi-kilobyte recon segments; writing that
verbatim into every run's trace buries the signal it exists to surface.
Measured on a realistic state: 1,612 bytes out, from a state whose `guidance`
field alone was 15,000.

Sabotage check: return the raw values instead of their shapes and
`test_large_values_are_reduced_to_shape` fails; drop the phase from
`_KEY_TRACE_PHASES` and `test_the_summary_is_a_key_trace_phase` fails.

    pytest tests/test_graph_state_summary.py -q
"""

import ast
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"
API = REPO / "app" / "rag-api" / "api.py"


def _summarize():
    """Load `summarize_state` in isolation — build_poc_graph imports the world."""
    if not GRAPH.exists():
        pytest.skip("build_poc_graph.py not found")
    src = GRAPH.read_text(encoding="utf-8")
    tree = ast.parse(src)
    ns = {"Dict": dict, "Any": object}
    for n in tree.body:
        if isinstance(n, ast.ClassDef) and n.name == "BuildPocState":
            anns = {f.target.id: "x" for f in n.body if isinstance(f, ast.AnnAssign)}
            ns["BuildPocState"] = type("BuildPocState", (), {"__annotations__": anns})
        if isinstance(n, ast.FunctionDef) and n.name == "summarize_state":
            exec(compile(ast.Module([n], []), "<t>", "exec"), ns)
    if "summarize_state" not in ns:
        pytest.fail("summarize_state is not defined in build_poc_graph.py")
    return ns["summarize_state"]


REAL = {
    "cve": "CVE-2024-3408", "ip": "172.19.14.107", "port": 9090,
    "product": "", "segments": ["x" * 9000, "y" * 4000],
    "session_info": {"ok": True, "method": "supplied", "cookie_header": "sid=abc"},
    "guidance": "g" * 15000, "iters": 9, "verified": False,
    "result": {"verified": False, "success": False, "stop_reason": "max_iters",
               "iterations": 9, "off_target": True, "drifted": False,
               "verification_method": "regex_missed"},
}


def test_large_values_are_reduced_to_shape():
    out = _summarize()(REAL)
    f = out["fields"]
    assert f["guidance"] == "str(15000 chars)", (
        f"a 15KB field was not reduced: {str(f['guidance'])[:60]!r}. Writing "
        "the state verbatim buries the signal the summary exists to surface")
    assert f["segments"] == "list(2)"
    assert str(f["session_info"]).startswith("dict(3)"), f["session_info"]


def test_the_whole_summary_stays_small():
    out = _summarize()(REAL)
    size = len(json.dumps(out))
    assert size < 8000, (
        f"the summary is {size} bytes; it goes into every run's trace and "
        "must stay readable")


def test_small_values_are_kept_verbatim():
    """Reducing everything to a shape would lose the answer."""
    f = _summarize()(REAL)["fields"]
    assert f["cve"] == "CVE-2024-3408"
    assert f["port"] == 9090
    assert f["iters"] == 9
    assert f["verified"] is False, "a False boolean must survive, not read as empty"


def test_empty_is_distinguished_from_never_set():
    """Two different problems with two different fixes."""
    out = _summarize()(REAL)
    assert out["fields"]["product"] == "empty", (
        "a field that exists but is blank must report `empty` — that is a "
        "pipeline that ran and found nothing")
    assert "known_good" in out["missing"], (
        "a field never set must be listed as missing, not reported empty — "
        "that is a step that never ran")
    assert out["populated"] + out["empty"] + len(out["missing"]) == \
        len(_summarize().__globals__["BuildPocState"].__annotations__), \
        "every declared field must appear in exactly one bucket"


def test_the_verdict_is_pulled_out():
    v = _summarize()(REAL)["verdict"]
    for k in ("verified", "success", "stop_reason", "iterations",
              "off_target", "drifted", "verification_method"):
        assert k in v, f"the verdict omits {k}"
    assert v["stop_reason"] == "max_iters"
    assert v["verification_method"] == "regex_missed"


def test_it_never_raises_on_a_broken_state():
    f = _summarize()
    for bad in ({}, {"result": None}, {"result": "not-a-dict"}, None):
        out = f(bad)
        assert isinstance(out, dict) and "fields" in out, bad


def test_the_summary_is_emitted_at_the_end_of_a_run():
    src = GRAPH.read_text(encoding="utf-8")
    fn = next((n for n in ast.walk(ast.parse(src))
               if isinstance(n, ast.FunctionDef) and n.name == "invoke_build_poc"), None)
    assert fn, "invoke_build_poc not found"
    body = ast.get_source_segment(src, fn) or ""
    # CALLED, checked on the AST. A substring match is satisfied by the
    # comment above the call ("See summarize_state:"), so replacing the call
    # with `_summary = {}` left this passing — the same trap that let a
    # deleted import through twice earlier today.
    called = {n.func.id for n in ast.walk(fn)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "summarize_state" in called, (
        "invoke_build_poc does not CALL summarize_state, so the final state "
        "is discarded at the end of every run")
    assert "graph_state_summary" in body, "the summary is not traced"
    # and it must run even when the graph produced no result
    i_sum = body.find("summarize_state")
    i_res = body.find('final.get("result")')
    assert 0 < i_sum < i_res, (
        "the summary is emitted after the result is unpacked; a run whose "
        "result is missing is exactly the one whose state needs reporting")


def test_the_summary_is_a_key_trace_phase():
    """Otherwise it does not reach the failure-analysis report."""
    src = API.read_text(encoding="utf-8")
    i = src.find("_KEY_TRACE_PHASES")
    assert i > 0, "_KEY_TRACE_PHASES is gone"
    block = src[i:i + 2500]
    for phase in ("graph_state_summary", "known_good_probe"):
        assert phase in block, (
            f"{phase!r} is not a key trace phase, so it never reaches the "
            "report a reviewer reads")
