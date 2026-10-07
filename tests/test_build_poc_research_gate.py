"""2026-10-07: the "is an additional payload needed" brake + RAG research hints
+ local-source recon. Post-mortem of CVE-2024-34359 (50 iterations of request
payloads against a sink fed by file metadata; the target's own source on disk
named both routes).

Dynamic where the helper is pure; structural for wiring.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest pyyaml && PYTHONPATH=. python -m pytest tests/test_build_poc_research_gate.py -v'
"""
from __future__ import annotations

import ast as _ast
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"
YAML = REPO / "knowledge" / "build_poc_research_patterns.yaml"


def _func_src(name: str, path=API) -> str | None:
    src = path.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


def _load(names) -> dict:
    src = API.read_text(); tree = _ast.parse(src); ns = {"os": os}
    # module-level constants the helpers reference
    for node in tree.body:
        if isinstance(node, _ast.Assign) and any(getattr(t, "id", "") in ("_INPUT_SOURCE_SIGNATURES", "_LOCAL_SOURCE_DIRS") for t in node.targets):
            exec(_ast.get_source_segment(src, node), ns)
    for n in names:
        node = next(x for x in _ast.walk(tree) if isinstance(x, _ast.FunctionDef) and x.name == n)
        exec(_ast.get_source_segment(src, node), ns)
    return ns


# ── input-source classifier (dynamic, real fix-diff lines) ─────────────────

REAL_34359_DIFF = "FILE llama_cpp/llama_chat_format.py\n+from jinja2.sandbox import ImmutableSandboxedEnvironment\n-        self._environment = jinja2.Environment(\n+        self._environment = ImmutableSandboxedEnvironment("


def test_classifier_flags_template_in_file_from_the_real_34359_diff():
    ns = _load(["_classify_input_source"])
    r = ns["_classify_input_source"]({"description": "SSTI in chat template rendering"}, REAL_34359_DIFF)
    assert r["source"] == "template_in_file" and r["artifact_required"] is True, r


def test_classifier_defaults_to_request():
    ns = _load(["_classify_input_source"])
    r = ns["_classify_input_source"]({"description": "SQL injection in the id parameter of /search"}, "")
    assert r["source"] == "request" and r["artifact_required"] is False, r


def test_classifier_flags_deserialization_and_upload():
    ns = _load(["_classify_input_source"])
    assert ns["_classify_input_source"]({"description": ""}, "-    obj = pickle.loads(data)\n+    obj = RestrictedUnpickler(io.BytesIO(data)).load()")["source"] == "deserialized_object"
    assert ns["_classify_input_source"]({"description": "arbitrary file upload"}, "+    filename = secure_filename(f.filename)")["artifact_required"] is True


# ── local-source recon (dynamic on the real challenge dir when present) ────

CHALLENGE = Path("/opt/cve-bench/src/critical/challenges/CVE-2024-34359/target")


@pytest.mark.skipif(not CHALLENGE.is_dir(), reason="cve-bench challenge dir not present on this host")
def test_local_source_finds_both_routes_and_the_field_names():
    ns = _load(["_local_source_routes"])
    r = ns["_local_source_routes"]("CVE-2024-34359")
    paths = {(x["path"], tuple(x["methods"])) for x in r["routes"]}
    assert ("/model", ("POST",)) in paths and ("/completion", ("POST",)) in paths, r["routes"]
    fields = {(f["carrier"], f["name"]) for f in r["fields"]}
    assert ("files", "file") in fields and ("json", "model_file_name") in fields, r["fields"]
    assert "AUTHORITATIVE" in r["text"]


def test_local_source_is_a_noop_without_a_dir():
    ns = _load(["_local_source_routes"])
    assert ns["_local_source_routes"]("CVE-1999-0000")["found"] is False


# ── wiring (structural) ────────────────────────────────────────────────────

def test_extract_target_spec_classifies_and_recalls_hints():
    body = _func_src("_extract_target_spec")
    assert "_classify_input_source(" in body and "_fetch_fix_diff_text(" in body, "spec must classify input source from advisory + fix diff"
    assert '"artifact_required"' in body and "_rag_hints_for(" in body, "spec must carry artifact_required and RAG hints"


def test_decomposed_pipeline_halts_when_artifact_required():
    body = _func_src("_decomposed_synthesize_cve_poc")
    i_brake = body.find('target_spec.get("artifact_required")')
    i_craft = body.find("_llm_craft_payload(target_spec")
    assert 0 < i_brake < i_craft, "the artifact brake must run BEFORE the LLM crafter"
    assert '"decomposed_artifact_required"' in body


def test_both_synth_lanes_receive_rag_hints():
    assert "RESEARCH_HINTS" in _func_src("_llm_craft_payload"), "decomposed crafter must inject RAG hints"
    assert "RESEARCH_HINTS" in _func_src("_synthesize_cve_poc"), "legacy synth must inject RAG hints"


def test_graph_runs_local_source_recon_ahead_of_other_segments():
    body = _func_src("node_basic_recon", GRAPH)
    assert "_local_source_routes(" in body and '"recon:local_source"' in body
    assert "seg.insert(0," in body, "local-source text must be placed FIRST so the strategist reads it before guessing"


# ── knowledge file + loader contract ──────────────────────────────────────

def test_research_patterns_yaml_is_well_formed_and_has_no_literal_payload():
    import yaml
    d = yaml.safe_load(YAML.read_text())
    ids = {p["id"] for p in d["patterns"]}
    for must in ("read_local_target_source", "json_body_at_root_is_self_documentation",
                 "method_not_allowed_means_change_verb_or_path", "fix_diff_names_the_input_source",
                 "artifact_required_classes", "cve_2024_34359_gguf_chat_template_ssti"):
        assert must in ids, must
    for p in d["patterns"]:
        assert p.get("guidance") and p.get("triggers") is not None, p["id"]
    text = YAML.read_text()
    assert "__globals__" not in text and "popen(" not in text, "knowledge file must describe the vector, not ship a payload"


def test_loader_is_idempotent_and_registered():
    src = (REPO / "etl" / "load_research_patterns.py").read_text()
    assert "DELETE FROM public.rag_documents WHERE metadata->>'source' = %s" in src
    assert "build_poc_research_pattern" in src
    cov = (REPO / "tests" / "test_knowledge_rag_coverage.py").read_text()
    assert '"build_poc_research_patterns.yaml": "etl/load_research_patterns.py"' in cov


# ── recon keeps a JSON body at / (dynamic) ────────────────────────────────

def test_scout_recon_retains_json_self_documentation():
    """Exec the real _scout_url_recon against a stub httpx client that serves
    CVE-2024-34359's actual landing JSON; the body + its routes must survive."""
    import json, types, sys
    src = API.read_text(); tree = _ast.parse(src)
    node = next(x for x in _ast.walk(tree) if isinstance(x, _ast.FunctionDef) and x.name == "_scout_url_recon")
    body = _ast.get_source_segment(src, node)
    landing = {"message": "llama.cpp server", "usage": {"upload": "POST /model (multipart file)",
                                                       "run": "POST /completion {model_file_name}"}}

    class _R:
        def __init__(s, status, text, ctype):
            s.status_code, s.text, s.headers = status, text, {"content-type": ctype}
    class _Cli:
        def __init__(s, *a, **k): pass
        def __enter__(s): return s
        def __exit__(s, *a): return False
        def get(s, url, **k):
            if url.endswith("/robots.txt"):
                return _R(404, "", "text/html")
            return _R(200, json.dumps(landing), "application/json")
    hx = types.ModuleType("httpx"); hx.Client = _Cli
    sys.modules.setdefault("httpx", hx)  # the function does `import httpx as _hx` locally; sidecar has none
    ns = {"_json": json, "json": json, "_re": __import__("re"), "re": __import__("re"), "httpx": hx, "_hx": hx,
          "os": os, "time": __import__("time")}
    # import stubs for whatever the function imports locally
    exec(body, ns)
    out = ns["_scout_url_recon"]("127.0.0.1", 8000, timeout=1)
    assert "JSON body at /" in out, out
    assert "/model" in out and "/completion" in out, out
