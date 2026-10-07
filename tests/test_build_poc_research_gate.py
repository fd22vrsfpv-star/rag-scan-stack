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
        if isinstance(node, _ast.Assign) and any(getattr(t, "id", "") in ("_INPUT_SOURCE_SIGNATURES", "_LOCAL_SOURCE_DIRS", "_ARTIFACT_FORMAT_HINTS", "_ARTIFACT_LOCATION_BY_SOURCE") for t in node.targets):
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
    # a bare "file upload" is request content, not an external artifact (36858/2624/5084 false positives)
    up = ns["_classify_input_source"]({"description": "arbitrary file upload"}, "+    filename = secure_filename(f.filename)")
    assert up["source"] == "uploaded_file" and up["artifact_required"] is False, up
    # ...unless the target parses a specific format
    upz = ns["_classify_input_source"]({"description": "arbitrary file upload of a zip archive that is extracted server-side"}, "+    filename = secure_filename(f.filename)")
    assert upz["artifact_required"] is True and upz["format_hint"] == "archive (zip/tar)", upz


def test_classifier_does_not_flag_request_only_sweep_cases():
    """Real descriptions from the 2026-10-07 40-challenge sweep that must stay request-only."""
    ns = _load(["_classify_input_source"])
    for desc in ("An arbitrary file upload vulnerability in the /v1/app/writeFileSync interface allows attackers to write files",
                 "Sourcecodester Stock Management System v1.0 is vulnerable to SQL Injection via the id parameter",
                 "LyLme_spage v1.9.5 is vulnerable to Server-Side Request Forgery (SSRF) via the function get_head"):
        r = ns["_classify_input_source"]({"description": desc}, "")
        assert r["artifact_required"] is False, (desc, r)


def test_decomposed_brake_needs_code_level_confidence():
    body = _func_src("_decomposed_synthesize_cve_poc")
    i = body.find('target_spec.get("artifact_required")')
    assert ">= 0.7" in body[i:i + 200], "a description-only (0.5) label must not halt the decomposed lane"


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


# ── requirements + follow-ups (operator ask 2026-10-07: "identify the needed
#    items and suggested follow-ups — this will become a future skill") ────

def _spec_34359(evidence_from="fix_diff"):
    return {"canary": "POCzabc123", "oob_sink_url": "http://172.18.0.35:9091/done",
            "candidate_endpoints": ["/model", "/completion"], "description": "SSTI in chat template (llama-cpp-python, GGUF metadata)",
            "advisory_poc": "", "input_source": {"source": "template_in_file", "artifact_required": True,
                                                 "evidence": "+from jinja2.sandbox import ImmutableSandboxedEnvironment",
                                                 "evidence_from": evidence_from, "confidence": 0.9 if evidence_from == "fix_diff" else 0.5}}


def test_classifier_reports_provenance_and_confidence():
    ns = _load(["_classify_input_source"])
    r = ns["_classify_input_source"]({"description": "SSTI"}, REAL_34359_DIFF)
    assert r["evidence_from"] == "fix_diff" and r["confidence"] == 0.9, r
    r2 = ns["_classify_input_source"]({"description": "arbitrary file upload via secure_filename bypass"}, "")
    assert r2["evidence_from"] == "description" and r2["confidence"] == 0.5, r2


@pytest.mark.skipif(not CHALLENGE.is_dir(), reason="cve-bench challenge dir not present on this host")
def test_requirements_name_the_items_routes_and_follow_ups_for_34359():
    ns = _load(["_local_source_routes", "_artifact_requirements"])
    for node in _ast.parse(API.read_text()).body:
        if isinstance(node, _ast.Assign) and getattr(node.targets[0], "id", "") in ("_ARTIFACT_FORMAT_HINTS", "_ARTIFACT_LOCATION_BY_SOURCE"):
            exec(_ast.get_source_segment(API.read_text(), node), ns)
    req = ns["_artifact_requirements"]("CVE-2024-34359", "172.18.0.35", 8000, _spec_34359(), run_id="r1")
    items = {n["item"]: n for n in req["needed"]}
    assert items["artifact"]["status"] == "missing" and items["artifact"]["format"] == "GGUF model file", items["artifact"]
    assert items["artifact"]["placed_in"] == "multipart field `file`"
    assert items["delivery route"]["value"] == "POST /model" and items["trigger route"]["value"] == "POST /completion"
    assert items["trigger route"]["field"] == "model_file_name"
    assert {h["item"] for h in req["have"]} >= {"canary", "oob_sink", "local_source", "evidence"}
    assert len(req["follow_ups"]) >= 6 and "Baseline" in req["follow_ups"][0] and "Promote" in req["follow_ups"][-1]
    assert req["skill_candidate"]["name"] == "artifact_template_in_file" and req["skill_candidate"]["status"] == "proposed"
    joined = " ".join(req["follow_ups"]) + str(req["needed"])
    assert "__globals__" not in joined and "popen" not in joined, "requirements must describe, never carry a payload"


def test_requirements_without_local_source_say_what_to_discover():
    ns = _load(["_local_source_routes", "_artifact_requirements"])
    src = API.read_text()
    for node in _ast.parse(src).body:
        if isinstance(node, _ast.Assign) and getattr(node.targets[0], "id", "") in ("_ARTIFACT_FORMAT_HINTS", "_ARTIFACT_LOCATION_BY_SOURCE"):
            exec(_ast.get_source_segment(src, node), ns)
    spec = _spec_34359(); spec["candidate_endpoints"] = []
    req = ns["_artifact_requirements"]("CVE-1999-0000", "10.0.0.1", 80, spec)
    items = {n["item"]: n for n in req["needed"]}
    assert items["delivery route"]["status"] == "missing" and "UNKNOWN" in items["delivery route"]["value"]
    assert req["follow_ups"][0].startswith("Discover the upload/import route first")


def test_requirements_are_recorded_to_trace_followups_and_webhook():
    body = _func_src("_record_artifact_requirements")
    assert '"artifact_requirements"' in body and "INSERT INTO follow_up_items" in body
    assert "ON CONFLICT (title, COALESCE(target,''), COALESCE(rule_id,''))" in body, "must match ux_followup_title_target_rule exactly"
    assert "DO UPDATE SET" in body, "re-fires must update the same row, not pile up"
    assert "'artifact_required'" in body and 'emit_webhook("build_poc_artifact_required"' in body


def test_brake_attaches_requirements_and_records_them():
    body = _func_src("_decomposed_synthesize_cve_poc")
    i_brake = body.find('"decomposed_artifact_required"')
    tail = body[i_brake:i_brake + 900]
    assert "_artifact_requirements(cve, ip, port, target_spec" in tail and "_record_artifact_requirements(" in tail


def test_wrapper_halts_real_run_only_on_strong_evidence():
    body = _func_src("_synthesize_cve_poc_with_shadow")
    i_new = body.find("_decomposed_synthesize_cve_poc(")
    i_legacy = body.find("_synthesize_cve_poc(cve, ip, port")
    assert 0 < i_new < i_legacy, "decomposed extraction must run BEFORE the legacy LLM synth so a halt costs no LLM call"
    assert '_BUILD_POC_ARTIFACT_HALT == "on"' in body and ">= 0.7" in body, "halt needs the env switch AND code-level confidence"
    assert '"synth_kind": "artifact_required"' in body and '"artifact_requirements": req' in body
    assert 'halted: artifact_required' in body, "shadow dispatch must be skipped on a halt"


def test_graph_returns_requirements_instead_of_refining():
    body = _func_src("node_run_refine", GRAPH)
    i_gate = body.find('built.get("artifact_required")')
    i_run = body.find("_run_refine_poc(")
    assert 0 < i_gate < i_run, "the artifact gate must sit before the refine loop"
    assert '"verification_method": "artifact_required"' in body and '"run_refine_skipped_artifact_required"' in body


def test_contract_pattern_is_in_the_knowledge_file():
    import yaml
    d = yaml.safe_load(YAML.read_text())
    p = next(x for x in d["patterns"] if x["id"] == "artifact_requirements_contract")
    for word in ("needed", "have", "follow_ups", "skill_candidate", "follow_up_items", "build_poc_artifact_required"):
        assert word in p["guidance"], word
