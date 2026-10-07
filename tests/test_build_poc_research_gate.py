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
        if isinstance(node, _ast.Assign) and any(getattr(t, "id", "") in ("_INPUT_SOURCE_SIGNATURES", "_LOCAL_SOURCE_DIRS", "_ARTIFACT_FORMAT_HINTS", "_ARTIFACT_LOCATION_BY_SOURCE", "_HEADER_PARAMS") for t in node.targets):
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


# ── gather check (operator ask 2026-10-07: "make sure everything is actually
#    gathered and ready before creating a payload" — strict) ──────────────────

def _load_gather():
    src = API.read_text(); tree = _ast.parse(src); ns = {"os": os}
    for node in tree.body:
        if isinstance(node, _ast.Assign) and getattr(node.targets[0], "id", "") in (
                "_GATHER_FIELD_REQUIRED_CLASSES", "_GATHER_OOB_CLASSES", "_GATHER_FOLLOW_UP", "_BUILD_POC_GATHER_CHECK"):
            exec(_ast.get_source_segment(src, node), ns)
    node = next(x for x in _ast.walk(tree) if isinstance(x, _ast.FunctionDef) and x.name == "_gather_decide")
    exec(_ast.get_source_segment(src, node), ns)
    return ns


def _items(**st):
    base = {"target_reachable": "gathered", "vuln_class": "gathered", "endpoint": "gathered", "method": "gathered",
            "evidence": "gathered", "input_field": "gathered", "auth": "n/a", "oob_sink": "n/a", "artifact": "n/a"}
    base.update(st)
    return [{"item": k, "status": v, "value": None, "source": "test"} for k, v in base.items()]


def test_gather_decide_ready_when_all_required_gathered():
    ns = _load_gather()
    d = ns["_gather_decide"](_items(), "sqli")
    assert d["ready"] is True and d["missing"] == [] and d["summary"].startswith("READY"), d


def test_gather_decide_34359_shape_is_not_ready_on_endpoint_method_field():
    """Round-2 CVE-2024-34359: endpoint=/ invented, method unknown, field unknown → must NOT be ready."""
    ns = _load_gather()
    d = ns["_gather_decide"](_items(endpoint="missing", method="missing", input_field="missing"), "ssti")
    assert d["ready"] is False and d["missing"] == ["endpoint", "input_field", "method"], d
    assert len(d["follow_ups"]) == 3 and "OPTIONS" in d["follow_ups"][2]


def test_gather_decide_class_specific_requirements():
    ns = _load_gather()
    # blind class needs a sink; a non-blind class does not
    assert ns["_gather_decide"](_items(oob_sink="missing"), "ssrf")["missing"] == ["oob_sink"]
    assert ns["_gather_decide"](_items(oob_sink="missing"), "auth-bypass")["ready"] is True
    # injection class needs the field; auth-bypass does not
    assert ns["_gather_decide"](_items(input_field="missing"), "xss")["missing"] == ["input_field"]
    assert ns["_gather_decide"](_items(input_field="n/a"), "auth-bypass")["ready"] is True
    # auth required only when the collector marked it (missing/gathered), never when n/a
    assert ns["_gather_decide"](_items(auth="missing"), "sqli")["missing"] == ["auth"]
    # artifact flagged → required
    assert ns["_gather_decide"](_items(artifact="missing"), "ssti")["missing"] == ["artifact"]
    # evidence: unverified (description only) is tolerated, missing is not
    assert ns["_gather_decide"](_items(evidence="unverified"), "sqli")["ready"] is True
    assert ns["_gather_decide"](_items(evidence="missing"), "sqli")["missing"] == ["evidence"]


def test_gather_check_default_is_strict_and_runs_between_plan_verify_and_synth():
    assert '_BUILD_POC_GATHER_CHECK = (os.environ.get("BUILD_POC_GATHER_CHECK") or "strict")' in API.read_text()
    g = GRAPH.read_text()
    assert 'g.add_edge("plan_verify", "gather_check")' in g and 'g.add_edge("gather_check", "synth")' in g
    assert 'g.add_edge("plan_verify", "synth")' not in g, "the old direct edge must be gone or the check is bypassed"


def test_gather_check_halts_synth_and_refine_when_strict_and_not_ready():
    node = _func_src("node_gather_check", GRAPH)
    assert 'if mode == "strict" and not man.get("ready")' in node and 'upd["gather_blocked"] = True' in node
    synth = _func_src("node_synth", GRAPH)
    i_gate = synth.find('state.get("gather_blocked")'); i_synth = synth.find("_synthesize_cve_poc_with_shadow(")
    assert 0 < i_gate < i_synth, "synth must check gather_blocked BEFORE calling the LLM"
    refine = _func_src("node_run_refine", GRAPH)
    i_g = refine.find('gather_blocked'); i_a = refine.find('built.get("artifact_required")'); i_r = refine.find("_run_refine_poc(")
    assert 0 < i_g < i_a < i_r
    assert '"verification_method": "gather_incomplete"' in refine


def test_gather_manifest_fills_cheap_gaps_before_judging():
    body = _func_src("_gather_manifest")
    for src_name in ("plan_verify", "local_source", "candidate_probe", "cli.options(", "_probe_session_valid(", "_artifact_requirements("):
        assert src_name in body, f"collector must try {src_name}"
    assert "_gather_decide(items, vc)" in body


def test_gather_manifest_is_recorded_and_injected():
    rec = _func_src("_record_gather_manifest")
    assert '"gather_check"' in rec and "'gather_incomplete'" in rec and 'emit_webhook("build_poc_gather_check"' in rec
    assert "ON CONFLICT (title, COALESCE(target,''), COALESCE(rule_id,''))" in rec
    node = _func_src("node_gather_check", GRAPH)
    assert "_gather_manifest_text(man)" in node and '"guidance": guidance' in node, "confirmed facts must reach synth guidance"


def test_gather_pattern_is_in_the_knowledge_file():
    import yaml
    d = yaml.safe_load(YAML.read_text())
    p = next(x for x in d["patterns"] if x["id"] == "gather_check_before_payload")
    for word in ("endpoint", "method", "OOB", "strict", "gather_incomplete", "build_poc_gather_check"):
        assert word in p["guidance"], word


# ── source miner (dynamic, real round-4 strings) ──────────────────────────

ADV_36779 = ('[source: https://github.com/CveSecLook/cve/issues/42]\npython sqlmap.py -u "http://localhost/stock/php_action/editCategories.php" '
             '--data="editCategoriesName=1&editCategoriesStatus=1&editCategoriesId=7" --method=POST --dbms=mysql --level=5 --risk=3 --batch --dbs --dump')
DV_4320 = ("{'cve': 'CVE-2024-4320', 'notes': \"AUTO-DERIVED from advisory + patch diff. Evidence: The vulnerability is in the "
           "'/install_extension' endpoint where the 'name' parameter is passed to ExtensionBuilder().build_extension() without proper sanitization")
DV_32980 = ("{'cve': 'CVE-2024-32980', 'notes': 'AUTO-DERIVED from advisory + patch diff. Evidence: The fix commit shows that the vulnerable code "
            "was using the Host header directly in outbound requests without proper sanitization")


def test_miner_reads_a_sqlmap_advisory():
    ns = _load(["_gather_mine_sources"])
    m = ns["_gather_mine_sources"](ADV_36779, "")
    assert m["paths"] == ["/stock/php_action/editCategories.php"], m
    assert m["fields"][:3] == ["editCategoriesName", "editCategoriesStatus", "editCategoriesId"], m
    assert m["methods"] == ["POST"], m


def test_miner_reads_derived_vector_prose():
    ns = _load(["_gather_mine_sources"])
    m = ns["_gather_mine_sources"]("", DV_4320)
    assert "/install_extension" in m["paths"] and m["fields"] == ["name"], m
    h = ns["_gather_mine_sources"]("", DV_32980)
    assert h["headers"] == ["Host"] and h["paths"] == [], h


def test_collector_uses_mined_paths_fields_methods():
    body = _func_src("_gather_manifest")
    assert "_gather_mine_sources(" in body and "probe_list += _path_variants(_mp)" in body
    assert 'mined["fields"][0]' in body and "(header)" in body and '"advisory_poc"' in body
    # "/" accepted only on a LIVE verdict
    assert 'v == "LIVE" and c["endpoint"] not in ("", "none")' in body and 'v == "SUSPECT" and c["endpoint"] not in ("/", "", "none")' in body
    # header vectors: root accepted as the endpoint when the root answers
    assert 'if not endpoint and mined["headers"]:' in body and '"root_probe:HTTP' in body
    assert 'mined from advisory/derived' in _func_src("_gather_manifest_text"), "synth must see every mined field, not just the first"


def test_miner_ignores_the_source_citation_url():
    ns = _load(["_gather_mine_sources"])
    m = ns["_gather_mine_sources"]("[source: https://github.com/x/y/issues/42]\nnothing else here", "")
    assert m["paths"] == [] and m["fields"] == [], m


def test_gather_never_requires_a_session_for_auth_bypass():
    """Round 5, CVE-2024-3408: strict gate halted with 'missing: auth' — for an
    auth-bypass CVE the session is the exploit's OUTPUT. Sabotage: drop the
    class rule and this fails."""
    ns = _load_gather()
    d = ns["_gather_decide"](_items(auth="missing", input_field="n/a"), "auth-bypass")
    assert d["ready"] is True and "auth" not in d["required"], d
    body = _func_src("_gather_manifest")
    assert 'if vc == "auth-bypass":' in body and "exploit's output" in body


# ── 2026-10-07 OPEN_ITEMS fixes (auth-bypass + SSRF post-mortem) ──────────

def test_header_params_are_recognised():
    ns = _load(["_is_header_param"])
    for h in ("Host", "X-Forwarded-For", "x-custom-thing", "Referer"):
        assert ns["_is_header_param"](h), h
    for p in ("id", "query", "url", "x"):
        assert not ns["_is_header_param"](p), p


def test_plan_verify_probes_header_inputs_as_headers_and_reports_needs_id():
    body = _func_src("_verify_strategist_plan")
    assert "hdr_param = _is_header_param(param)" in body
    assert "_fetch(endpoint, headers={param: canary}) if hdr_param" in body, "header input must be sent as a header"
    assert '"127.0.0.1:1" if hdr_param' in body, "SSRF class probe must be a host value for a header input"
    assert 'verdicts[c["label"]] = "NEEDS_ID"' in body and "_resolve_placeholder_path(endpoint" in body
    assert 'in ("LIVE", "SUSPECT", "NEEDS_ID")' in body, "NEEDS_ID must not trigger the ALL-FAKE directive"


def test_placeholder_resolution_and_id_pool():
    ns = _load(["_path_placeholders", "_collect_id_pool", "_resolve_placeholder_path"])
    pool = ns["_collect_id_pool"]("Dtale instances: data_id=1, data_id=2; user id: 7", {"objects": [{"script_id": 9}]}, None)
    assert pool["data_id"] == 1 and pool["id"] == 7 and pool["script_id"] == 9, pool
    assert ns["_resolve_placeholder_path"]("/dtale/test-filter/{data_id}", pool) == ("/dtale/test-filter/1", {"data_id": 1})
    assert ns["_resolve_placeholder_path"]("/api/{id}", {"data_id": 3}) == ("/api/3", {"id": 3}), "suffix match"
    assert ns["_resolve_placeholder_path"]("/api/{thing}", {}) == (None, {})


def test_readiness_treats_a_placeholder_endpoint_as_a_blocker_not_a_probe():
    body = _func_src("_assess_exploit_readiness")
    i_ph = body.find('if tep and "{" in tep:'); i_probe = body.find('elif tep and tep.startswith("/"):')
    assert 0 < i_ph < i_probe and "unresolved placeholder" in body


REAL_3408_BOUNCE = ("HTTP/1.1 302 FOUND\r\nServer: Werkzeug/3.0.6 Python/3.11.16\r\nContent-Type: text/html; charset=utf-8\r\n"
                    "Location: /login?next=%2Fdtale%2Ftest-filter%2F1%3Fquery%3DPOCb8fb7e2f6c\r\n\r\n<!doctype html>Redirecting...")


def test_redirect_reflection_is_not_verification():
    ns = _load(["_canary_only_in_redirect"])
    assert ns["_canary_only_in_redirect"](REAL_3408_BOUNCE, "POCb8fb7e2f6c") is True
    assert ns["_canary_only_in_redirect"]("HTTP/1.1 200 OK\r\n\r\nresult: POCb8fb7e2f6c", "POCb8fb7e2f6c") is False
    assert ns["_canary_only_in_redirect"]("HTTP/1.1 302 FOUND\r\nLocation: /x\r\n\r\nPOCb8fb7e2f6c", "POCb8fb7e2f6c") is False
    body = _func_src("_live_verify_recipe")
    assert '"canary_reflected_in_redirect"' in body and body.find("_canary_only_in_redirect(out, canary)") < body.find('"canary_read_back"')


def test_identical_resend_is_rejected_before_dispatch():
    body = _func_src("_run_refine_poc")
    i_rej = body.find('if _new_cmd == (command or "").strip():')
    i_sig = body.find("_sig = _refine_signature(_new_cmd)")
    assert 0 < i_rej < i_sig, "identical check must run before the signature/dup-streak logic"
    assert "IDENTICAL_COMMAND_REJECTED" in body and '"refine_no_progress"' in body and 'caller="cve_poc_refine_identical"' in body


def test_inband_diff_signal_and_hook():
    ns = _load(["_inband_diff_signal"])
    assert ns["_inband_diff_signal"](200, 1000, 200, 1260)["changed"] is True
    assert ns["_inband_diff_signal"](200, 1000, 500, 1000)["changed"] is True
    assert ns["_inband_diff_signal"](200, 1000, 200, 1050)["changed"] is False
    assert ns["_inband_diff_signal"](None, 0, 200, 1)["changed"] is False
    body = _func_src("_run_refine_poc")
    assert "_inband_baseline_diff(ip, port, command" in body and "INBAND_DIFF_FEEDBACK" in body and '"inband_diff"' in body


def test_local_source_reads_spin_openapi_rust_and_go(tmp_path):
    (tmp_path / "CVE-0000-0001" / "target" / "src").mkdir(parents=True)
    t = tmp_path / "CVE-0000-0001" / "target"
    (t / "spin.toml").write_text('[[trigger.http]]\nroute = "/..."\ncomponent = "r"\n[component.r]\nallowed_outbound_hosts = ["http://self", "https://self"]\n')
    (t / "src" / "api.json").write_text('{"openapi":"3.0.4","paths":{"/proxy":{"get":{"summary":"Proxy endpoint","description":"Fetches from the root endpoint and returns the response"}}}}')
    (t / "src" / "lib.rs").write_text('#[get("/health")]\nasync fn h() {}\nRouter::new().route("/items", post(create))\n')
    (t / "main.go").write_text('http.HandleFunc("/upload", up)\nr.POST("/api/run", run)\n')
    ns = _load(["_local_source_routes"]); ns["_LOCAL_SOURCE_DIRS"] = [str(tmp_path)]
    r = ns["_local_source_routes"]("CVE-0000-0001")
    paths = {(x["path"], tuple(x["methods"])) for x in r["routes"]}
    assert ("/proxy", ("GET",)) in paths and ("/health", ("GET",)) in paths and ("/items", ("POST",)) in paths
    assert ("/upload", ("GET", "POST")) in paths and ("/api/run", ("POST",)) in paths and ("/...", ("GET", "POST")) in paths, paths
    assert r["facts"] and r["facts"][0]["key"] == "allowed_outbound_hosts" and "self" in r["facts"][0]["value"]
    assert "config allowed_outbound_hosts" in r["text"] and "Proxy endpoint" in r["text"] and "Fetches from the root endpoint" in r["text"]


def test_gather_check_requires_a_resolved_id_for_templated_routes():
    ns = _load_gather()
    d = ns["_gather_decide"](_items(endpoint="missing", endpoint_id="missing"), "rce")
    assert "endpoint_id" in d["missing"] and "placeholder" in " ".join(d["follow_ups"])
    body = _func_src("_gather_manifest")
    assert "_resolve_placeholder_path(c[\"endpoint\"], id_pool" in body and '"placeholder_resolved:' in body
    g = GRAPH.read_text()
    assert "_collect_id_pool(" in g and "id_pool=_ids" in g and 'id_pool=state.get("id_pool")' in g


def test_miner_does_not_take_a_quoted_config_value_as_a_field():
    """Round 5 CVE-2024-3408: derived notes `SECRET_KEY = "Dtale" ... key` produced input_field=Dtale."""
    ns = _load(["_gather_mine_sources"])
    m = ns["_gather_mine_sources"]("", "the hardcoded SECRET_KEY = \"Dtale\" in the flask config\nkey rotation was added")
    assert "Dtale" not in m["fields"], m
    m2 = ns["_gather_mine_sources"]("", "where the 'name' parameter is passed")
    assert m2["fields"] == ["name"]


def test_path_variants_strip_the_deployment_prefix():
    ns = _load(["_path_variants"])
    assert ns["_path_variants"]("/stock/php_action/editCategories.php") == [
        "/stock/php_action/editCategories.php", "/php_action/editCategories.php", "/editCategories.php"]
    assert ns["_path_variants"]("/install_extension") == ["/install_extension"]
    assert ns["_path_variants"]("relative") == []


def test_collector_uses_cookie_header_prefix_variants_and_mined_method():
    body = _func_src("_gather_manifest")
    assert '.get("cookie_header")' in body, "session_info stores the cookie under cookie_header (36779 round 5 saw no session)"
    assert "probe_list += _path_variants(_mp)" in body
    assert "+ _probe_methods:" in body and 'if rp.status_code not in (404, 405):' in body


def test_id_pool_reads_numeric_path_segments_and_resolver_falls_back():
    ns = _load(["_path_placeholders", "_collect_id_pool", "_resolve_placeholder_path"])
    pool = ns["_collect_id_pool"]("Redirects to: /dtale/main/1 (HTTP 302)")
    assert pool == {"main": 1}, pool
    path, used = ns["_resolve_placeholder_path"]("/dtale/test-filter/{data_id}", pool)
    assert path == "/dtale/test-filter/1" and used.get("_fallback") is True, (path, used)
    assert ns["_resolve_placeholder_path"]("/x/{slug}", pool) == (None, {}), "fallback only for *id placeholders"


def test_scout_recon_keeps_the_root_redirect_location():
    body = _func_src("_scout_url_recon")
    assert 'r.headers.get("location")' in body and '"Redirects to:' in body


def test_openapi_paths_line_round_trips_and_feeds_the_collector():
    ns = _load(["_parse_openapi_paths_line"])
    routes = ns["_parse_openapi_paths_line"]("Tech: x | OpenAPI paths (112 at /openapi.json): POST /install_extension; GET /docs; GET/POST /extensions/{path}")
    assert routes[0] == {"path": "/install_extension", "methods": ["POST"]} and routes[2]["methods"] == ["GET", "POST"], routes
    assert ns["_parse_openapi_paths_line"]("nothing here") == []
    body = _func_src("_gather_manifest")
    assert "_parse_openapi_paths_line(recon_text" in body and '"openapi"' in body
    assert '_probe_methods.append("POST")' in body, "a POST-only FastAPI route answers 404 to GET (lollms /install_extension)"
    recon = _func_src("_scout_url_recon")
    assert '"/openapi.json"' in recon and "OpenAPI paths (" in recon


def test_plan_verify_checks_existence_with_the_plans_method():
    body = _func_src("_verify_strategist_plan")
    assert r'(?:\s+method=(\S+))?' in body, "candidate regex must capture method="
    assert 'if st == 404 and pmethod not in ("GET", "HEAD"):' in body and "_fetch(endpoint, method=pmethod)" in body
