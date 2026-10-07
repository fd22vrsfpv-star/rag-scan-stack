"""Phase 3 of the B rollout — decomposed synth pipeline guard.

extract → craft → assemble → (next-iter) diagnose. Each LLM call sees
~500-1000 tokens of focused context instead of 4000+. Deterministic
assembly removes shell-escape bugs. Fallback stub preserves the dict
shape on any stage failure so shadow comparison always records.

Run on demand (sidecar):

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_build_poc_decomposed_pipeline.py -v'
"""
from __future__ import annotations

import ast as _ast
import re
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"


def _func_src(name: str) -> str | None:
    src = API.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


# ── Vuln-class classifier ──────────────────────────────────────────────────


def test_vuln_class_classifier_covers_main_classes():
    body = _func_src("_vuln_class_from_cve")
    assert body, "_vuln_class_from_cve missing"
    # Each class must have a quoted literal somewhere in the function.
    for cls in ("ssrf", "sqli", "ssti", "lfi", "cmdi", "xss", "auth-bypass",
                "upload", "xxe", "deserialization", "unknown"):
        assert f'"{cls}"' in body or f"'{cls}'" in body, (
            f"classifier must know about {cls}"
        )


def test_vuln_class_classifier_fail_soft():
    body = _func_src("_vuln_class_from_cve")
    assert body, "_vuln_class_from_cve missing"
    # Function returns "unknown" at the end — fail-soft contract.
    assert 'return "unknown"' in body, (
        "classifier must return 'unknown' when no pattern matches — fail-soft"
    )


# ── target_spec extractor ──────────────────────────────────────────────────


def test_extract_target_spec_pulls_from_derived_cve_specs():
    body = _func_src("_extract_target_spec")
    assert body, "_extract_target_spec missing"
    # Must query derived_cve_specs for the vector.
    assert "derived_cve_specs" in body, (
        "extractor must read derived_cve_specs — that's where the published "
        "vector lives after prior derivation runs"
    )
    # Must detect the OOB sink.
    assert ":9091" in body, (
        "extractor must probe the CVE-Bench sink at :9091 — the deeptest "
        "corpus's proof mechanism depends on it"
    )
    # Must pull candidate_endpoints from recon.
    assert "candidate_endpoints" in body, (
        "spec must expose candidate_endpoints so the crafter can prefer "
        "live paths over invented ones"
    )


# ── Crafter: narrow prompt, parseable JSON, per-class guidance ────────────


def test_crafter_prompt_is_narrow():
    """The crafter prompt replaces the 4000-token single-prompt synth with
    a focused one. Must include target spec + class guidance + JSON schema."""
    src = API.read_text()
    assert "_CRAFT_PAYLOAD_PROMPT" in src, "crafter prompt constant missing"
    # Must demand JSON-only output.
    prompt_block = src[src.find("_CRAFT_PAYLOAD_PROMPT ="):][:3000]
    assert "No prose outside the JSON" in prompt_block, (
        "crafter prompt must demand JSON-only output — otherwise _poc_extract_json "
        "has to guess"
    )
    # Must reference the vuln class.
    assert "{vuln_class}" in prompt_block, (
        "crafter prompt must substitute vuln_class so per-class guidance "
        "lands in the right place"
    )


def test_crafter_class_guidance_covers_major_classes():
    src = API.read_text()
    assert "_CRAFT_CLASS_GUIDANCE" in src, "class guidance dict missing"
    guidance_block = src[src.find("_CRAFT_CLASS_GUIDANCE ="):][:4000]
    # Each major class gets at least one line of guidance.
    for cls in ("ssrf", "sqli", "ssti", "lfi", "cmdi", "upload",
                "auth-bypass", "xxe"):
        assert f'"{cls}"' in guidance_block, (
            f"class guidance must cover {cls}"
        )


def test_crafter_llm_wrapper_is_fail_soft():
    body = _func_src("_llm_craft_payload")
    assert body, "_llm_craft_payload missing"
    # Must return {"ok": False, ...} on any failure, never raise.
    assert '"ok": False' in body or "'ok': False" in body, (
        "crafter must return ok:False on LLM error / bad JSON — never raise"
    )
    # Must use the narrow caller tag so metrics distinguish decomposed from legacy.
    assert '"decomposed_craft"' in body or "'decomposed_craft'" in body, (
        "crafter must use caller='decomposed_craft' so llm_request_metrics "
        "can separate shadow vs legacy spend"
    )


# ── Deterministic assembler ───────────────────────────────────────────────


def test_assembler_uses_shlex_quote():
    body = _func_src("_assemble_curl")
    assert body, "_assemble_curl missing"
    # Must use shlex.quote so weird payloads don't break the shell.
    assert "_shlex.quote" in body or "shlex.quote" in body, (
        "assembler must shlex-quote fields to prevent shell-escape bugs — "
        "the whole point of deterministic assembly"
    )
    # Must handle method, path, query, headers, body.
    for marker in ("method", "path", "query", "headers", "body"):
        assert marker in body, (
            f"assembler must handle `{marker}` field from the crafted payload"
        )


def test_assembler_appends_sink_poll_for_ssrf():
    body = _func_src("_assemble_curl")
    assert body, "_assemble_curl missing"
    # SSRF / XXE / CMDi all need a sink poll when OOB sink is present.
    assert "SINK-VERIFIED" in body, (
        "assembler must append a sink-poll with SINK-VERIFIED marker for "
        "OOB-class vulns — the verdict matches on this marker"
    )
    assert "oob_sink_url" in body, (
        "assembler must read oob_sink_url from the target_spec"
    )


# ── Pipeline + fallback ────────────────────────────────────────────────────


def test_decomposed_pipeline_falls_back_on_each_stage():
    body = _func_src("_decomposed_synthesize_cve_poc")
    assert body, "_decomposed_synthesize_cve_poc missing"
    # Must have fallback branches for extract / craft / assemble failures.
    for stage in ("extract failed", "craft failed", "assemble failed"):
        assert stage in body, (
            f"decomposed pipeline must have an explicit fallback for `{stage}` — "
            f"otherwise one stage's failure takes down the whole shadow lane"
        )
    # Must call all three stages.
    for fn in ("_extract_target_spec", "_llm_craft_payload", "_assemble_curl"):
        assert fn + "(" in body, (
            f"decomposed pipeline must invoke {fn}"
        )


def test_decomposed_stub_fallback_preserves_shape():
    body = _func_src("_decomposed_stub")
    assert body, "_decomposed_stub missing"
    for field in ("command", "assertion", "rationale", "synth_kind", "run_id",
                  "canary", "metrics", "llm_error_reason"):
        assert f'"{field}"' in body, (
            f"stub must include `{field}` so the shadow comparison dict shape "
            f"stays identical to the legacy synth result"
        )


def test_decomposed_pipeline_does_not_call_legacy():
    """Shadow mode compares INDEPENDENT paths; calling legacy from the
    decomposed function defeats the purpose + risks infinite recursion."""
    body = _func_src("_decomposed_synthesize_cve_poc")
    assert body, "_decomposed_synthesize_cve_poc missing"
    # Word boundary — the function's own def signature contains the legacy
    # name as a substring, which is fine.
    import re
    assert not re.search(r"(?<![A-Za-z0-9_])_synthesize_cve_poc\(", body), (
        "decomposed path must not call legacy synth — breaks shadow-mode "
        "independence AND would recurse infinitely"
    )
