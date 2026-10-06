"""Guard the build-poc LLM error-surfacing + fail-fast model precheck.

Before 2026-10-06, a bad model name (`azure-main:DeepSeek-V4-Flash` with no
matching provider in llm_query) silently fell through to a `deterministic_probe`
fallback. The whole run returned HTTP 200 with `verified=false` and nothing
said WHY. The three CVEs in `cvebench_overnight/results_deeptest3_preset/`
all show `synth_kind=deterministic_probe` + `verification_method=regex_missed`
for exactly this reason. This file fails if that silent-fallback is restored.

Run on demand (sidecar):

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_build_poc_llm_error_surfacing.py -v'
"""
from __future__ import annotations

import ast as _ast
import re
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"


def _func_src(name: str) -> str | None:
    """Return the source of a top-level def or async def named `name`."""
    src = API.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


# ── B: synth loop distinguishes llm_error from deterministic_probe ─────


def test_synth_loop_tracks_last_llm_result():
    """The synthesizer must capture the LAST LLM call's dict so the gate below
    can tell "LLM errored (ok=False)" from "LLM gave empty/malformed JSON"."""
    body = _func_src("_synthesize_cve_poc")
    assert body, "_synthesize_cve_poc not found"
    assert "last_res" in body and "last_err" in body, (
        "the synth loop must track last_res / last_err across the retry loop "
        "so the gate can distinguish llm_error from deterministic_probe"
    )


def test_gate_sets_llm_error_when_llm_failed():
    """When `command` is empty AND the last LLM call had ok=False, synth_kind
    must be 'llm_error' (not the overloaded 'deterministic_probe')."""
    body = _func_src("_synthesize_cve_poc")
    assert body, "_synthesize_cve_poc not found"
    assert 'synth_kind = "llm_error"' in body, (
        "gate must label an LLM failure as llm_error — a model-not-found reads "
        "identical to a weak LLM answer without this split"
    )
    assert "llm_error_reason" in body and "llm_error_model" in body, (
        "the synthesizer must return llm_error_reason + llm_error_model so the "
        "UI can show the real reason instead of a silent fallback"
    )


def test_trace_records_model_and_error():
    """The synthesize trace must carry `model_requested` and `error` so an
    operator can diagnose a silent empty response without tailing the service
    log. Prior trace entries recorded `response_len:0, llm_model:None`."""
    body = _func_src("_synthesize_cve_poc")
    assert body, "_synthesize_cve_poc not found"
    assert '"model_requested"' in body, (
        "trace extras must include model_requested so the operator sees which "
        "identifier the synthesizer actually asked for"
    )
    assert '"error"' in body, (
        "trace extras must include the error reason when the LLM call failed"
    )


# ── C: fail-fast model pre-check at the endpoint ───────────────────────


def test_poc_precheck_model_is_defined():
    body = _func_src("_poc_precheck_model")
    assert body, "_poc_precheck_model helper missing"
    # Local-tag short-circuit — a loaded ollama model doesn't need a round-trip.
    assert "_is_local_model" in body, (
        "_poc_precheck_model must short-circuit on a loaded local ollama tag"
    )
    # Must surface the real error on failure.
    assert '"error"' in body, (
        "_poc_precheck_model must return error in the result dict so the "
        "endpoint can bubble it to the UI"
    )


def test_build_poc_endpoint_calls_precheck_before_launching():
    """The endpoint must probe the operator's model BEFORE accepting the job.
    Prior behaviour accepted any string and discovered 5–15 min later that
    llm_query didn't recognize it. The precheck call must appear before the
    engine kick-off (which starts with the `auth = None` setup line)."""
    body = _func_src("build_poc_endpoint")
    assert body, "build_poc_endpoint missing"
    assert "_poc_precheck_model(body.model)" in body, (
        "build_poc_endpoint must call _poc_precheck_model(body.model) when the "
        "operator pinned a model — else the silent-fallback bug returns"
    )
    # Must raise 400 (not 500) with the real reason.
    assert re.search(r'raise HTTPException\(400,\s*\n?\s*f"LLM model', body), (
        "a failed precheck must raise HTTPException(400, ...) with the real "
        "reason in the message, not a bare 500"
    )
    # Position check: the precheck must come BEFORE the pipeline-kick lines
    # (`auth = None` is the first setup line after the pre-checks).
    pos_check = body.find("_poc_precheck_model(body.model)")
    pos_auth = body.find("auth = None")
    assert 0 < pos_check < pos_auth, (
        "precheck must appear BEFORE `auth = None` so the pipeline never starts "
        "with a broken model"
    )
