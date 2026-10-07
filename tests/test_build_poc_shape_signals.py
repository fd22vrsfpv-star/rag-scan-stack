"""Guard the three shape-signal improvements added 2026-10-06.

1. _prerun_payload_probe captures response body + Allow header
2. Dispatch surfaces probe body preview into the output refine reads
3. _fetch_advisory_poc extracts the real PoC snippet from GHSA pages
4. _synthesize_cve_poc injects KNOWN_GOOD_SHAPE_FROM_ADVISORY when present

Run on demand (sidecar):

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_build_poc_shape_signals.py -v'
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


# ── #1: probe captures body + Allow ───────────────────────────────────────


def test_probe_captures_body_preview():
    body = _func_src("_prerun_payload_probe")
    assert body, "_prerun_payload_probe missing"
    assert "body_preview" in body, (
        "probe must capture the first ~500 bytes of the response body so a "
        "diagnostic like {'detail':'Field required: body.url'} reaches refine"
    )
    assert "allow_header" in body, (
        "probe must also capture the Allow header from an OPTIONS probe so "
        "method-not-allowed is visible without a wasted exploit run"
    )


def test_probe_sends_options_for_allow_header():
    body = _func_src("_prerun_payload_probe")
    assert body, "_prerun_payload_probe missing"
    assert '"OPTIONS"' in body, (
        "probe must send an OPTIONS request to read Allow / "
        "Access-Control-Allow-Methods"
    )


# ── #2 dispatch surface: body preview feeds the refine output ─────────────


def test_dispatch_prepends_probe_body_feedback_on_4xx_5xx():
    """When the probe got a non-2xx with a diagnostic body, the dispatch must
    prepend `PRERUN_PROBE_FEEDBACK status=... body=...` to the run output so
    the refine loop's "last attempt's response" block carries the server's
    own shape hint."""
    src = API.read_text()
    assert "PRERUN_PROBE_FEEDBACK" in src, (
        "the dispatch must surface the probe's body preview to the refine "
        "loop with the PRERUN_PROBE_FEEDBACK marker"
    )
    # The feedback is only prepended when the probe status is >= 400
    # (2xx responses are usually irrelevant / huge).
    assert "_probe_st >= 400" in src or "_probe_st>= 400" in src, (
        "feedback must be gated on probe status >= 400 so success responses "
        "don't pollute the refine output"
    )


# ── #3: GHSA PoC extraction + synth injection ─────────────────────────────


def test_extract_poc_recognises_poc_sections_and_curl_blocks():
    body = _func_src("_extract_poc_from_text")
    assert body, "_extract_poc_from_text missing"
    assert "Proof[-\\s]?of[-\\s]?Concept" in body or "Proof" in body, (
        "the extractor must recognise the canonical GHSA heading"
    )
    assert "curl" in body.lower(), (
        "the extractor must prioritise fenced blocks containing curl"
    )


def test_fetch_advisory_poc_prioritises_ghsa_sources():
    body = _func_src("_fetch_advisory_poc")
    assert body, "_fetch_advisory_poc missing"
    # Must weight GitHub advisories + nuclei templates + gists above other refs.
    for marker in ("github.com/advisories/", "nuclei-templates", "gist.github.com"):
        assert marker in body, (
            f"ranker must prefer {marker!r} — that's where real PoCs live"
        )


def test_synth_prompt_injects_advisory_poc_when_present():
    body = _func_src("_synthesize_cve_poc")
    assert body, "_synthesize_cve_poc missing"
    assert "KNOWN_GOOD_SHAPE_FROM_ADVISORY" in body, (
        "the synth prompt must inject the advisory PoC verbatim as a "
        "KNOWN_GOOD_SHAPE_FROM_ADVISORY block when details.advisory_poc "
        "is non-empty"
    )
    # Must instruct the LLM to mimic shape, not invent a new one.
    assert "MIMIC" in body or "mimic" in body, (
        "the injection block must direct the LLM to MIMIC the published "
        "shape, not improvise around it"
    )


def test_fetch_cve_details_populates_advisory_poc():
    """`_fetch_cve_details` must call `_fetch_advisory_poc` on the NVD refs
    and attach the result to the cached details dict so the synth prompt can
    consume it on the next call."""
    body = _func_src("_fetch_cve_details")
    assert body, "_fetch_cve_details missing"
    assert "_fetch_advisory_poc" in body, (
        "_fetch_cve_details must invoke _fetch_advisory_poc on the NVD refs"
    )
    assert '"advisory_poc"' in body or "'advisory_poc'" in body, (
        "the result must be stored on details['advisory_poc'] so the synth "
        "prompt can read it"
    )
