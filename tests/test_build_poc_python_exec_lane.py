"""Phase 2 of the B rollout — curl→httpx execution lane guard.

Shipped 2026-10-06. Parses curl commands into structured HTTP requests and
runs them via httpx.Client so we capture r.status_code / r.headers / r.cookies
/ r.elapsed natively. Shell lane is preserved for non-HTTP commands.

Run on demand (sidecar):

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_build_poc_python_exec_lane.py -v'
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


# ── Can-execute detector ───────────────────────────────────────────────────


def test_can_execute_detector_rejects_shell_features():
    body = _func_src("_can_execute_in_python")
    assert body, "_can_execute_in_python missing"
    # Must reject process substitution, command substitution.
    for marker in ("`", "$(", "<(", ">("):
        assert repr(marker) in body or marker in body, (
            f"detector must reject shell feature {marker!r}"
        )


def test_can_execute_detector_rejects_non_curl_tools():
    body = _func_src("_can_execute_in_python")
    assert body, "_can_execute_in_python missing"
    for tool in ("nmap", "nc", "wget", "python", "bash", "awk", "grep", "sed"):
        assert tool in body, (
            f"detector must reject non-curl tool {tool!r} to force shell fallback"
        )


def test_can_execute_detector_accepts_pure_curl_chain():
    """Run the detector on a known-safe curl chain. This is a structural
    test, not a dynamic one — just verify the detector names curl / sleep /
    && / ; as the allowed set."""
    body = _func_src("_can_execute_in_python")
    assert body, "_can_execute_in_python missing"
    for tok in ('"curl"', '"sleep"', '"&&"', '";"'):
        assert tok in body, (
            f"allowed_bins must include {tok} for pure curl chains to pass"
        )


# ── Curl parser ────────────────────────────────────────────────────────────


def test_curl_parser_recognises_common_flags():
    body = _func_src("_curl_to_request")
    assert body, "_curl_to_request missing"
    for flag in ('"-X"', '"-H"', '"-d"', '"--data-urlencode"', '"-G"', '"-F"',
                 '"-b"', '"-c"', '"-u"', '"-k"', '"-L"', '"--max-time"'):
        assert flag in body, (
            f"parser must handle curl flag {flag} — otherwise common exploit "
            f"shapes fall back to shell unnecessarily"
        )


def test_curl_parser_returns_full_request_spec():
    body = _func_src("_curl_to_request")
    assert body, "_curl_to_request missing"
    for field in ("method", "url", "headers", "body", "cookies", "auth",
                  "verify", "timeout", "follow_redirects"):
        assert f'"{field}"' in body, (
            f"request spec must include `{field}` so the executor has the "
            f"full HTTP spec from one parse pass"
        )


# ── Chain executor ─────────────────────────────────────────────────────────


def test_executor_uses_httpx_client_as_session():
    body = _func_src("_execute_http_chain")
    assert body, "_execute_http_chain missing"
    # Must use httpx.Client (so cookies persist across steps naturally).
    assert "_hx.Client" in body or "httpx.Client" in body, (
        "executor must use httpx.Client — cookie persistence across chained "
        "curls is the whole point of the Python lane"
    )
    # Must honour follow_redirects per-request (NOT globally — some steps need to see 302s).
    assert "follow_redirects" in body, (
        "executor must honour per-request follow_redirects (not global on/off)"
    )


def test_executor_captures_structured_response_per_step():
    body = _func_src("_execute_http_chain")
    assert body, "_execute_http_chain missing"
    for field in ('"status"', '"headers"', '"body_preview"', '"elapsed_ms"',
                  '"cookies"'):
        assert field in body, (
            f"per-step response dict must include {field} — this is the Phase 2 "
            f"win vs curl stdout parsing"
        )


def test_executor_mirrors_shell_double_amp_short_circuit():
    body = _func_src("_execute_http_chain")
    assert body, "_execute_http_chain missing"
    # On 4xx/5xx or exception, remaining steps should NOT run (mirrors `&&`).
    assert "break" in body, (
        "executor must `break` on step failure so chained `curl && curl` "
        "semantics are preserved (next command runs only if prior succeeded)"
    )


# ── Dispatch hook integration ─────────────────────────────────────────────


def test_dispatch_runs_python_lane_in_shadow_mode():
    src = API.read_text()
    # Must call _execute_curl_chain_in_python in the dispatch area.
    assert "_execute_curl_chain_in_python(command" in src, (
        "dispatch must invoke _execute_curl_chain_in_python so the shadow "
        "lane runs alongside shell"
    )
    # Shadow invocation must gate on the mode flag.
    assert ('_BUILD_POC_DECOMPOSED_MODE in ("shadow", "on")' in src
            or "_BUILD_POC_DECOMPOSED_MODE in ('shadow', 'on')" in src), (
        "python-lane dispatch must gate on BUILD_POC_DECOMPOSED mode"
    )
    # Divergence recorded via _poc_shadow_record with phase="dispatch".
    assert 'phase="dispatch"' in src, (
        "python-lane shadow must record phase='dispatch' so analytics can "
        "distinguish synth-shadow from dispatch-shadow"
    )


def test_dispatch_fallback_records_skip_reason():
    src = API.read_text()
    assert 'phase="dispatch_skipped"' in src, (
        "when the Python lane can't execute the command (shell tool, pipe, "
        "etc.), a dispatch_skipped shadow row must be written so operators "
        "see HOW OFTEN the fallback fires"
    )
