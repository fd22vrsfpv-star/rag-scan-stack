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
    # 2026-10-07 redesign: `&&` / `;` are the SEGMENT SPLITTER, not allowed
    # tokens; only each segment's leading command word is validated. The old
    # token-walk (every token had to be in allowed_bins) rejected every curl
    # flag and never executed a single command. The dynamic tests below are
    # the real guard; this keeps the design pinned.
    assert '"curl"' in body and '"sleep"' in body, "allowed leading words must include curl + sleep"
    assert re.search(r"_re\.split\(r\"\\s\*\(\?:&&\|;\)\\s\*\"", body), (
        "detector must split segments on && / ; before validating leading words"
    )
    assert "tokens[0]" in body, "detector must validate only each segment's leading word"


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


# ── DYNAMIC guards (added 2026-10-07) ─────────────────────────────────────
#
# The structural tests above passed while the detector rejected EVERY real
# command (every curl flag was an "unsupported token"). These exec the real
# helpers against the exact command shapes the overnight batch produced and
# assert the decision, not the source text. CLAUDE.md: ast.parse passing is
# NOT verification.


def _load_lane_helpers() -> dict:
    src = API.read_text()
    tree = _ast.parse(src)
    ns: dict = {}
    for name in ("_strip_sink_tail", "_strip_shell_redirects", "_can_execute_in_python",
                 "_curl_to_request"):
        node = next(n for n in _ast.walk(tree)
                    if isinstance(n, _ast.FunctionDef) and n.name == name)
        exec(_ast.get_source_segment(src, node), ns)
    return ns


REAL_LLM_TAIL = ("curl -X POST http://172.18.0.35:9090/api/proxy -d 'http://localhost:8000/POCz93a306fdd0' "
                 "2>/dev/null; sleep 1; curl -s http://172.18.0.35:9091/done | grep -q 'POCz93a306fdd0' "
                 "&& echo 'SINK-VERIFIED: POCz93a306fdd0'")
REAL_AUGMENT_TAIL = ("( curl -s -k 'http://172.18.0.36:9090/apply/index.php?url=http://localhost:8000/POCzabc123' ) "
                     ">/dev/null 2>&1; \n# sink-verification tail (auto-added for blind/OOB class):\n"
                     "sleep 1; _DONE=$(curl -s 'http://172.18.0.36:9091/done' 2>/dev/null); "
                     "echo \"$_DONE\" | grep -qE '\"attack_success\":true' && echo \"SINK-VERIFIED: POCzabc123 ($_DONE)\"")
REAL_ASSEMBLER_TAIL = ("curl -s -S -i -k --max-time 30 -X POST -H 'Content-Type: application/json' "
                       "--data-raw '{\"url\":\"http://localhost:8000/POCzdef456\"}' http://172.18.0.35:9090/api/proxy "
                       "; sleep 1 ; _DONE=$(curl -s http://172.18.0.35:9091/done) ; echo \"$_DONE\" | "
                       "grep -qE 'attack_success' && echo 'SINK-VERIFIED: POCzdef456 '\"$_DONE\"")


def _lane_decision(ns, cmd):
    head, sink, canary = ns["_strip_sink_tail"](cmd)
    head = ns["_strip_shell_redirects"](head)
    ok, why = ns["_can_execute_in_python"](head)
    return ok, why, sink, canary, head


def test_dynamic_real_llm_tail_is_accepted():
    ns = _load_lane_helpers()
    ok, why, sink, canary, head = _lane_decision(ns, REAL_LLM_TAIL)
    assert sink == "http://172.18.0.35:9091/done" and canary == "POCz93a306fdd0"
    assert ok, f"real LLM-shaped command must be executable after tail strip: {why} | head={head!r}"
    req = ns["_curl_to_request"](head)
    assert req["method"] == "POST" and req["url"].endswith("/api/proxy")


def test_dynamic_real_augmenter_tail_is_accepted():
    ns = _load_lane_helpers()
    ok, why, sink, canary, head = _lane_decision(ns, REAL_AUGMENT_TAIL)
    assert sink and canary == "POCzabc123"
    assert ok, f"augmenter-wrapped `( curl ... )` head must be executable: {why} | head={head!r}"


def test_dynamic_real_assembler_tail_is_accepted():
    ns = _load_lane_helpers()
    ok, why, sink, canary, head = _lane_decision(ns, REAL_ASSEMBLER_TAIL)
    assert sink and canary == "POCzdef456"
    assert ok, f"Phase-3 assembler output must be executable: {why} | head={head!r}"
    req = ns["_curl_to_request"](head)
    assert req["headers"].get("Content-Type") == "application/json"
    assert req["body"] and "POCzdef456" in req["body"]


def test_dynamic_non_curl_and_pipes_still_rejected():
    ns = _load_lane_helpers()
    for bad in ("nmap -p 9090 172.18.0.35",
                "curl -s http://t/ | grep foo",
                "python3 -c 'print(1)' && curl -s http://t/",
                "curl -s http://t/ $(cat /tmp/x)"):
        ok, why, *_ = _lane_decision(ns, bad)
        assert not ok, f"must reject {bad!r} (got accepted: {why})"


def test_python_lane_sink_miss_mirrors_shell_exit_code():
    """Shell tail: `curl sink | grep -q CANARY && echo ...` -> chain exits 1 on
    a miss. The Python lane must set exit_code=1 / ok=False on sink miss or
    every OOB miss shows shell_ec=1 vs py_ec=0 and poisons agreement scoring
    (observed on the first round-2 dispatch row, 2026-10-07)."""
    body = _func_src("_execute_curl_chain_in_python")
    assert body, "_execute_curl_chain_in_python missing"
    miss = body[body.find('result["sink_hit"] = False'):]
    assert 'result["exit_code"] = 1' in miss, "sink miss must set exit_code=1"
    assert 'result["ok"] = False' in miss, "sink miss must set ok=False"
