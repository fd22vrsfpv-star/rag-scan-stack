"""Guard the three brakes added 2026-10-06 after the three-CVE deeptest analysis.

- `_prerun_payload_probe` — method-aware endpoint probe. Catches `all_404`
  BEFORE a 60s listener call runs the heavy exploit against a dead path.
- Plan rewriter — when ALL strategist candidates verify as FAKE, synth gets a
  strict directive instead of a plan it can keep hallucinating against.
- Dedup — the near-duplicate short-circuit still runs `_live_verify_recipe`
  so a stale all_404 doesn't persist when target state has changed.

Each test is sabotage-proven: reverting the brake fails the matching test.

Run on demand (sidecar):

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_build_poc_prerun_probe.py -v'
"""
from __future__ import annotations

import ast as _ast
import re
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"


def _func_src(name: str) -> str | None:
    src = API.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


# ── D (payload pre-check): the helper exists and does what the dispatch wants ─


def test_prerun_payload_probe_defined():
    body = _func_src("_prerun_payload_probe")
    assert body, "_prerun_payload_probe missing"
    # Extracts method; defaults to GET.
    assert '"GET"' in body or "'GET'" in body, (
        "probe must default to GET when curl has no explicit -X"
    )
    # Honors `-X METHOD` from the command.
    assert "-X" in body and re.search(r"-X\\s", body) is not None, (
        "probe must parse the exploit's explicit -X METHOD"
    )
    # Uses httpx.request so any method is first-class (not .post/.get).
    assert "httpx" in body or "_hx" in body, "probe must use httpx for method-agnostic request"
    assert ".request" in body, "probe must call .request(method, ...) not .post/.get"
    # Treats 404 as hard-fail; other statuses pass.
    assert "status == 404" in body or "status==404" in body, (
        "probe must treat 404 as hard-fail and let other statuses pass"
    )


def test_prerun_probe_hooked_before_dispatch():
    """The probe MUST be called before the heavy `/vectors/run` POST, else the
    exploit still spends 60s on dead endpoints. api.py has multiple
    `vectors/run` call sites (reflection check, dispatch, etc.); we pin on
    the specific `_build_poc_core` dispatch pattern: the probe call, the
    `prerun_probe` trace tag, the `PRERUN_PROBE_FAIL` output guard, and the
    `skipped_runs_prerun_404` metric must all appear and precede a nearby
    `vectors/run` dispatch within the same block."""
    src = API.read_text()
    # The probe invocation on the exact call site we hook.
    hook_pos = src.find("_prerun_payload_probe(ip, port, command")
    assert hook_pos >= 0, (
        "_prerun_payload_probe must be invoked in the dispatch path"
    )
    # Trace tag must appear so operators see the probe outcome in the log.
    assert '"prerun_probe"' in src, (
        "the probe outcome must be traced as 'prerun_probe' so an operator "
        "sees why an iteration was short-circuited"
    )
    # Short-circuit output marker.
    assert "PRERUN_PROBE_FAIL" in src, (
        "when probe fails, the run must short-circuit with PRERUN_PROBE_FAIL "
        "output so the refine loop sees the real reason"
    )
    # Metric so a batch run surfaces how often the brake fired.
    assert "skipped_runs_prerun_404" in src, (
        "the pre-run probe short-circuits must bump a metric so the operator "
        "can audit how often the brake fired across a batch"
    )
    # The dispatch must come AFTER the probe hook — otherwise we're probing
    # but still running the heavy exploit regardless. Window widened
    # 2000 → 8000 on 2026-10-07: the OOB check + shape-feedback + Python-lane
    # shadow blocks now sit between the hook and the dispatch.
    post = src[hook_pos : hook_pos + 8000]
    assert "vectors/run" in post, (
        "the listener /vectors/run dispatch must appear within the same "
        "block as the probe hook, not before it"
    )


# ── B: plan_verified ALL-FAKE directive ───────────────────────────────────


def test_plan_rewrite_blocks_all_fake_candidates():
    """When every strategist candidate verified FAKE, the rewriter must emit a
    strict directive that forbids reusing those paths. Prior code returned the
    plan with just a banner — synth kept inventing against FAKE endpoints."""
    src = API.read_text()
    # Find the branch that fires when nothing is LIVE or SUSPECT.
    assert "if not live_or_suspect:" in src, (
        "the all-FAKE branch is the hook point for the brake"
    )
    # The directive must forbid reusing proven-fake paths.
    assert "DO NOT RE-USE" in src or "DO NOT RE-USE" in src.upper(), (
        "the directive must explicitly forbid the LLM from reusing paths that "
        "were proven FAKE in this verification pass"
    )
    # It must point the LLM at DISCOVERED LIVE PATHS from recon.
    assert "DISCOVERED LIVE PATHS" in src, (
        "the directive must point the LLM at the recon-discovered live paths"
    )


# ── C: dedup preserves verify ─────────────────────────────────────────────


def test_dedup_branch_still_runs_live_verify():
    """The near-duplicate branch must still call `_live_verify_recipe` with a
    short timeout so a stale verdict doesn't persist across iterations when
    target state has changed (session established, WAF reconfigured)."""
    src = API.read_text()
    # Find the dedup branch; it was previously an immediate return.
    m = re.search(
        r"_dup = _is_duplicate_recipe\(spec, prior_hints\)\s*\n\s*if _dup:",
        src,
    )
    assert m, "dedup branch must bind `_dup` and gate on it"
    # Within the next ~1500 chars (the branch body), _live_verify_recipe must appear.
    branch = src[m.start() : m.start() + 2000]
    assert "_live_verify_recipe(ip, port, spec" in branch, (
        "the dedup branch must still invoke _live_verify_recipe — otherwise a "
        "stale verdict persists even when target state has changed"
    )
    # A short timeout (15s) distinguishes the dedup fast-verify from the
    # full ~30s verify. The number is bounded; a bare `_live_verify_recipe(...)`
    # without a timeout would use the function default and defeat the point.
    assert "timeout=15" in branch or "timeout=10" in branch or "timeout=20" in branch, (
        "the dedup fast-verify must bound the timeout (<=20s); otherwise the "
        "'save iteration' purpose of the dedup is defeated"
    )
    # If the dedup-verify DOES pass (target state changed), it must store the spec.
    assert "intel-dup-verified" in branch, (
        "when the dedup fast-verify unexpectedly passes, the result must be "
        "stored with a distinguishable source so the operator can audit "
        "which runs were saved by the fresh-verify"
    )
