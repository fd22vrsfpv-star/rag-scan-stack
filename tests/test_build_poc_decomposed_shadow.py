"""Phase 1 of the B rollout — shadow mode scaffolding guard.

Shipped 2026-10-06. See `BUILD_POC_DECOMPOSED` doc at the top of its api.py
section + CHANGES_MADE entry for the architecture overview.

Run on demand (sidecar):

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_build_poc_decomposed_shadow.py -v'
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


# ── scaffolding exists ─────────────────────────────────────────────────────


def test_mode_flag_defaults_off():
    """The default must be `off` so Phase 1 ships without changing live
    behaviour. Any accidental enable (via the env var or a code default
    change) must fail this test."""
    src = API.read_text()
    assert "_BUILD_POC_DECOMPOSED_MODE" in src, "mode constant missing"
    # The default value in the fallback must be the literal "off".
    assert 'os.environ.get("BUILD_POC_DECOMPOSED") or "off"' in src, (
        "mode constant must default to 'off' — any other default risks "
        "enabling the shadow path by accident"
    )


def test_ensure_shadow_table_is_idempotent():
    body = _func_src("_ensure_shadow_table")
    assert body, "_ensure_shadow_table missing"
    # Must use CREATE TABLE IF NOT EXISTS + idempotent index creation.
    assert "CREATE TABLE IF NOT EXISTS build_poc_shadow_runs" in body, (
        "shadow table creation must be idempotent"
    )
    assert "CREATE INDEX IF NOT EXISTS" in body, (
        "indexes must be created idempotently so a cold start never fails"
    )


def test_shadow_record_is_fail_soft():
    body = _func_src("_poc_shadow_record")
    assert body, "_poc_shadow_record missing"
    # Must swallow its own exceptions — a broken DB connection should never
    # kill the main build-poc run.
    assert "except Exception" in body or "except" in body, (
        "shadow record must be wrapped in try/except — a DB failure must not "
        "break the main synth path"
    )


def test_divergence_calc_returns_structured_dict():
    body = _func_src("_poc_shadow_divergence")
    assert body, "_poc_shadow_divergence missing"
    for field in ("same_command", "same_assertion", "same_synth_kind",
                  "legacy_only_fields", "new_only_fields", "identical"):
        assert f'"{field}"' in body or f"'{field}'" in body, (
            f"divergence dict must expose `{field}` so analytics can filter + sort on it"
        )


# ── decomposed skeleton has the right shape ────────────────────────────────


def test_decomposed_returns_synth_poc_shape():
    """The Phase 1 skeleton must return the SAME dict shape as the legacy
    synth — otherwise the divergence calc is comparing apples/oranges and
    the Phase 2+3 pipeline can't drop into the same consumer."""
    body = _func_src("_decomposed_synthesize_cve_poc")
    assert body, "_decomposed_synthesize_cve_poc missing"
    for required in ("command", "assertion", "synth_kind", "run_id",
                     "canary", "metrics"):
        assert f'"{required}"' in body, (
            f"decomposed skeleton must return `{required}` so downstream "
            f"consumers work unchanged"
        )
    # Phase 1 should NOT call the legacy synth — the point of shadow mode is
    # to compare two INDEPENDENT paths. Phase 1 produces a stub; Phases 2+3
    # fill in real crafting. Use a word-boundary regex so the `def
    # _decomposed_synthesize_cve_poc(` signature itself (which contains the
    # legacy name as a substring) doesn't trip the check.
    assert not re.search(r"(?<![A-Za-z0-9_])_synthesize_cve_poc\(", body), (
        "decomposed path must not call legacy synth — infinite recursion + "
        "defeats the independence of shadow mode"
    )


# ── shadow wrapper + call-site integration ─────────────────────────────────


def test_shadow_wrapper_always_returns_legacy_result():
    body = _func_src("_synthesize_cve_poc_with_shadow")
    assert body, "_synthesize_cve_poc_with_shadow missing"
    # The wrapper's return at the top level must be `return legacy` so a
    # Phase-2+ bug in the decomposed path never changes the authoritative
    # result until the mode is "on" (post-Phase-4 flip).
    assert "return legacy" in body, (
        "wrapper must return legacy result unchanged in Phase 1 — the "
        "decomposed path is observed-only"
    )
    # Must gate the shadow call on the mode flag so default-off truly
    # bypasses the extra work.
    assert '"shadow"' in body or "'shadow'" in body, (
        "shadow invocation must gate on BUILD_POC_DECOMPOSED == 'shadow'"
    )
    assert '"on"' in body or "'on'" in body, (
        "shadow invocation must also fire on 'on' (future flip)"
    )


def test_shadow_wrapper_is_used_at_the_external_call_site():
    """The one external call site of `_synthesize_cve_poc` (inside the
    build-poc inner routine) must now go through the wrapper. If someone
    reverts the call site to the bare legacy function, shadow mode never
    runs — this test catches that."""
    src = API.read_text()
    # Count call sites outside the wrapper definition itself.
    # Allow legitimate uses inside the wrapper body + its docstring.
    # The external call must be the wrapper form.
    assert "_synthesize_cve_poc_with_shadow(cve, ip, port, product, version, eid)" in src, (
        "the external call site must use the shadow wrapper, not the bare "
        "legacy function"
    )


# ── observability endpoint ────────────────────────────────────────────────


def test_shadow_runs_endpoint_defined():
    body = _func_src("build_poc_shadow_runs")
    assert body, "build_poc_shadow_runs endpoint missing"
    # Must expose basic filters + stats.
    for marker in ("only_divergent", "limit", "stats"):
        assert marker in body, (
            f"shadow-runs endpoint must support `{marker}` so operators can "
            f"narrow the view + see aggregate agreement rate"
        )
    # Must surface the current mode so operators can tell whether shadow is
    # even being written.
    assert "_BUILD_POC_DECOMPOSED_MODE" in body, (
        "endpoint response must include the mode so operators see whether "
        "shadow is live"
    )
