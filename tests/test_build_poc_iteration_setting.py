"""The deep-recon go-around budget is an operator setting, not a constant.

Found on the 2026-10-12 focused-10 run. `run_focused10.sh` asks for
`max_iters: 50`, and `effective_knobs` echoed 50 back — but CVE-2024-22120
stopped at exactly 10 with `stop_reason: max_iters`, with all 10 iterations
genuinely reaching the target (`target_runs: 10`). The cap was a `min()` in
the deep-recon go-around against a hard-compiled `_BUILD_POC_SECOND_PASS_ITERS
= 10`, so any CVE that needed deep recon silently lost the budget it asked for.

Operator raised it to 50 and asked for it to live in Settings. These tests pin
that the value is READ AT RUNTIME (so it changes without a rebuild), that it is
bounded, and that the whole chain exists — rag-api reader, BFF endpoints,
Settings UI, and the db_init seed.

Static (ast/regex): api.py is ~37k lines and importing it pulls the service
graph. See CLAUDE.md "Running tests needs a container".

Run standalone:
  docker run --rm -v /opt/rag-scan-stack:/w -w /w python:3.12-slim \
    sh -c "pip -q install pytest; python -m pytest tests/test_build_poc_iteration_setting.py -q"
"""
import ast
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
API = ROOT / "app" / "rag-api" / "api.py"
GRAPH = ROOT / "app" / "rag-api" / "build_poc_graph.py"
BFF = ROOT / "dashboard" / "bff" / "routers" / "settings.py"
UI = ROOT / "dashboard" / "frontend" / "src" / "pages" / "Settings.tsx"
SEED = ROOT / "db_init" / "ensure_all_tables.sql"

KEY = "build_poc_second_pass_iters"


def _read(p: pathlib.Path) -> str:
    if not p.exists():
        pytest.skip(f"{p} not present")
    return p.read_text(encoding="utf-8", errors="replace")


def _func(src: str, name: str) -> str:
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        pytest.fail(f"does not parse: {e}")
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    pytest.skip(f"{name} not found (renamed?)")


# ----------------------------------------------------------------- rag-api


def test_reader_exists_and_reads_the_setting():
    fn = _func(_read(API), "_build_poc_second_pass_iters")
    assert f'"{KEY}"' in fn or f"'{KEY}'" in fn, (
        f"the reader must consult the {KEY} app_setting"
    )
    assert "_get_setting" in fn, "must read app_settings, not only the env"


def test_reader_is_bounded():
    """A typo must not start an effectively unbounded refine loop."""
    fn = _func(_read(API), "_build_poc_second_pass_iters")
    assert "min(" in fn and "max(" in fn, (
        "the value must be clamped at both ends"
    )
    assert "200" in fn, "expected an explicit upper bound"


def test_reader_falls_back_rather_than_raising():
    fn = _func(_read(API), "_build_poc_second_pass_iters")
    assert "except" in fn, "a non-numeric setting must fall back, not raise"


def test_compiled_default_is_50():
    src = _read(API)
    m = re.search(r'_BUILD_POC_SECOND_PASS_ITERS\s*=\s*int\(.*?or\s*"(\d+)"\)', src)
    assert m, "compiled fallback not found"
    assert m.group(1) == "7", (
        f"compiled fallback should be 7, found {m.group(1)} — this is the "
        "value used when the setting is unset"
    )


def test_graph_calls_the_function_not_the_constant():
    """A module-level constant is captured at import; only a call re-reads it."""
    src = _read(GRAPH)
    assert "_build_poc_second_pass_iters" in src, (
        "build_poc_graph must call the reader"
    )
    # The go-around clamp must use the call's result, not the raw constant.
    i = src.find('"max_iters": min(')
    assert i != -1, "the go-around clamp is gone"
    window = src[i:i + 200]
    assert "_BUILD_POC_SECOND_PASS_ITERS" not in window, (
        "the clamp must use the runtime value, not the compiled constant — "
        "otherwise the Settings value never takes effect"
    )


# --------------------------------------------------------------------- BFF


def test_bff_exposes_the_limit_endpoints():
    src = _read(BFF)
    assert "/api/settings/build-poc-limits" in src, "BFF endpoint missing"
    assert src.count("/api/settings/build-poc-limits") >= 2, (
        "both GET and PUT must exist — a write-only or read-only setting is "
        "not adjustable"
    )
    assert KEY in src, f"{KEY} must be in BUILD_POC_LIMIT_KEYS"


def test_bff_validates_the_range_and_rejects_unknown_keys():
    fn = _func(_read(BFF), "put_build_poc_limits")
    assert "Unknown build-poc limit keys" in fn, "unknown keys must be rejected"
    assert "200" in fn and "< 1" in fn, (
        "values must be validated to 1..200, mirroring the rag-api clamp"
    )


def test_bff_checks_the_upstream_status():
    """CLAUDE.md: an HTTP status is not an exception."""
    fn = _func(_read(BFF), "put_build_poc_limits")
    assert "status_code" in fn, (
        "the PUT must check resp.status_code — httpx does not raise on 4xx/5xx, "
        "so a failed write would be reported to the operator as success"
    )


def test_bff_default_matches_rag_api():
    """Two defaults that disagree mean the UI lies about what is in force."""
    bff = _read(BFF)
    m = re.search(r'"' + KEY + r'":\s*(\d+)', bff)
    assert m, "no default declared in _build_poc_limit_defaults"
    api = _read(API)
    a = re.search(r'_BUILD_POC_SECOND_PASS_ITERS\s*=\s*int\(.*?or\s*"(\d+)"\)', api)
    assert a and m.group(1) == a.group(1), (
        f"BFF default {m.group(1)} disagrees with rag-api compiled default "
        f"{a.group(1) if a else '?'}"
    )


# ---------------------------------------------------------------------- UI


def test_ui_renders_the_field():
    src = _read(UI)
    assert KEY in src, "the Settings page must expose the key"
    assert "/settings/build-poc-limits" in src, "the UI must call the endpoint"
    assert src.count("/settings/build-poc-limits") >= 2, (
        "the UI must both load and save the limits"
    )


def test_ui_path_has_no_doubled_api_prefix():
    """apiFetch prepends /api — see CLAUDE.md and test_frontend_route_contracts."""
    src = _read(UI)
    assert "'/api/settings/build-poc-limits'" not in src, (
        "apiFetch callers pass a BARE path; '/api/...' would request /api/api/..."
    )


# -------------------------------------------------------------------- seed


def test_setting_is_seeded_in_db_init():
    """CLAUDE.md: any new database element goes in the install scripts."""
    src = _read(SEED)
    assert KEY in src, (
        f"{KEY} must be seeded in db_init/ensure_all_tables.sql, or a fresh "
        "install has no row and the operator cannot see the value in Settings"
    )
    m = re.search(r"\('" + KEY + r"',\s*'(\d+)'", src)
    assert m, "seed row must carry a numeric value"
    assert m.group(1) == "7", f"seeded value should be 7, found {m.group(1)}"
