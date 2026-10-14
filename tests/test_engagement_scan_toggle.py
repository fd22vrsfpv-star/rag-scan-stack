"""The per-engagement scan toggle must write the ENFORCED control, not a new flag.

An "enable/disable scans" switch is only worth having if a disabled engagement
actually refuses to dispatch. The enforcement already exists and has exactly one
home: `platform_control`, read by `etl/scope_gate.is_halted` inside
`load_dispatch_scope`, which returns `([], "halted")` — and every gated
dispatcher treats an empty scope as "refuse". A second flag somewhere else would
be a switch that looks like it works.

Verified live before the UI was wired (2026-10-14), against the running stack:

    POST /api/control/halt {"scope": "<engagement>"}   -> halted: true
    POST /api/recon/preview  (same engagement)         -> HTTP 503
        "dispatch is HALTED by the kill switch — refusing."
    POST /api/control/resume {"scope": "<engagement>"} -> halted: false

This guard pins the three things that would silently break it:

  1. the toggle posts to /control/halt and /control/resume with the ENGAGEMENT
     as `scope` — posting `"global"` would stop every engagement at once;
  2. the gate still consults `is_halted` (delete that call and the toggle
     becomes decorative);
  3. the UI distinguishes a global halt from this engagement's own state, and
     an unreadable state from "enabled".

Static: regex over the .tsx (the precedent is tests/test_severity_scale.py) and
`ast` over the gate. No node, no DB, no running stack.

Sabotage check: change the toggle's scope to 'global' and
`test_toggle_scopes_to_the_engagement` fails; delete the `is_halted` call in
`load_dispatch_scope` and `test_gate_still_enforces_the_halt` fails.

    pytest tests/test_engagement_scan_toggle.py -q
"""

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
CONTROL_TS = REPO / "dashboard" / "frontend" / "src" / "api" / "control.ts"
PAGE_TSX = REPO / "dashboard" / "frontend" / "src" / "pages" / "Engagements.tsx"
GATE = REPO / "etl" / "scope_gate.py"
BFF_CONTROL = REPO / "dashboard" / "bff" / "routers" / "control.py"


def _read(p: Path) -> str:
    if not p.exists():
        pytest.skip(f"{p} not found")
    return p.read_text(encoding="utf-8")


def _set_scans_body() -> str:
    """The body of useSetEngagementScans, where the mutation is built."""
    src = _read(CONTROL_TS)
    m = re.search(r"export function useSetEngagementScans\b.*?\n}\n", src, re.S)
    assert m, "useSetEngagementScans not found in api/control.ts"
    return m.group(0)


def test_toggle_scopes_to_the_engagement():
    """`scope` must be the engagement id, never the literal 'global'."""
    body = _set_scans_body()
    assert re.search(r"scope:\s*engagementId\b", body), (
        "the toggle does not scope its halt to the engagement — check what it "
        "posts as `scope`")
    assert not re.search(r"scope:\s*['\"]global['\"]", body), (
        "the per-engagement toggle posts scope:'global' — flipping one "
        "engagement would stop every other engagement's dispatch too")


def test_toggle_uses_the_existing_control_endpoints():
    body = _set_scans_body()
    for path in ("/control/halt", "/control/resume"):
        assert path in body, (
            f"the toggle does not call {path} — a switch that writes anywhere "
            "else is not enforced by the scope gate")


@pytest.mark.parametrize("path", ["/api/control/halt", "/api/control/resume",
                                  "/api/control/status"])
def test_bff_declares_the_routes_the_toggle_calls(path):
    """apiFetch prepends /api; each target must be a declared BFF route."""
    src = _read(BFF_CONTROL)
    assert re.search(rf'@router\.(get|post)\(\s*["\']{re.escape(path)}["\']', src), (
        f"{path} is not declared in routers/control.py — the toggle would 404")


def test_gate_still_enforces_the_halt():
    """Without this call the toggle is decorative."""
    tree = ast.parse(_read(GATE))
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "load_dispatch_scope"), None)
    assert fn, "load_dispatch_scope not found in etl/scope_gate.py"
    calls = {n.func.id for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "is_halted" in calls, (
        "load_dispatch_scope no longer consults is_halted — a disabled "
        "engagement would dispatch anyway and the toggle would be a lie")


def test_halt_check_covers_the_engagement_scope():
    """A halt keyed only on 'global' could not express a per-engagement stop."""
    tree = ast.parse(_read(GATE))
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "is_halted"), None)
    assert fn, "is_halted not found"
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "engagement_id" in names, (
        "is_halted ignores engagement_id — only a global halt could work")


def test_ui_separates_global_halt_from_this_engagement():
    """An engagement shown as enabled while a global halt blocks it is a lie."""
    page = _read(PAGE_TSX)
    m = re.search(r"function ScanToggle\b.*?\n}\n", page, re.S)
    assert m, "ScanToggle not found in Engagements.tsx"
    toggle = m.group(0)
    assert re.search(r"\bglobalHalted\b", toggle), (
        "ScanToggle never reads globalHalted — an engagement would read "
        "'scans enabled' while the global kill switch refuses every dispatch")
    assert re.search(r"\bengagementHalted\b", toggle), (
        "ScanToggle does not track this engagement's own state separately, so "
        "it cannot tell the operator which level is holding the halt")


def test_unreadable_control_state_is_not_shown_as_enabled():
    """Three outcomes, as everywhere else in this repo."""
    page = _read(PAGE_TSX)
    m = re.search(r"function ScanToggle\b.*?\n}\n", page, re.S)
    assert m, "ScanToggle not found"
    toggle = m.group(0)
    # It must come OUT of the hook, not be a local the component defines —
    # `const isError = false` satisfies a bare name check and nothing else.
    assert re.search(r"\{[^}]*\bisError\b[^}]*\}\s*=\s*useEngagementControl\(", toggle), (
        "ScanToggle does not destructure isError from useEngagementControl — a "
        "control state that could not be read would render as a confident "
        "'scans enabled'")
    assert re.search(r"if\s*\([^)]*\bisError\b", toggle), (
        "isError is read but never branched on")
