"""A scope that could not be READ must not be reported as a scope that is EMPTY.

Both produce zero rows and both MUST refuse — the gate is fail-closed and that
is correct. But they are different problems with different fixes, and the
generic message sends the operator to the wrong one:

    no scope targets are configured — refusing to dispatch.
    Configure the engagement scope first.

Observed 2026-10-13: the operator asked to preview
`https://wealthscreening.examplecorp.com` through an exit node and got a 403 with
that text. The BFF log for the same second says why:

    scope_guard WARNING scope load failed (connection to server at
    "rag-postgres" (172.18.0.15), port 5432 failed: timeout expired)
    — treating everything as out of scope

The engagement's scope had **5,791 rows** and the host was in it. Nothing needed
configuring; the database had not answered. This is the repo's recurring
"unreachable reported as absent" (Docs/Memories.md) landing in an error message.

`scope_rows_for` already distinguishes the causes and returns `source`; every
caller discarded it. `refusal_reason_for_source` is the shared translation, and
`/api/recon/preview` answers **503** for an unreadable scope rather than 403 —
the scope was never consulted, so there is no authorisation verdict to report.

Static (ast + direct import of the helper): no DB, no running stack.

Sabotage check: make `refusal_reason_for_source` return None for "unavailable"
and `test_unreadable_sources_are_named` fails; delete the 503 raise in
`proxied_preview` and `test_preview_answers_503_for_an_unreadable_scope` fails.

    pytest tests/test_scope_unreadable_vs_empty.py -q
"""

import ast
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
BFF = REPO / "dashboard" / "bff"
FINDINGS = BFF / "routers" / "findings.py"

sys.path.insert(0, str(BFF))
scope_guard = pytest.importorskip(
    "scope_guard", reason="dashboard/bff/scope_guard.py not importable here")


# ── the shared translation ────────────────────────────────────────────────────

@pytest.mark.parametrize("source", ["unavailable", "halted", "budget-exceeded"])
def test_unreadable_sources_are_named(source):
    """Each non-verdict cause gets its own explanation."""
    msg = scope_guard.refusal_reason_for_source(source)
    assert msg, f"{source!r} produces no explanation — it reads as an empty scope"
    low = msg.lower()
    assert "refus" in low, f"{source!r}: {msg!r} does not say it refused"
    # It must NOT send the operator to configure a scope.
    assert "configure the engagement scope first" not in low, (
        f"{source!r} still tells the operator to configure the scope: {msg!r}")


@pytest.mark.parametrize("source", ["engagement", "all-engagements", "", None])
def test_readable_sources_produce_no_override(source):
    """A real verdict must fall through to the normal scope check."""
    assert scope_guard.refusal_reason_for_source(source) is None, (
        f"{source!r} is a successful read; it must not short-circuit the gate")


def test_every_unreadable_source_scope_rows_for_can_return_is_covered():
    """The list cannot silently fall behind the gate it translates."""
    src = (REPO / "etl" / "scope_gate.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "load_dispatch_scope"),
              None)
    assert fn, "load_dispatch_scope not found in etl/scope_gate.py"
    # Every `return [], "<tag>"` in the gate is a zero-row outcome with a cause.
    tags = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Tuple):
            continue
        elts = node.value.elts
        if len(elts) != 2 or not isinstance(elts[1], ast.Constant):
            continue
        if isinstance(elts[0], ast.List) and not elts[0].elts:
            tags.add(elts[1].value)
    assert tags, "no zero-row returns found — has the gate's shape changed?"
    for tag in tags:
        assert scope_guard.refusal_reason_for_source(tag), (
            f"load_dispatch_scope can return ([], {tag!r}) and nothing explains "
            "it — the operator would be told to configure the scope")


# ── the endpoint that was hit ─────────────────────────────────────────────────

def _preview_fn() -> ast.AsyncFunctionDef:
    tree = ast.parse(FINDINGS.read_text(encoding="utf-8"))
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, (ast.AsyncFunctionDef, ast.FunctionDef))
               and n.name == "proxied_preview"), None)
    assert fn, "proxied_preview not found in routers/findings.py"
    return fn


def _raises(fn):
    """[(status, {names referenced in the detail})] for each HTTPException."""
    out = []
    for node in ast.walk(fn):
        if (isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call)
                and getattr(node.exc.func, "id", "") == "HTTPException"
                and node.exc.args and isinstance(node.exc.args[0], ast.Constant)):
            detail = node.exc.args[1] if len(node.exc.args) > 1 else None
            names = {n.id for n in ast.walk(detail) if isinstance(n, ast.Name)} \
                if detail is not None else set()
            out.append((node.exc.args[0].value, names))
    return out


def test_preview_answers_503_for_an_unreadable_scope():
    """The 503 must carry the unreadable-scope reason, not just exist.

    Checking only that `503` appears somewhere passes while this raise is
    deleted — the `except` branch raises 503 too. The reason has to be the
    one the gate produced.
    """
    raises = _raises(_preview_fn())
    assert any(status == 503 and "unreadable" in names for status, names in raises), (
        "proxied_preview never raises 503 with the unreadable-scope reason — "
        "a database timeout is reported as an authorisation verdict the gate "
        "never actually made")
    assert any(status == 403 for status, _ in raises), (
        "proxied_preview no longer refuses out-of-scope targets at all")


def test_preview_consults_the_source():
    """The cause must be read, not just bound and dropped."""
    calls = [n for n in ast.walk(_preview_fn())
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "refusal_reason_for_source"]
    assert calls, (
        "proxied_preview discards scope_rows_for's `source` — a database "
        "timeout will again be reported as 'no scope targets are configured'")


def test_preview_uses_the_active_engagement():
    """It was the only scope_rows_for caller in the BFF hardcoding None."""
    for node in ast.walk(_preview_fn()):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "scope_rows_for"):
            assert node.args, "scope_rows_for called with no engagement at all"
            arg = node.args[0]
            assert not (isinstance(arg, ast.Constant) and arg.value is None), (
                "proxied_preview hardcodes scope_rows_for(None) — it checks the "
                "union of every engagement instead of the operator's own, "
                "looser than every sibling dispatch path")
            return
    pytest.fail("proxied_preview no longer calls scope_rows_for — it is ungated")
