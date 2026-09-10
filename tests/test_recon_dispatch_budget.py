"""The recon agent's per-cycle dispatch budget.

Carries the finding from PR #37: the agent draining a large KB queue was always
CONCURRENT-CAP-bound, never dispatch-budget-bound, so the old 5/2 budget was
never the limiter — it only made the setting's intent misleading.

The safety property is that raising the budget CANNOT raise scan volume: every
dispatch site clamps to `_recon_concurrency()`, which is the operator's shared
MAX_CONCURRENT_SCANS. That clamp is what these tests protect.

PR #37 also proposed a private `MAX_CONCURRENT_RECON_SCANS` default of 6.
That constant was deleted by 9eb36b8 because a private concurrency number
defeats the shared cap (CLAUDE.md: "No component invents a private concurrency
number"), and `test_no_private_concurrency_constant_returns` keeps it gone.

Standalone: pytest tests/test_recon_dispatch_budget.py
"""
import ast
import io
import os
import sys

import pytest

REPO = os.path.join(os.path.dirname(__file__), "..")
AGENT = os.path.join(REPO, "dashboard", "bff", "services", "recon_agent.py")


@pytest.fixture()
def budget():
    """`_dispatch_budget` loaded WITHOUT importing the whole BFF service.

    recon_agent pulls in the dashboard's config/router stack, which is not
    importable in a bare checkout — so the function is exec'd from source.
    Skips (not fails) if the shape ever changes.
    """
    src = io.open(AGENT, encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next((n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name == "_dispatch_budget"), None)
    consts = [n for n in tree.body if isinstance(n, ast.Assign)
              and any(getattr(t, "id", "").startswith("_DISPATCH_BUDGET")
                      for t in n.targets)]
    if fn is None or not consts:
        pytest.skip("_dispatch_budget not present in this checkout")

    class _Log:
        def warning(self, *a, **kw):
            pass

    ns = {"log": _Log()}
    for c in consts:
        exec(compile(ast.Module(body=[c], type_ignores=[]), AGENT, "exec"), ns)
    exec(compile(ast.Module(body=[fn], type_ignores=[]), AGENT, "exec"), ns)
    return ns["_dispatch_budget"]


def test_defaults_per_profile(budget):
    assert budget({}, "pentest") == 10
    assert budget({}, "redteam") == 4


def test_redteam_stays_below_pentest(budget):
    """OPSEC: the redteam profile must never dispatch as freely as pentest."""
    assert budget({}, "redteam") < budget({}, "pentest")


def test_explicit_config_always_wins(budget):
    assert budget({"max_dispatches_per_cycle": 1}, "pentest") == 1
    assert budget({"max_dispatches_per_cycle": 99}, "redteam") == 99
    assert budget({"max_dispatches_per_cycle": 0}, "pentest") == 0


def test_unknown_profile_gets_the_conservative_default(budget):
    """A typo in the profile name must not quietly WIDEN the budget."""
    assert budget({}, "pentst") == 4
    assert budget({}, "") == 4
    assert budget({}, None) == 4


def test_garbage_config_falls_back_rather_than_raising(budget):
    """A bad value in engagement config must not take the cycle down."""
    assert budget({"max_dispatches_per_cycle": "lots"}, "pentest") == 10
    assert budget({"max_dispatches_per_cycle": None}, "redteam") == 4


def test_negative_is_clamped_to_zero(budget):
    assert budget({"max_dispatches_per_cycle": -5}, "pentest") == 0


# ---------------------------------------------------------------------------
# The clamp is the whole safety argument for raising the budget
# ---------------------------------------------------------------------------

def test_kb_drain_is_clamped_by_the_shared_concurrency_cap():
    """Raising max_dispatches must not be able to raise scan volume.

    Checked on the AST of the `kb_budget` assignment itself, not by grepping
    the file: the first version of this guard searched the whole source, found
    the phrase in an explanatory COMMENT, and passed while the real clamp was
    deleted. A guard that cannot fail is worse than none.

    Sabotage check: drop `_recon_concurrency()` from that min() and this fails.
    """
    tree = ast.parse(io.open(AGENT, encoding="utf-8").read())
    assign = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                getattr(t, "id", "") == "kb_budget" for t in node.targets):
            assign = node
            break
    assert assign is not None, "kb_budget assignment not found"

    names = {n.id for n in ast.walk(assign) if isinstance(n, ast.Name)}
    calls = {n.func.id for n in ast.walk(assign)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}

    assert "_recon_concurrency" in calls, (
        "the KB drain no longer clamps to the shared concurrency cap — the "
        "per-cycle budget would become a real scan-volume increase"
    )
    assert "max_dispatches" in names, (
        "the per-cycle budget is no longer part of the kb_budget clamp"
    )
    assert "min" in calls, "the two budgets are no longer combined with min()"


def test_no_private_concurrency_constant_returns():
    """CLAUDE.md: no component invents a private concurrency number.

    PR #37 wanted MAX_CONCURRENT_RECON_SCANS back with a default of 6; 9eb36b8
    removed it so the operator's MAX_CONCURRENT_SCANS actually reaches this
    service.
    """
    src = io.open(AGENT, encoding="utf-8").read()
    # Strip `#` comments: the file deliberately EXPLAINS why that constant was
    # removed, and matching that prose would fail on the correct code. (Naive
    # split — good enough here, and a `#` inside a string would only ever make
    # this guard stricter, never weaker.)
    code = "\n".join(l.split("#")[0] for l in src.splitlines())
    assert "MAX_CONCURRENT_RECON_SCANS" not in code, (
        "a private concurrent-scan constant is back — the shared cap no longer "
        "decides the answer"
    )
    assert "def _recon_concurrency" in code


def test_the_budget_is_not_a_bare_literal_at_the_call_site():
    """It used to be `5 if profile == "pentest" else 2` inline, which cannot be
    unit-tested and hid the OPSEC distinction in an expression."""
    src = io.open(AGENT, encoding="utf-8").read()
    assert "_dispatch_budget(config, profile)" in src
    assert '5 if profile == "pentest" else 2' not in src
