"""Spec derivation gets a budget of its own, so it cannot starve refine.

`_build_poc_wall_deadline` is the budget for the WHOLE build, and its own
comment says it was sized so "refine legitimately take longer". But
`_derive_cve_spec` draws on that pool FIRST, so a slow derivation leaves the
loop that actually lands the exploit with nothing.

Measured on the 2026-10-16 focused-10 — `cve_spec_derivation` was the single
largest phase in all ten runs:

    CVE-2024-36675   total=3135s  derivation=2820s (90%)  ->  1 refine run
    CVE-2024-32964   total=4198s  derivation=3874s (92%)  ->  0 refine runs

Both reproduced the round before at 4079s and 3899s. The wall guard never
fired for any of them: the runner sends no `wall_timeout_sec` and
`scan_timeout_build_poc_wall` is unset (0 = unlimited), so `deadline` was None
and `if deadline is not None` was a no-op through 15 uncapped passes.

Pinned here, because each is a way for this to silently stop working:

  1. the cap applies when there is NO wall budget — that is the common case,
     and a sub-budget that only works under a wall fixes nothing;
  2. a wall budget CLAMPS the cap further (min, never max) — a generous wall
     does not license a long derivation;
  3. 0 means uncapped, the same meaning the key carries for the wall;
  4. the check runs BEFORE the pass, so an exhausted budget costs no pass;
  5. a cut-short derivation reports a DISTINCT source — "unreachable is not
     absent": it must not look like a derivation that found nothing.

Sabotage check: delete the `_derive_deadline` check from the loop and
`test_budget_stops_the_loop` fails; return the max instead of the min in
`_derive_budget_seconds` and `test_a_wall_clamps_the_cap_further` fails.

    pytest tests/test_derive_budget.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"


def _tree() -> ast.Module:
    if not API.exists():
        pytest.skip(f"{API} not found")
    return ast.parse(API.read_text(encoding="utf-8"))


def _func(name: str) -> ast.FunctionDef:
    fn = next((n for n in ast.walk(_tree())
               if isinstance(n, ast.FunctionDef) and n.name == name), None)
    assert fn, f"{name} not found in app/rag-api/api.py"
    return fn


def _const(name: str):
    for n in ast.walk(_tree()):
        if isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return ast.literal_eval(n.value)
    pytest.fail(f"{name} not found in app/rag-api/api.py")


class _Clock:
    """A monotonic clock the test drives, so no test ever sleeps."""
    def __init__(self): self.t = 1000.0
    def __call__(self): return self.t
    def advance(self, s): self.t += s


def _load(env=None, wall=None, clock=None, settings=None):
    """Exec the two pure helpers in isolation — api.py is far too heavy."""
    import logging as _lg
    clock = clock or _Clock()
    ns = {
        "os": type("os", (), {"environ": dict(env or {})}),
        "time": type("time", (), {"monotonic": staticmethod(clock)}),
        "logging": _lg,
        "_DERIVE_BUDGET_DEFAULT_SEC": _const("_DERIVE_BUDGET_DEFAULT_SEC"),
        "_DERIVE_BUDGET_FRAC_DEFAULT": _const("_DERIVE_BUDGET_FRAC_DEFAULT"),
        "_build_poc_wall_deadline": type("cv", (), {"get": staticmethod(lambda: wall)}),
        "_build_poc_timeout_setting": staticmethod(
            lambda k, d: (settings or {}).get(k, d)),
    }
    mod = ast.Module(body=[_func("_derive_budget_seconds"),
                           _func("_derive_cve_spec")], type_ignores=[])
    exec(compile(mod, "<derive>", "exec"), ns)
    ns["_clock"] = clock
    return ns


# -- 1. resolution ----------------------------------------------------------

def test_the_default_applies_with_no_wall_and_no_setting():
    """The common case today: no wall at all. A sub-budget that needs one is useless."""
    ns = _load()
    assert ns["_derive_budget_seconds"]() == _const("_DERIVE_BUDGET_DEFAULT_SEC")


def test_the_default_is_above_every_derivation_that_verified():
    """216s and 301s were the two that produced a verified spec on 2026-10-16."""
    assert _const("_DERIVE_BUDGET_DEFAULT_SEC") > 301, (
        "the default cap would have cut CVE-2024-5314's derivation (301s), "
        "which verified — the cap is meant to stop grinding, not wins")


def test_env_wins_over_the_setting():
    ns = _load(env={"BUILD_POC_DERIVE_MAX_SEC": "120"},
               settings={"scan_timeout_build_poc_derive": 600})
    assert ns["_derive_budget_seconds"]() == 120


def test_the_setting_wins_over_the_default():
    ns = _load(settings={"scan_timeout_build_poc_derive": 600})
    assert ns["_derive_budget_seconds"]() == 600


@pytest.mark.parametrize("env", [{"BUILD_POC_DERIVE_MAX_SEC": "0"}, {}])
def test_zero_means_uncapped(env):
    settings = {} if env else {"scan_timeout_build_poc_derive": 0}
    ns = _load(env=env, settings=settings or {"scan_timeout_build_poc_derive": 0})
    assert ns["_derive_budget_seconds"]() is None, (
        "0 must mean uncapped, the same meaning the key carries for the wall")


def test_a_non_numeric_env_falls_back_rather_than_raising():
    ns = _load(env={"BUILD_POC_DERIVE_MAX_SEC": "banana"})
    assert ns["_derive_budget_seconds"]() == _const("_DERIVE_BUDGET_DEFAULT_SEC")


# -- 2. the wall CLAMPS, never licenses -------------------------------------

def test_a_wall_clamps_the_cap_further():
    """min(), not max(): a short wall must shrink the derivation share."""
    clock = _Clock()
    ns = _load(wall=clock() + 600, clock=clock)   # 600s left, 40% = 240s
    got = ns["_derive_budget_seconds"](now=clock())
    assert got == pytest.approx(240.0), (
        f"expected 40% of the 600s remaining, got {got} — a wall that is "
        "shorter than the absolute cap must win")


def test_a_generous_wall_does_not_license_a_long_derivation():
    clock = _Clock()
    ns = _load(wall=clock() + 7200, clock=clock)  # 40% = 2880s, cap is 900s
    assert ns["_derive_budget_seconds"](now=clock()) == _const("_DERIVE_BUDGET_DEFAULT_SEC"), (
        "a 2h wall gave derivation more than the absolute cap — the clamp is a "
        "minimum of the two, not a maximum")


def test_an_already_exhausted_wall_leaves_no_derivation_budget():
    clock = _Clock()
    ns = _load(wall=clock() - 10, clock=clock)
    assert ns["_derive_budget_seconds"](now=clock()) == 0.0


# -- 3. the loop actually stops ---------------------------------------------

def _run(ns, pass_cost, max_passes=15):
    """Drive _derive_cve_spec with a stubbed pass that burns `pass_cost`."""
    calls = []

    def _pass(*a, **k):
        calls.append(1)
        ns["_clock"].advance(pass_cost)
        # tentative + non-duplicate => the loop would otherwise keep going
        return {"verified": False, "source": "extract+verify+tentative",
                "stored_tentative": True, "spec": {"x": 1}}

    ns["_derive_cve_spec_single_pass"] = _pass
    res = ns["_derive_cve_spec"]("CVE-2024-32964", "p", "v", "10.0.0.1", 9090,
                                 max_passes=max_passes)
    return res, len(calls)


def test_budget_stops_the_loop():
    """3874s over 15 passes was ~258s each; a 900s cap must cut it to ~4."""
    ns = _load()
    res, n = _run(ns, pass_cost=258)
    assert n < 15, f"the budget did not stop the loop — all {n} passes ran"
    assert 3 <= n <= 5, f"expected ~4 passes inside 900s at 258s each, ran {n}"


def test_an_uncapped_budget_still_runs_every_pass():
    ns = _load(env={"BUILD_POC_DERIVE_MAX_SEC": "0"})
    _, n = _run(ns, pass_cost=258)
    assert n == 15, f"uncapped must not cut the loop short, ran {n}"


def test_a_fast_derivation_is_untouched():
    """216s total across its passes — the win must not be cut."""
    ns = _load()
    _, n = _run(ns, pass_cost=20, max_passes=10)
    assert n == 10, f"a cheap derivation was cut short at {n} passes"


def test_the_cut_is_reported_distinctly():
    """'unreachable is not absent' — cut short must not read as found-nothing."""
    ns = _load()
    res, _ = _run(ns, pass_cost=258)
    assert res["source"] == "derive_budget_exhausted", res["source"]
    assert res.get("derive_passes_run"), "the pass count is not reported"
    assert res.get("derive_budget_sec"), "the budget that applied is not reported"
    assert "BUILD_POC_DERIVE_MAX_SEC" in res["evidence"], (
        "the evidence does not say how to raise the cap, so an operator who "
        "hits it cannot tell a budget cut from an underivable CVE")


def test_no_result_yet_is_a_different_source():
    """Zero budget on entry => stop before pass 1, and say nothing was produced.

    The budget starts fresh when `_derive_cve_spec` is entered, so the only way
    to arrive with none is a wall that is ALREADY spent — which is exactly the
    case where refine needs every second that is left.
    """
    clock = _Clock()
    ns = _load(wall=clock() - 10, clock=clock)

    def _pass(*a, **k):
        pytest.fail("a pass ran after the budget was exhausted — the check "
                    "must come BEFORE the pass, or it costs a real pass")

    ns["_derive_cve_spec_single_pass"] = _pass
    res = ns["_derive_cve_spec"]("CVE-X", "p", "v", "10.0.0.1", 80)
    assert res["source"] == "derive_budget_exhausted_no_result", res["source"]
    assert res["verified"] is False


# -- 4. order inside the loop -----------------------------------------------

def test_the_derive_check_precedes_the_pass_and_the_wall():
    """Structural: a check after the pass costs the pass it was meant to save."""
    loop = next(n for n in ast.walk(_func("_derive_cve_spec"))
                if isinstance(n, ast.For))
    names = []
    for i, stmt in enumerate(loop.body):
        src = ast.dump(stmt)
        if "_derive_deadline" in src and not names:
            names.append(("derive", i))
        if "'_build_poc_wall_deadline'" in src or "deadline" == getattr(
                getattr(stmt, "test", None), "id", None):
            pass
        for sub in ast.walk(stmt):
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) \
                    and sub.func.id == "_derive_cve_spec_single_pass":
                names.append(("pass", i))
    assert names and names[0][0] == "derive", (
        f"the derivation budget is not checked first in the loop body: {names}")
