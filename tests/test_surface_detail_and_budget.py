"""SurfaceTester messages must show WHAT was examined, and phases must be able to
run through instead of truncating at the step budget.

Run on demand:

    pytest tests/test_surface_detail_and_budget.py -v

WHY THIS EXISTS
---------------
The SurfaceTester messages gave only counts ("15 custom tests — 7 safe, 8
impactful"), so an operator could not see which services/ports/commands were
examined. And the phase step budgets were tight enough that Analyzer (26) and
Exploit (22) ran out mid-work and returned LangGraph's "Sorry, need more steps"
in place of a conclusion.

Pinned here:
  * _fmt_surface_tests renders one line per test (tier, name, service:port,
    command/module) so the message expands to explain itself.
  * the surface plan / safe-exec / auto-exec messages include that detail.
  * PHASE_STEP_BUDGET is raised AND per-phase env-overridable so a phase can
    finish (or an operator can grant more without a code change).

SABOTAGE PROOF
--------------
* Make _fmt_surface_tests return "" and test_fmt_lists_service_and_command fails.
* Drop _fmt_surface_tests from surface_plan and test_surface_messages_carry_detail fails.
* Lower a PHASE_STEP_BUDGET default back below 30 and test_phase_budgets_raised fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")


def _src():
    if not os.path.exists(ENGINE):
        pytest.skip("langgraph_engine.py not present")
    return open(ENGINE, encoding="utf-8").read()


def _load(name):
    tree = ast.parse(_src())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            ns = {"os": os}
            exec(compile(ast.Module(body=[node], type_ignores=[]), ENGINE, "exec"), ns)
            return ns[name]
    pytest.fail(f"{name} not found — guard is stale")


def test_fmt_lists_service_and_command():
    fmt = _load("_fmt_surface_tests")
    tests = [
        {"tier": "safe", "name": "http title", "service": "http", "port": 80,
         "command": "curl -sI http://192.168.1.150:80/"},
        {"tier": "impactful", "name": "samba usermap", "service": "netbios-ssn",
         "port": 139, "exploit_ref": {"module": "exploit/multi/samba/usermap_script"}},
    ]
    out = fmt(tests)
    assert "http:80" in out and "curl -sI" in out, "safe test must show service:port + command"
    assert "netbios-ssn:139" in out and "usermap_script" in out, (
        "impactful test must show service:port + the MSF module")
    assert "[safe]" in out and "[impactful]" in out, "each line must show the tier"
    # bounded + empty-safe
    assert fmt([]) == "  (none)"
    assert "and 1 more" in fmt([{"name": str(i)} for i in range(31)], limit=30)


def test_surface_messages_carry_detail():
    src = _src()
    # all three SurfaceTester summaries must include per-test detail, not bare counts
    assert "Services examined" in src, "surface_plan must list the services examined"
    assert src.count("_fmt_surface_tests(") >= 1, (
        "surface_plan must render the test list via _fmt_surface_tests")
    # safe-exec and auto-exec build their own per-result detail blocks
    assert "def _fmt_res(" in src and "def _fmt_imp(" in src, (
        "safe-exec and auto-exec must append a per-test result breakdown")


def test_phase_budgets_raised_and_overridable():
    src = _src()
    tree = ast.parse(src)
    # _phase_budget reads PHASE_STEP_BUDGET_<PHASE> from the environment
    assert "PHASE_STEP_BUDGET_" in src and "def _phase_budget" in src, (
        "phase budgets must be per-phase env-overridable")
    # find the PHASE_STEP_BUDGET dict literal and check the raised defaults
    fn = _load("_phase_budget")
    # Analyzer and Exploit were the ones that truncated at 26/22 — must be higher
    assert fn("Analyzer", 44) >= 40 and fn("Exploit", 44) >= 40
    # env override wins
    os.environ["PHASE_STEP_BUDGET_EXPLOIT"] = "60"
    try:
        assert fn("Exploit", 44) == 60
    finally:
        del os.environ["PHASE_STEP_BUDGET_EXPLOIT"]
    # and the defaults in the source are raised (not the old 26/22)
    m = __import__("re").search(r'"Analyzer":\s*_phase_budget\("Analyzer",\s*(\d+)\)', src)
    assert m and int(m.group(1)) >= 40, "Analyzer default must be raised from 26"
    m2 = __import__("re").search(r'"Exploit":\s*_phase_budget\("Exploit",\s*(\d+)\)', src)
    assert m2 and int(m2.group(1)) >= 40, "Exploit default must be raised from 22"
