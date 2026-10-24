"""Deep recon should answer the gap, not widen everything.

THE DEFECT (CVE-2023-37999, 2026-10-23)
---------------------------------------
Operator: "let's break the recon piece up to smaller sections to focus it."

A deep-recon plan is assembled in two halves — `_deep_recon_plan` widens the
surface generically, then the tools from knowledge/gap_tools.yaml that answer
the SPECIFIC missing items are appended. Appending them last was deliberate
(the deterministic path stays the backstop), but it means a build missing ONE
item pays for the whole widen set first:

    missing=['identity']
    steps=['product_id','auth_crawl','zap_spider','arjun_params',
           'user_enum_rest','user_enum_generic','user_enum_author_scan']

A Playwright crawl, a ZAP spider and an arjun sweep — none of which can answer
"which accounts exist" — ahead of the three curl commands that can. ~390s per
attempt, and the budget the widen set spends is budget the answering tools then
do not get (`_left()` bounds the whole plan).

WHAT MUST NOT REGRESS
---------------------
The generic path is the BACKSTOP and must survive whenever a gap has no tool
(`test_an_uncovered_gap_keeps_the_generic_steps`). Focusing is about ORDER and
relevance, not about removing the fallback.

    pytest tests/test_focused_recon_plan.py
"""
from __future__ import annotations

import ast
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _ast_assert  # noqa: E402
from _ast_assert import calls, call_kwarg, defines, call_order  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
API = ROOT / "app" / "rag-api" / "api.py"

# the real plan and tool costs from the 2026-10-23 trace
OBSERVED = ["product_id", "auth_crawl", "zap_spider", "arjun_params",
            "user_enum_rest", "user_enum_generic", "user_enum_author_scan"]
ANSWERING = {
    "user_enum_rest": (5, {"identity", "user_ids", "endpoint_id"}),
    "user_enum_generic": (10, {"identity", "user_ids"}),
    "user_enum_author_scan": (12, {"identity", "user_ids"}),
}


@pytest.fixture(scope="module")
def focus():
    src = API.read_text(encoding="utf-8")
    fn = next((n for n in ast.walk(ast.parse(src))
               if isinstance(n, ast.FunctionDef) and n.name == "_focus_plan"), None)
    if fn is None:
        pytest.fail("_focus_plan is gone from api.py")
    ns: dict = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                 "<api-subset>", "exec"), ns)
    return ns["_focus_plan"]


def test_one_gap_runs_only_what_answers_it(focus):
    assert focus(OBSERVED, {"identity"}, ANSWERING) == [
        "user_enum_rest", "user_enum_generic", "user_enum_author_scan"]


def test_the_answering_tools_run_cheapest_first(focus):
    """`cost` exists to order the plan; a 5s curl should precede a 12s loop."""
    got = focus(OBSERVED, {"identity"}, ANSWERING)
    costs = [ANSWERING[s][0] for s in got]
    assert costs == sorted(costs), got


def test_an_uncovered_gap_keeps_the_generic_steps(focus):
    """SABOTAGE GUARD. The deterministic path is the backstop — dropping it
    when a gap has no tool would leave the build with nothing to try."""
    got = focus(OBSERVED, {"identity", "endpoint"}, ANSWERING)
    for generic in ("auth_crawl", "zap_spider", "arjun_params"):
        assert generic in got, f"{generic} was dropped while `endpoint` had no tool"


def test_the_specific_answer_precedes_the_general_sweep(focus):
    got = focus(OBSERVED, {"identity", "endpoint"}, ANSWERING)
    assert got.index("user_enum_rest") < got.index("zap_spider"), (
        "the cheap specific answer must be tried before the expensive sweep")


def test_no_tools_at_all_changes_nothing(focus):
    """SABOTAGE GUARD. With nothing to focus on, the plan is untouched —
    focusing must not be able to empty a plan."""
    assert focus(OBSERVED, {"endpoint"}, {}) == OBSERVED


def test_an_empty_need_set_changes_nothing(focus):
    assert focus(OBSERVED, set(), ANSWERING) == OBSERVED
    assert focus(OBSERVED, None, ANSWERING) == OBSERVED


def test_it_never_invents_a_step(focus):
    """Whatever it returns must be a subset of the plan it was given."""
    for needs in ({"identity"}, {"identity", "endpoint"}, {"endpoint"}, set()):
        assert set(focus(OBSERVED, needs, ANSWERING)) <= set(OBSERVED)


def test_it_is_wired_into_the_plan():
    src = API.read_text(encoding="utf-8")
    assert calls(src, "_focus_plan"), (
        "the focusing is computed and then discarded")
    assert "_answering" in src, (
        "nothing records which tool answers which gap")
