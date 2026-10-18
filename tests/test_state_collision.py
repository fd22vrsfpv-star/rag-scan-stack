"""A record our own earlier attempt created is a STATE collision, not a dead payload.

Run standalone:  pytest tests/test_state_collision.py -q

WHY THIS EXISTS
---------------
CVE-2023-37999 (WordPress HT Mega registration privilege escalation) verified
three times on fresh targets, then ran 10 iterations and failed on 2026-10-18.
Every attempt re-registered `test@example.com`; from the first success onward
the target answered

    {"registerauth":false,"message":"Email Already in Use"}

The outcome classifier filed that under the catch-all `other` tier, whose
directive is "change the PARAMETER" -- so the model churned payloads and kept
the same email. Worse, a fresh email is a payload-VALUE change, which the axis
gate (`_axes_differ` ignores values by design) would refuse as payload-only.

So a collision gets its own tier, its own directive on the FIRST occurrence,
and bypasses the axis gate. Functions are EXECUTED, compiled out of api.py.
"""
import ast
import pathlib

import pytest

API = pathlib.Path(__file__).resolve().parents[1] / "app" / "rag-api" / "api.py"

REAL = '{"registerauth":false,"message":"Email Already in Use"}'


def _load():
    if not API.exists():
        pytest.skip("api.py not present")
    tree = ast.parse(API.read_text(encoding="utf-8"))
    fns = {"_state_collision", "_error_signature"}
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in fns]
    missing = fns - {n.name for n in body}
    if missing:
        pytest.fail(f"function(s) gone from api.py: {sorted(missing)}")
    body += [n for n in tree.body if isinstance(n, ast.Assign)
             and any(getattr(t, "id", "") in ("_STATE_COLLISION_MARKERS", "_ERR_SIG_MAX")
                     for t in n.targets)]
    ns: dict = {"_WAF_FINGERPRINTS": ()}
    exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])),
                 "<api-subset>", "exec"), ns)
    return ns


@pytest.fixture(scope="module")
def api():
    return _load()


@pytest.mark.parametrize("body", [
    REAL,
    "HTTP/1.1 409 Conflict\n\nUser already exists",
    "<div class='error'>That username is already taken.</div>",
    "ERROR 1062 (23000): Duplicate entry 'admin' for key 'user_login'",
    "Sorry, that email address is already registered.",
])
def test_collision_bodies_are_the_state_tier(api, body):
    assert api["_state_collision"](body)
    _sig, tier = api["_error_signature"](body, method="regex_missed")
    assert tier == "state", (
        f"a 'record already exists' reply was filed as {tier!r}; its directive "
        "would tell the model to change the payload, not the identity")


@pytest.mark.parametrize("body", [
    "HTTP/1.1 404 Not Found",
    '{"success":true,"data":{"user_id":12}}',
    "<html><title>Log In</title>Invalid username or password</html>",
])
def test_ordinary_bodies_are_not_collisions(api, body):
    assert api["_state_collision"](body) is None
    assert api["_error_signature"](body)[1] != "state"


def _loop_src():
    src = API.read_text(encoding="utf-8")
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name == "_run_refine_poc":
            return node, src
    pytest.fail("_run_refine_poc is gone")


def test_state_tier_bypasses_the_axis_gate():
    """The `state` branch must come BEFORE the axis-gate branch and clear any
    pending axis demand, or a fresh-email command is refused as payload-only."""
    node, _ = _loop_src()
    found = False
    for n in ast.walk(node):
        if not isinstance(n, ast.If):
            continue
        consts = {c.value for c in ast.walk(n.test) if isinstance(c, ast.Constant)}
        if "state" not in consts:
            continue
        cleared = any(isinstance(a, ast.Assign)
                      and any(getattr(t, "id", "") == "_axis_required" for t in a.targets)
                      and isinstance(a.value, ast.Constant) and a.value.value is None
                      for a in ast.walk(ast.Module(n.body, [])))
        gate_in_else = any(isinstance(c, ast.Call) and getattr(c.func, "id", "") == "_dead_axis_for_tier"
                           for c in ast.walk(ast.Module(n.orelse, [])))
        if cleared and gate_in_else:
            found = True
    assert found, ("no `if ... == 'state'` branch that clears _axis_required "
                   "with the axis gate in its else -- a collision would arm the "
                   "gate and the fresh-identity fix would be refused")


def test_refine_prompt_carries_the_state_note():
    node, src = _loop_src()
    seg = ast.get_source_segment(src, node) or ""
    names = {c.func.id for c in ast.walk(node)
             if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
    assert "_state_collision" in names, "the refine loop never checks for a collision"
    fstr_names = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "rprompt" for t in n.targets):
            fstr_names |= {x.id for x in ast.walk(n.value) if isinstance(x, ast.Name)}
    assert "_state_note" in fstr_names, (
        "the collision directive is built but never reaches the refine prompt")
    assert seg  # keeps the segment read honest if the function moves
