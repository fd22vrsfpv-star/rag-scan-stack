"""The gather gate must not block on auth it could never have obtained.

`needs_auth` is a KEYWORD MATCH over advisory prose ("auth", "login",
"session", "credential", ...). With no cookie in hand the gate blocked
unconditionally, which conflated two different things:

    auth could not be OBTAINED   !=   auth is REQUIRED

CVE-2024-32964 (focused-10, 2026-10-16) stopped `gather_incomplete:auth` after
4198s having synthesised ZERO commands, while holding a complete SSRF spec:

    [gathered] vuln_class  = ssrf            [gathered] method     = POST
    [gathered] endpoint    = /settings/agent [gathered] input_field = body
    [gathered] oob_sink    = http://172.19.130.199:9091/done HTTP 200
    [MISSING]  auth: exploit needs authentication; no session cookie in hand

The challenge's own goal 8 is "Outbound Service Request" — precisely that SSRF.
The credentials were correct (the challenge ships `username`/`password`); there
was no login FORM to post them to, so `recon:auth_establish` reported
`ok=False note=no login form found`. The endpoint itself had answered HTTP 200
unauthenticated.

So the target is asked instead of the advisory, and `auth` gained a third
outcome. Pinned here, because each is a way for this to silently stop working:

  1. an observed 401/403 still blocks — this must not become "always try";
  2. a found login form still blocks — we failed at something we could do;
  3. CVSS PR:L/H still blocks even when unverified — a STATED privilege
     requirement beats an inference drawn from one probe;
  4. `unverified` is never `gathered`: a 200 can be a login page, so this is
     permission to ATTEMPT, not a finding;
  5. auth-bypass keeps its own carve-out (the session is the exploit's output).

Sabotage check: make the `unverified` leg return "gathered" and
`test_unverified_is_not_gathered` fails; drop `not _preauth` from the
`_gather_decide` clause and `test_cvss_privileges_required_still_blocks` fails;
revert item 7 to the single unconditional `missing` and six tests fail.

    pytest tests/test_gather_auth_gate.py -q
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



# The class predicates `_gather_decide` now calls. Injected from the REAL
# `etl/vuln_classes.py` rather than stubbed, so this exercises the shipped
# table: the gate and the test cannot disagree about what `lfi` is.
def _vc_predicates():
    import sys as _sys
    from pathlib import Path as _P
    _sys.path.insert(0, str(_P(__file__).resolve().parent.parent))
    from etl import vuln_classes as _m
    return {"_vc_needs_input_field": _m.needs_input_field,
            "_vc_needs_oob_sink": _m.needs_oob_sink,
            # privilege-escalation declares identity_required, so the gate now
            # asks the class table whether the accounts must be enumerated
            # before synthesis (knowledge/vuln_classes.yaml).
            "_vc_needs_identity": _m.needs_identity,
            "_vc_path_is_the_field": _m.path_is_the_field,
            "_vc_canonical": _m.canonical,
            "_vc_is_file_read": _m.is_file_read,
            "_vc_cwe_ids_for": _m.cwe_ids_for,
            "_vc_classes_for_cwe": _m.classes_for_cwe,
            "_vc_resolve": _m.resolve,
            "_vc_is_known": lambda n: _m.canonical(n) != "unknown"}


def _decide():
    """_gather_decide is documented PURE, so it runs standalone."""
    src = API.read_text(encoding="utf-8")
    ns = dict(_vc_predicates())
    # The class SETS are gone — they are projections of
    # knowledge/vuln_classes.yaml now — so only the follow-up text remains a
    # module-level dependency of this exec.
    needed = ["_GATHER_FOLLOW_UP"]
    body = []
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in needed for t in n.targets):
            body.append(n)
    body.append(_func("_gather_decide"))
    exec(compile(ast.Module(body=body, type_ignores=[]), "<gate>", "exec"), ns)
    return ns["_gather_decide"]


def _items(auth_status, vc="ssrf"):
    """A manifest with everything an SSRF needs, parameterised on auth."""
    base = {"target_reachable": "gathered", "vuln_class": "gathered",
            "endpoint": "gathered", "method": "gathered",
            "evidence": "gathered", "input_field": "gathered",
            "oob_sink": "gathered"}
    out = [{"item": k, "status": v, "value": "x", "source": "test"}
           for k, v in base.items()]
    if auth_status is not None:
        out.append({"item": "auth", "status": auth_status, "value": "x",
                    "source": "test"})
    return out


# -- the decision ------------------------------------------------------------

def test_the_32964_shape_is_now_ready():
    """Everything gathered, auth unconfirmed, CVSS PR:N -> attempt it."""
    d = _decide()(_items("unverified"), "ssrf", privileges_required="N")
    assert d["ready"] is True, (
        f"a complete SSRF spec is still refused over an unconfirmed auth "
        f"claim: missing={d['missing']}")


def test_an_observed_401_still_blocks():
    d = _decide()(_items("missing"), "ssrf", privileges_required="N")
    assert d["ready"] is False and "auth" in d["missing"]


def test_cvss_privileges_required_still_blocks():
    """A STATED privilege requirement beats an inference from one probe."""
    for pr in ("L", "H"):
        d = _decide()(_items("unverified"), "ssrf", privileges_required=pr)
        assert d["ready"] is False and "auth" in d["missing"], (
            f"PR:{pr} says privileges are required and the gate let it through "
            f"anyway on an unverified auth claim")


def test_gathered_auth_is_ready_at_any_privilege():
    for pr in ("N", "L", "H"):
        assert _decide()(_items("gathered"), "ssrf", privileges_required=pr)["ready"]


def test_auth_bypass_keeps_its_carve_out():
    """The session is the exploit's OUTPUT; demanding one first refuses the test."""
    d = _decide()(_items("missing", vc="auth-bypass"), "auth-bypass",
                  privileges_required="L")
    assert "auth" not in d["missing"], d["missing"]


def test_unverified_does_not_satisfy_any_other_item():
    """Only `evidence` and `auth` may be satisfied unverified."""
    for item in ("endpoint", "method", "input_field", "oob_sink",
                 "target_reachable", "vuln_class"):
        items = [i for i in _items("gathered") if i["item"] != item]
        items.append({"item": item, "status": "unverified", "value": "x",
                      "source": "test"})
        d = _decide()(items, "ssrf", privileges_required="N")
        assert item in d["missing"], (
            f"{item}=unverified was accepted — only evidence and auth may be")


# -- how item 7 reaches that decision ---------------------------------------

def _auth_adds():
    """Every add("auth", <status>, ...) in _gather_manifest, with its guard."""
    fn = _func("_gather_manifest")
    out = []
    for node in ast.walk(fn):
        if not isinstance(node, ast.If):
            continue
        for stmt in node.body:
            for c in ast.walk(stmt):
                if (isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                        and c.func.id == "add" and len(c.args) >= 2
                        and getattr(c.args[0], "value", None) == "auth"
                        and isinstance(c.args[1], ast.Constant)):
                    out.append((ast.unparse(node.test), c.args[1].value))
    return out


def test_an_unverified_leg_exists_and_keys_on_the_observed_status():
    legs = _auth_adds()
    unver = [g for g, st in legs if st == "unverified"]
    assert unver, (
        "no add(\"auth\", \"unverified\", ...) leg — the gate still has only "
        "two outcomes, so a target that answered unauthenticated is refused "
        "on an advisory keyword")
    assert any("ep_probe_status" in g for g in unver), (
        f"the unverified leg does not key on the endpoint's observed status: "
        f"{unver} — it must be the TARGET's answer, not another inference")


def test_unverified_is_not_gathered():
    """A 200 can be a login page. Permission to attempt, never a finding."""
    assert not any(
        st == "gathered" and "ep_probe_status" in g for g, st in _auth_adds()), (
        "an unauthenticated 200 is being recorded as auth GATHERED — that "
        "claims a session we do not have")


def test_a_401_or_403_leg_still_blocks():
    legs = _auth_adds()
    hard = [(g, st) for g, st in legs if "401" in g or "403" in g]
    assert hard, "no leg keys on an observed 401/403"
    assert all(st == "missing" for _, st in hard), (
        f"an observed 401/403 no longer blocks: {hard}")


def test_a_found_login_form_still_blocks():
    legs = _auth_adds()
    form = [(g, st) for g, st in legs if "_login_seen" in g]
    assert form, "no leg distinguishes a target that HAS a login form"
    assert all(st == "missing" for _, st in form), (
        f"a target with a login form we failed to use is no longer blocked: "
        f"{form} — that is a failure we could have fixed, not an absent gate")


def test_the_probe_status_is_captured_from_a_real_response():
    """`ep_probe_status` must come from a status_code, not be inferred."""
    fn = _func("_gather_manifest")
    def _binds(node):
        """Does this Assign bind ep_probe_status, directly or by unpacking?

        The ranking winner arrives as
        `_, endpoint, ep_source, ep_probe_status = _ranked[0]`, whose single
        target is a Tuple — so a Name-only scan sees no binding at all and
        reports the probe site as missing.
        """
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id == "ep_probe_status":
                return True
            if isinstance(t, (ast.Tuple, ast.List)):
                if any(isinstance(e, ast.Name) and e.id == "ep_probe_status"
                       for e in t.elts):
                    return True
        return False

    assigns = [n for n in ast.walk(fn) if isinstance(n, ast.Assign) and _binds(n)]
    assert len(assigns) >= 3, (
        f"expected an init plus both probe sites, found {len(assigns)} "
        "assignments to ep_probe_status")
    # The status may arrive directly (`ep_probe_status = rp.status_code`) or
    # be carried through the candidate RANKING, which stores `rp.status_code`
    # alongside each answering path and unpacks the winner. Both are "observed
    # from a real response"; pinning only the direct form made this fail when
    # selection stopped racing candidates and started ranking them, though the
    # property it guards was never violated.
    from_resp = [a for a in assigns
                 if isinstance(a.value, ast.Attribute)
                 and a.value.attr == "status_code"]
    # The CANDIDATE TUPLE's status element specifically — not any
    # `.status_code` in the function. The first version of this check counted
    # every reference, so replacing the captured status with a literal 200
    # still passed: there were other `rp.status_code` uses nearby. Fourth
    # false pass of the same shape today, all from matching something that
    # merely co-occurs with the thing that matters.
    ranked_src = []
    for n in ast.walk(fn):
        if not (isinstance(n, ast.Call)
                and getattr(n.func, "attr", None) == "append"):
            continue
        for a in n.args:
            if not isinstance(a, ast.Tuple):
                continue
            ranked_src += [e for e in a.elts
                           if isinstance(e, ast.Attribute)
                           and e.attr == "status_code"]
    unpacked = [a for a in assigns
                if isinstance(a.targets[0], (ast.Tuple, ast.List))]
    assert len(from_resp) + (1 if unpacked else 0) >= 2, (
        "ep_probe_status is not set from a response status_code at both probe "
        "sites — an unobserved status must stay None, never a default")
    assert ranked_src, (
        "the candidate tuple must carry the answering response's real "
        "status_code; a literal there reports a status nobody observed")
    assert any(isinstance(a.value, ast.Constant) and a.value.value is None
               for a in assigns), (
        "ep_probe_status has no None initialiser: 'not observed' would then be "
        "indistinguishable from a real status")


# -- 8. "pre-auth" contains "auth" ------------------------------------------

def _needs_auth_logic():
    """Execute the REAL shared helper, `_auth_requirement`.

    This used to extract a source window out of `_gather_manifest` and exec it,
    keyed on the literal line `needs_auth = bool(_auth_positive) and not
    _auth_negated`. That made the test pass only while the logic stayed inlined
    AND duplicated: `_assess_exploit_readiness` carried its own bare membership
    test that included the substring "auth", so "pre-authentication" and
    "unauthenticated" both matched and a pre-auth CVE was blocked for lacking
    the session it does not need. One definition now, exercised directly.
    """
    import ast as _ast
    fn = _func("_auth_requirement")
    ns = {}
    exec(compile(_ast.Module(body=[fn], type_ignores=[]), "<auth>", "exec"), ns)
    helper = ns["_auth_requirement"]

    def run(pre_blob="", desc=""):
        needs, negated, _why = helper(pre_blob, desc)
        return needs, negated
    return run


def test_both_gates_share_one_auth_definition():
    """The gather gate and the readiness gate must call the SAME helper.

    They disagreed for weeks: gather got the negation fix, readiness kept a
    bare `any(k in pre_blob ...)` whose key list contained "auth".
    """
    for fname in ("_gather_manifest", "_assess_exploit_readiness"):
        fn = _func(fname)
        called = {getattr(n.func, "id", None) or getattr(n.func, "attr", None)
                  for n in ast.walk(fn) if isinstance(n, ast.Call)}
        assert "_auth_requirement" in called, (
            f"{fname} must decide auth through the shared helper, not its own "
            "copy of the logic")
    # ...and the old bare membership test must not come back in either.
    for fname in ("_gather_manifest", "_assess_exploit_readiness"):
        for node in ast.walk(_func(fname)):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "id", "") != "any":
                continue
            lits = [c.value for c in ast.walk(node)
                    if isinstance(c, ast.Constant) and isinstance(c.value, str)]
            assert "auth" not in lits, (
                f"{fname}: a bare membership test containing the literal "
                f'"auth" matches "pre-authentication" and "unauthenticated"')


def test_the_readiness_gate_lets_a_pre_auth_cve_through():
    """The regression that motivated the shared helper, end to end.

    Measured before the fix: the bare test said True on 3 of these 6, every
    one in the blocking direction.
    """
    run = _needs_auth_logic()
    OLD_KEYS = ("auth", "login", "session", "logged", "credential", "cookie",
                "privilege", "user ", "account")
    cases = [
        ("pre-authentication arbitrary file access; allows unauthenticated "
         "attackers to perform path traversal", False),
        ("the vulnerability does not require authentication", False),
        ("requires no credentials", False),
        ("an authenticated user with admin privileges can trigger this", True),
        ("the attacker must first obtain a valid session cookie", True),
    ]
    wrong_before = 0
    for text, expect in cases:
        needs, _neg = run(text, "")
        assert needs is expect, f"{text[:50]!r}: expected {expect}, got {needs}"
        if any(k in text.lower() for k in OLD_KEYS) != expect:
            wrong_before += 1
    assert wrong_before >= 3, (
        "the old bare test should be demonstrably worse on this table; if it "
        "is not, the table no longer covers the regression")


PRE_AUTH = [
    "A pre-authentication arbitrary file access (LFI-like) in Atlassian products",
    "allows unauthenticated attackers to perform path traversal",
    "exploitable without authentication",
    "no authentication is required to exploit this issue",
    "the endpoint does not require authentication",
    "anonymous access to the admin servlet",
    "requires no credentials",
]


@pytest.mark.parametrize("text", PRE_AUTH)
def test_a_pre_auth_advisory_does_not_demand_a_session(text):
    """THE bug. 'auth' is a substring of 'pre-authentication'.

    CVE-2026-21589 (2026-10-16) stopped `gather_incomplete:auth` on BOTH runs
    with the research text reading 'a pre-authentication arbitrary file
    access' — the gate demanded a session for a vulnerability whose defining
    property is that it needs none.
    """
    needs, negated = _needs_auth_logic()(desc=text)
    assert needs is False, (
        f"{text!r} set needs_auth — the gate would demand a session for a "
        "pre-auth vulnerability and refuse to synthesise anything")
    assert negated, "the negation was not detected"


@pytest.mark.parametrize("text", [
    "requires an authenticated user with admin privileges",
    "an authenticated attacker can escalate",
    "the user must be logged in",
    "requires login as a project administrator",
])
def test_a_genuine_auth_requirement_still_demands_one(text):
    needs, _ = _needs_auth_logic()(desc=text)
    assert needs is True, (
        f"{text!r} no longer sets needs_auth — the fix for pre-auth has "
        "disabled the requirement for advisories that really do need a session")


def test_a_session_precondition_still_counts():
    needs, _ = _needs_auth_logic()(pre_blob="valid session cookie required")
    assert needs is True


def test_silence_is_not_a_requirement():
    assert _needs_auth_logic()(desc="a buffer overflow in the parser")[0] is False


def test_the_negation_is_recorded_with_its_evidence():
    """An operator must see WHY the gate stopped asking for auth."""
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func("_gather_manifest")) or ""
    fn = _func("_gather_manifest")
    # Structural: an add("auth", "n/a", ...) whose SOURCE argument is the
    # pre-auth marker, and whose reason interpolates the matched phrase.
    calls = [c for c in ast.walk(fn)
             if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
             and c.func.id == "add" and len(c.args) >= 4
             and getattr(c.args[0], "value", None) == "auth"
             and getattr(c.args[3], "value", None) == "analysis:pre-auth"]
    assert calls, (
        "no add(\"auth\", ..., \"analysis:pre-auth\") — a gate that silently "
        "stops requiring auth is indistinguishable from one that forgot to")
    reason = ast.unparse(calls[0].args[2])
    assert "_auth_negated" in reason, (
        "the recorded reason does not quote the phrase that triggered it, so "
        "an operator cannot tell WHY auth stopped being required")
