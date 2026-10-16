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


def _decide():
    """_gather_decide is documented PURE, so it runs standalone."""
    src = API.read_text(encoding="utf-8")
    ns = {}
    needed = ["_GATHER_FIELD_REQUIRED_CLASSES", "_GATHER_OOB_CLASSES",
              "_GATHER_FOLLOW_UP"]
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
    assigns = [n for n in ast.walk(fn) if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "ep_probe_status"
                       for t in n.targets)]
    assert len(assigns) >= 3, (
        f"expected an init plus both probe sites, found {len(assigns)} "
        "assignments to ep_probe_status")
    from_resp = [a for a in assigns
                 if isinstance(a.value, ast.Attribute)
                 and a.value.attr == "status_code"]
    assert len(from_resp) >= 2, (
        "ep_probe_status is not set from a response status_code at both probe "
        "sites — an unobserved status must stay None, never a default")
    assert any(isinstance(a.value, ast.Constant) and a.value.value is None
               for a in assigns), (
        "ep_probe_status has no None initialiser: 'not observed' would then be "
        "indistinguishable from a real status")


# -- 8. "pre-auth" contains "auth" ------------------------------------------

def _needs_auth_logic():
    """Exec just the needs_auth decision from _gather_manifest.

    Extracted by source window rather than imported: _gather_manifest is a
    ~700-line function that probes the network, and the decision under test is
    a dozen lines of pure string logic inside it.
    """
    import re as _re
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func("_gather_manifest")) or ""
    i = src.index("_blob = f\"{pre_blob} {desc}\"")
    j = src.index("needs_auth = bool(_auth_positive) and not _auth_negated")
    body = src[i:j] + "needs_auth = bool(_auth_positive) and not _auth_negated\n"
    body = "\n".join(line[4:] if line.startswith("    ") else line
                     for line in body.split("\n"))

    def run(pre_blob="", desc=""):
        ns = {"_re": _re, "pre_blob": pre_blob.lower(), "desc": desc.lower()}
        exec(compile(body, "<auth>", "exec"), ns)
        return ns["needs_auth"], ns["_auth_negated"]
    return run


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
