"""OSINT scans must not leak the operator's own IP.

An operator saw scans against an external target attributed to their own public
address. `osint_runner._build_proxy_env` was fail-OPEN by construction --

    if proxy:
        env["ALL_PROXY"] = proxy
        ...
    return env

-- and `proxy` is `Optional[str] = None` on ~25 request models, so a scan
started without one egressed direct. The audit row then recorded the bare label
`"local"`, which an operator cannot distinguish from "ran here, proxied", and
the OpSec console rendered it in the same neutral grey as every unremarkable
value.

WHAT IS PINNED HERE

  1. the policy is the SHARED one (`etl/attack_proxy`), not a second copy -- a
     divergent second implementation is the failure CLAUDE.md asks for an
     agreement test about, and this file is that test;
  2. THREE outcomes, never two: an unreadable policy, an unreachable database
     or an unattributable target is `undetermined`, and `.required` reads
     undetermined as YES. "Could not determine" is not "permitted";
  3. the default is unchanged: with nobody opted in, `_build_proxy_env`
     returns exactly the environment it returned before this existed --
     including no proxy variables at all when the caller passed none;
  4. the enforcement lives in the CHOKEPOINT (`_build_proxy_env`), not at the
     ~25 call sites, one of which would eventually be added without it;
  5. the gowitness path rebinds `proxy` from the decision BEFORE building the
     command, because chromium ignores ALL_PROXY and an env-only decision
     would screenshot every URL from this host's own address;
  6. the scope gate is untouched. The proxy policy decides HOW packets leave,
     never WHETHER they may -- conflating the two is how an opsec setting ends
     up granting authorisation.

SABOTAGE CHECKS (each re-run before this landed, failing by name):
  * make `_build_proxy_env` build the env itself again ->
    test_the_chokepoint_delegates_to_the_policy
  * let `PolicyVerdict.required` return `verdict == POLICY_REQUIRED` ->
    test_undetermined_is_required / test_a_dead_database_does_not_permit_direct
  * drop the `if eg.proxy` rebind in the gowitness job ->
    test_gowitness_decides_the_proxy_before_building_the_command

    pytest tests/test_osint_egress_policy.py -q
"""
import ast
import importlib.util
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ast_assert import calls, defines, function_source, ref_order  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
OSINT = REPO / "osint_runner" / "osint_runner.py"
PROXY = REPO / "etl" / "attack_proxy.py"

if not OSINT.exists() or not PROXY.exists():      # pragma: no cover
    pytest.skip("osint_runner / attack_proxy not present", allow_module_level=True)

OSINT_SRC = OSINT.read_text(encoding="utf-8")


def _load_attack_proxy():
    spec = importlib.util.spec_from_file_location("_ap_egress", PROXY)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


ap = _load_attack_proxy()


# ── fake database ─────────────────────────────────────────────────────────
# Keyed by a fragment of the statement. The LONGEST matching key wins, so
# "SELECT require_proxy FROM engagements" is not answered by a "FROM
# engagements" entry meant for the node lookup.

class _Boom(Exception):
    def __init__(self, msg="db down", pgcode=None):
        super().__init__(msg)
        self.pgcode = pgcode


class _Cur:
    def __init__(self, answers, raise_on=()):
        self.answers, self.raise_on, self.sql = answers, raise_on, ""

    def execute(self, sql, params=None):
        self.sql = sql
        for frag, exc in (self.raise_on or {}).items():
            if frag in sql:
                raise exc

    def _answer(self):
        hits = [(len(k), v) for k, v in self.answers.items() if k in self.sql]
        return max(hits)[1] if hits else None

    def fetchone(self):
        v = self._answer()
        return v[0] if isinstance(v, list) else v

    def fetchall(self):
        v = self._answer()
        return v if isinstance(v, list) else ([v] if v else [])

    def __enter__(self): return self
    def __exit__(self, *a): return False


class _Conn:
    def __init__(self, answers, raise_on=(), fail_connect=False):
        self.answers, self.raise_on = answers, raise_on
    def cursor(self): return _Cur(self.answers, self.raise_on)
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _db(answers=None, raise_on=None, fail_connect=False):
    def f():
        if fail_connect:
            raise _Boom("could not connect to server")
        return _Conn(answers or {}, raise_on or {})
    return f


_EXISTS = "SELECT EXISTS (SELECT 1 FROM engagements"
_FLAG = "SELECT require_proxy FROM engagements"
_SCOPE = "FROM scope_targets"
_NODES = "FROM remote_nodes"
EID = "11111111-2222-3333-4444-555555555555"


# ── 1. three outcomes, and `required` is the fail-closed reading ──────────

def test_nobody_opted_in_is_a_determined_no():
    v = ap.engagement_requires_proxy(_db({_EXISTS: (False,)}), target="example-corp.com")
    assert v.verdict == ap.POLICY_NOT_REQUIRED
    assert v.required is False and v.determined is True


def test_an_engagement_that_opted_in_requires_a_proxy():
    v = ap.engagement_requires_proxy(
        _db({_EXISTS: (True,), _SCOPE: (EID,), _FLAG: (True,)}),
        target="host-a.example.com")
    assert v.verdict == ap.POLICY_REQUIRED and v.required is True
    assert v.engagement_id == EID


def test_an_engagement_that_opted_out_does_not():
    v = ap.engagement_requires_proxy(
        _db({_EXISTS: (True,), _SCOPE: (EID,), _FLAG: (False,)}), target="h.example.com")
    assert v.verdict == ap.POLICY_NOT_REQUIRED and v.required is False


@pytest.mark.parametrize("name,factory", [
    # the policy table cannot be reached at all
    ("dead_connection", _db(fail_connect=True)),
    # the EXISTS answers, but the per-engagement read fails
    ("flag_unreadable", _db({_EXISTS: (True,), _SCOPE: (EID,)},
                            raise_on={_FLAG: _Boom()})),
    # an engagement requires a proxy and this target belongs to no engagement
    ("unattributable_target", _db({_EXISTS: (True,)})),
    # the scope lookup itself errors
    ("scope_unreadable", _db({_EXISTS: (True,)}, raise_on={_SCOPE: _Boom()})),
    # the engagement id does not exist in the table
    ("engagement_vanished", _db({_EXISTS: (True,), _SCOPE: (EID,)})),
    # the column exists but the row is NULL
    ("null_flag", _db({_EXISTS: (True,), _SCOPE: (EID,), _FLAG: (None,)})),
])
def test_undetermined_is_required(name, factory):
    """Each of these is a way of NOT KNOWING. None of them may read as
    permission to egress from the operator's own address."""
    v = ap.engagement_requires_proxy(factory, target="host-a.example.com")
    assert v.verdict == ap.POLICY_UNDETERMINED, f"{name}: {v}"
    assert v.required is True, f"{name} was treated as 'no proxy needed': {v}"
    assert v.determined is False
    assert v.reason, "a refusal with no reason cannot be acted on"


def test_a_dead_database_does_not_permit_direct():
    v = ap.engagement_requires_proxy(_db(fail_connect=True), engagement_id=EID)
    assert v.required is True


def test_an_absent_column_is_a_determined_no_not_an_unknown():
    """A database with no `engagements.require_proxy` cannot HOLD an opt-in, so
    no engagement can have made one. That is a proven negative -- distinct from
    a transient error, which is not."""
    v = ap.engagement_requires_proxy(
        _db(raise_on={_EXISTS: _Boom('column "require_proxy" does not exist',
                                     pgcode="42703")}),
        target="example-corp.com")
    assert v.verdict == ap.POLICY_NOT_REQUIRED and v.required is False


def test_the_schema_absent_sqlstates_are_the_real_ones():
    """The "feature not deployed" branch keys on SQLSTATE. A typo there turns
    a genuine schema gap into an `undetermined` that refuses every scan -- or,
    worse, turns a transient error into a permit."""
    errorcodes = pytest.importorskip("psycopg2.errorcodes")
    assert set(ap._SCHEMA_ABSENT_SQLSTATES) == {
        errorcodes.UNDEFINED_COLUMN, errorcodes.UNDEFINED_TABLE}


def test_a_blank_scope_target_is_not_a_wildcard():
    """A '' scope row matches everything; attributing every target to whichever
    engagement last had an empty scope would be worse than no attribution."""
    assert ap.engagement_for_target(_db({_SCOPE: (EID,)}), "") is None
    assert ap.engagement_for_target(_db({_SCOPE: (EID,)}), None) is None


def test_the_scope_lookup_excludes_blank_and_null_rows():
    """The SQL itself, not just the Python guard above."""
    captured = {}

    class _C(_Cur):
        def execute(self, sql, params=None):
            captured["sql"] = sql
            super().execute(sql, params)

    class _K(_Conn):
        def cursor(self): return _C(self.answers, self.raise_on)

    ap.engagement_for_target(lambda: _K({_SCOPE: (EID,)}), "host-a.example.com")
    sql = " ".join(captured["sql"].split())
    assert "engagement_id IS NOT NULL" in sql
    assert "btrim" in sql, "blank scope targets are not excluded"


# ── 2. the runner's chokepoint, executed ──────────────────────────────────
# osint_runner imports a service image's worth of dependencies, so the egress
# functions are lifted out of the real source by AST and executed against
# stubs. The code under test is the shipped code; only its neighbours are fake.

_LIFT = {"EgressOutcome", "_first_target", "_egress", "_refuse_egress",
         "_build_proxy_env"}


def _lift_egress(policy_available=True, audits=None, webhooks=None, db=None,
                 engagement_id=None):
    tree = ast.parse(OSINT_SRC)
    body = [n for n in tree.body
            if (isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in _LIFT)
            or (isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "EXECUTION_MODE_BLOCKED"
                        for t in n.targets))]
    missing = _LIFT - {getattr(n, "name", None) for n in body}
    assert not missing, f"osint_runner no longer defines {sorted(missing)}"

    from fastapi import HTTPException
    import logging
    from typing import NamedTuple, Optional
    from urllib.parse import urlparse

    ns = {
        "os": os, "logging": logging, "urlparse": urlparse,
        "NamedTuple": NamedTuple, "Optional": Optional,
        "HTTPException": HTTPException,
        "EGRESS_POLICY_AVAILABLE": policy_available,
        "_eng_requires_proxy": ap.engagement_requires_proxy,
        "_resolve_proxy": ap.resolve,
        "_attack_proxy_env": ap.proxy_env,
        "_POLICY_NOT_REQUIRED": ap.POLICY_NOT_REQUIRED,
        "conn": db or _db(),
        "_get_api_keys": lambda: {"SHODAN_API_KEY": "k"},
        "_request_engagement_id": lambda: engagement_id,
        "write_audit": lambda *a, **k: (audits if audits is not None else []).append((a, k)),
        "emit_webhook_event": lambda *a, **k: (webhooks if webhooks is not None else []).append((a, k)),
    }
    exec(compile(ast.Module(body=body, type_ignores=[]), str(OSINT), "exec"), ns)
    return ns


def test_default_behaviour_is_byte_for_byte_unchanged():
    """require_proxy=false everywhere -> the old env, including NO proxy vars
    when the caller supplied none. This is the regression that matters most:
    the control must be invisible until an operator turns it on."""
    ns = _lift_egress(db=_db({_EXISTS: (False,)}))
    env = ns["_build_proxy_env"](None, targets=["example-corp.com"])
    expected = dict(os.environ)
    expected["SHODAN_API_KEY"] = "k"
    assert env == expected
    for var in ("ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy"):
        assert var not in env or var in os.environ


def test_default_behaviour_still_honours_an_explicit_proxy():
    ns = _lift_egress(db=_db({_EXISTS: (False,)}))
    out = ns["_egress"]("socks5h://box:9050", targets=["example-corp.com"])
    assert out.execution_mode == "proxied"
    assert out.env["ALL_PROXY"] == "socks5h://box:9050"
    assert out.env["HTTPS_PROXY"] == "socks5h://box:9050"


def test_the_one_intentional_difference_is_socks5h():
    """Reusing the shared `proxy_env()` changes two things for a caller who
    supplied a proxy, and both are deliberate: the lowercase variants are set
    too (several of these tools read only those), and `socks5://` is upgraded
    to `socks5h://` so DNS resolves AT THE PROXY. Resolving the target's name
    locally and connecting remotely leaks exactly what this fix is about."""
    ns = _lift_egress(db=_db({_EXISTS: (False,)}))
    env = ns["_egress"]("socks5://box:9050", targets=["example-corp.com"]).env
    assert env["ALL_PROXY"] == "socks5h://box:9050"
    assert env["all_proxy"] == "socks5h://box:9050"


def test_a_required_engagement_with_no_node_is_refused():
    from fastapi import HTTPException
    audits, hooks = [], []
    ns = _lift_egress(audits=audits, webhooks=hooks,
                      db=_db({_EXISTS: (True,), _SCOPE: (EID,), _FLAG: (True,),
                              _NODES: []}))
    with pytest.raises(HTTPException) as ei:
        ns["_build_proxy_env"](None, targets=["example-corp.com"])
    assert ei.value.status_code == 400
    assert "fail-closed" in str(ei.value.detail)
    assert audits, "a refusal that is not recorded cannot be reviewed"
    (evt, tool, src, data), _ = audits[0]
    assert evt == "scan_blocked"
    assert data["execution_mode"] == ns["EXECUTION_MODE_BLOCKED"]
    assert data["execution_mode"] == "required_proxy_missing"
    assert data["proxy_reason"] and data["engagement_id"] == EID
    assert hooks and hooks[0][0][0] == "scan_blocked"


def test_a_required_engagement_with_a_node_is_proxied_and_said_so():
    ns = _lift_egress(db=_db({_EXISTS: (True,), _SCOPE: (EID,), _FLAG: (True,),
                              _NODES: [("rt_scan1", 10120, "203.0.113.9")]}))
    out = ns["_egress"](None, targets=["example-corp.com"])
    assert out.execution_mode == "proxied"
    assert out.proxy.startswith("socks5h://") and out.proxy.endswith(":10120")
    assert out.env["ALL_PROXY"] == out.proxy
    assert out.audit()["proxy"] == out.proxy
    assert out.audit()["proxy_policy"] == ap.POLICY_REQUIRED


def test_an_undetermined_policy_refuses_rather_than_scans():
    from fastapi import HTTPException
    ns = _lift_egress(db=_db(fail_connect=True))
    with pytest.raises(HTTPException) as ei:
        ns["_build_proxy_env"](None, targets=["example-corp.com"])
    assert ei.value.status_code == 400


def test_a_missing_policy_module_refuses_rather_than_scans():
    """`etl/` unmounted is 'could not read the policy', not 'no policy'."""
    from fastapi import HTTPException
    ns = _lift_egress(policy_available=False)
    with pytest.raises(HTTPException):
        ns["_build_proxy_env"](None, targets=["example-corp.com"])


def test_the_audit_never_calls_a_blocked_scan_local():
    ns = _lift_egress(db=_db({_EXISTS: (False,)}))
    local = ns["_egress"](None, targets=["example-corp.com"]).audit()
    assert local["execution_mode"] == "local"
    assert local["proxy"] is None and local["proxy_reason"]
    blocked = ns["EgressOutcome"](None, {}, ns["EXECUTION_MODE_BLOCKED"],
                                  "required", EID, "why").audit()
    assert blocked["execution_mode"] != "local"


def test_a_url_target_is_reduced_to_its_host():
    ns = _lift_egress()
    assert ns["_first_target"](["https://host-a.example.com/a?b=1"]) == "host-a.example.com"
    assert ns["_first_target"](["", "  ", "example-corp.com"]) == "example-corp.com"
    assert ns["_first_target"]([]) is None


# ── 3. structural guards ──────────────────────────────────────────────────

def test_the_chokepoint_delegates_to_the_policy():
    """Every tool this service spawns takes its environment from
    `_build_proxy_env`. If it builds one itself again, the fail-open hole is
    back at all ~25 call sites at once."""
    body = function_source(OSINT_SRC, "_build_proxy_env")
    assert body and calls(body, "_egress"), \
        "_build_proxy_env must delegate to _egress, not assemble the env itself"
    tree = ast.parse(body)
    assigned = {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign)
                for t in n.targets if isinstance(t, ast.Name)}
    assert not assigned, \
        f"_build_proxy_env builds local state again ({assigned}) instead of delegating"


def test_the_runner_does_not_keep_its_own_copy_of_the_policy():
    """The agreement rule: one definition, in etl/attack_proxy. A second read
    of `require_proxy` here is the divergence this test exists to prevent."""
    assert not defines(OSINT_SRC, "engagement_requires_proxy")
    assert not defines(OSINT_SRC, "_require_proxy")
    # A QUERY for it, not a mention of it: the refusal message names the column
    # so the operator knows which switch to flip, and that is not a second
    # implementation.
    import re
    _sql = re.compile(r"\bSELECT\b[\s\S]*\bFROM\b")
    sql_literals = [n.value for n in ast.walk(ast.parse(OSINT_SRC))
                    if isinstance(n, ast.Constant) and isinstance(n.value, str)
                    and "require_proxy" in n.value and _sql.search(n.value)]
    assert not sql_literals, \
        f"osint_runner reads the policy itself instead of asking the shared module: {sql_literals}"


_PROXY_FLAGS = {"--chrome-proxy", "--proxy", "-proxy", "-p", "--chrome-proxy="}


def _functions(tree):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield n


def _decision_names(fn):
    """Names bound from an `_egress(...)` call, and names rebound from one of
    those (`proxy, env = eg.proxy, eg.env` / `proxy = eg.proxy`)."""
    decided, rebound, first = set(), set(), None
    assigns = [n for n in ast.walk(fn) if isinstance(n, ast.Assign)]
    # Two passes: ast.walk is breadth-first, so the rebind can be visited
    # before the `_egress` call it derives from.
    for n in assigns:
        if any(getattr(c.func, "id", None) == "_egress"
               for c in ast.walk(n.value) if isinstance(c, ast.Call)):
            decided |= {t.id for t in ast.walk(n) if isinstance(t, ast.Name)
                        and isinstance(t.ctx, ast.Store)}
            first = n.lineno if first is None else min(first, n.lineno)
    for n in assigns:
        if any(isinstance(v, ast.Attribute) and v.attr == "proxy"
               and getattr(v.value, "id", None) in decided
               for v in ast.walk(n.value)):
            rebound |= {t.id for t in ast.walk(n) if isinstance(t, ast.Name)
                        and isinstance(t.ctx, ast.Store)}
    return decided, rebound - decided, first


def _proxy_splices(fn):
    """(lineno, value-node) for every `[<proxy flag>, X]` built in this body."""
    out = []
    for n in ast.walk(fn):
        if not isinstance(n, ast.List) or len(n.elts) != 2:
            continue
        flag = n.elts[0]
        if isinstance(flag, ast.Constant) and flag.value in _PROXY_FLAGS:
            out.append((n.lineno, n.elts[1]))
    return out


def test_a_command_never_carries_the_callers_proxy_past_the_policy():
    """chromium ignores ALL_PROXY, and so do several of these tools' own
    `-proxy` flags. A decision that reaches only the ENVIRONMENT screenshots
    every URL from this host's own address while the audit row claims a proxy,
    so every function that consults the policy must splice the DECISION into
    its command, never the value the caller passed."""
    tree = ast.parse(OSINT_SRC)
    checked, offenders = [], []
    for fn in _functions(tree):
        decided, rebound, first = _decision_names(fn)
        if not decided:
            continue
        splices = _proxy_splices(fn)
        if not splices:
            continue
        checked.append(fn.name)
        for lineno, val in splices:
            name = (getattr(val, "id", None)
                    or (getattr(val.value, "id", None)
                        if isinstance(val, ast.Attribute) and val.attr == "proxy" else None))
            if name not in (decided | rebound) or lineno < (first or 0):
                offenders.append(f"{fn.name}:{lineno} splices {ast.dump(val)[:60]}")
    assert checked, "no function both consults the policy and builds a proxy flag — re-check this guard"
    assert set(checked) >= {"run_subfinder", "_run_gowitness_job",
                            "_run_passive_recon", "_run_recon_pipeline"}, checked
    assert not offenders, "\n".join(offenders)


def test_every_subprocess_env_comes_from_the_chokepoint():
    """A tool spawned with `env=` built anywhere else bypasses the policy."""
    tree = ast.parse(OSINT_SRC)
    offenders = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        fn = getattr(n.func, "attr", None)
        if fn not in ("run", "Popen", "check_output"):
            continue
        for kw in n.keywords:
            if kw.arg != "env":
                continue
            v = kw.value
            ok = (isinstance(v, ast.Call)
                  and getattr(v.func, "id", None) == "_build_proxy_env")
            ok = ok or isinstance(v, (ast.Name, ast.Attribute))
            if not ok:
                offenders.append(n.lineno)
    assert not offenders, \
        f"subprocess env built inline, bypassing _build_proxy_env, at lines {offenders}"


def test_the_refusal_always_raises():
    """`_refuse_egress` returning instead of raising would let `_egress` fall
    through and hand back an env with no proxy in it."""
    body = function_source(OSINT_SRC, "_refuse_egress")
    tree = ast.parse(body)
    fn = tree.body[0]
    assert isinstance(fn.body[-1], ast.Raise), \
        "_refuse_egress must end in a raise — a return here is a silent direct scan"
    assert not [n for n in ast.walk(fn) if isinstance(n, ast.Return)]


def test_the_opsec_console_flags_local_as_a_warning():
    """A direct scan rendered in the same neutral grey as every other value is
    how a run of them went unnoticed."""
    tsx = (REPO / "dashboard" / "frontend" / "src" / "pages" / "OpSec.tsx")
    if not tsx.exists():                           # pragma: no cover
        pytest.skip("OpSec.tsx not present")
    src = tsx.read_text(encoding="utf-8")
    neutral = "text-muted-foreground"
    # find the style map and check what `local` maps to
    import re
    m = re.search(r"EXECUTION_MODE_STYLES[^{]*\{(.*?)\n\}", src, re.S)
    assert m, "the execution-mode style map is gone"
    entry = re.search(r"\blocal:\s*'([^']+)'", m.group(1))
    assert entry, "no style for execution_mode 'local'"
    assert neutral not in entry.group(1), \
        f"'local' still renders neutral ({entry.group(1)}) — it is a warning"
    assert re.search(r"\brequired_proxy_missing:\s*'([^']+)'", m.group(1)), \
        "a refused scan has no style of its own"
