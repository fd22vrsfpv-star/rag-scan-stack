"""The egress policy is NOT a second copy of the scope gate.

CLAUDE.md: "When gate logic must be duplicated ... add an agreement test
pinning both implementations to a shared case table." The OSINT egress fix
adds a control that *looks* like the scope gate -- it reads the engagement, it
refuses, it fails closed -- and the way that goes wrong is subtle: the proxy
policy starts being treated as *the* gate, the scope check is dropped as
redundant, and an out-of-scope target becomes reachable as long as a SOCKS node
happens to be online.

So this file pins the SEPARATION as hard as the agreement:

  * both answer "cannot determine" the same way (the shared case table below);
  * they answer DIFFERENT questions -- scope says WHETHER, proxy says HOW -- and
    neither module implements the other's;
  * `osint_runner` still carries the scope gate that
    `tests/test_dispatch_invariants.py` discovers, and the egress functions
    contain none of that test's scope markers, so removing the scope gate still
    fails the invariants test rather than being masked by the new control.

SABOTAGE CHECKS:
  * delete the `_scope_refusal_for_targets` call from the asnmap job ->
    test_the_scope_gate_is_still_there_and_still_separate
  * name the egress helper `_egress_scope_gate` ->
    test_the_egress_policy_does_not_masquerade_as_a_scope_gate

    pytest tests/test_osint_proxy_scope_agreement.py -q
"""
import ast
import importlib.util
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _ast_assert import calls, defines, function_source  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
OSINT = REPO / "osint_runner" / "osint_runner.py"
PROXY = REPO / "etl" / "attack_proxy.py"
SCOPE = REPO / "etl" / "scope_gate.py"

for p in (OSINT, PROXY, SCOPE):
    if not p.exists():                             # pragma: no cover
        pytest.skip(f"{p.name} not present", allow_module_level=True)

OSINT_SRC = OSINT.read_text(encoding="utf-8")


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


ap = _load(PROXY, "_ap_agree")
sg = _load(SCOPE, "_sg_agree")

try:
    import test_dispatch_invariants as di
except Exception as e:                             # pragma: no cover
    di = None
    _di_err = e


# ── 1. the shared case table: "cannot determine" ──────────────────────────
# One table, both gates. Each row is a way of NOT KNOWING; both must refuse.

def _dead_factory():
    def f():
        raise RuntimeError("could not connect to server")
    return f


CANNOT_DETERMINE = [
    ("no database at all", "dead"),
    ("no configuration readable", "empty"),
]


@pytest.mark.parametrize("label,kind", CANNOT_DETERMINE, ids=[c[0] for c in CANNOT_DETERMINE])
def test_both_gates_refuse_what_they_cannot_determine(label, kind):
    """The invariant both share. Verified WITHOUT a database, which is the
    failure mode -- `tests/test_dispatch_invariants.py` pins the same property
    on the scope gate, and this asserts the proxy policy has not been written
    with the opposite default."""
    # scope gate: refuses, returning an operator-facing string
    sg._ENFORCE_CACHE.update({"rows": None, "at": 0.0})
    refusal = sg.enforce_target_scope("203.0.113.5", dsn="")
    assert refusal and "refusing" in refusal.lower(), \
        f"scope gate permitted an undeterminable case ({label}): {refusal!r}"

    # proxy policy: refuses, as an UNDETERMINED verdict whose .required is True
    verdict = ap.engagement_requires_proxy(_dead_factory(), target="203.0.113.5")
    assert verdict.verdict == ap.POLICY_UNDETERMINED, verdict
    assert verdict.required is True, \
        f"proxy policy permitted an undeterminable case ({label}): {verdict}"


def test_neither_gate_has_a_two_outcome_api():
    """Three outcomes, never two. The scope gate returns a refusal STRING or
    None (so "no refusal" is the only permit); the proxy policy carries an
    explicit third verdict rather than a boolean."""
    assert {ap.POLICY_REQUIRED, ap.POLICY_NOT_REQUIRED, ap.POLICY_UNDETERMINED} == \
        {"required", "not_required", "undetermined"}
    v = ap.PolicyVerdict(ap.POLICY_UNDETERMINED, None, "x")
    assert v.required is True and v.determined is False


# ── 2. they answer different questions ────────────────────────────────────

def test_the_proxy_policy_does_not_decide_authorisation():
    """A proxy being available must never make an out-of-scope target
    reachable, so the proxy module must not read scope at all for its verdict.
    (`engagement_for_target` reads scope_targets for ATTRIBUTION -- which
    engagement owns this host -- and returns an id, never a permission.)"""
    psrc = PROXY.read_text(encoding="utf-8")
    assert not defines(psrc, "check_targets_file")
    assert not defines(psrc, "enforce_target_scope")
    assert not defines(psrc, "load_dispatch_scope")
    body = function_source(psrc, "engagement_requires_proxy")
    assert body and "scope" not in body.lower().split("def ")[0], \
        "the verdict itself must not be derived from scope"
    # the attribution helper returns an id, not a boolean
    helper = function_source(psrc, "engagement_for_target")
    returns = [n for n in ast.walk(ast.parse(helper)) if isinstance(n, ast.Return)]
    assert returns and not any(
        isinstance(r.value, ast.Constant) and r.value.value is True for r in returns), \
        "engagement_for_target must never return a permission"


def test_the_scope_gate_does_not_decide_egress():
    ssrc = SCOPE.read_text(encoding="utf-8")
    assert not defines(ssrc, "engagement_requires_proxy")
    assert "socks5h://" not in ssrc, \
        "the scope gate has grown a proxy opinion — one definition, in attack_proxy"


# ── 3. osint_runner keeps BOTH, and they stay distinguishable ─────────────

def test_the_scope_gate_is_still_there_and_still_separate():
    """The egress fix must not have been mistaken for the gate and replaced
    it. `_scope_refusal_for_targets` is what `tests/test_dispatch_invariants.py`
    discovers for this module."""
    assert defines(OSINT_SRC, "_scope_refusal_for_targets")
    # BOTH wirings: the in-process call (the asnmap job gates its own targets
    # file) and the hand-off to the shared runner, which gates every tool job.
    # Counting only one lets the other be deleted silently.
    tree = ast.parse(OSINT_SRC)
    refs = [n for n in ast.walk(tree) if isinstance(n, ast.Name)
            and n.id == "_scope_refusal_for_targets" and isinstance(n.ctx, ast.Load)]
    direct = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
              and getattr(n.func, "id", None) == "_scope_refusal_for_targets"]
    handoff = [kw for n in ast.walk(tree) if isinstance(n, ast.Call)
               for kw in n.keywords
               if getattr(kw.value, "id", None) == "_scope_refusal_for_targets"]
    assert direct, "the scope gate is defined but never called in-process"
    assert handoff, "the scope gate is no longer handed to the shared tool runner"
    assert len(refs) >= 2, refs


def test_the_egress_policy_does_not_masquerade_as_a_scope_gate():
    """If the egress helpers carried the invariants test's scope markers, that
    test would report this module as gated even after the real gate was
    deleted. The markers are its only evidence."""
    if di is None:                                 # pragma: no cover
        pytest.skip(f"test_dispatch_invariants not importable: {_di_err}")
    for fname in ("_egress", "_refuse_egress", "_build_proxy_env"):
        body = function_source(OSINT_SRC, fname)
        assert body, f"{fname} is gone"
        hits = [m for m in di._SCOPE_MARKERS if m in body]
        assert not hits, (
            f"{fname} contains scope marker(s) {hits}; the dispatch-invariants "
            f"ratchet would then count the PROXY policy as the scope gate")


def test_osint_runner_is_not_in_the_scope_debt_list():
    """It is gated today. The egress change must not have pushed it back into
    debt, and a reader of either list must not have to guess which control a
    line refers to."""
    if di is None:                                 # pragma: no cover
        pytest.skip(f"test_dispatch_invariants not importable: {_di_err}")
    assert "osint_runner/osint_runner.py" not in di.SCOPE_DEBT
    for rel, why in list(di.SCOPE_DEBT.items()) + list(di.LIMIT_DEBT.items()):
        assert "proxy" not in why.lower() or "scope" not in why.lower(), (
            f"{rel}: a debt reason that mixes the scope gate and the proxy "
            f"policy makes the two controls indistinguishable: {why}")


def test_the_runner_imports_the_shared_policy_and_defines_none():
    """One implementation. A local copy is the thing this file exists to stop."""
    tree = ast.parse(OSINT_SRC)
    imported = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and (n.module or "").endswith("attack_proxy"):
            imported |= {a.name for a in n.names}
    assert "engagement_requires_proxy" in imported, \
        "osint_runner must ask etl.attack_proxy, not implement the policy"
    assert "resolve" in imported and "proxy_env" in imported
    assert not defines(OSINT_SRC, "engagement_requires_proxy")
