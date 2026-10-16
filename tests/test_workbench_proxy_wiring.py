"""The workbench must RESOLVE a proxy before it dispatches, and the listener
must APPLY it.

`etl/attack_proxy.py` having the right policy is worth nothing if the dispatch
path does not call it. That was precisely the previous state: exploit-runner
enforced a proxy on every execute path while the Exploit Workbench posted
straight to `kali-listener /vectors/run` — a different service — and
`grep -c proxy kali_listener/listener_service.py` returned **0**.

Structural (`ast`), so it works on a bare checkout and fails by name when a
refactor moves the dispatch somewhere that skips the policy.

Sabotage check: delete the `_px_resolve` call and
`test_the_refine_loop_resolves_a_proxy` fails; drop `env=run_env` from the
listener's subprocess call and `test_the_listener_runs_under_the_proxy_env`
fails; count a refused command as a target run and
`test_a_refused_command_is_not_counted_as_a_target_run` fails.

    pytest tests/test_workbench_proxy_wiring.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
LISTENER = REPO / "kali_listener" / "listener_service.py"


def _tree(path):
    if not path.exists():
        pytest.skip(f"{path} not found")
    return ast.parse(path.read_text(encoding="utf-8"))


def _func(path, name):
    fn = next((n for n in ast.walk(_tree(path))
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == name), None)
    assert fn, f"{name} not found in {path.name}"
    return fn


def _refine_src():
    return ast.get_source_segment(API.read_text(encoding="utf-8"),
                                  _func(API, "_run_refine_poc")) or ""


# -- the workbench side ------------------------------------------------------

#: Dispatches to /vectors/run that do NOT target a remote host. Not debt --
#: they run a command against the listener itself (a loopback listener, a
#: `command -v` binary check), so there is nothing to proxy.
#: Keyed by a marker that must appear IN THE PAYLOAD, not by function name:
#: `_run_tool_validation` dispatches twice -- a local `command -v` check and a
#: real tool run at the target -- so a function-level exemption would wave
#: through the one that matters.
PROXY_LOCAL_ONLY = {
    "'127.0.0.1'": "a loopback listener inside the container; nothing to proxy",
    "command -v":  "a binary-existence check in the listener; never touches the target",
}

#: Whole-function exemptions, for a probe whose command is built into a
#: variable so no payload marker can see it. Guarded: a function listed here
#: must have exactly ONE dispatch, so it cannot also hide a target-bound one.
PROXY_LOCAL_ONLY_FUNCS = {
    "_runner_has_binaries": "`command -v` roll-call in the listener; never touches the target",
}

#: Target-bound dispatches that still carry NO proxy decision. Each would
#: egress from the listener's own address.
#:
#: Found 2026-10-16: this test's FIRST run found thirteen, after the live
#: `[proxy] UNDECIDED` line exposed the first. All were then routed through
#: `_listener_vectors_run`, so the list is empty — which is the point of a
#: ratchet. A NEW un-proxied site fails by name; nothing may be added here
#: without a stated reason in the commit.
PROXY_DISPATCH_DEBT: dict = {}


def _vectors_run_sites():
    """{enclosing function: [(line, payload)]} for every /vectors/run post."""
    tree = _tree(API)
    owner = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for n in ast.walk(fn):
                if hasattr(n, "lineno"):
                    owner.setdefault(n.lineno, fn.name)
    out = {}
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call) and call.args):
            continue
        if "/vectors/run" not in ast.unparse(call.args[0]):
            continue
        kw = {k.arg: k.value for k in call.keywords}
        payload = ast.unparse(kw["json"]) if "json" in kw else ""
        out.setdefault(owner.get(call.lineno, "?"), []).append((call.lineno, payload))
    return out


def test_every_vectors_run_dispatch_carries_a_proxy():
    """THE invariant. Not 'the refine loop is wired' — EVERY call site is.

    The first fix wired the refine loop inline and missed `_known_good_probe`,
    a second site posting to the same endpoint. Its nuclei probe egressed from
    the listener's own address while the refine loop beside it was proxied;
    the live `[proxy] UNDECIDED` line caught it on 2026-10-16. A guard naming
    the two known sites would pass again the next time a third appeared, so
    this one finds them by what they DO — and found thirteen more.
    """
    offenders = []
    for fn, calls in _vectors_run_sites().items():
        if fn in PROXY_DISPATCH_DEBT or fn in PROXY_LOCAL_ONLY_FUNCS:
            continue
        for line, payload in calls:
            if "_vectors_run_payload" in payload or "proxy_url" in payload:
                continue
            if any(m in payload for m in PROXY_LOCAL_ONLY):
                continue
            offenders.append(f"{fn}:{line}")
    assert not offenders, (
        "these /vectors/run dispatches carry no proxy decision, so the listener "
        f"reports them UNDECIDED and they egress from its own address: "
        f"{offenders}. Route them through `_attack_proxy_for` + "
        "`_vectors_run_payload`, or declare them in PROXY_DISPATCH_DEBT with a "
        "reason.")


def test_the_local_only_markers_still_match_something():
    """A marker matching nothing is a stale exemption hiding a real site."""
    payloads = [p for calls in _vectors_run_sites().values() for _l, p in calls]
    unused = [m for m in PROXY_LOCAL_ONLY if not any(m in p for p in payloads)]
    assert not unused, (
        f"these PROXY_LOCAL_ONLY markers match no dispatch any more: {unused}. "
        "Delete them — an exemption nobody uses will eventually exempt "
        "something nobody meant.")


def test_a_whole_function_exemption_hides_only_one_dispatch():
    """A function with two dispatches cannot be exempted wholesale.

    `_run_tool_validation` is exactly that case: a local `command -v` check
    beside a real tool run at the target. Exempting it by name would wave the
    second one through.
    """
    sites = _vectors_run_sites()
    for fn in PROXY_LOCAL_ONLY_FUNCS:
        calls = sites.get(fn) or []
        assert len(calls) == 1, (
            f"{fn} is exempted by name but has {len(calls)} dispatches — one of "
            "them may be target traffic. Use a payload marker instead.")


def test_the_debt_list_does_not_rot():
    """A fixed entry must be DELETED, or the list stops meaning anything."""
    sites = _vectors_run_sites()
    stale = []
    for fn in list(PROXY_DISPATCH_DEBT):
        calls = sites.get(fn)
        if not calls:
            stale.append(f"{fn} (no /vectors/run dispatch any more)")
        elif fn in PROXY_DISPATCH_DEBT and all(
                "_vectors_run_payload" in p or "proxy_url" in p for _l, p in calls):
            stale.append(f"{fn} (now proxied — delete it from the debt list)")
    assert not stale, f"stale declarations: {stale}"


def test_the_debt_list_only_shrinks():
    """Ratchet. Raising this number needs a stated reason in the commit."""
    assert len(PROXY_DISPATCH_DEBT) <= 0, (
        f"PROXY_DISPATCH_DEBT grew to {len(PROXY_DISPATCH_DEBT)} — a new "
        "un-proxied dispatch site was declared rather than wired")


def test_the_proxy_helper_is_the_only_resolver():
    """Both sites must use the shared helper, not a second inline copy."""
    tree = _tree(API)
    callers = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) \
                    and n.func.id == "_attack_proxy_for":
                callers.add(fn.name)
    for required in ("_run_refine_poc", "_known_good_probe"):
        assert required in callers, (
            f"{required} does not call _attack_proxy_for — it dispatches to the "
            "target without resolving a proxy")


def test_the_helper_refuses_rather_than_returning_a_bare_none():
    """(decision, refusal): a caller must be able to tell refusal from success."""
    fn = _func(API, "_attack_proxy_for")
    rets = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    assert rets, "_attack_proxy_for never returns"
    for r in rets:
        assert isinstance(r.value, ast.Tuple) and len(r.value.elts) == 2, (
            f"_attack_proxy_for returns a non-pair at line {r.lineno}; a caller "
            "cannot distinguish 'no proxy needed' from 'refused'")


def test_the_known_good_probe_skips_on_refusal():
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func(API, "_known_good_probe")) or ""
    i = src.find("_attack_proxy_for")
    assert i > 0, "the known-good probe does not resolve a proxy"
    tail = src[i:i + 500]
    assert "proxy refused" in tail, (
        "the known-good probe resolves a proxy but does not skip when it is "
        "refused — it would dispatch anyway")


def test_the_refine_loop_resolves_a_proxy():
    """It must CALL the resolver, not merely import or mention it."""
    fn = _func(API, "_run_refine_poc")
    called = {n.func.id for n in ast.walk(fn)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "_attack_proxy_for" in called, (
        "the refine loop never calls the proxy resolver, so build-PoC commands "
        "egress from the listener's own address while exploit-runner's "
        "sibling path is proxied")
    assert "_vectors_run_payload" in called, (
        "the dispatch payload is hand-built, so a field can be forgotten")


def test_the_dispatch_carries_the_proxy():
    """The payload builder must carry the fields the listener keys on."""
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func(API, "_vectors_run_payload")) or ""
    for key in ("proxy_url", "proxy_label", "proxy_source", "proxy_decided"):
        assert key in src, (
            f"{key} is not in the /vectors/run payload — the listener cannot "
            "tell a caller that ran no policy from one that resolved 'direct'")


def test_a_refused_dispatch_sends_nothing():
    """A refusal must skip the POST, not send and then complain."""
    src = _refine_src()
    assert "_SkipDispatch" in src, "no skip path — a refused command still dispatches"
    fn = _func(API, "_run_refine_poc")
    raises = [n for n in ast.walk(fn) if isinstance(n, ast.Raise)
              and isinstance(n.exc, ast.Call)
              and isinstance(n.exc.func, ast.Name)
              and n.exc.func.id == "_SkipDispatch"]
    assert raises, "_SkipDispatch is referenced but never raised"


def test_a_refused_command_is_not_counted_as_a_target_run():
    """Counting it would inflate dispatch metrics with traffic that never left."""
    src = _refine_src()
    i = src.find('metrics["target_runs"] += 1')
    assert i > 0, "the target_runs counter is gone"
    guard = src[max(0, i - 260):i]
    assert "_px_err" in guard, (
        "target_runs is incremented unconditionally, so a command the proxy "
        "policy refused is counted as a run against the target")


def test_a_policy_error_refuses_rather_than_attacking_direct():
    """'Could not evaluate' is an unknown, never permission."""
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func(API, "_attack_proxy_for")) or ""
    i = src.find("proxy policy could not be evaluated")
    assert i > 0, (
        "an exception while evaluating the proxy policy does not produce a "
        "refusal — it would fall through and attack direct by default")


def test_the_decision_is_traced_either_way():
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func(API, "_attack_proxy_for")) or ""
    for phase in ("proxy_selected", "proxy_refused"):
        assert phase in src, (
            f"no `{phase}` trace row — an operator reading the run cannot see "
            "how it egressed")


# -- the listener side -------------------------------------------------------

def test_the_listener_accepts_a_proxy():
    cls = next((n for n in ast.walk(_tree(LISTENER))
                if isinstance(n, ast.ClassDef) and n.name == "VectorRunRequest"), None)
    assert cls, "VectorRunRequest not found"
    fields = {s.target.id for s in cls.body if isinstance(s, ast.AnnAssign)}
    for f in ("proxy_url", "proxy_decided"):
        assert f in fields, f"VectorRunRequest has no {f}"


def test_the_listener_runs_under_the_proxy_env():
    """The subprocess must get the proxy environment, or nothing is proxied."""
    fn = _func(LISTENER, "vectors_run")
    runs = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute) and n.func.attr == "run"]
    assert runs, "no subprocess.run in vectors_run"
    assert any(any(k.arg == "env" for k in r.keywords) for r in runs), (
        "subprocess.run is called without env=, so ALL_PROXY never reaches the "
        "command and every attack goes direct regardless of what was resolved")


def test_the_listener_reports_what_it_did():
    src = ast.get_source_segment(LISTENER.read_text(encoding="utf-8"),
                                 _func(LISTENER, "vectors_run")) or ""
    for marker in ("[proxy] DIRECT", "UNDECIDED"):
        assert marker in src, (
            f"{marker!r} missing — a caller that ran no policy is "
            "indistinguishable from one that resolved 'no proxy needed'")


def test_an_unapplied_proxy_refuses_rather_than_running_direct():
    """If the proxy cannot be applied, the command must not run anyway."""
    fn = _func(LISTENER, "vectors_run")
    src = ast.get_source_segment(LISTENER.read_text(encoding="utf-8"), fn) or ""
    i = src.find("proxy could not be applied")
    assert i > 0, (
        "a failure to apply the proxy does not refuse — the command would run "
        "direct under a line claiming it was proxied")
