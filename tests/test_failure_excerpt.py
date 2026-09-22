"""A failed credential attempt must produce a DISTINGUISHING excerpt.

WHY THIS EXISTS
---------------
The open item said "most services never produce a usable failure signature" and
blamed the output being discarded. That was misstated — the output IS kept
(`cred_checker._classify_hydra_failure` returned `output.strip()[:180]`). The
real defect was WHICH 180 characters: the first ones, which for hydra are its
constant banner —

    Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - for legal purposes only

— about 205 characters. So every `unknown` failure yielded the same excerpt,
hashed to the same `failure_signature`, and the learner could not tell a telnet
refusal from a mysql one. Two of the three fallbacks returned `None` outright,
which is worse: `"attempt failed: auth_failed"` is identical across every
service.

`_failure_excerpt` now reuses `etl.tool_learning.salient_lines`, which picks
diagnostic lines, normalises IPs/ports so the same failure hashes stably across
hosts, and redacts `login:`/`password:` pairs.

Sabotage: return `output.strip()[:180]` again -> the banner test fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CRED = os.path.join(REPO, "nmap_scanner", "cred_checker.py")

BANNER = ("Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - for legal "
          "purposes only. Hydra starting at 2026-09-21 22:00:00")


def _excerpt_fn():
    """Load `_failure_excerpt` alone — cred_checker imports heavy deps at module
    scope, and this function's whole contract is pure text in, text out."""
    if not os.path.exists(CRED):
        pytest.skip("cred_checker.py not present")
    tl = pytest.importorskip("etl.tool_learning")
    src = open(CRED, encoding="utf-8").read()
    fn = next((n for n in ast.parse(src).body
               if isinstance(n, ast.FunctionDef) and n.name == "_failure_excerpt"), None)
    assert fn, "_failure_excerpt not found — the excerpt is unguarded again"
    ns = {"logger": type("L", (), {"debug": staticmethod(lambda *a, **k: None)})(),
          "_tool_learning": lambda: tl}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<x>", "exec"), ns)
    return ns["_failure_excerpt"]


def test_the_banner_does_not_become_the_signature():
    """The defect, directly: the first 180 chars of hydra output are boilerplate."""
    f = _excerpt_fn()
    got = f(BANNER + "\n[ERROR] could not connect to ssh://192.168.1.150:22 - kex error")
    assert "could not connect" in got, (
        f"the excerpt is the banner again, not the diagnostic line: {got!r}")
    assert "van Hauser" not in got, f"banner leaked into the excerpt: {got!r}"


def test_different_services_produce_different_excerpts():
    """The whole point: the learner has to tell telnet from mysql."""
    f = _excerpt_fn()
    mysql = f(BANNER + "\n[ERROR] mysql: Access denied for user 'root'@'10.0.0.1'")
    telnet = f(BANNER + "\n[ERROR] telnet: Connection closed by foreign host")
    assert mysql != telnet, (
        "two different service failures still yield the same excerpt, so they "
        f"hash to the same failure_signature: {mysql!r}")


def test_the_same_failure_on_two_hosts_hashes_the_same():
    """Normalisation is what makes support accumulate instead of fragmenting."""
    f = _excerpt_fn()
    a = f("[ERROR] could not connect to ssh://192.168.1.150:22 - kex error")
    b = f("[ERROR] could not connect to ssh://10.20.30.40:2222 - kex error")
    assert a == b, f"the same failure on two hosts produced different excerpts: {a!r} vs {b!r}"


def test_a_credential_line_is_redacted():
    """A raw hydra line can echo the pair that was tried."""
    f = _excerpt_fn()
    got = f("[22][ssh] host: 192.168.1.150   login: msfadmin   password: hunter2")
    assert "hunter2" not in got, f"the password survived into the excerpt: {got!r}"


def test_an_empty_run_yields_no_excerpt():
    """"Said nothing" must not become a signature shared by every silent failure."""
    assert _excerpt_fn()("") == ""


def test_every_classifier_return_carries_an_excerpt():
    """Two fallbacks used to return None, so `auth_failed` was identical across
    telnet, mysql, postgres and vnc — the item's actual complaint."""
    src = open(CRED, encoding="utf-8").read()
    fn = next((n for n in ast.parse(src).body
               if isinstance(n, ast.FunctionDef) and n.name == "_classify_hydra_failure"), None)
    assert fn, "_classify_hydra_failure not found"
    bad = []
    for n in ast.walk(fn):
        if not (isinstance(n, ast.Return) and isinstance(n.value, ast.Tuple)
                and len(n.value.elts) == 2):
            continue
        second = n.value.elts[1]
        # Accept: a call to _failure_excerpt, or a literal line pulled from the
        # output (the kex/connection branches already select the RIGHT line).
        # Reject: a bare None, and also `output[:180] if ... else None` — the
        # original slice wearing a conditional, which an "is it None" check
        # misses. That exact form was the bug.
        names = {x.id for x in ast.walk(second) if isinstance(x, ast.Name)}
        calls = {(getattr(c.func, "id", None) or getattr(c.func, "attr", None))
                 for c in ast.walk(second) if isinstance(c, ast.Call)}

        # GOOD: delegates to _failure_excerpt, or returns a line the branch
        # already SELECTED from the output (the kex/connection branches loop over
        # splitlines and pick the matching one — that is diagnostic by
        # construction), or an explanatory literal.
        ok = ("_failure_excerpt" in calls
              or "line" in names
              or (isinstance(second, ast.Constant) and isinstance(second.value, str)))

        # BAD: the whole raw output sliced — the original defect. Rejected whether
        # it is bare or wearing a conditional (`output[:180] if ... else None`),
        # because an "is it None" check misses the conditional form.
        # NOTE the order: `_failure_excerpt(output)` also mentions `output`, so
        # delegation has to win before the raw-slice rule is applied at all.
        if "_failure_excerpt" not in calls:
            if "output" in names:
                ok = False          # the whole raw output, sliced
            if isinstance(second, ast.Constant) and second.value is None:
                ok = False
        if not ok:
            bad.append(n.lineno)
    assert not bad, (
        f"these classifier returns carry no DISTINGUISHING excerpt (lines {bad}) — "
        "either a bare None, or the raw first-180-chars slice, so every service "
        "failing that way shares one signature")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
