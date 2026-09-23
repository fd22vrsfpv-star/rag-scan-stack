"""Passive scans: allowed without a proxy, but the leaky ones ASK first.

WHY THIS EXISTS
---------------
"Block local scans" used to be a binary: a hard-coded PASSIVE_TYPES set got a
silent pass, everything else got a flat 403. That was wrong in both directions.

* It disagreed with the frontend. `dashboard/frontend/src/lib/constants.ts`
  marks EIGHT further tools `passive: true` — amass, censys, gau, hashcat,
  passive-recon, trufflehog, vulnx-scope, waybackurls — so the launcher offered
  them as passive and the BFF answered 403. `passive-recon` itself was among
  them. This is the duplicated-logic case CLAUDE.md requires an agreement test
  for, and there wasn't one.

* "Passive" conflates two different things. `hashcat` sends nothing anywhere.
  `crtsh`, `gau`, `waybackurls`, `censys` and `uncover` never touch the TARGET
  but they do tell a third party which target you are interested in — and a
  proxy is precisely what hides who is asking. Granting those a silent pass is
  a disclosure decision made on the operator's behalf.

So there are now three classes: NO_EGRESS_TYPES run unconditionally,
THIRD_PARTY_PASSIVE_TYPES run with a proxy or with explicit consent
(HTTP 409 -> re-send with allow_local=true), everything else needs a proxy.

Static (ast) rather than import-based: dashboard/bff imports its own settings
module and is not importable outside its container.

SABOTAGE PROOF
--------------
* Drop "waybackurls" from THIRD_PARTY_PASSIVE_TYPES -> the agreement test fails
  by name.
* Make the passive branch `return` instead of raising 409 -> the consent test
  fails.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SCANS = os.path.join(REPO, "dashboard", "bff", "routers", "scans.py")
CONSTANTS = os.path.join(REPO, "dashboard", "frontend", "src", "lib", "constants.ts")


def _backend_sets():
    if not os.path.exists(SCANS):
        pytest.skip("scans.py not present")
    src = open(SCANS, encoding="utf-8").read()
    tree = ast.parse(src)
    out = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        for t in node.targets:
            name = getattr(t, "id", None)
            if name in ("NO_EGRESS_TYPES", "THIRD_PARTY_PASSIVE_TYPES"):
                out[name] = {e.value for e in ast.walk(node.value)
                             if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return out, src


def _frontend_passive():
    """Tool ids the launcher declares `passive: true`."""
    if not os.path.exists(CONSTANTS):
        pytest.skip("constants.ts not present")
    txt = open(CONSTANTS, encoding="utf-8").read()
    ids = set()
    for m in re.finditer(r"\{\s*id:\s*'([a-z0-9-]+)'(.*?)\}", txt, re.S):
        if "passive: true" in m.group(2):
            ids.add(m.group(1))
    return ids


def test_the_two_definitions_of_passive_agree():
    """Every tool the UI offers as passive must be classified by the BFF."""
    sets, _ = _backend_sets()
    assert sets.get("THIRD_PARTY_PASSIVE_TYPES"), "THIRD_PARTY_PASSIVE_TYPES is gone"
    backend = sets["THIRD_PARTY_PASSIVE_TYPES"] | sets.get("NO_EGRESS_TYPES", set())
    frontend = _frontend_passive()
    if not frontend:
        pytest.skip("could not parse any passive tools from constants.ts")
    missing = sorted(frontend - backend)
    assert not missing, (
        f"the launcher offers these as passive but the BFF does not classify them, "
        f"so launching one with 'block local scans' on returns a flat 403: {missing}")


def test_the_historical_url_tools_are_classified():
    """The specific tools that can be started from two places."""
    sets, _ = _backend_sets()
    passive = sets.get("THIRD_PARTY_PASSIVE_TYPES", set())
    for tool in ("gau", "waybackurls"):
        assert tool in passive, (
            f"{tool} queries a third-party archive and never touches the target; "
            f"it must be classified passive, not treated as an active scan")


def test_a_leaky_passive_scan_asks_rather_than_silently_running():
    """409 + needs_confirmation, not a silent pass."""
    _sets, src = _backend_sets()
    fn = None
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, ast.FunctionDef) and n.name == "_check_proxy_required":
            fn = ast.get_source_segment(src, n)
    assert fn, "_check_proxy_required not found"
    assert "needs_confirmation" in fn, (
        "the passive-without-proxy path does not ask for confirmation — it either "
        "runs silently or refuses, and the operator never gets the choice")
    assert "allow_local" in fn, "there is no way for the caller to answer the prompt"
    tree = ast.parse(fn.lstrip())
    codes = {n.args[0].value for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and (getattr(n.func, "id", None) == "HTTPException")
             and n.args and isinstance(n.args[0], ast.Constant)}
    assert 409 in codes, "no 409 (confirmation required) path"
    assert 403 in codes, "the hard refusal for ACTIVE scans is gone"

    # REACHABILITY, not just presence. `if True: return` above the raise leaves
    # every string and status code in the source while making the prompt dead --
    # that exact sabotage passed an earlier version of this test, which is how
    # a guard becomes decoration.
    for n in ast.walk(tree):
        if isinstance(n, ast.If) and isinstance(n.test, ast.Constant):
            pytest.fail(
                f"a constant `if {n.test.value}:` short-circuits _check_proxy_required "
                f"(line {n.lineno}) — the branch below it can never run")

    # the early-return that skips the prompt must be guarded BY the consent flag
    consent_guards = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.If)
        and any(isinstance(x, ast.Name) and x.id == "allow_local" for x in ast.walk(n.test))
    ]
    assert consent_guards, (
        "nothing branches on allow_local, so answering the prompt cannot change "
        "the outcome")


def test_no_egress_tools_never_need_a_proxy():
    """A proxy hides who is asking; with no egress there is nobody to hide from."""
    sets, _ = _backend_sets()
    assert "hashcat" in sets.get("NO_EGRESS_TYPES", set()), (
        "hashcat is local compute — it must not require a proxy or a prompt")


def test_consent_is_not_forwarded_to_the_runner():
    """allow_local answers a BFF prompt; it is not a scan parameter."""
    _sets, src = _backend_sets()
    assert "delattr(req, \"allow_local\")" in src or "allow_local = None" in src, (
        "allow_local is never consumed, so it rides ScanRequest's extra='allow' "
        "into the runner's request body as an unknown field")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
