"""An IP that belongs to an in-scope hostname's asset is in scope (and vice versa).

Run on demand:

    pytest tests/test_scope_gate_alias_resolution.py -v

WHY THIS EXISTS
---------------
The exploit runner dispatches by RESOLVED IP (e.g. 65.61.137.117) while a web-app
scope is defined by hostname/URL (demo.testfire.net). The shared dispatch gate
(enforce_target_scope) loaded scope rows but did NOT resolve the target's other
observed identities, so every approved web exploit fail-closed with
"target 65.61.137.117 is not in the configured scope". The alias machinery
already existed (load_host_aliases from the assets table, is_in_scope_with_aliases)
but this path never used it. enforce_target_scope now loads aliases and passes
them to check_dispatch.

FAIL-CLOSED still holds: aliases come from OBSERVED asset pairings, never live
DNS, and an IP with no in-scope alias is still refused.

SABOTAGE PROOF
--------------
Remove the `aliases` argument from enforce_target_scope's check_dispatch call
(or the load_host_aliases wiring) and test_enforce_wires_aliases fails.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATE = os.path.join(REPO, "etl", "scope_gate.py")

sg = pytest.importorskip("etl.scope_gate") if os.path.exists(GATE) else None


def _sg():
    if sg is None:
        pytest.skip("etl/scope_gate.py not importable")
    return sg


SCOPE = [("http://demo.testfire.net", "url")]  # hostname/URL-defined scope


def test_ip_matches_via_in_scope_hostname_alias():
    m = _sg()
    # The asset pairs this IP with the in-scope hostname → in scope.
    assert m.is_in_scope_with_aliases(
        "65.61.137.117", SCOPE,
        aliases={"65.61.137.117", "demo.testfire.net"}) is True


def test_hostname_matches_scope_directly():
    m = _sg()
    assert m.is_in_scope_with_aliases("demo.testfire.net", SCOPE) is True


def test_ip_with_no_in_scope_alias_is_refused():
    m = _sg()
    # Fail-closed: an IP whose only known identity is itself, not in scope.
    assert m.is_in_scope_with_aliases(
        "203.0.113.9", SCOPE, aliases={"203.0.113.9"}) is False
    # And with no aliases at all.
    assert m.is_in_scope_with_aliases("203.0.113.9", SCOPE) is False


def test_check_dispatch_allows_ip_with_in_scope_alias():
    m = _sg()
    refusal = m.check_dispatch(
        "65.61.137.117", SCOPE, command="msf exploit RHOSTS=65.61.137.117",
        aliases={"65.61.137.117", "demo.testfire.net"})
    assert refusal is None, refusal


def test_enforce_wires_aliases():
    """enforce_target_scope must load aliases and pass them to check_dispatch."""
    src = open(GATE, encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "enforce_target_scope"), None)
    assert fn is not None, "enforce_target_scope not found"
    body = ast.get_source_segment(src, fn)
    assert "load_host_aliases" in body, (
        "enforce_target_scope must resolve the target's observed identities via "
        "load_host_aliases, or an IP target never matches a hostname scope.")
    assert "check_dispatch(target, rows, command, aliases)" in body, (
        "enforce_target_scope must pass the resolved aliases to check_dispatch.")
