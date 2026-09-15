"""execute_approved_exploit must send the RIGHT MSF module type.

Run on demand:

    pytest tests/test_msf_module_type.py -v

WHY THIS EXISTS
---------------
A live run dispatched every planner-queued MSF module with module_type defaulting
to "exploit". MSF rejects an auxiliary/post module sent as an exploit:

    MSF RPC error: Client provided module type 'exploit' did not match expected
    type for 'auxiliary/scanner/smb/smb_version'

so smb/ssh/ftp login-scanner modules (the bulk of what the planner queues) all
returned success=false, output=null. The type must be DERIVED from the module
name prefix (auxiliary/ -> auxiliary, post/ -> post, else exploit) unless the
caller set it explicitly.

SABOTAGE PROOF
--------------
Restore `params.get("module_type", "exploit")` in execute_approved_exploit and
test_module_type_is_derived_from_the_name fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SCAN_TOOLS = os.path.join(REPO, "autogen_agents", "scan_tools.py")


def _fn_src(name):
    if not os.path.exists(SCAN_TOOLS):
        pytest.skip("scan_tools.py not present")
    src = open(SCAN_TOOLS, encoding="utf-8").read()
    tree = ast.parse(src)
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == name), None)
    assert fn, f"{name} not found — guard is stale"
    return ast.get_source_segment(src, fn)


def test_module_type_is_derived_from_the_name():
    body = _fn_src("execute_approved_exploit")
    # must NOT blindly default the type to "exploit"
    assert 'params.get("module_type", "exploit")' not in body, (
        "module_type must be derived from the module name, not defaulted to "
        "'exploit' — that made MSF reject every auxiliary/post module")
    # must branch on the auxiliary/ (and post/) prefixes
    assert 'startswith("auxiliary/")' in body and '"auxiliary"' in body, (
        "auxiliary/ modules must dispatch with module_type='auxiliary'")
    assert 'startswith("post/")' in body and '"post"' in body, (
        "post/ modules must dispatch with module_type='post'")
    # an explicit caller-set type still wins
    assert 'params.get("module_type")' in body or 'params["module_type"]' in body, (
        "an explicitly-provided module_type must still be honored")


def test_module_name_still_falls_back_to_exploit_id():
    body = _fn_src("execute_approved_exploit")
    assert 'exploit["exploit_id"]' in body, (
        "the module name must fall back to exploit_id (where the planner stores "
        "the full module path)")
