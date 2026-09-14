"""A credential check's reported count must agree with the stored findings.

Run on demand:

    pytest tests/test_credential_reconciliation.py -v

WHY THIS EXISTS
---------------
A live run (msf_sept14-1524 against 192.168.1.150) reported "11 valid" credentials
while only 8 landed in credential_findings, and nothing flagged the gap. The cause
was NOT lost data — it was an OVER-COUNT: cred_checker counted raw hydra/nmap
success LINES (hydra prints an extra "login: <user>" line for an anonymous login;
nmap re-reported), while the store dedups on (ip, port, username, auth_type). So
the headline count (11) disagreed with the findings (8).

Three things now hold and are pinned here:
  * _dedup_valid_results collapses duplicate success rows to DISTINCT credentials
    (by username, keeping the row that carries a password) so the summary, the
    emitted valid_credentials, and the stored rows all agree.
  * the credential-check handler reconciles distinct-sent vs stored and emits a
    credential_count_mismatch webhook when they diverge (the safety net for a
    REAL loss, which an over-count fix would otherwise hide).
  * the scan status summary carries valid_credentials, so a completed cred check
    that found logins no longer reads as an empty/failed scan.

SABOTAGE PROOF
--------------
* Make _dedup_valid_results `return results` unchanged and
  test_dedup_collapses_duplicate_usernames fails.
* Delete the credential_count_mismatch emit and
  test_handler_reconciles_and_flags fails.
"""
import ast
import os
import types

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CRED = os.path.join(REPO, "nmap_scanner", "cred_checker.py")
NMAP_API = os.path.join(REPO, "nmap_scanner", "nmap-api.py")
SCAN_TOOLS = os.path.join(REPO, "autogen_agents", "scan_tools.py")


def _load_func(path, name, extra_globals=None):
    """Exec a single top-level function in isolation (its body must be
    dependency-light) so the heavy module need not import."""
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            mod = ast.Module(body=[node], type_ignores=[])
            ns = dict(extra_globals or {})
            exec(compile(mod, path, "exec"), ns)
            return ns[name]
    pytest.fail(f"{name} not found in {os.path.basename(path)} — guard is stale")


def _cred(username, password):
    return types.SimpleNamespace(username=username, password=password,
                                 method="hydra", details=None)


def test_dedup_collapses_duplicate_usernames():
    from typing import Any, Dict, List
    dedup = _load_func(CRED, "_dedup_valid_results",
                       {"Any": Any, "Dict": Dict, "List": List})
    # the live port-21 shape: anonymous printed twice (empty pw, then real pw)
    rows = [_cred("anonymous", ""), _cred("anonymous", "anonymous@"),
            _cred("ftp", "ftp"), _cred("msfadmin", "msfadmin")]
    out = dedup(rows)
    users = [r.username for r in out]
    assert users == ["anonymous", "ftp", "msfadmin"], (
        f"duplicate usernames must collapse to distinct creds; got {users}")
    # the kept anonymous row must be the one that carries a password
    anon = next(r for r in out if r.username == "anonymous")
    assert anon.password == "anonymous@", (
        "when a username is duplicated, keep the row with the real password")
    # a genuinely distinct set is left untouched
    assert len(dedup([_cred("msfadmin", "x"), _cred("user", "y")])) == 2


def test_handler_reconciles_and_flags():
    src = open(NMAP_API, encoding="utf-8").read()
    assert "reconciliation" in src, (
        "the credential-check handler must reconcile reported vs stored counts")
    assert "credential_count_mismatch" in src, (
        "a divergence between the output count and the stored findings must emit "
        "a credential_count_mismatch webhook — silently passing it is the bug")


def test_scan_summary_carries_credential_count():
    src = open(SCAN_TOOLS, encoding="utf-8").read()
    assert "valid_credentials" in src and "total_valid_credentials" in src, (
        "get_session_scan_status must put the credential count in a cred check's "
        "result_summary, or a completed check that found logins reads as empty.")
