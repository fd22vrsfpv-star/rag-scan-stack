"""Analysis must start on the quick discovery scans, not wait out the deep sweep.

Run on demand:

    pytest tests/test_early_analysis_on_quick_scans.py -v

WHY THIS EXISTS
---------------
The graph's scan node is non-blocking: it dispatches scans and returns, and a
background thread (_rerun_analysis_when_scans_finish) re-runs analysis once the
session's scans finish. It used to wait for ALL of them — including the full
1-65535 sweep, which routinely runs for an hour+ through a proxy/node. So a host
whose quick top-1000 scan had already found 25 open services sat un-analysed and
un-exploited until the deep sweep finished. The engine now runs an EARLY analysis
pass the moment the quick discovery scans are done, while the deep sweep keeps
running, then a FINAL pass when everything completes.

Two things must hold and are pinned here:
  * _is_deep_scan correctly separates the slow full-range sweep (type full_scan /
    deep_port_scan, or a 1-65535 / -p- port range) from the quick scans.
  * _rerun_analysis_when_scans_finish has an early-trigger branch that calls
    _run_analysis_pass when the deep sweep is still running but no quick scan is.

SABOTAGE PROOF
--------------
* Drop "full_scan" from _DEEP_SCAN_TYPES and test_is_deep_scan_classifies fails.
* Delete the early-trigger branch (the `not quick_pending` block) and
  test_early_analysis_branch_exists fails.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")


def _source():
    if not os.path.exists(ENGINE):
        pytest.skip("langgraph_engine.py not present")
    return open(ENGINE, encoding="utf-8").read()


def _load_is_deep_scan():
    """Exec just _DEEP_SCAN_TYPES + _is_deep_scan (pure, stdlib-only) so the
    classification can be exercised without importing the heavy engine module."""
    tree = ast.parse(_source())
    wanted = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "_DEEP_SCAN_TYPES"
                for t in node.targets):
            wanted["_DEEP_SCAN_TYPES"] = node
        if isinstance(node, ast.FunctionDef) and node.name == "_is_deep_scan":
            wanted["_is_deep_scan"] = node
    if "_DEEP_SCAN_TYPES" not in wanted or "_is_deep_scan" not in wanted:
        pytest.fail("_DEEP_SCAN_TYPES / _is_deep_scan not found — guard is stale")
    mod = ast.Module(body=[wanted["_DEEP_SCAN_TYPES"], wanted["_is_deep_scan"]],
                     type_ignores=[])
    ns = {}
    exec(compile(mod, ENGINE, "exec"), ns)  # noqa: S102 — repo-local source only
    return ns["_is_deep_scan"]


def test_is_deep_scan_classifies():
    is_deep = _load_is_deep_scan()
    # deep: the slow full-range sweep, by type or by port range
    assert is_deep({"type": "full_scan"})
    assert is_deep({"type": "deep_port_scan"})
    assert is_deep({"type": "nmap", "params": {"ports": "1-65535"}})
    assert is_deep({"type": "nmap", "params": {"ports": "-p-"}})
    # quick: the discovery scans analysis must NOT block on
    assert not is_deep({"type": "masscan", "params": {"ports": "<top-1000>"}})
    assert not is_deep({"type": "naabu"})
    assert not is_deep({"type": "nmap", "params": {"ports": "21,22,80,443"}})
    assert not is_deep({"type": "httpx"})


def test_early_analysis_branch_exists():
    """The rescan thread must run an early pass when the deep sweep is still
    running but the quick scans are done."""
    src = _source()
    m = re.search(
        r"def _rerun_analysis_when_scans_finish\(.*?\n(.*?)\ndef ", src, re.S)
    assert m, "_rerun_analysis_when_scans_finish not found — guard is stale"
    body = m.group(1)
    assert "_is_deep_scan" in body, (
        "the rescan wait loop must classify running scans with _is_deep_scan")
    assert re.search(r"not\s+quick_pending", body), (
        "there must be an early-trigger branch gated on the quick scans being "
        "done (`not quick_pending`) while a deep sweep still runs.")
    assert "_run_analysis_pass" in body, (
        "the early branch must call _run_analysis_pass to analyse the quick-scan "
        "results instead of waiting out the deep sweep.")
