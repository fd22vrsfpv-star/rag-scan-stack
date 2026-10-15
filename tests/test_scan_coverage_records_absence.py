"""A clean port scan must leave a record, and a FAILED one must not.

masscan reports open ports only. Of 268 IPs scanned on the redteam3 engagement,
44 had something listening and the other 224 produced no asset row, no port row
and no trace of any kind — indistinguishable from hosts nobody had ever pointed
a scanner at. So `/scope/reclassify`, which files a host as `no_services` only
when it can prove the host WAS scanned and answered nothing, found 1 candidate
out of 338 and correctly refused to move the rest.

`scope_coverage` is the record of the scan itself, which is what turns an empty
result into evidence of absence. Three things have to hold:

  1. A completed port scan records coverage for every target it was given —
     the quiet ones are the entire point.
  2. A FAILED scan records `failed`, never `completed`. A scan that could not
     run is not proof the host has nothing listening; conflating the two is how
     "unreachable" gets filed as "absent" (see Docs/Memories.md).
  3. The read side treats a coverage record as proof of scanning, not just the
     presence of port rows — port rows are the one proof a clean scan never
     produces.

Structural, by design: it reads source with `ast`, so it runs anywhere, with no
DB, no fastapi and no node_manager import (that module needs sliver-py, boto3
and a live DSN).

Sabotage check: change the failure-path call's status to "completed" and
`test_failed_scan_is_not_recorded_as_coverage` fails; delete either
`scope_coverage` read and `test_read_side_consults_coverage` fails by file name.

    pytest tests/test_scan_coverage_records_absence.py -q
"""

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
NODE_MANAGER = REPO / "node_manager" / "node_manager.py"
READERS = {
    "app/rag-api/api.py": "reclassify_engagement_scope",
    "app/rag-api/scope_classifier.py": None,   # module-level batch context
}


def _tree(path: Path) -> ast.Module:
    if not path.exists():
        pytest.skip(f"{path} not found")
    return ast.parse(path.read_text(encoding="utf-8"))


def _coverage_calls() -> list[ast.Call]:
    return [n for n in ast.walk(_tree(NODE_MANAGER))
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == "_record_scan_coverage"]


def _status_of(call: ast.Call) -> str | None:
    """Last positional arg is the status literal."""
    if call.args and isinstance(call.args[-1], ast.Constant):
        return call.args[-1].value
    for kw in call.keywords:
        if kw.arg == "status" and isinstance(kw.value, ast.Constant):
            return kw.value.value
    return None


def test_port_scan_types_include_masscan():
    for node in ast.walk(_tree(NODE_MANAGER)):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "PORT_SCAN_TYPES"
                for t in node.targets):
            types = ast.literal_eval(node.value)
            assert "masscan" in types, types
            assert "nmap" in types, types
            return
    pytest.fail("PORT_SCAN_TYPES not defined in node_manager.py")


def test_completed_scan_records_coverage():
    statuses = [_status_of(c) for c in _coverage_calls()]
    assert "completed" in statuses, (
        "no _record_scan_coverage(..., 'completed') call — a clean scan leaves "
        "no record, so every quiet host still looks unscanned")


def test_failed_scan_is_not_recorded_as_coverage():
    """The distinction the whole feature rests on."""
    calls = _coverage_calls()
    assert calls, "node_manager records no scan coverage at all"
    statuses = [_status_of(c) for c in calls]
    assert "failed" in statuses, (
        "the failure path records no outcome — a failed scan silently vanishes")
    assert all(s in ("completed", "failed", "running") for s in statuses), statuses

    # The call on the failure path must not claim 'completed'. Find it by
    # looking for a _record_scan_coverage call in the same block as the
    # scan_failed audit write.
    for node in ast.walk(_tree(NODE_MANAGER)):
        if not isinstance(node, (ast.If, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = list(ast.walk(node))
        audits_failure = any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == "write_audit" and n.args
            and isinstance(n.args[0], ast.Constant)
            and n.args[0].value == "scan_failed"
            for n in body)
        if not audits_failure or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        local = [n for n in body if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name)
                 and n.func.id == "_record_scan_coverage"]
        for c in local:
            assert _status_of(c) == "failed", (
                f"the failure path records status={_status_of(c)!r} — a scan "
                "that could not run is not proof the host has nothing listening")
        return
    pytest.fail("no scan_failed branch found to check")


@pytest.mark.parametrize("rel", sorted(READERS))
def test_read_side_consults_coverage(rel):
    """port_scanned must not depend solely on port rows existing."""
    src = (REPO / rel).read_text(encoding="utf-8") if (REPO / rel).exists() else None
    if src is None:
        pytest.skip(f"{rel} not found")
    tree = ast.parse(src)
    # A SELECT ... FROM scope_coverage somewhere in the file, as a real string
    # literal (not a comment, which `in src` would also match).
    found = any(
        isinstance(n, ast.Constant) and isinstance(n.value, str)
        and "scope_coverage" in n.value and "SELECT" in n.value.upper()
        for n in ast.walk(tree))
    assert found, (
        f"{rel} never reads scope_coverage — port_scanned falls back to "
        "'has port rows', which a clean scan never produces")


@pytest.mark.parametrize("rel", sorted(READERS))
def test_a_completed_scan_counts_as_having_been_probed(rel):
    """An asset row only exists when something was FOUND.

    The `probed` condition reads `has_asset`, which stood in for "did anyone
    look". For a host that was scanned and answered nothing there is no asset
    row at all, so `has_asset` said no while scope_coverage said yes — and the
    host was neither filed nor counted.

    Measured on redteam3 (2026-10-14): www.keys3.examplecorp.com,
    www.education.examplecorp.com and mail.hi.examplecorp.com each had coverage=1
    and asset_rows=0. None became a candidate, and each blocked its parent,
    which is how all 49 reclassify candidates stayed put through two fixes.
    """
    path = REPO / rel
    if not path.exists():
        pytest.skip(f"{rel} not found")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    # The coverage loop sets port_scanned; it must set has_asset too.
    for node in ast.walk(tree):
        if not isinstance(node, ast.For):
            continue
        body = ast.dump(node)
        if "port_scanned" not in body or "setdefault" not in body:
            continue
        assert "has_asset" in body, (
            f"{rel}: the coverage loop marks port_scanned without marking the "
            "host probed, so a scanned-but-empty host fails the `probed` "
            "condition and is never classified")
        # and it must be set TRUE, not defaulted False
        falses = [n for n in ast.walk(node)
                  if isinstance(n, ast.Constant) and n.value is False]
        trues = [n for n in ast.walk(node)
                 if isinstance(n, ast.Constant) and n.value is True]
        assert trues, (
            f"{rel}: has_asset is never set True in the coverage loop — a "
            "completed scan is the strongest evidence that someone looked")
        return
    pytest.fail(f"{rel}: no coverage loop found that sets port_scanned")


@pytest.mark.parametrize("rel", sorted(READERS))
def test_open_ports_follow_the_ip_not_the_hostname(rel):
    """A vhost on a listening IP has attack surface and must not be buried.

    masscan reports an IP, so its ports land on an IP-keyed asset row with a
    NULL hostname. Counting open ports on the hostname's OWN row alone showed 0
    for 1,044 scope hostnames whose IP was listening; 6 of 50 sampled
    reclassify candidates were in that set — each reachable with a Host header
    and about to be filed as "no attack surface".

    The self-join must also exclude the 0.0.0.0/:: sentinels, or every
    unresolved host inherits every other unresolved host's ports.
    """
    path = REPO / rel
    if not path.exists():
        pytest.skip(f"{rel} not found")
    sqls = [n.value for n in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and "FILTER (WHERE p.is_open)" in n.value]
    assert sqls, f"{rel} has no open-port state query to check"
    for sql in sqls:
        flat = " ".join(sql.split())
        assert re.search(r"\ba2\.ip\s*=\s*a\.ip\b", flat), (
            f"{rel}: open ports counted on the hostname's own asset row only — "
            "masscan's results live on the IP-keyed row")
        assert re.search(r"host\(a\.ip\)\s+NOT\s+IN", flat, re.I), (
            f"{rel}: the IP self-join does not exclude the unresolved "
            "sentinels, so every 0.0.0.0 host inherits every other one's ports")
