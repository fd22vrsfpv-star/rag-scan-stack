"""nmap enrichment must refuse to touch a host outside the configured scope.

Run on demand:

    pytest tests/test_enrichment_scope_gate.py -v

WHY THIS EXISTS
---------------
`app/run_masscan_nmap.py` subprocesses `nmap -sV` at every host with an open
port ON RECORD — not at the targets of the job that invoked it. So a scan
dispatched for ONE host reaches every host in the database:

    start_nmap_scan(ip_address='3.225.93.164', ports='443')
      -> masscan 3.225.93.164        (one host, as asked)
      -> nmap enrichment             (349 hosts, none re-checked)

Every one of those 349 happened to be in scope, so no unauthorised traffic left.
"Happened to be" is not an authorisation control: the moment the ports table
holds a host the scope does not cover — an import, a narrowed scope, an older
engagement — it would be scanned silently, and the operator would have no way to
know from the job they started.

The scope check cannot live at the caller, because the caller's targets are not
what gets scanned. It has to live in the host selection, and it has to FAIL
CLOSED.

WHY IT IS NOT ENOUGH TO EXTEND test_dispatch_invariants
------------------------------------------------------
That guard reads source for evidence that a module consults the gate. It was
sabotage-tested here: deleting the filtering loop while leaving the imports and
the fail-closed branches in place STILL PASSED, because the keywords were all
still present. It proves a module knows about the gate, not that the gate
changes what gets scanned. This asserts the behaviour instead.

Sabotage proofs performed:
  * replaced the filter with `allowed = rows`   -> test_out_of_scope_hosts_are_dropped RED
  * returned rows when scope_rows is empty      -> test_empty_scope_refuses_everything RED
  * returned rows when the gate import failed   -> test_missing_gate_refuses_everything RED
"""
import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SRC = REPO / "app" / "run_masscan_nmap.py"


def _load(scope_rows, gate_ok=True, rows=None):
    """Exec get_open_ports_by_host() against fake DB + scope, no imports.

    The module imports psycopg2 at module scope and connects inside the
    function, so the function is extracted and given a namespace instead —
    which keeps this runnable on a bare checkout.
    """
    if not SRC.exists():
        pytest.skip("app/run_masscan_nmap.py not present")
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    fn = next((n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name == "get_open_ports_by_host"), None)
    assert fn is not None, (
        "get_open_ports_by_host was renamed or removed — this guard would pass "
        "vacuously, which is the failure mode it exists to prevent")

    rows = rows if rows is not None else [
        {"ip": "10.0.0.1", "ports": [443]},      # in scope
        {"ip": "10.0.0.2", "ports": [80]},       # in scope
        {"ip": "203.0.113.9", "ports": [22]},    # NOT in scope
    ]
    logged = {"error": [], "warning": [], "info": []}

    class _Cur:
        def execute(self, *a, **k): pass
        def fetchall(self): return list(rows)
        def __enter__(self): return self
        def __exit__(self, *a): return False

    class _Conn:
        def cursor(self, **k): return _Cur()
        def __enter__(self): return self
        def __exit__(self, *a): return False

    class _Log:
        def error(self, msg, *a): logged["error"].append(msg % a if a else msg)
        def warning(self, msg, *a): logged["warning"].append(msg % a if a else msg)
        def info(self, msg, *a): logged["info"].append(msg % a if a else msg)

    ns = {
        "psycopg2": type("m", (), {"connect": staticmethod(lambda dsn: _Conn())}),
        "RealDictCursor": object,
        "DB_DSN": "postgresql://x/y",
        "logger": _Log(),
        "_SCOPE_GATE_OK": gate_ok,
        "_SCOPE_GATE_ERROR": "" if gate_ok else "etl not mounted",
        "load_dispatch_scope": lambda cur: scope_rows,
        # in scope = the 10.0.0.0/8 fixture space
        "is_in_scope": lambda ip, sr: ip.startswith("10."),
    }
    exec(compile(ast.Module([fn], []), "<f>", "exec"), ns)
    return ns["get_open_ports_by_host"](), logged


def test_out_of_scope_hosts_are_dropped():
    """The whole point: a host outside the scope must not be enriched."""
    out, _ = _load(scope_rows=[{"target": "10.0.0.0/8"}])
    ips = [r["ip"] for r in out]
    assert "203.0.113.9" not in ips, (
        "an out-of-scope host survived the filter — enrichment would send "
        "nmap -sV at a host the engagement does not cover")
    assert ips == ["10.0.0.1", "10.0.0.2"]


def test_refused_hosts_are_named_in_the_log():
    """A host skipped for authorisation reasons must be visible, not silent."""
    _, logged = _load(scope_rows=[{"target": "10.0.0.0/8"}])
    assert any("203.0.113.9" in m for m in logged["warning"]), (
        f"the refused host was not named in any warning: {logged['warning']}")


def test_empty_scope_refuses_everything():
    """Fail closed. An unconfigured scope is a setup problem, not permission to
    scan every host on record."""
    out, logged = _load(scope_rows=[])
    assert out == [], "no scope configured, yet hosts were returned for scanning"
    assert logged["error"], "refusing to scan was not reported as an error"


def test_missing_gate_refuses_everything():
    """A missing etl/ bind-mount must not be indistinguishable from 'authorised'."""
    out, logged = _load(scope_rows=[{"target": "10.0.0.0/8"}], gate_ok=False)
    assert out == [], "the scope gate was unavailable, yet hosts were returned"
    assert any("scope gate unavailable" in m for m in logged["error"])


def test_in_scope_hosts_still_get_through():
    """Fail-closed must not mean fail-always — the feature has to still work."""
    out, _ = _load(scope_rows=[{"target": "10.0.0.0/8"}],
                   rows=[{"ip": "10.1.2.3", "ports": [443, 8443]}])
    assert [r["ip"] for r in out] == ["10.1.2.3"]
    assert out[0]["ports"] == [443, 8443]
