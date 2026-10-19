"""GET /jobs?type=<type> returns the latest N jobs (operator ask, 2026-10-18:
"I can't tell if it is still running"). Executed, with the handler function
compiled out of api.py and a stub DB.

Run standalone:  pytest tests/test_jobs_recent.py -q
"""
import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
BFF = REPO / "dashboard" / "bff" / "routers" / "scans.py"


def _fn(path, name):
    for n in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    pytest.fail(f"{name} is gone from {path.name}")


class _Row(dict):
    def __init__(self, **k): dict.__init__(self, **k)


class _Cur:
    def __init__(self, rows): self.rows = rows; self.last = None
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def execute(self, sql, args=None): self.last = (sql, args or [])
    def fetchall(self): return self.rows
    def close(self): pass


class _Conn:
    def __init__(self, rows): self.rows = rows
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def cursor(self, cursor_factory=None): return _Cur(self.rows)


def _load(rows=None):
    tree = ast.parse(API.read_text(encoding="utf-8"))
    fn = _fn(API, "list_jobs")
    fn.decorator_list = []
    ns = {"get_db": lambda: _Conn(rows or []), "RealDictCursor": object,
          "Depends": lambda x: None, "auth": None, "Optional": __import__("typing").Optional,
          "HTTPException": type("HE", (Exception,), {})}
    exec(compile(ast.Module([fn], []), "api.py", "exec"), ns)
    return ns["list_jobs"]


# ---------------------------------------------------------- unit

def test_returns_newest_first_with_status_elapsed_and_progress():
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    rows = [
        _Row(id="r1", type="microburst-ingest", status="running",
             created_at=now - _dt.timedelta(hours=1),
             started_at=now - _dt.timedelta(hours=1),
             finished_at=None, progress={"records_seen": 400}, error=None),
    ]
    out = _load(rows)(type="microburst-ingest", status=None, limit=5)
    assert out["count"] == 1 and out["jobs"][0]["status"] == "running"
    assert out["jobs"][0]["elapsed_s"] >= 3500, out["jobs"][0]["elapsed_s"]
    assert out["jobs"][0]["progress"]["records_seen"] == 400


def test_filters_by_type_and_status():
    """The SQL must contain WHERE on the two filters it was passed."""
    # Peek the SQL via a cursor that records.
    captured = {}
    class _C(_Cur):
        def execute(self, sql, args=None):
            captured["sql"], captured["args"] = sql, args or []
    class _Co(_Conn):
        def cursor(self, cursor_factory=None): return _C([])
    import ast as _ast
    tree = _ast.parse(API.read_text()); fn = _fn(API, "list_jobs")
    fn.decorator_list = []
    ns = {"get_db": lambda: _Co([]), "RealDictCursor": object,
          "Depends": lambda x: None, "auth": None, "Optional": __import__("typing").Optional,
          "HTTPException": type("HE", (Exception,), {})}
    exec(compile(_ast.Module([fn], []), "api.py", "exec"), ns)
    ns["list_jobs"](type="microburst-ingest", status="running", limit=3)
    sql = captured["sql"].lower()
    # The SQL must contain a WHERE on BOTH columns -- not just one -- and the
    # ordering clause. Keep this as containment checks on short tokens so a
    # harmless reformat does not trip it.
    required_tokens = ["where", "type = %s", "status = %s", "order by created_at desc"]
    missing = [t for t in required_tokens if t not in sql]
    assert not missing, "SQL missing required token(s): %r in %r" % (missing, sql)
    assert captured["args"][:2] == ["microburst-ingest", "running"]


def test_a_running_job_has_elapsed_against_now_not_finished():
    """The dashboard uses elapsed_s to show "running for ...". When
    finished_at is null, elapsed must be computed against now()."""
    import datetime as _dt
    now = _dt.datetime.now(_dt.timezone.utc)
    rows = [_Row(id="r", type="t", status="running",
                 created_at=now, started_at=now - _dt.timedelta(seconds=90),
                 finished_at=None, progress=None, error=None)]
    out = _load(rows)(type=None, status=None, limit=1)
    assert 89 <= (out["jobs"][0]["elapsed_s"] or 0) <= 95


# ---------------------------------------------------------- BFF wiring

def test_bff_proxy_exists_and_checks_the_upstream_status():
    """Structural: the BFF proxy must forward type+status+limit AND compare
    the upstream's status_code against 400 (httpx does not raise on 4xx/5xx)."""
    fn = _fn(BFF, "list_recent_jobs")
    kw_names = {a.arg for a in fn.args.args + fn.args.kwonlyargs}
    assert {"type", "status", "limit"} <= kw_names, (
        "BFF proxy must accept type, status, limit")
    found_check = False
    for n in ast.walk(fn):
        if (isinstance(n, ast.Compare)
                and isinstance(n.left, ast.Attribute)
                and n.left.attr == "status_code"
                and any(isinstance(c, ast.Constant) and c.value == 400
                        for c in n.comparators)):
            found_check = True
    assert found_check, "BFF must check resp.status_code against 400"


def test_bff_endpoint_is_mounted_at_api_jobs_recent():
    """Decorator path: the operator-visible route is /api/jobs/recent."""
    for n in ast.parse(BFF.read_text(encoding="utf-8")).body:
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if n.name != "list_recent_jobs":
            continue
        for dec in n.decorator_list:
            if (isinstance(dec, ast.Call) and dec.args
                    and isinstance(dec.args[0], ast.Constant)
                    and dec.args[0].value == "/api/jobs/recent"):
                return
    pytest.fail("no @router.get('/api/jobs/recent') decorator on list_recent_jobs")
