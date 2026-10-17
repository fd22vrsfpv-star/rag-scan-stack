"""Ingest writers must not hold one transaction across a whole batch.

The four-hour-transaction incident (see tests/test_db_transaction_hygiene.py)
was fixed in the live services. Two INGEST paths kept the same shape:

  * etl/parse_httpx.py  — one `conn.commit()` AFTER the record loop, and a
    blocking `socket.gethostbyname()` INSIDE it. gethostbyname goes through the
    C resolver, so it honours neither socket.setdefaulttimeout() nor any
    Postgres setting: a black-holed resolver blocks for tens of seconds per
    hostname while the transaction sits idle holding locks.
  * app/load_all.py — already autocommits per INSERT (since 90037788), but its
    connection carried no connect/lock/idle caps.

What is pinned here:

  1. Both connections carry connect_timeout + the idle-in-transaction and lock
     caps (same values as the reference, etl/access.py::_connect).
  2. parse_httpx resolves hostnames BEFORE opening the connection, and makes no
     resolver call inside the function at all. Per-record commits alone do NOT
     fix this: the lookup happens part-way through a record, after that record's
     statements have already opened the transaction.
  3. parse_httpx commits per RECORD, not per batch — proven by running the real
     parser against a fake connection, not by reading the source.

    docker run --rm -v "$PWD":/repo -w /repo python:3.12-slim sh -c \
      'pip install -q -r tests/requirements.txt; \
       PYTHONPATH=.:tests python -m pytest tests/test_ingest_transaction_hygiene.py -q'
"""
from __future__ import annotations

import ast
import json
import socket
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
HTTPX = REPO / "etl" / "parse_httpx.py"
LOAD_ALL = REPO / "app" / "load_all.py"

# etl/access.py::_connect — the reference every DB writer copies.
EXPECTED_OPTIONS = {
    "idle_in_transaction_session_timeout": "120000",
    "lock_timeout": "5000",
}

# Anything that performs a name lookup. None of these may appear inside
# parse_httpx(), which runs with a transaction open.
RESOLVER_CALLS = {
    "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
    "getaddrinfo", "getfqdn", "create_connection",
}


# ── AST helpers ─────────────────────────────────────────────────────────────

def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _callee(node: ast.AST) -> str | None:
    if not isinstance(node, ast.Call):
        return None
    f = node.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


def _connect_kwargs(path: Path) -> dict:
    """kwargs of the single psycopg2.connect() call in `path`."""
    found = []
    for node in ast.walk(_tree(path)):
        if _callee(node) == "connect":
            found.append(node)
    assert len(found) == 1, f"{path.name}: expected one connect() call, found {len(found)}"
    out = {}
    for kw in found[0].keywords:
        out[kw.arg] = kw.value.value if isinstance(kw.value, ast.Constant) else kw.value
    return out


def _parse_options(opts: str) -> dict:
    """`-c a=1 -c b=2` → {'a': '1', 'b': '2'}."""
    parts = str(opts).split()
    out = {}
    for flag, setting in zip(parts, parts[1:]):
        if flag == "-c" and "=" in setting:
            k, _, v = setting.partition("=")
            out[k] = v
    return out


def _function(path: Path, name: str) -> ast.FunctionDef:
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{path.name}: no function {name}()")


# ── 1. session caps on both connections ─────────────────────────────────────

@pytest.mark.parametrize("path", [HTTPX, LOAD_ALL], ids=["parse_httpx", "load_all"])
def test_connection_carries_session_caps(path):
    kw = _connect_kwargs(path)
    assert kw.get("connect_timeout"), f"{path.name}: connect() has no connect_timeout"
    assert isinstance(kw["connect_timeout"], int) and 0 < kw["connect_timeout"] <= 15
    opts = kw.get("options")
    assert isinstance(opts, str), f"{path.name}: connect() has no literal options=..."
    settings = _parse_options(opts)
    for setting, value in EXPECTED_OPTIONS.items():
        assert settings.get(setting) == value, (
            f"{path.name}: options is missing {setting}={value} (got {settings})")


# ── 2. no name lookup inside the transaction ────────────────────────────────

def test_parse_httpx_makes_no_resolver_call_inside_the_connection():
    fn = _function(HTTPX, "parse_httpx")
    offenders = sorted({
        c for c in (_callee(n) for n in ast.walk(fn)) if c in RESOLVER_CALLS
    })
    assert not offenders, (
        "parse_httpx() resolves names while a transaction is open: "
        f"{offenders}. Resolve in the pre-pass instead.")


def test_hostnames_are_resolved_before_the_connection_is_opened():
    """Statically: the prefetch call precedes the connect call in the body."""
    fn = _function(HTTPX, "parse_httpx")
    at = {}
    for n in ast.walk(fn):
        name = _callee(n)
        if name in ("_prefetch_host_ips", "connect"):
            at.setdefault(name, n.lineno)
    assert "_prefetch_host_ips" in at, "parse_httpx() no longer pre-resolves hostnames"
    assert "connect" in at, "parse_httpx() no longer opens a connection"
    assert at["_prefetch_host_ips"] < at["connect"], (
        f"the hostname pre-pass must precede connect(), got {at}")


# ── 3. one transaction per record, not per batch ────────────────────────────

def test_commit_is_inside_the_record_loop():
    fn = _function(HTTPX, "parse_httpx")
    loops = [n for n in ast.walk(fn)
             if isinstance(n, ast.For) and isinstance(n.target, ast.Name)
             and n.target.id == "rec"]
    assert loops, "parse_httpx() no longer has a `for rec in ...` loop"
    commits = [n for n in ast.walk(loops[0])
               if _callee(n) == "commit"]
    assert commits, ("parse_httpx() commits only after the record loop — one "
                     "transaction for the whole batch")


# ── 4. the same three properties, proven by RUNNING the parser ──────────────
#
# Real httpx -json output. Three records: one already-an-IP host (the lab
# target, nothing to resolve), two hostnames (one resolvable, one NXDOMAIN).

HTTPX_JSONL = [
    {"timestamp": "2026-10-17T09:14:02.117Z", "url": "http://172.18.0.32:80",
     "host": "172.18.0.32", "port": "80", "scheme": "http",
     "webserver": "Apache/2.2.8 (Ubuntu) DAV/2", "content_length": 891,
     "status_code": 200, "title": "Metasploitable2 - Linux",
     "tech": ["Apache HTTP Server:2.2.8", "Ubuntu"], "failed": False},
    {"timestamp": "2026-10-17T09:14:02.904Z", "url": "https://host-a.example.com",
     "host": "host-a.example.com", "port": "443", "scheme": "https",
     "webserver": "nginx", "content_length": 5126, "status_code": 200,
     "title": "Example Corp", "tech": ["Nginx:1.24.0", "HSTS"], "failed": False},
    {"timestamp": "2026-10-17T09:14:03.551Z", "url": "https://gone.legacy-corp.net",
     "host": "gone.legacy-corp.net", "port": "443", "scheme": "https",
     "failed": True},
]


class _FakeCursor:
    def __init__(self, log):
        self.log = log
        self._last = ""

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._last = str(sql)
        self.log.append(("sql", " ".join(self._last.split())[:60]))

    def fetchall(self):
        return []          # no scope rows configured → enforce=False

    def fetchone(self):
        # SELECT ... → asset not known yet; INSERT ... RETURNING id → new row.
        if "RETURNING id" in self._last:
            return {"id": "11111111-1111-1111-1111-111111111111"}
        return None


class _FakeConn:
    def __init__(self, log):
        self.log = log

    def cursor(self, **_kw):
        return _FakeCursor(self.log)

    def commit(self):
        self.log.append(("commit", ""))

    def close(self):
        self.log.append(("close", ""))


@pytest.fixture()
def run_parser(tmp_path, monkeypatch):
    """Run the real parse_httpx() against a fake connection; return (stats, log)."""
    parse_httpx = pytest.importorskip("etl.parse_httpx")

    path = tmp_path / "httpx.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in HTTPX_JSONL), encoding="utf-8")

    log: list = []

    def _fake_gethostbyname(host):
        log.append(("dns", host))
        if host.startswith("gone."):
            raise socket.gaierror(-2, "Name or service not known")
        return "198.51.100.17"

    def _fake_connect(dsn, **kwargs):
        log.append(("connect", kwargs))
        return _FakeConn(log)

    monkeypatch.setattr(socket, "gethostbyname", _fake_gethostbyname)
    monkeypatch.setattr(parse_httpx.psycopg2, "connect", _fake_connect)

    stats = parse_httpx.parse_httpx(str(path))
    return stats, log


def test_live_every_record_is_its_own_transaction(run_parser):
    stats, log = run_parser
    commits = [e for e in log if e[0] == "commit"]
    assert stats["records_seen"] == len(HTTPX_JSONL)
    assert stats["errors"] == 0, stats["error_examples"]
    assert len(commits) == len(HTTPX_JSONL), (
        f"expected one commit per record ({len(HTTPX_JSONL)}), got {len(commits)} "
        "— the batch is still one transaction")


def test_live_every_dns_lookup_happens_before_the_connection(run_parser):
    _stats, log = run_parser
    kinds = [e[0] for e in log]
    assert "dns" in kinds, "the hostname pre-pass did not run"
    connect_at = kinds.index("connect")
    last_dns = max(i for i, k in enumerate(kinds) if k == "dns")
    assert last_dns < connect_at, (
        "a name lookup ran after the connection was opened — a stalled resolver "
        "can hold the transaction open")


def test_live_connect_kwargs_are_the_capped_ones(run_parser):
    _stats, log = run_parser
    kwargs = next(e[1] for e in log if e[0] == "connect")
    assert kwargs.get("connect_timeout")
    assert _parse_options(kwargs.get("options", "")) == EXPECTED_OPTIONS


def test_live_unresolvable_host_falls_back_to_the_sentinel(run_parser):
    """Behaviour must be unchanged: NXDOMAIN still stores the 0.0.0.0 sentinel,
    and the record is still ingested."""
    stats, log = run_parser
    parse_httpx = pytest.importorskip("etl.parse_httpx")
    assert parse_httpx._prefetch_host_ips(HTTPX_JSONL) == {
        "host-a.example.com": "198.51.100.17",
        "gone.legacy-corp.net": parse_httpx.UNRESOLVED_IP,
    }, "an IP host must not be resolved; an NXDOMAIN host must get the sentinel"
    assert stats["findings_inserted"] == len(HTTPX_JSONL)
