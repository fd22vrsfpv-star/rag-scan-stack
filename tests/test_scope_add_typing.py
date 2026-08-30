"""A scope target added without an explicit type must still be enforceable.

Run on demand:

    pytest tests/test_scope_add_typing.py -v

WHY THIS EXISTS
---------------
`is_in_scope` (etl/scope_gate.py) matches on target_type: 'ip' exact, 'cidr'
network, 'domain'/'url' suffix, and IGNORES a row whose type it does not
recognise. `POST /scope/add` inserted `t.get("target_type")` verbatim, so a
caller sending only `{"target": "192.168.1.150"}` created a row with
target_type=NULL — present in the scope list, matched by NO branch, therefore
silently OUT of scope. A target you authorised was invisible to the dispatcher,
which is the worst direction for a scope bug to fail: it looks configured.

The insert also always used engagement_id IS NULL, so an engagement's target
went to the GLOBAL list only and the engagement-scoped gate never saw it.

These tests pin the classifier and the round-trip enforceability. The DB-backed
half skips cleanly without a database.
"""
import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"


def _infer():
    """Extract _infer_target_type without importing the whole API module."""
    if not API.exists():
        pytest.skip("app/rag-api/api.py not present")
    tree = ast.parse(API.read_text(encoding="utf-8"))
    fn = next((n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name == "_infer_target_type"), None)
    assert fn is not None, (
        "_infer_target_type was removed — /scope/add would insert NULL types "
        "again and the gate would silently drop them")
    ns = {}
    exec(compile(ast.Module([fn], []), "<f>", "exec"), ns)
    return ns["_infer_target_type"]


def test_bare_ip_is_typed_ip():
    f = _infer()
    assert f("192.168.1.150") == "ip"
    assert f("8.8.8.8") == "ip"
    assert f("2001:db8::1") == "ip"


def test_cidr_is_typed_cidr():
    f = _infer()
    assert f("10.0.0.0/8") == "cidr"
    assert f("192.168.1.0/24") == "cidr"


def test_hostname_is_typed_domain():
    f = _infer()
    assert f("example.com") == "domain"
    assert f("host.internal.lan") == "domain"


def test_never_returns_empty():
    """NULL/empty is the exact value the gate cannot match — never emit it."""
    f = _infer()
    for t in ("192.168.1.1", "x.com", "10/8", ""):
        assert f(t) in ("ip", "cidr", "domain")


def test_the_handler_infers_and_attaches_engagement():
    """Structural: the insert must use the inferred type and the engagement id,
    not the raw (possibly-NULL) type under a NULL engagement."""
    src = API.read_text(encoding="utf-8")
    i = src.index('@app.post("/scope/add"')
    body = src[i:src.index("\n@app.", i + 10)]
    assert "_infer_target_type" in body, "handler no longer infers a missing type"
    assert "_resolve_engagement_id" in body, "handler no longer attaches the engagement"
    assert "engagement_id) " in body or "engagement_id)\n" in body, (
        "the INSERT column list no longer includes engagement_id")


def test_typed_row_is_enforceable_end_to_end():
    """A round-trip through the REAL gate: an ip-typed row authorises that host
    and nothing else. Skips without a database."""
    psycopg2 = pytest.importorskip("psycopg2")
    import os, sys
    sys.path.insert(0, str(REPO))
    try:
        from etl.scope_gate import is_in_scope
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"etl.scope_gate not importable: {e}")
    # a NULL-typed row must NOT match; an ip-typed one must
    assert is_in_scope("192.168.1.150", [("192.168.1.150", "ip")]) is True
    assert is_in_scope("192.168.1.150", [("192.168.1.150", None)]) is False
    assert is_in_scope("8.8.8.8", [("192.168.1.150", "ip")]) is False
