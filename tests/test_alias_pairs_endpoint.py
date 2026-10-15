"""The scope gate's alias source must answer inside its callers' timeouts.

Alias resolution is what lets the gate authorise a scan by IP of a host whose
scope entry is a hostname. Two callers built that map by fetching the FULL
asset list:

    nmap_scanner/nmap-api.py::_alias_map   GET /assets?limit=5000  timeout=20
    dashboard/bff/routers/scans.py::_host_aliases                  timeout=10

Measured from inside nmap_scanner on 2026-10-14:

    assets fetch: http=200 total=80.443648s size=1178332

80 seconds. Neither caller ever saw a response. `_alias_map` logged
`alias map fetch failed: ... Read timed out (read timeout=20)` and returned an
empty map; `_host_aliases` swallowed the ReadTimeout and returned `{host}`,
which is indistinguishable from "this host has no aliases". A proxied nmap of
122 in-scope IPs returned HTTP 500 with no job created.

`/assets/alias-pairs` returns the same ip<->hostname observations and nothing
else. Same database, same moment: 0.200s for 2,258 pairs.

This is the repo's recurring "unreachable is not absent" in its authorisation
path, so the guard checks the shape rather than the latency: no alias caller
may go back to the heavy endpoint, and the pairs query may not pair on the
`0.0.0.0` sentinel — every nameless asset carries it, so one bucket would alias
every unresolved host in the estate to every other, and an alias bucket widens
authorisation.

Structural (`ast`), so it runs with no database, no fastapi and no imports of
the modules under test. The live leg executes the endpoint when a stack is up
and SKIPS otherwise.

Sabotage check: point `_alias_map` back at `/assets` and
`test_alias_callers_do_not_fetch_the_full_asset_list` fails by caller name;
drop the sentinel filter and `test_pairs_query_excludes_the_sentinels` fails.

    pytest tests/test_alias_pairs_endpoint.py -q
"""

import ast
import os
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
CALLERS = {
    "nmap_scanner/nmap-api.py": "_alias_map",
    "dashboard/bff/routers/scans.py": "_host_aliases",
}
ROUTE = "/assets/alias-pairs"


def _tree(path: Path) -> ast.Module:
    if not path.exists():
        pytest.skip(f"{path} not found")
    return ast.parse(path.read_text(encoding="utf-8"))


def _func(tree: ast.Module, name: str):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _strings_in(node) -> list[str]:
    return [n.value for n in ast.walk(node)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def test_the_endpoint_is_declared():
    """A route decorator naming the path, not a comment mentioning it."""
    for node in ast.walk(_tree(API)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and dec.args \
                    and isinstance(dec.args[0], ast.Constant) \
                    and dec.args[0].value == ROUTE:
                return
    pytest.fail(f"no handler declares {ROUTE} — both alias callers now request it")


def test_declared_before_the_parameterised_assets_routes():
    """`/assets/{ip}/...` is three segments and this is two, so they cannot
    collide today — but a future `/assets/{something}` would shadow it, and
    FastAPI resolves in declaration order. Pin the order now."""
    tree = _tree(API)
    pairs_at = param_at = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not (isinstance(dec, ast.Call) and dec.args
                    and isinstance(dec.args[0], ast.Constant)):
                continue
            path = dec.args[0].value
            if not isinstance(path, str) or not path.startswith("/assets"):
                continue
            if path == ROUTE:
                pairs_at = dec.lineno if pairs_at is None else min(pairs_at, dec.lineno)
            elif re.match(r"^/assets/\{[^/]+\}$", path):
                param_at = dec.lineno if param_at is None else min(param_at, dec.lineno)
    if pairs_at is None:
        pytest.fail(f"{ROUTE} is not declared")
    if param_at is not None:
        assert pairs_at < param_at, (
            f"{ROUTE} is declared at line {pairs_at}, after a single-segment "
            f"/assets/{{param}} route at line {param_at} — the parameterised "
            "route matches first and the literal one becomes unreachable")


def test_pairs_query_excludes_the_sentinels():
    """0.0.0.0 is carried by every unresolved asset."""
    tree = _tree(API)
    fn = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if any(isinstance(d, ast.Call) and d.args
               and isinstance(d.args[0], ast.Constant) and d.args[0].value == ROUTE
               for d in node.decorator_list):
            fn = node
            break
    if fn is None:
        pytest.fail(f"{ROUTE} is not declared")
    sql = " ".join(" ".join(s.split()) for s in _strings_in(fn))
    assert re.search(r"host\(ip\)\s+NOT\s+IN", sql, re.I), (
        "the pairs query does not exclude the unresolved sentinel — every "
        "nameless asset shares 0.0.0.0, so one alias bucket would contain the "
        "whole estate and any member of it would authorise a scan of any other")
    assert "0.0.0.0" in sql, "the sentinel filter names no sentinel"


@pytest.mark.parametrize("rel", sorted(CALLERS))
def test_alias_callers_do_not_fetch_the_full_asset_list(rel):
    """The whole defect: an 80s fetch behind a 10-20s timeout."""
    path = REPO / rel
    fn = _func(_tree(path), CALLERS[rel])
    if fn is None:
        pytest.skip(f"{rel}: {CALLERS[rel]} not found")
    # A url built from a `/assets` literal, with a limit= keyword anywhere in
    # the same call. Comments and docstrings quoting the old URL are fine --
    # they are how the reason survives -- so only f-strings and call kwargs
    # count.
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        urls = []
        for a in list(node.args) + [k.value for k in node.keywords]:
            if isinstance(a, ast.JoinedStr):
                urls += [v.value for v in a.values
                         if isinstance(v, ast.Constant) and isinstance(v.value, str)]
        if not any(u.rstrip("/").endswith("/assets") for u in urls):
            continue
        kw = {k.arg for k in node.keywords}
        has_limit = "limit" in kw or any(
            isinstance(k.value, ast.Dict) and any(
                isinstance(d, ast.Constant) and d.value == "limit"
                for d in k.value.keys)
            for k in node.keywords)
        assert not has_limit, (
            f"{rel}:{node.lineno} {CALLERS[rel]}() fetches the full asset "
            f"list again. That endpoint takes 80s to build; this caller's "
            f"timeout is 10-20s, so the alias map comes back empty every "
            f"time and the scope gate runs with no aliases. Use {ROUTE}.")


@pytest.mark.parametrize("rel", sorted(CALLERS))
def test_alias_callers_request_the_pairs_endpoint(rel):
    path = REPO / rel
    fn = _func(_tree(path), CALLERS[rel])
    if fn is None:
        pytest.skip(f"{rel}: {CALLERS[rel]} not found")
    assert any(ROUTE in s for s in _strings_in(fn)), (
        f"{rel}: {CALLERS[rel]}() never requests {ROUTE}")


@pytest.mark.parametrize("rel", sorted(CALLERS))
def test_a_non_200_is_handled_as_a_failure_not_as_no_aliases(rel):
    """`httpx`/`requests` do not raise on 4xx/5xx.

    An alias source that answers 404 must not read as "this host has no
    aliases" — that is the same unreachable-reported-as-absent bug one layer
    down, and here it silently changes an authorisation decision.
    """
    path = REPO / rel
    fn = _func(_tree(path), CALLERS[rel])
    if fn is None:
        pytest.skip(f"{rel}: {CALLERS[rel]} not found")
    checks_status = any(
        isinstance(n, ast.Attribute) and n.attr == "status_code"
        for n in ast.walk(fn))
    assert checks_status, (
        f"{rel}: {CALLERS[rel]}() never reads status_code, so a 404 from the "
        "alias source is indistinguishable from an empty alias map")


def test_endpoint_executes_live():
    """Executes it. Skips when no stack is reachable."""
    base = os.environ.get("RAG_API_URL")
    key = os.environ.get("API_KEY") or os.environ.get("RAG_API_KEY")
    if not base:
        pytest.skip("RAG_API_URL not set — no live stack to query")
    requests = pytest.importorskip("requests")
    try:
        r = requests.get(f"{base.rstrip('/')}{ROUTE}",
                         headers={"x-api-key": key or ""}, timeout=30, verify=False)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"rag-api not reachable: {e}")
    assert r.status_code == 200, r.text[:300]
    body = r.json()
    assert isinstance(body.get("pairs"), list), body
    assert body.get("count") == len(body["pairs"])
    for pair in body["pairs"][:200]:
        assert len(pair) == 2, pair
        assert pair[0] not in ("0.0.0.0", "::"), (
            f"the sentinel reached the alias map: {pair}")
