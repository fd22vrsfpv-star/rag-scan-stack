"""Structural guarantees about the REST surface.

Run on demand:

    pytest tests/test_route_contracts.py -v

WHY THIS EXISTS
---------------
There are ~1,150 distinct (method, path) endpoints across the services and about
11% are mentioned by any test. Writing a case per endpoint is not realistic;
catching the failure modes that recur is.

A parameterless smoke sweep over 173 BFF GET endpoints found four broken ones in
under two minutes:

  * /api/exploits/results/all — SELECT referenced pe.module_path, a column
    pending_exploits does not have. The approval flow read the same field, so an
    approved Metasploit module could never resolve its module path either.
  * /api/nodes/implants, /api/nodes/sessions — and six more — were UNREACHABLE:
    /api/nodes/{node_id} was declared first, so FastAPI matched it and passed
    "implants" where a uuid was expected.

Route shadowing is the one worth a permanent guard: it produces endpoints that
exist in the source, appear in the OpenAPI schema, and can never be called.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
BFF = os.path.join(REPO, "dashboard", "bff")

DECORATOR = re.compile(
    r'@(?:app|router)\.(get|post|put|patch|delete)\(\s*[\'"]([^\'"]+)[\'"]')


def _routes(path):
    out = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            m = DECORATOR.search(line)
            if m:
                out.append((i, m.group(1).upper(), m.group(2)))
    return out


def _router_files():
    files = []
    for dp, dn, fn in os.walk(BFF):
        dn[:] = [d for d in dn if d not in ("__pycache__", "node_modules")]
        files.extend(os.path.join(dp, f) for f in fn if f.endswith(".py"))
    return files


def _shadowed(routes):
    """Literal routes a same-shape dynamic route already claimed.

    FastAPI matches in declaration order, so a dynamic route declared FIRST wins
    for every path of the same depth — including literals meant to be distinct.
    """
    problems = []
    for i, meth, path in routes:
        if "{" not in path:
            continue
        depth = path.count("/")
        for j, meth2, path2 in routes:
            if j <= i or "{" in path2 or meth2 != meth:
                continue
            if path2.count("/") == depth and path2.startswith(path.split("{")[0]):
                problems.append(f"{meth2} {path2} (line {j}) is unreachable — "
                                f"{path} (line {i}) matches first")
    return problems


@pytest.mark.parametrize("path", sorted(_router_files()), ids=lambda p: os.path.basename(p))
def test_no_literal_route_is_shadowed_by_a_dynamic_one(path):
    """A shadowed route is dead code that still appears in the schema.

    It answers requests as the wrong handler — /api/nodes/implants arrived as
    node_id="implants" and returned 500 from a uuid cast, which reads as a
    backend fault rather than a routing mistake.
    """
    problems = _shadowed(_routes(path))
    assert not problems, (os.path.basename(path) + ":\n  " + "\n  ".join(problems))


def test_the_shadowing_detector_would_catch_a_planted_case(tmp_path):
    """Guards the guard: it has to fail on a known-bad ordering."""
    f = tmp_path / "r.py"
    f.write_text(
        '@router.get("/api/things/{thing_id}")\n'
        'def get_thing(thing_id): ...\n'
        '@router.get("/api/things/special")\n'
        'def special(): ...\n')
    problems = _shadowed(_routes(str(f)))
    assert problems and "special" in problems[0], f"detector missed it: {problems}"


def test_detector_allows_the_correct_ordering(tmp_path):
    """And must NOT fire when the literal comes first."""
    f = tmp_path / "ok.py"
    f.write_text(
        '@router.get("/api/things/special")\n'
        'def special(): ...\n'
        '@router.get("/api/things/{thing_id}")\n'
        'def get_thing(thing_id): ...\n')
    assert _shadowed(_routes(str(f))) == []


def test_endpoint_count_is_reported_not_asserted():
    """Records the size of the surface so the coverage gap stays visible.

    Deliberately not a threshold: an arbitrary number would either block honest
    growth or pass while coverage rotted. The point is that ~1,150 endpoints
    exist and a smoke sweep is the only realistic way to touch them all.
    """
    total = sum(len(_routes(p)) for p in _router_files())
    assert total > 0, "no routes found — has the BFF layout changed?"
    print(f"\n  BFF declares {total} route decorators")


# ---------------------------------------------------------------------------
# A route decorator must decorate its HANDLER
# ---------------------------------------------------------------------------
# Inserting a helper function directly above an existing handler puts it
# BETWEEN the decorator and the function, so the decorator silently registers
# the helper as the endpoint. FastAPI then derives the route's query
# parameters from the helper's signature and every call 422s:
#
#   {"detail":[{"type":"missing","loc":["query","vec"], ...}]}
#
# Observed 2026-10-17 on POST /rag/knowledge/search, which registered
# `_rag_log_retrieval` and demanded `vec`, `rows` and `source` as query
# params. ast.parse passed, the container was healthy, and the real handler
# was simply unreachable.

ROUTE_DECORATORS = ("get", "post", "put", "patch", "delete", "head", "options")


def _route_source_files():
    """api.py plus every BFF router — the files that declare HTTP routes."""
    files = [os.path.join(REPO, "app", "rag-api", "api.py")]
    files += _router_files()
    return [f for f in files if os.path.exists(f)]


def _decorated_routes(path):
    """(decorator_path, handler_name, lineno) for every HTTP route in a file."""
    with open(path, encoding="utf-8", errors="replace") as fh:
        tree = ast.parse(fh.read())
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call):
                continue
            f = dec.func
            if not isinstance(f, ast.Attribute) or f.attr not in ROUTE_DECORATORS:
                continue
            route = None
            if dec.args and isinstance(dec.args[0], ast.Constant):
                route = dec.args[0].value
            if isinstance(route, str) and route.startswith("/"):
                out.append((route, node.name, node.lineno))
    return out


def test_no_route_is_registered_on_a_private_helper():
    """A handler named `_foo` means a decorator lost its function.

    Public handlers are the convention everywhere in this codebase, so a
    leading underscore is a reliable signal that a helper was spliced in
    between the decorator and the real handler.
    """
    offenders = []
    for path in _route_source_files():
        for route, name, lineno in _decorated_routes(path):
            if name.startswith("_"):
                offenders.append(
                    f"{os.path.basename(path)}:{lineno} {route} -> {name}()")
    assert not offenders, (
        "a route decorator is attached to a private helper, so the real "
        "handler is unreachable and the route takes the helper's signature "
        "as its parameters:\n  " + "\n  ".join(offenders))


def test_the_private_handler_detector_would_catch_a_planted_case(tmp_path):
    """Sabotage-proof: the detector must flag the exact shape of the bug."""
    f = tmp_path / "planted.py"
    f.write_text(
        "import fastapi\n"
        "app = fastapi.FastAPI()\n"
        "\n"
        '@app.post("/x/y")\n'
        "def _helper(query, vec, rows, *, source):\n"
        "    return None\n"
        "\n"
        "def real_handler(body):\n"
        "    return {}\n", encoding="utf-8")
    found = _decorated_routes(str(f))
    assert len(found) == 1, found
    route, name, lineno = found[0]
    assert (route, name) == ("/x/y", "_helper"), found
    assert name.startswith("_"), "the detector must see the private name"
    # the real handler is present but unreachable — exactly the live symptom
    assert "real_handler" not in [n for _, n, _ in found]
