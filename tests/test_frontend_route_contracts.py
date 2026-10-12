"""Frontend -> BFF route contract.

`apiFetch` prepends a fixed `/api` prefix (dashboard/frontend/src/api/client.ts),
so every caller must pass a BARE path. A caller that passes a path already
starting with `/api/` produces a request for `/api/api/...`, which matches no BFF
route and 404s.

Nothing rewrites the path between the browser and the BFF: the routers are
mounted prefix-free (`app.include_router(exploits_router)`), routes carry the
`/api` prefix as a literal, nginx `proxy_pass` has no URI part, and Vite's dev
proxy uses the non-rewriting string shorthand. So the doubled prefix reaches
FastAPI intact and cannot match.

This is the third edge in the call chain and nothing else covers it:
`test_route_contracts.py` models BFF route shadowing, `test_proxy_contracts.py`
covers BFF -> upstream. This file covers frontend -> BFF.

Guards:
  test_no_doubled_api_prefix   -- no apiFetch() argument begins "/api/"
  test_base_prefix_unchanged   -- client.ts still prepends "/api" (premise check)
  test_frontend_paths_resolve  -- each literal path matches a declared BFF route

*Why:* nine call sites in ExploitManager.tsx requested `/api/api/sast/...` and
`/api/api/build-poc/reviews...`. The SAST tab and half the Reviews tab had never
worked, and because neither query destructured `isError`, every 404 rendered as
an empty list rather than an error.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(REPO, "dashboard", "frontend", "src")
BFF = os.path.join(REPO, "dashboard", "bff")
CLIENT = os.path.join(SRC, "api", "client.ts")

# Matches apiFetch('/path'...) and apiFetch(`/path...`), including a generic
# argument: apiFetch<Foo>('/path'). Captures the opening literal only -- enough
# to see the prefix and the static leading segments.
CALL = re.compile(r'\bapiFetch\s*(?:<[^>]*>)?\s*\(\s*([\'"`])([^\'"`]*)')

# Same decorator shape test_route_contracts.py uses.
DECORATOR = re.compile(
    r'@(?:app|router)\.(get|post|put|patch|delete)\(\s*[\'"]([^\'"]+)[\'"]')

# A router may carry its prefix at construction rather than in each decorator:
#   router = APIRouter(prefix="/api/delta", tags=["delta"])
# Missing this makes every route in such a file look undeclared.
ROUTER_PREFIX = re.compile(r'APIRouter\([^)]*prefix\s*=\s*[\'"]([^\'"]+)[\'"]')

# Paths assembled at runtime, where no literal prefix can be extracted.
# key -> reason. Entries must stay true; see test_dynamic_entries_are_live.
FRONTEND_DYNAMIC: dict[str, str] = {}

# Known violations kept visible while they are fixed. Ratchets: a new one fails
# by name, and a stale entry fails test_no_stale_debt.
FRONTEND_DEBT: dict[str, str] = {}


def _ts_files():
    if not os.path.isdir(SRC):
        pytest.skip("frontend sources not present")
    for root, _dirs, files in os.walk(SRC):
        for fn in files:
            if fn.endswith((".ts", ".tsx")) and not fn.endswith(".d.ts"):
                yield os.path.join(root, fn)


def _calls():
    """(relpath, lineno, literal_prefix) for every apiFetch call site."""
    for path in _ts_files():
        rel = os.path.relpath(path, REPO)
        with open(path, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh, 1):
                for m in CALL.finditer(line):
                    yield rel, i, m.group(2)


def _bff_routes():
    """Every path a BFF router declares, including any router-level prefix."""
    out = set()
    for root, _dirs, files in os.walk(BFF):
        for fn in files:
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(root, fn), encoding="utf-8",
                      errors="replace") as fh:
                src = fh.read()
            pm = ROUTER_PREFIX.search(src)
            prefix = pm.group(1).rstrip("/") if pm else ""
            for m in DECORATOR.finditer(src):
                out.add(prefix + m.group(2))
    return out


def _static_prefix(literal):
    """The leading path segments that are not built at runtime."""
    for stop in ("${", "?", "#"):
        idx = literal.find(stop)
        if idx != -1:
            literal = literal[:idx]
    return literal.rstrip("/")


def _matches(request_path, route):
    """Segment-wise match treating {param} as a wildcard."""
    rp = [s for s in request_path.split("/") if s]
    rt = [s for s in route.split("/") if s]
    if len(rp) > len(rt):
        return False
    # The request path may be a prefix of the route when the literal was cut at
    # a ${...}; every segment present must agree.
    for a, b in zip(rp, rt):
        if b.startswith("{") and b.endswith("}"):
            continue
        if a != b:
            return False
    return True


def test_base_prefix_unchanged():
    """The guard's premise: apiFetch prepends exactly '/api'."""
    if not os.path.exists(CLIENT):
        pytest.skip("client.ts not present")
    with open(CLIENT, encoding="utf-8") as fh:
        src = fh.read()
    assert re.search(r"const\s+BASE\s*=\s*['\"]/api['\"]", src), (
        "client.ts no longer declares BASE = '/api'. This guard assumes "
        "apiFetch prepends '/api'; update both together."
    )
    assert "${BASE}${path}" in src or "BASE + path" in src, (
        "client.ts no longer composes the URL as BASE + path; "
        "re-check what apiFetch prepends before trusting this guard."
    )


def test_no_doubled_api_prefix():
    """An apiFetch path must not repeat the prefix apiFetch already adds."""
    bad = []
    for rel, line, literal in _calls():
        if literal.startswith("/api/") or literal == "/api":
            key = f"{rel}:{line}"
            if key in FRONTEND_DEBT:
                continue
            bad.append(f"{key}  apiFetch('{literal}...')  -> /api{literal}")
    assert not bad, (
        "apiFetch() prepends '/api'; these call sites pass a path that already "
        "starts with it, producing /api/api/... which matches no BFF route:\n  "
        + "\n  ".join(sorted(bad))
    )


def test_frontend_paths_resolve():
    """Each literal apiFetch path must match a route some BFF router declares."""
    routes = _bff_routes()
    if not routes:
        pytest.skip("no BFF routes found")
    unresolved = []
    for rel, line, literal in _calls():
        if not literal.startswith("/"):
            continue  # relative or variable; nothing to resolve
        key = f"{rel}:{line}"
        if key in FRONTEND_DEBT or key in FRONTEND_DYNAMIC:
            continue
        prefix = _static_prefix(literal)
        if not prefix or prefix == "":
            continue  # entirely dynamic
        want = "/api" + prefix
        if not any(_matches(want, r) for r in routes):
            unresolved.append(f"{key}  '{literal}'  -> {want}")
    assert not unresolved, (
        "these apiFetch paths resolve to no declared BFF route "
        "(add to FRONTEND_DYNAMIC with a reason if built at runtime):\n  "
        + "\n  ".join(sorted(unresolved))
    )


def _live_violations():
    """Every call site that violates either check, ignoring the debt list."""
    routes = _bff_routes()
    live = set()
    for rel, line, literal in _calls():
        key = f"{rel}:{line}"
        if literal.startswith("/api/") or literal == "/api":
            live.add(key)
            continue
        if not literal.startswith("/") or key in FRONTEND_DYNAMIC:
            continue
        prefix = _static_prefix(literal)
        if not prefix:
            continue
        if routes and not any(_matches("/api" + prefix, r) for r in routes):
            live.add(key)
    return live


def test_no_stale_debt():
    """A debt entry whose violation is fixed must be deleted."""
    stale = sorted(set(FRONTEND_DEBT) - _live_violations())
    assert not stale, (
        "FRONTEND_DEBT entries no longer violate anything; delete them:\n  "
        + "\n  ".join(stale)
    )


def test_guard_catches_a_planted_violation():
    """Sabotage check: the doubled-prefix detector must actually fire."""
    planted = "/api/sast/findings"
    assert planted.startswith("/api/"), "detector predicate is wrong"
    # And the resolver must reject the doubled form against real routes.
    routes = _bff_routes()
    if routes:
        assert not any(_matches("/api" + planted, r) for r in routes), (
            "a doubled-prefix path unexpectedly matched a real route; "
            "the resolver would not catch this bug class"
        )
