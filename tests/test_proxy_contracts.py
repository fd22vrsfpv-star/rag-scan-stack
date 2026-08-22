"""Every BFF proxy call must name a path some service actually declares.

Run on demand:

    pytest tests/test_proxy_contracts.py -v

WHY THIS EXISTS
---------------
68% of BFF routes (361 of 532) are thin proxies: one upstream call, under 25
lines. Their characteristic failure is not logic — it is naming an upstream path
that does not exist. That is statically decidable, so one test covers all of
them instead of 361 hand-written cases.

The first run of this check found four, all masked from every other form of
verification because a fallback or a bare `except` absorbed the 404:

  * POST /findings/web (Burp import) — no such route. The call sat inside
    `except Exception: pass`, so importing N findings returned
    {"ok": true, "imported": 0}. Silent data loss reported as success.
  * GET /api/exploits/pending — dead, AND its fallback leg was dead too
    (exploit_runner declares only /exploits/all), so the endpoint returned
    {"detail": "Not Found"} and Pending Exploits could never populate.
  * GET /settings/ollama_active_model — dead, swallowed, so the operator's
    active-model choice in Settings was silently ignored.
  * GET /scan-recommendations — dead primary leg; the scan_recommender
    fallback carried it, costing a wasted round-trip on every page load.

Containers were healthy, the suite was green, and the OpenAPI schema listed
every one of these BFF routes. Nothing had ever checked the far end.

WHAT THIS DOES AND DOES NOT PROVE
---------------------------------
Matching is segment-wise, and an upstream {param} segment matches any caller
segment — because that is what FastAPI does. So this proves a call will not
404. It does not prove the call will not 422: passing "pending" where a uuid is
expected matches the route and fails validation. Catching that needs a live
call, which is the smoke sweep's job, not this test's.
"""
import ast
import os
import re

try:
    import pytest
except ImportError:  # pragma: no cover
    # Standalone mode: scripts/post-install-check.sh runs this file directly on
    # hosts with no pytest, the same way it runs check_shared_code.py. Only the
    # fixture decorator is needed at import time, and _main() calls the plain
    # helpers rather than the test functions.
    class _NoPytest:
        @staticmethod
        def fixture(*args, **kwargs):
            def wrap(fn):
                return fn
            return wrap(args[0]) if args and callable(args[0]) else wrap

    pytest = _NoPytest()

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
BFF = os.path.join(REPO, "dashboard", "bff")

VERBS = ("get", "post", "put", "patch", "delete")

# BFF settings attribute -> directory of the service it addresses.
SERVICES = {
    "rag_api_url": "app/rag-api",
    "scan_recommender_url": "scan_recommender",
    "nmap_scanner_url": "nmap_scanner",
    "pd_runner_url": "pd_runner",
    "web_scanner_url": "web_scanner",
    "osint_runner_url": "osint_runner",
    "kali_listener_url": "kali_listener",
    "exploit_runner_url": "exploit_runner",
    "playwright_url": "playwright_scanner",
    "brutus_runner_url": "brutus_runner",
    "autogen_url": "autogen_agents",
    "tunnel_manager_url": "node_manager",
    "news_runner_url": "news_runner",
}

# Calls whose path is assembled at runtime, so the far end cannot be resolved
# statically. Each entry needs a reason. These are NOT exempt from being
# correct — they are exempt from being checkable HERE, and belong to the live
# smoke sweep instead.
PROXY_DYNAMIC = {
    ("maintenance.py", "/cleanup/{}"): "cleanup kind chosen by caller; targets /cleanup/<kind> literals",
    ("scans.py", "/ingest/{}"): "parser name is the path segment",
    ("targeted_recon.py", "/ingest/{}"): "parser name is the path segment",
    ("nodes.py", "/{}"): "entire upstream path forwarded verbatim from the request",
}

# Known-bad upstream paths that still ship. RATCHETS: a new one fails by name,
# and a fixed one must be deleted from this dict (test_no_stale_proxy_debt).
PROXY_DEBT = {}


def _norm(path):
    """Collapse interpolations to {} and strip query/trailing slash."""
    path = re.sub(r"\{[^}]*\}", "{}", path.split("?")[0])
    return "/" + path.strip("/")


def _service_routes(directory):
    """Every (METHOD, path) a service declares, honouring APIRouter(prefix=)."""
    found = set()
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", "node_modules")]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            full = os.path.join(dirpath, name)
            with open(full, encoding="utf-8", errors="replace") as fh:
                src = fh.read()
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue

            # router variable -> prefix. A missed prefix reads as a missing
            # route and would flood this test with false positives: /kb and
            # /rag alone account for 44 calls.
            prefixes = {}
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)):
                    continue
                func = node.value.func
                fname = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if fname != "APIRouter":
                    continue
                prefix = ""
                for kw in node.value.keywords:
                    if kw.arg == "prefix" and isinstance(kw.value, ast.Constant):
                        prefix = kw.value.value or ""
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        prefixes[target.id] = prefix

            for node in ast.walk(tree):
                for dec in getattr(node, "decorator_list", []):
                    if not isinstance(dec, ast.Call):
                        continue
                    func = dec.func
                    if not isinstance(func, ast.Attribute) or func.attr.lower() not in VERBS:
                        continue
                    if not dec.args or not isinstance(dec.args[0], ast.Constant):
                        continue
                    owner = getattr(func.value, "id", "")
                    raw = prefixes.get(owner, "") + str(dec.args[0].value)
                    found.add((func.attr.upper(), _norm(raw)))
    return found


def _upstream_path(node):
    """Rebuild an f-string upstream path, returning (settings_attr, path).

    The leading {s.<attr>_url} identifies the target service and is dropped;
    every other interpolation becomes {}.
    """
    if not isinstance(node, ast.JoinedStr):
        return None, None
    attr, parts = None, []
    for value in node.values:
        if isinstance(value, ast.Constant):
            parts.append(str(value.value))
            continue
        inner = value.value if isinstance(value, ast.FormattedValue) else None
        if (
            isinstance(inner, ast.Attribute)
            and isinstance(getattr(inner, "value", None), ast.Name)
            and inner.value.id in ("s", "settings")
            and not parts
        ):
            attr = inner.attr
        else:
            parts.append("{}")
    return attr, "".join(parts)


def _matches(method, path, declared):
    """True if FastAPI would route (method, path) to something declared.

    Segment-wise, with a declared {} matching any single caller segment.
    """
    if (method, path) in declared:
        return True
    want = path.strip("/").split("/")
    for dmethod, dpath in declared:
        if dmethod != method:
            continue
        have = dpath.strip("/").split("/")
        if len(have) != len(want):
            continue
        if all(h == "{}" or h == w for h, w in zip(have, want)):
            return True
    return False


def _bff_calls():
    """Every statically resolvable upstream call the BFF makes."""
    calls = []
    for dirpath, dirnames, filenames in os.walk(BFF):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", "node_modules")]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            full = os.path.join(dirpath, name)
            with open(full, encoding="utf-8", errors="replace") as fh:
                src = fh.read()
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                verb = node.func.attr.lower()
                if verb not in VERBS or not node.args:
                    continue
                attr, path = _upstream_path(node.args[0])
                if not attr or attr not in SERVICES:
                    continue
                calls.append((name, node.lineno, verb.upper(), attr, _norm(path)))
    return calls


@pytest.fixture(scope="module")
def declared():
    out = {}
    for attr, rel in SERVICES.items():
        directory = os.path.join(REPO, rel)
        out[attr] = _service_routes(directory) if os.path.isdir(directory) else set()
    return out


@pytest.fixture(scope="module")
def calls():
    return _bff_calls()


def test_harness_is_not_vacuous(declared, calls):
    """This test has silently scanned nothing twice before. Prove it sees code.

    Once the copy-detector's REPO pointed at tests/.. and matched its own skip
    rule, scanning zero files while a planted violation sat in the tree. Once a
    drift guard skipped 20 assertions because a matcher had moved. Both looked
    green. An assertion on the input size is the cheapest defence.
    """
    assert os.path.isdir(BFF), BFF
    populated = {a: r for a, r in declared.items() if r}
    assert len(populated) >= 8, f"only {len(populated)} services resolved routes: {sorted(populated)}"
    total_routes = sum(len(r) for r in declared.values())
    assert total_routes >= 500, f"only {total_routes} upstream routes found"
    assert len(calls) >= 300, f"only {len(calls)} BFF upstream calls found"


def test_router_prefixes_are_resolved(declared):
    """Prefixed routers must contribute prefixed paths.

    Without this, APIRouter(prefix="/kb") is invisible and all 44 /kb and /rag
    calls report as missing — which is exactly what the first draft did.
    """
    sr = declared["scan_recommender_url"]
    assert ("GET", "/kb/services") in sr, "APIRouter(prefix='/kb') not applied"
    assert any(m == "GET" and p.startswith("/rag/") for m, p in sr), "prefix='/rag' not applied"
    api = declared["rag_api_url"]
    assert any(p.startswith("/health/") for _, p in api), "prefix='/health' not applied"
    assert any(p.startswith("/metrics/") for _, p in api), "prefix='/metrics' not applied"


def test_literal_matches_declared_parameter():
    """A caller literal must satisfy a declared {param} of the same shape.

    /settings/config/burp_proxy_url is served by /settings/config/{key_name}.
    Treating those as a mismatch produced three false positives.
    """
    declared = {("GET", "/settings/config/{}")}
    assert _matches("GET", "/settings/config/burp_proxy_url", declared)
    assert not _matches("GET", "/settings/config/a/b", declared)
    assert not _matches("POST", "/settings/config/x", declared)


def test_upstream_paths_exist(declared, calls):
    """The guard. Every proxy call must resolve to a declared upstream route."""
    missing = []
    for name, lineno, method, attr, path in calls:
        if not declared.get(attr):
            continue  # service directory absent from this checkout
        if (name, path) in PROXY_DYNAMIC:
            continue
        if _matches(method, path, declared[attr]):
            continue
        if PROXY_DEBT.get((name, method, path)):
            continue
        missing.append(f"{name}:{lineno} {method} {{{attr}}}{path}")
    assert not missing, (
        f"{len(missing)} proxy call(s) name an upstream path no service declares.\n"
        "Fix the path, or add it to PROXY_DYNAMIC/PROXY_DEBT with a reason:\n  "
        + "\n  ".join(sorted(missing))
    )


def test_no_stale_proxy_debt(declared, calls):
    """A resolved debt entry must be deleted, or the list stops meaning anything."""
    live = {(n, m, p) for n, _, m, a, p in calls if declared.get(a)}
    stale = [k for k in PROXY_DEBT if k not in live]
    assert not stale, f"PROXY_DEBT entries no longer present; delete them: {stale}"

    resolved = [
        (n, m, p) for (n, m, p) in PROXY_DEBT
        if (n, m, p) in live and _matches(m, p, declared[next(
            a for x, _, mm, a, pp in calls if (x, mm, pp) == (n, m, p))])
    ]
    assert not resolved, f"PROXY_DEBT entries now resolve; delete them: {resolved}"


def test_no_stale_dynamic_exemptions(calls):
    """Same ratchet for PROXY_DYNAMIC: an exemption for a call that no longer
    exists hides the next one that does."""
    live = {(n, p) for n, _, _, _, p in calls}
    stale = [k for k in PROXY_DYNAMIC if k not in live]
    assert not stale, f"PROXY_DYNAMIC entries no longer present; delete them: {stale}"


def test_fallback_legs_are_checked(calls):
    """A fallback is an endpoint too.

    /api/exploits/pending had a dead primary AND a dead fallback, so the
    endpoint could never work. Both legs appear in `calls`, so this asserts the
    harness sees more than one call per file where fallbacks exist rather than
    stopping at the first.
    """
    exploits = [c for c in calls if c[0] == "exploits.py"]
    assert len(exploits) >= 2, "fallback legs are not being collected"


def _main():
    """Standalone entry point, so scripts/post-install-check.sh can run this
    without pytest installed. Exits 1 if any proxy path is unresolvable."""
    declared_map = {}
    for attr, rel in SERVICES.items():
        directory = os.path.join(REPO, rel)
        declared_map[attr] = _service_routes(directory) if os.path.isdir(directory) else set()
    found = _bff_calls()

    checkable = [c for c in found if declared_map.get(c[3])]
    missing = []
    for name, lineno, method, attr, path in checkable:
        if (name, path) in PROXY_DYNAMIC or PROXY_DEBT.get((name, method, path)):
            continue
        if not _matches(method, path, declared_map[attr]):
            missing.append(f"{name}:{lineno} {method} {{{attr}}}{path}")

    total = sum(len(r) for r in declared_map.values())
    print(f"Checked {len(checkable)} BFF proxy call(s) against {total} declared "
          f"upstream route(s) in {sum(1 for r in declared_map.values() if r)} service(s)")
    print(f"  {len(PROXY_DYNAMIC)} exempt (runtime-built path), "
          f"{len(PROXY_DEBT)} known debt")

    if missing:
        print(f"\n{len(missing)} proxy call(s) name an upstream path no service declares:")
        for line in sorted(missing):
            print(f"  ✗ {line}")
        return 1
    print("\n✅ every proxy call resolves to a declared upstream route")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
