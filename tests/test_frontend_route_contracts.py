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
    # Structural rather than a pinned fragment: match a template literal or a
    # concatenation that uses BOTH names, in either order, whatever the
    # spacing. The property is "the URL is BASE composed with path", not one
    # exact spelling of it.
    composes = re.search(r"\$\{\s*BASE\s*\}\s*\$\{\s*path\s*\}", src) or \
        re.search(r"\bBASE\b\s*\+\s*\bpath\b", src)
    assert composes, (
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


def test_apiurl_is_called_never_interpolated():
    """`apiUrl` is a FUNCTION. `${apiUrl}` in a template literal interpolates
    its SOURCE TEXT, producing a URL like

        function apiUrl(path){return `${BASE}${path}`;}/screenshots/foo.png

    which no server answers. It fails silently: an <img> with a bad src renders
    nothing and throws no error the page can see.

    This broke EVERY screenshot thumbnail in the app — the asset drawer's
    Screenshots tab showed six filename boxes and no pictures, which read as
    "GoWitness captured nothing" rather than "the URL is malformed". Found
    2026-10-13 from an operator screenshot.

    Same family as the doubled-/api bug this module already guards: the path
    looks plausible in source and resolves to nothing at runtime.
    """
    import pathlib
    import re
    root = pathlib.Path(__file__).resolve().parents[1] / "dashboard" / "frontend" / "src"
    if not root.exists():
        import pytest
        pytest.skip(f"{root} not present")
    bad = []
    for p in sorted(root.rglob("*.ts")) + sorted(root.rglob("*.tsx")):
        for n, line in enumerate(p.read_text(encoding="utf-8",
                                             errors="replace").splitlines(), 1):
            if re.search(r"\$\{\s*apiUrl\s*\}", line):
                rel = p.relative_to(root.parents[2]).as_posix()
                bad.append(f"{rel}:{n}: {line.strip()[:110]}")
    assert not bad, (
        "apiUrl interpolated instead of called — the resulting URL contains the "
        "function's source and resolves to nothing:\n  " + "\n  ".join(bad)
        + "\n\nUse apiUrl(`/path`) instead of `${apiUrl}/path`."
    )


def test_scope_is_fetched_whole_not_a_truncated_prefix():
    """A scope-filtered VIEW hides any row whose host is not in the fetched
    target list, so fetching a PREFIX of the scope silently hides in-scope
    data.

    The examplecorp scope has 909 targets. `/scope` defaults to 500, ordered by
    added_at, and that first 500 did NOT contain the apex `examplecorp.com` — so
    Content Intelligence reported "2 of 100 extractions (98 hidden by scope
    filter)" while all 100 were in scope. The operator read it as "no data".
    """
    import pathlib
    import re
    api = (pathlib.Path(__file__).resolve().parents[1]
           / "dashboard" / "frontend" / "src" / "api" / "scope.ts")
    if not api.exists():
        import pytest
        pytest.skip(f"{api} not present")
    src = api.read_text(encoding="utf-8")
    m = re.search(r"SCOPE_FETCH_LIMIT\s*=\s*(\d+)", src)
    assert m, "SCOPE_FETCH_LIMIT is gone — useScope would fall back to the server default of 500"
    assert int(m.group(1)) >= 5000, (
        f"SCOPE_FETCH_LIMIT is {m.group(1)}; the /scope endpoint allows 5000 and "
        "anything less silently truncates a large scope")
    # both legs must carry it — the engagement-scoped lookup and the global one
    assert len(re.findall(r"limit=\$\{SCOPE_FETCH_LIMIT\}", src)) >= 2, (
        "only one of the two scope lookups requests the full list; the other "
        "still returns a truncated prefix")


def test_scope_view_filter_fails_open_when_truncated():
    """A view filter is NOT an authorization gate. If the target list is known
    to be incomplete, showing an extra row costs a glance; hiding a real one
    costs evidence the operator already collected. Authorization lives in
    etl/scope_gate.py and fails CLOSED — these are different jobs."""
    import pathlib
    hook = (pathlib.Path(__file__).resolve().parents[1]
            / "dashboard" / "frontend" / "src" / "hooks" / "useScopeFilter.ts")
    if not hook.exists():
        import pytest
        pytest.skip(f"{hook} not present")
    src = hook.read_text(encoding="utf-8")
    assert "truncated" in src, "the hook does not detect a truncated target list"
    i = src.find("if (truncated)")
    assert i != -1, "nothing branches on truncation"
    assert "return true" in src[i:i + 60], (
        "truncation must fail OPEN (return true) — failing closed hides "
        "in-scope rows, which is the bug this guards")


def test_content_intel_matches_hosts_not_substrings():
    """`url.includes(domain)` is both too loose and too tight: it matches
    `evil-examplecorp.com.attacker.net`, and it only fires when the exact domain
    is present in a list that was truncated."""
    import pathlib
    page = (pathlib.Path(__file__).resolve().parents[1]
            / "dashboard" / "frontend" / "src" / "pages" / "ContentIntel.tsx")
    if not page.exists():
        import pytest
        pytest.skip(f"{page} not present")
    src = page.read_text(encoding="utf-8")
    # Regex, not a pinned fragment: the PROPERTY is "no bare substring match on
    # the url, and a real suffix match exists", in any spelling or spacing.
    assert not re.search(r"\.url\s*\.includes\s*\(", src), (
        "ContentIntel still substring-matches the URL against scope domains")
    assert re.search(r"endsWith\s*\(\s*['\"]\.['\"]\s*\+", src), (
        "no suffix match — a subdomain of an in-scope apex will be hidden")


def test_asset_detail_tab_survives_changing_asset():
    """Selecting the next asset must KEEP the operator's tab.

    The row click reset it to 'ports' on every selection, so walking a list to
    compare one thing — pick Screenshots, click the next host — bounced back to
    Ports every time, which makes paging through assets unusable.

    The single allowed override is a cloud-import asset: its IP is a synthetic
    127.0.x.x marker with no ports or screenshots, so 'recon' is the only tab
    with anything in it.
    """
    import pathlib
    import re
    page = (pathlib.Path(__file__).resolve().parents[1]
            / "dashboard" / "frontend" / "src" / "pages" / "AssetBrowser.tsx")
    if not page.exists():
        import pytest
        pytest.skip(f"{page} not present")
    src = page.read_text(encoding="utf-8")
    # the reset took the form setDetailTab(isCloudImport ? 'recon' : 'ports')
    assert not re.search(r"setDetailTab\s*\(\s*\w+\s*\?\s*['\"]recon['\"]\s*:\s*['\"]ports['\"]", src), (
        "the row click still resets the detail tab to 'ports' on every asset "
        "selection — paging through assets loses the tab")
    # it must preserve the previous value via the functional form
    assert re.search(r"setDetailTab\s*\(\s*prev\s*=>", src), (
        "nothing preserves the previous tab when the selected asset changes")


def test_asset_detail_tab_is_persisted_fail_soft():
    """Per the repo's tab convention: persist the selection so a refresh does
    not bounce to the first tab, and fail soft — localStorage throws in a
    private window and the remembered tab is a convenience, not state the page
    needs to render."""
    import pathlib
    import re
    page = (pathlib.Path(__file__).resolve().parents[1]
            / "dashboard" / "frontend" / "src" / "pages" / "AssetBrowser.tsx")
    if not page.exists():
        import pytest
        pytest.skip(f"{page} not present")
    src = page.read_text(encoding="utf-8")
    i = src.find("assets-detail-tab")
    assert i != -1, "the detail tab is not persisted"
    window = src[max(0, i - 900):i + 900]
    assert window.count("try") >= 2 and window.count("catch") >= 2, (
        "localStorage read/write is not wrapped — it throws in a private "
        "window and would take the page down with it")
