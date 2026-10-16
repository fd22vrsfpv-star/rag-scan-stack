"""A long request's timeouts must widen OUTWARDS, or the wrong layer gives up.

The model bake-off returned `504 Gateway Time-out` from nginx while rag-api
carried on working, because the three layers disagreed:

    nginx   location ^~ /api/   proxy_read_timeout  300s   <- gave up first
    BFF     httpx.AsyncClient   timeout             600s   ("generous")
    rag-api bakeoff             unbounded: one LLM call AND one dispatched
                                run PER MODEL, serially, over every local
                                ollama tag by default

The layer furthest from the work had the shortest patience, so the operator
saw a gateway error, the run kept going server-side, and the work was paid for
twice. CLAUDE.md: "Client timeouts MUST cover the worst admitted latency at
the limit — admitting a request and then abandoning it wastes the work twice."

Also pinned here: an nginx `^~` prefix location STOPS regex evaluation. The
first version of the fix added a regex location for the bakeoff path (the
exploit id sits mid-path, so a prefix cannot express it) while
`location ^~ /api/` still sat below it — which meant the new location could
never match. Caught before deploy; this test is why it stays caught.

Sabotage check: restore `^~` on the `/api/` location and
`test_the_catchall_does_not_block_regex_locations` fails; drop the BFF
timeout below nginx's and `test_the_chain_widens_outwards` fails.

    pytest tests/test_timeout_chain.py -q
"""

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
NGINX = REPO / "dashboard" / "nginx.conf"
BFF = REPO / "dashboard" / "bff" / "routers" / "exploits.py"


def _conf() -> str:
    if not NGINX.exists():
        pytest.skip("nginx.conf not found")
    return NGINX.read_text(encoding="utf-8")


def _locations():
    """[(raw_location_line, read_timeout_seconds_or_None)] in file order."""
    out, cur, timeout = [], None, None
    for line in _conf().split("\n"):
        m = re.match(r"\s*location\s+(.+?)\s*\{", line)
        if m:
            if cur is not None:
                out.append((cur, timeout))
            cur, timeout = m.group(1), None
            continue
        t = re.match(r"\s*proxy_read_timeout\s+(\d+)s", line)
        if t and cur is not None:
            timeout = int(t.group(1))
    if cur is not None:
        out.append((cur, timeout))
    return out


def _bakeoff_location():
    for loc, t in _locations():
        if "bakeoff" in loc:
            return loc, t
    return None, None


def _catchall_timeout():
    for loc, t in _locations():
        if loc.strip() in ("/api/", "^~ /api/"):
            return t
    pytest.fail("no catch-all /api/ location found in nginx.conf")


def _bff_timeout():
    if not BFF.exists():
        pytest.skip("exploits.py not found")
    src = BFF.read_text(encoding="utf-8")
    i = src.find("bakeoff")
    assert i > 0, "no bakeoff proxy in the BFF"
    m = re.search(r"AsyncClient\(timeout=(\d+)\)", src[i:i + 2000])
    assert m, "the bakeoff proxy sets no explicit client timeout"
    return int(m.group(1))


# -- the chain ---------------------------------------------------------------

def test_the_bakeoff_has_its_own_location():
    loc, t = _bakeoff_location()
    assert loc, (
        "the bake-off has no dedicated nginx location, so it inherits the "
        f"catch-all {_catchall_timeout()}s — it runs one LLM call and one "
        "dispatched run PER MODEL and cannot fit in that")
    assert t, f"the bakeoff location {loc!r} sets no proxy_read_timeout"


def test_the_chain_widens_outwards():
    """nginx >= BFF. The layer furthest from the work must be the most patient."""
    _loc, ng = _bakeoff_location()
    bff = _bff_timeout()
    assert ng >= bff, (
        f"nginx ({ng}s) gives up BEFORE the BFF client ({bff}s), so the "
        "operator gets a 504 while the work carries on server-side — exactly "
        "the bake-off failure of 2026-10-16")


def test_the_bakeoff_beats_the_catchall():
    _loc, ng = _bakeoff_location()
    assert ng > _catchall_timeout(), (
        f"the bakeoff location ({ng}s) is no longer than the catch-all "
        f"({_catchall_timeout()}s), so it buys nothing")


# -- the nginx footgun -------------------------------------------------------

def test_the_catchall_does_not_block_regex_locations():
    """`^~` on /api/ stops regex evaluation — the bakeoff location dies.

    nginx matching order: exact `=`, then the longest `^~` prefix (and if one
    matches, REGEX LOCATIONS ARE NEVER EVALUATED), then regexes in order.
    With `^~ /api/` present, a regex location for an /api/ path is dead code.
    """
    locs = [loc for loc, _ in _locations()]
    assert "^~ /api/" not in locs, (
        "the catch-all /api/ location uses `^~`, which stops nginx evaluating "
        "regex locations — the bakeoff location can never match")
    assert "/api/" in locs, "the catch-all /api/ location is gone entirely"


def test_the_bakeoff_location_is_a_regex():
    """The exploit id is mid-path, so a prefix cannot express it."""
    loc, _ = _bakeoff_location()
    assert loc.startswith("~"), (
        f"the bakeoff location {loc!r} is not a regex; a prefix cannot match "
        "/api/exploit-store/<id>/bakeoff without also matching every other "
        "exploit-store route")


def test_the_longer_prefix_locations_still_win():
    """Removing `^~` from /api/ must not demote the specific ^~ locations."""
    locs = [loc for loc, _ in _locations()]
    specific = [l for l in locs if l.startswith("^~ /api/") and l != "^~ /api/"]
    assert specific, (
        "no specific `^~ /api/...` locations remain — the long-running "
        "maintenance and convert endpoints would fall back to the catch-all")


def test_the_bakeoff_pattern_matches_a_real_path():
    loc, _ = _bakeoff_location()
    pattern = loc.lstrip("~").strip()
    assert re.search(pattern, "/api/exploit-store/abc-123/bakeoff"), (
        f"{pattern!r} does not match a real bakeoff path")
    assert not re.search(pattern, "/api/exploit-store/abc-123/versions"), (
        f"{pattern!r} is too broad — it matches other exploit-store routes")
