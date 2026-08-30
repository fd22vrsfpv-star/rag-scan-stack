"""Live endpoint smoke sweep, as a test.

    pytest tests/test_endpoint_smoke.py -v
    SMOKE_BASE=https://localhost:3002 pytest tests/test_endpoint_smoke.py

Skips when no stack is reachable, so a laptop unit run stays green. The sweep
itself lives in scripts/smoke_endpoints.py — the same code post-install-check.sh
runs, so there is one implementation rather than a second copy that can drift.

CI does NOT run this: bringing up sixteen services on a hosted runner is not
practical. The structural half of the problem — routes shadowed by declaration
order — IS checked in CI by tests/test_route_contracts.py, with no stack needed.
"""
import importlib.util
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
_SCRIPT = os.path.join(REPO, "scripts", "smoke_endpoints.py")
BASE = os.environ.get("SMOKE_BASE", "https://localhost:3002")


@pytest.fixture(scope="module")
def smoke():
    if not os.path.exists(_SCRIPT):              # pragma: no cover
        pytest.skip("scripts/smoke_endpoints.py not present")
    spec = importlib.util.spec_from_file_location("smoke_endpoints", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def results(smoke):
    paths = smoke.discover()
    if not paths:                                # pragma: no cover
        pytest.skip("no endpoints discovered")
    # One cheap probe first: no point sweeping 170 endpoints to learn the stack
    # is down, and a pile of connection errors would read as mass breakage.
    _p, status, _b = smoke.probe(BASE, paths[0], 10, os.environ.get("API_KEY"))
    if status == 0:
        pytest.skip(f"no stack reachable at {BASE}")
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=6) as ex:
        return list(ex.map(
            lambda p: smoke.probe(BASE, p, 20, os.environ.get("API_KEY")), paths))


# Endpoints that are legitimately slow — they do real work — and sit close
# enough to the sweep's 20s budget to flap. They are reported by
# test_slow_endpoints_are_declared, NOT counted as 5xx: a timeout says "this is
# slower than the budget", a 500 says "this is broken", and merging the two made
# a genuine 500 (session-bundle) look like the same class of problem as an
# endpoint that simply takes 13 seconds.
#
# Measured 2026-08-28: /api/diagnostics/errors ~19.6s,
# /api/settings/database/compare ~13.0s. Both return 200.
KNOWN_SLOW = {
    "/api/diagnostics/errors":
        "reads `docker logs` for ~30 containers; ~19.6s measured",
    # /api/settings/database/compare used to sit here at ~13s. It was slow
    # because a bare GET STARTED the local Postgres to read its stats — which
    # also handed that container the `rag-postgres` network alias and made a
    # share of the whole stack's DB connections fail. It now defaults to
    # start_local=false and answers in ~1.3s.
}


def test_no_endpoint_returns_5xx(smoke, results):
    """A 5xx is the endpoint being broken, not the request being wrong.

    4xx is explicitly fine: many of these require parameters and correctly
    reject a bare GET. Timeouts (status 0) are NOT counted here — see
    KNOWN_SLOW and test_slow_endpoints_are_declared.
    """
    bad = [(p, s, b[:160]) for p, s, b in results
           if s >= 500 and p not in smoke.EXPECTED_5XX]
    assert not bad, "failing endpoints:\n  " + "\n  ".join(
        f"{s} {p} — {b}" for p, s, b in bad)


def test_slow_endpoints_are_declared(smoke, results):
    """An endpoint that cannot answer inside the sweep's budget is a real
    problem — just a different one from a 500.

    Undeclared timeouts fail: a newly-slow endpoint is a regression worth
    seeing, and letting timeouts pass silently is how a broken endpoint hides.
    Declared ones are tolerated and named, so the list stays reviewable.
    """
    timed_out = [(p, b[:120]) for p, s, b in results
                 if s == 0 and p not in smoke.EXPECTED_5XX]
    undeclared = [(p, b) for p, b in timed_out if p not in KNOWN_SLOW]
    assert not undeclared, (
        "endpoints that did not answer within the sweep budget and are not in "
        "KNOWN_SLOW:\n  " + "\n  ".join(f"{p} — {b}" for p, b in undeclared)
        + "\n\nEither make them faster or declare them with a measured time.")


def test_the_sweep_actually_probed_something(results):
    """A sweep that probed nothing passes and proves nothing — a failure mode
    this repo's guards have hit more than once."""
    assert len(results) > 50, f"only {len(results)} endpoints probed"


def test_tolerated_failures_are_documented(smoke):
    """Every 5xx exemption must carry a reason, so the list cannot quietly
    become a place where broken endpoints go to be ignored."""
    for path, reason in smoke.EXPECTED_5XX.items():
        assert reason and len(reason) > 15, f"{path} is exempt without a real reason"
