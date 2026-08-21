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


def test_no_endpoint_returns_5xx(smoke, results):
    """A 5xx is the endpoint being broken, not the request being wrong.

    4xx is explicitly fine: many of these require parameters and correctly
    reject a bare GET.
    """
    bad = [(p, s, b[:160]) for p, s, b in results
           if (s == 0 or s >= 500) and p not in smoke.EXPECTED_5XX]
    assert not bad, "failing endpoints:\n  " + "\n  ".join(
        f"{s} {p} — {b}" for p, s, b in bad)


def test_the_sweep_actually_probed_something(results):
    """A sweep that probed nothing passes and proves nothing — a failure mode
    this repo's guards have hit more than once."""
    assert len(results) > 50, f"only {len(results)} endpoints probed"


def test_tolerated_failures_are_documented(smoke):
    """Every 5xx exemption must carry a reason, so the list cannot quietly
    become a place where broken endpoints go to be ignored."""
    for path, reason in smoke.EXPECTED_5XX.items():
        assert reason and len(reason) > 15, f"{path} is exempt without a real reason"
