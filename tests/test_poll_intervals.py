"""2026-10-22: an interval shorter than the response time is a queue, not a poll.

Operator: "lets reduce the poll time, 30seconds is to low."

Every tier was shorter than the endpoint behind it could answer on a real
estate, so each tick started before the last finished and they ACCUMULATED.
Measured on the redteam engagement that day:

    /assets                      >60s   polled at NORMAL (30s)   2:1 overlap
    /software/cves-without-poc  ~137s   polled at FAST   (10s)  13:1 overlap

29 concurrent copies of the assets query were observed, the oldest 34 minutes
old, until the database was saturated and unrelated pages — News among them —
timed out and rendered blank. CLAUDE.md: "shed, do not queue."

Both queries were fixed in the same change, but the intervals were the
multiplier: a slow query costs one request; a slow query on a short poll costs
an unbounded number.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_poll_intervals.py -v'
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
POLLING = REPO / "dashboard" / "frontend" / "src" / "lib" / "polling.ts"
EXPLOITS_API = REPO / "dashboard" / "frontend" / "src" / "api" / "exploits.ts"

pytestmark = pytest.mark.skipif(not POLLING.exists(), reason="polling.ts not present")

# The floor each tier must not drop below again, in milliseconds.
FLOORS = {
    "REALTIME": 15000,
    "FAST": 30000,
    "NORMAL": 90000,
    "SLOW": 180000,
    "BACKGROUND": 300000,
}


@pytest.fixture(scope="module")
def tiers() -> dict:
    src = POLLING.read_text(encoding="utf-8")
    found = dict(re.findall(r"(\w+):\s*smartInterval\((\d+)\)", src))
    assert found, "no POLL tiers found"
    return {k: int(v) for k, v in found.items()}


@pytest.mark.parametrize("tier,floor", sorted(FLOORS.items()))
def test_no_tier_drops_below_its_floor(tiers, tier, floor):
    assert tier in tiers, f"the {tier} tier is gone"
    assert tiers[tier] >= floor, (
        "%s fell to %sms (floor %sms). A dashboard refresh rate shorter than "
        "the endpoint's response time accumulates requests rather than "
        "replacing them." % (tier, tiers[tier], floor))


def test_the_tiers_stay_ordered(tiers):
    """REALTIME < FAST < NORMAL < SLOW < BACKGROUND, or the names lie about
    which is cheaper and a caller picking 'SLOW' may poll faster."""
    order = ["REALTIME", "FAST", "NORMAL", "SLOW", "BACKGROUND"]
    vals = [tiers[t] for t in order if t in tiers]
    assert vals == sorted(vals), dict(zip(order, vals))
    assert len(set(vals)) == len(vals), "two tiers share an interval: %s" % vals


def test_polling_still_pauses_on_a_hidden_tab(tiers):
    """The cheapest control of all — a background tab must poll nothing."""
    src = POLLING.read_text(encoding="utf-8")
    assert re.search(r"document\.hidden\s*\?\s*false", src), \
        "smartInterval no longer pauses when the tab is hidden"


def test_the_slow_endpoint_is_not_on_a_fast_tier():
    """/software/cves-without-poc measured 19-27s AFTER its query was fixed, so
    it must not sit on a tier that fires faster than that."""
    src = EXPLOITS_API.read_text(encoding="utf-8")
    m = re.search(r"cves-without-poc.{0,900}?refetchInterval:\s*POLL\.(\w+)", src, re.S)
    assert m, "the cves-without-poc poll interval was not found"
    tier = m.group(1)
    assert tier in ("SLOW", "BACKGROUND"), (
        "cves-without-poc is polled at POLL.%s; it answers in 19-27s" % tier)
