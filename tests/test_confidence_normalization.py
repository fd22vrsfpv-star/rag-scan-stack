"""match_confidence is stored and consumed as a 0.0-1.0 fraction (the UI renders
`conf * 100`%). LLM callers of queue_exploit_for_approval passed a 0-100
percentage (95), which stored as 95 and rendered as 9500%. normalize_confidence
coerces any value > 1 to a fraction.

Run: pytest tests/test_confidence_normalization.py -v

SABOTAGE PROOF: make normalize_confidence return the value unchanged and
test_percentage_is_divided fails (95 stays 95).
"""
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "autogen_agents"))

du = pytest.importorskip("db_utils", reason="db_utils not importable (missing deps)")
n = du.normalize_confidence


def test_none_passes_through():
    assert n(None) is None


def test_fraction_is_unchanged():
    assert n(0.35) == 0.35
    assert n(0.95) == 0.95
    assert n(1.0) == 1.0
    assert n(0.0) == 0.0


def test_percentage_is_divided():
    # The actual bug: the Exploit Agent stored 70/85/90/95/99.
    assert n(95) == 0.95
    assert n(99.0) == 0.99
    assert n(70) == 0.70


def test_out_of_range_is_clamped():
    assert n(150) == 1.0     # >100 clamps to 1
    assert n(-5) == 0.0      # negative clamps to 0


def test_garbage_is_none():
    assert n("abc") is None
    assert n(object()) is None
