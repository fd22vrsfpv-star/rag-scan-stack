"""One numeric severity scale for the whole stack.

WHY THIS EXISTS
---------------
Severity ordering was written out by hand in many places, in at least five
mutually incompatible conventions:

    app/rag-api/api.py:1592    CASE ... 'critical' THEN 5 ... ELSE 0   descending
    app/rag-api/api.py:5321    CASE ... 'critical' THEN 1 ... ELSE 7   ascending
    app/rag-api/api.py:7668    CASE ... 'critical' THEN 1 ... ELSE 4   ascending, truncated
    app/rag-api/api.py:7684    {"critical": 0, ... "recon": 5}         ascending
    app/rag-api/api.py:19275   CASE ... 'critical' THEN 1 ... ELSE 5   ascending
    frontend AttackMap.tsx     { critical: 5, ... info: 1 }            descending
    frontend ContentIntel.tsx  { critical: 0, ... info: 4 }            ascending

Two of them also disagreed about whether `low` and `info` are distinct, and none
of the frontend copies knew about the backend's `recon` value — which is how 1495
attack vectors came to sort below `info`, tied with garbage.

THE SCALE
---------
Higher is more severe, so `ORDER BY severity_rank(...) DESC` reads the way it
sounds and an unknown value sorts last rather than first. This matches the
frontend's SEVERITY_RANK in dashboard/frontend/src/lib/constants.ts, and the SQL
function public.severity_rank(); all three are pinned together by
tests/test_severity_scale.py.

WHAT THIS IS NOT
----------------
Deliberately NOT unified into this scale, because they are different numbers that
merely look similar:

  * `_severity_to_nessus()` in api.py — Nessus's 0-4 risk level is defined by the
    .nessus file format, not by us. Changing it corrupts exports.
  * `risk_map` in api.py — a 0-3 weighting that intentionally collapses
    critical and high into one bucket for scoring.
  * the `priority` column orderings — a different column with its own vocabulary.
  * `by_severity` dicts in the parsers — count accumulators initialised to zero,
    not ranks.
"""
from typing import Dict, Iterable, List, Optional

__all__ = [
    "SEVERITY_RANK",
    "UNKNOWN_RANK",
    "severity_rank",
    "compare_severity",
    "severities_by_rank",
    "worst_severity",
]

# The canonical scale. Higher = more severe.
#
# `error` sits below `info`: a scan that failed is not a finding about the
# target, and ranking it above informational results would push real output down.
# `recon` is the pre-2026-08-22 name for `info` and ranks identically, so rows
# written before that migration sort correctly instead of falling to unknown.
SEVERITY_RANK: Dict[str, int] = {
    "critical": 6,
    "high": 5,
    "medium": 4,
    "low": 3,
    "info": 2,
    "error": 1,
    "recon": 2,      # legacy alias for info
}

# Unknown, empty and NULL all rank here, so they sort LAST in a descending sort.
# The copies this replaces used `?? 0`, `ELSE 0`, `ELSE 4`, `ELSE 5` and `ELSE 7`
# for the same intent, in both directions.
UNKNOWN_RANK = 0


def severity_rank(severity: Optional[str]) -> int:
    """Numeric rank for a severity string. Higher is more severe.

    Case-insensitive and whitespace-tolerant, because scanner output is neither.
    Returns UNKNOWN_RANK for None, empty or unrecognised values.
    """
    if not severity:
        return UNKNOWN_RANK
    return SEVERITY_RANK.get(str(severity).strip().lower(), UNKNOWN_RANK)


def compare_severity(a: Optional[str], b: Optional[str]) -> int:
    """Comparator giving most-severe-first. Negative when `a` is worse."""
    return severity_rank(b) - severity_rank(a)


def severities_by_rank(include_legacy: bool = False) -> List[str]:
    """Severity names, most severe first. Legacy aliases excluded by default."""
    names = [s for s in SEVERITY_RANK if include_legacy or s != "recon"]
    return sorted(names, key=lambda s: (-SEVERITY_RANK[s], s))


def worst_severity(severities: Optional[Iterable[Optional[str]]]) -> Optional[str]:
    """The most severe of the given values, or None if none are recognised."""
    best, best_rank = None, UNKNOWN_RANK
    for s in severities or ():
        r = severity_rank(s)
        if r > best_rank:
            best, best_rank = s, r
    return best
