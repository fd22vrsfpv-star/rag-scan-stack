"""etl/approval_match.py — the wildcard grammar behind approval rules.

Run on demand:

    pytest tests/test_approval_match.py -v

WHY THIS EXISTS
---------------
Two approval surfaces route through this one module: standing exploit-approval
rules, and credential spray approvals. Both decide whether an impactful action
against a live host is authorised, so the matcher's edge cases are not
cosmetic — a pattern that matches more than the operator meant is an
unauthorised action, and one that matches less silently blocks work.

The three that actually bite:

  * **NULL.** `pending_exploits.exploit_type` is nullable. A catch-all matches
    NULL; a glob or a literal must NOT. If `web*` swept up untyped rows, an
    operator approving "web exploits" would also have approved everything the
    classifier could not label — the opposite of what they asked for.
  * **Specificity.** Rules overlap. An exact rule must beat a glob, and a glob
    must beat a catch-all, or "approve all, except this one" is unexpressible.
  * **Deny wins ties.** At equal specificity the DENY must win. A revocation
    that can be outvoted by a broader allow is not a revocation.

No database and no stack: pure logic, so it runs anywhere.
"""
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "etl"))

approval_match = pytest.importorskip(
    "approval_match", reason="etl/approval_match.py not importable")

matches = approval_match.matches
specificity = approval_match.specificity
is_catch_all = approval_match.is_catch_all
best_match = approval_match.best_match
match_score = approval_match.match_score
alternatives = approval_match.alternatives

EXACT, GLOB, CATCH_ALL = 2, 1, 0


# ── The grammar ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("pattern,value,expected", [
    ("rce", "rce", EXACT),
    ("RCE", "rce", EXACT),              # case-insensitive
    ("rce", " rce ", EXACT),            # values are stripped
    ("rce", "sqli", None),
    ("all", "anything", CATCH_ALL),
    ("any", "anything", CATCH_ALL),
    ("*", "anything", CATCH_ALL),
    ("%", "anything", CATCH_ALL),       # SQL-style wildcard, as the UI teaches
    ("", "anything", CATCH_ALL),        # an omitted field means "all"
    (None, "anything", CATCH_ALL),
    ("web*", "webapp_other", GLOB),
    ("web*", "rce", None),
    ("*injection", "command_injection", GLOB),
    ("*x*", "xxe", GLOB),
    ("s?li", "sqli", GLOB),             # single-char wildcard
    ("rce,sqli", "sqli", EXACT),        # list of alternatives
    ("rce,sqli", "xss", None),
    ("rce,*", "rce", EXACT),            # the MOST specific alternative scores
])
def test_specificity(pattern, value, expected):
    assert specificity(pattern, value) == expected
    assert matches(pattern, value) is (expected is not None)


@pytest.mark.parametrize("pattern,expected", [
    ("all", True), ("*", True), ("%", True), ("", True), (None, True),
    ("rce,all", True),      # a list containing a catch-all IS a catch-all
    ("rce", False), ("web*", False),
])
def test_is_catch_all(pattern, expected):
    assert is_catch_all(pattern) is expected


# ── NULL: the case that decides whether a wildcard over-approves ───────────

@pytest.mark.parametrize("pattern,should_match", [
    ("all", True), ("*", True), ("", True), (None, True),
    ("web*", False),        # a glob must NOT sweep up untyped rows
    ("rce", False),
    ("rce,sqli", False),
])
def test_null_value_matches_only_a_catch_all(pattern, should_match):
    """`pending_exploits.exploit_type` is nullable and untyped rows are real."""
    assert matches(pattern, None) is should_match


# ── Resolution between overlapping rules ───────────────────────────────────

def test_exact_rule_beats_catch_all():
    rows = [{"username": "all", "service": "all", "approved": True},
            {"username": "root", "service": "ssh", "approved": False}]
    won = best_match(rows, ["root", "ssh"], pattern_fields=["username", "service"])
    assert won["approved"] is False, "the specific rule must win over 'all'"


def test_deny_wins_an_equal_specificity_tie():
    """Otherwise 'approve all, except X' is not expressible."""
    rows = [{"t": "all", "approved": True}, {"t": "all", "approved": False}]
    assert best_match(rows, ["rce"], pattern_fields=["t"])["approved"] is False
    # ...and the order the rows arrive in must not change the verdict.
    assert best_match(list(reversed(rows)), ["rce"],
                      pattern_fields=["t"])["approved"] is False


def test_glob_beats_catch_all_but_loses_to_exact():
    rows = [{"t": "all", "id": "catch"},
            {"t": "web*", "id": "glob"},
            {"t": "webapp_other", "id": "exact"}]
    assert best_match(rows, ["webapp_other"], pattern_fields=["t"],
                      deny_field=None)["id"] == "exact"
    assert best_match(rows[:2], ["webapp_other"], pattern_fields=["t"],
                      deny_field=None)["id"] == "glob"


def test_no_rule_matches_returns_none():
    """None means 'unmatched', which callers must not confuse with 'approved'."""
    rows = [{"username": "root", "service": "all", "approved": True}]
    assert best_match(rows, ["admin", "ssh"],
                      pattern_fields=["username", "service"]) is None


def test_dimensions_are_anded():
    """A rule naming username svc_* AND service ssh must not apply to smb."""
    assert match_score(["svc_*", "ssh"], ["svc_backup", "smb"]) is None
    assert match_score(["svc_*", "ssh"], ["svc_backup", "ssh"]) == GLOB + EXACT


def test_misaligned_dimensions_raise():
    """A silent zip() truncation would evaluate a rule against fewer dimensions
    than it declares, which is an over-broad match by construction."""
    with pytest.raises(ValueError):
        match_score(["a"], ["x", "y"])


def test_alternatives_parsing():
    assert alternatives("rce, sqli ,") == ["rce", "sqli"]
    assert alternatives(None) == [""]
    assert alternatives(["RCE", "Sqli"]) == ["rce", "sqli"]


def test_empty_rule_set_matches_nothing():
    """Fail closed: no rules must never read as 'everything is approved'."""
    assert best_match([], ["rce"], pattern_fields=["t"]) is None
