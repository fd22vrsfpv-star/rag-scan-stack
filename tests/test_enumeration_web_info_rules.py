"""Deepen INFORMATIONAL web findings (deterministic tier).

Info/low web findings were stored and never acted on. These tests pin:
  * _matches gained list (any-of) and {contains: ...} semantics, without
    breaking the existing exact/bool matching.
  * facts_from_web_findings now carries `issue_type` so rules can key off WHAT a
    finding is, not only severity.
  * the new enumeration_rules.yaml info-finding rules fire on a matching info
    finding and DON'T fire when severity/name don't match.

SABOTAGE PROOF
--------------
Remove the `contains` branch from _matches and test_matches_contains fails.
Drop the web-info-disclosure-capture rule and test_info_rule_fires fails.

Run on demand:  pytest tests/test_enumeration_web_info_rules.py -v
"""
import os
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

pe = pytest.importorskip("etl.post_enumeration")


# ── matcher semantics ────────────────────────────────────────────────────────
def _rule(where):
    return {"when": {"fact": "web_finding", "where": where}}


def test_matches_exact_and_bool_still_work():
    assert pe._matches(_rule({"severity": "info"}), {"fact": "web_finding", "severity": "info"})
    assert not pe._matches(_rule({"severity": "high"}), {"fact": "web_finding", "severity": "info"})
    assert pe._matches({"when": {"fact": "share", "where": {"writable": True}}},
                       {"fact": "share", "writable": True})


def test_matches_list_any_of():
    r = _rule({"severity": ["info", "low"]})
    assert pe._matches(r, {"fact": "web_finding", "severity": "low"})
    assert not pe._matches(r, {"fact": "web_finding", "severity": "medium"})


def test_matches_contains():
    r = _rule({"name": {"contains": "information disclosure"}})
    assert pe._matches(r, {"fact": "web_finding", "name": "Information Disclosure - Debug"})
    assert not pe._matches(r, {"fact": "web_finding", "name": "XSS reflected"})


# ── fact enrichment ──────────────────────────────────────────────────────────
class _Cur:
    def execute(self, *a, **k):
        pass

    def fetchall(self):
        # Mirrors facts_from_web_findings SELECT: id, ip, url, severity, name,
        # issue_type, method, payload.
        return [("wid1", "10.0.0.9", "http://10.0.0.9/x", "info",
                 "Directory Browsing", "dir-listing", "GET", "")]


def test_facts_carry_issue_type():
    facts = pe.facts_from_web_findings(_Cur(), target="10.0.0.9")
    assert facts and facts[0]["issue_type"] == "dir-listing"
    assert facts[0]["name"] == "Directory Browsing" and facts[0]["severity"] == "info"


# ── the info rules fire selectively ──────────────────────────────────────────
def _web_rules():
    rules = [r for r in pe.load_rules() if (r.get("when") or {}).get("fact") == "web_finding"]
    if not rules:
        pytest.skip("no web_finding rules loaded")
    return rules


def _fires(rules, fact):
    return {r.get("id") for r in rules if pe._matches(r, fact)}


def test_info_rule_fires():
    rules = _web_rules()
    fired = _fires(rules, {"fact": "web_finding", "severity": "info",
                           "name": "Information Disclosure - Sensitive Info", "issue_type": "info-leak"})
    assert "web-info-disclosure-capture" in fired


def test_info_rule_not_fired_on_high_severity():
    # same name, but high severity is out of the info/low list -> the info rule
    # must not fire (high-severity has its own rule).
    rules = _web_rules()
    fired = _fires(rules, {"fact": "web_finding", "severity": "high",
                           "name": "Information Disclosure - Sensitive Info", "issue_type": "info-leak"})
    assert "web-info-disclosure-capture" not in fired


def test_exposed_vcs_rule_fires_any_severity():
    rules = _web_rules()
    fired = _fires(rules, {"fact": "web_finding", "severity": "info",
                           "name": "Exposed .git directory", "issue_type": "exposed"})
    assert "web-exposed-vcs-capture" in fired
