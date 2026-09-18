"""Promotion: a shape the LLM repeatedly discovers becomes a permanent,
operator-approved, deterministic extractor — stored in the SHARED extractor_learned
table (tool=_enumeration), not a parallel one.

WHY THIS EXISTS
---------------
The LLM fallback re-derives an unknown shape every time (bounded by the router
budget). Promotion closes the loop: a confirmed, specific-kind secret is proposed
as a learned extractor; once an operator approves it (status='active'),
load_extractors() picks it up and the shape is caught for free, deterministically.
This must reuse the existing extractor_learned store (one review surface), and a
one-off or a vague "generic" must never be promoted.

WHAT IS PROVEN
--------------
  * _synthesize_regex generalizes a sample into a precise regex that matches it,
    and refuses too-short / unusable input.
  * propose_learned_extractor refuses unpromotable kinds (generic/llm/unknown) and,
    for a specific kind, writes a proposed row whose rule carries the synthesized
    pattern and the right emit shape.
  * _load_promoted_extractors compiles approved rows into usable extractors.

SABOTAGE PROOF
--------------
Add "generic" back as promotable and test_unpromotable_kinds_refused fails.
Make _synthesize_regex return the literal value and
test_synthesize_generalizes fails.

Run on demand:

    pytest tests/test_enumeration_promotion.py -v
"""
import os
import re
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

pe = pytest.importorskip("etl.post_enumeration")


# ── regex synthesis (no DB) ──────────────────────────────────────────────────
def test_synthesize_generalizes():
    pat = pe._synthesize_regex("AKIAIOSFODNN7EXAMPLE")
    assert pat and re.compile(pat).search("AKIAIOSFODNN7EXAMPLE")
    # it is generalized, not the literal value
    assert "AKIA" not in pat
    assert "[A-Z]" in pat and "{" in pat


def test_synthesize_refuses_unusable():
    assert pe._synthesize_regex("abc") is None          # too short
    assert pe._synthesize_regex("") is None
    assert pe._synthesize_regex("x" * 500) is None      # too long


# ── proposal writer (fake DB) ────────────────────────────────────────────────
class _FakeCur:
    # sightings: what _count_kind_sightings sees; insert_status: status the
    # INSERT ... RETURNING reports back.
    def __init__(self, store, sightings=0, insert_status="proposed"):
        self.store = store
        self._sightings = sightings
        self._insert_status = insert_status

    def execute(self, sql, params=None):
        self.store.append((sql, params))
        self._last = sql

    def fetchone(self):
        last = getattr(self, "_last", "")
        if "count(*)" in last and "enumeration_observations" in last:
            return (self._sightings,)
        if "INSERT INTO public.extractor_learned" in last:
            return ("fake-row-id", self._insert_status)
        return None

    def fetchall(self):
        return []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def __init__(self, store, sightings=0, insert_status="proposed"):
        self.store = store
        self._sightings = sightings
        self._insert_status = insert_status

    def cursor(self):
        return _FakeCur(self.store, self._sightings, self._insert_status)

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_unpromotable_kinds_refused(monkeypatch):
    calls = []
    monkeypatch.setattr(pe, "_connect", lambda: _FakeConn(calls))
    for k in ("generic", "llm", "unknown", ""):
        assert pe.propose_learned_extractor(k, "AKIAIOSFODNN7EXAMPLE") is None
    assert calls == [], "no DB write for an unpromotable kind"


def test_no_regex_no_proposal(monkeypatch):
    calls = []
    monkeypatch.setattr(pe, "_connect", lambda: _FakeConn(calls))
    # a value too short to synthesize a pattern -> no proposal
    assert pe.propose_learned_extractor("api_token", "abc") is None
    assert calls == []


def test_specific_kind_proposes_with_pattern(monkeypatch):
    calls = []
    monkeypatch.setattr(pe, "_connect", lambda: _FakeConn(calls))
    monkeypatch.setattr(pe, "_emit_webhook", lambda *a, **k: None)
    rid = pe.propose_learned_extractor("aws_access_key", "AKIAIOSFODNN7EXAMPLE",
                                       why="cloud cred")
    assert rid == "fake-row-id"
    # the INSERT carried a rule with the synthesized pattern + emit shape
    inserts = [p for (s, p) in calls if "INSERT INTO public.extractor_learned" in s]
    assert inserts, "no INSERT issued"
    # params tuple is (tool, Json(rule), source); rule is index 1
    rule_param = inserts[0][1]
    rule = rule_param.adapted if hasattr(rule_param, "adapted") else rule_param
    # Json(x) fallback returns the dict directly in the test env
    assert isinstance(rule, dict)
    assert rule["emit"] == {"fact": "secret", "kind": "aws_access_key"}
    assert re.compile(rule["match"]).search("AKIAIOSFODNN7EXAMPLE")


def test_auto_approve_after_threshold(monkeypatch):
    # threshold met (sightings 3 >= 3) -> INSERT lands 'active', embed is called.
    calls = []
    embedded = {"n": 0}
    monkeypatch.setattr(pe, "_connect",
                        lambda: _FakeConn(calls, sightings=3, insert_status="active"))
    monkeypatch.setattr(pe, "_emit_webhook", lambda *a, **k: None)
    monkeypatch.setattr(pe, "_embed_learned_to_rag",
                        lambda: embedded.__setitem__("n", embedded["n"] + 1))
    rid = pe.propose_learned_extractor("aws_access_key", "AKIAIOSFODNN7EXAMPLE",
                                       auto_approve_after=3)
    assert rid == "fake-row-id"
    ins = [p for (s, p) in calls if "INSERT INTO public.extractor_learned" in s][0]
    # 3rd INSERT param is the status the row is created with
    assert ins[2] == "active", f"expected active status, got {ins[2]}"
    assert embedded["n"] == 1, "auto-approve must embed into RAG"


def test_auto_approve_below_threshold_stays_proposed(monkeypatch):
    calls = []
    embedded = {"n": 0}
    monkeypatch.setattr(pe, "_connect",
                        lambda: _FakeConn(calls, sightings=1, insert_status="proposed"))
    monkeypatch.setattr(pe, "_emit_webhook", lambda *a, **k: None)
    monkeypatch.setattr(pe, "_embed_learned_to_rag",
                        lambda: embedded.__setitem__("n", embedded["n"] + 1))
    pe.propose_learned_extractor("aws_access_key", "AKIAIOSFODNN7EXAMPLE",
                                 auto_approve_after=3)  # only 1 sighting < 3
    ins = [p for (s, p) in calls if "INSERT INTO public.extractor_learned" in s][0]
    assert ins[2] == "proposed"
    assert embedded["n"] == 0, "no RAG embed when it stays proposed"


def test_default_is_manual_no_auto(monkeypatch):
    # auto_approve_after=0 (default) -> never auto, regardless of sightings.
    calls = []
    monkeypatch.setattr(pe, "_connect",
                        lambda: _FakeConn(calls, sightings=99, insert_status="proposed"))
    monkeypatch.setattr(pe, "_emit_webhook", lambda *a, **k: None)
    pe.propose_learned_extractor("aws_access_key", "AKIAIOSFODNN7EXAMPLE")
    ins = [p for (s, p) in calls if "INSERT INTO public.extractor_learned" in s][0]
    assert ins[2] == "proposed", "default must stay manual even with many sightings"
    # and the count query is never even needed to force active
    assert calls, "an INSERT should still happen"


def test_load_promoted_compiles_active_rows(monkeypatch):
    active_rule = {"id": "learned-jwt", "match": r"eyJ[A-Za-z]{3}",
                   "emit": {"fact": "secret", "kind": "jwt"}, "fields": {"value": 0}}

    class _Cur(_FakeCur):
        def fetchall(self):
            return [(active_rule,)]

    class _Conn(_FakeConn):
        def cursor(self):
            return _Cur(self.store)

    monkeypatch.setattr(pe, "_connect", lambda: _Conn([]))
    pe._PROMOTED_CACHE = None            # bypass cache
    pe._PROMOTED_CACHE_AT = 0.0
    got = pe._load_promoted_extractors()
    assert len(got) == 1
    assert got[0]["_promoted"] is True and got[0]["_rx"].search("eyJabc")
