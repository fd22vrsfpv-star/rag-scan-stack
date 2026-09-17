"""The enumeration LLM router: per-role model routing, triage, and fact review.

WHY THIS EXISTS
---------------
Enumeration uses the LLM for two roles — EXTRACTION (facts from output the
deterministic extractors missed) and REVIEW (validate candidate facts before they
are queued). The router (a) picks the model/params per role from operator config
and (b) triages so the LLM runs only when it adds value. The risks are: the LLM
run when deterministic extraction already succeeded (waste), a review that drops
real findings on an error (data loss), and a review that pays to re-check
high-confidence deterministic facts. This pins all three.

WHAT IS PROVEN
--------------
  * route() returns per-role params, and an app_settings override wins over the
    code default.
  * should_extract() triage: only when there are NO deterministic facts, output
    is substantive, and the role is enabled.
  * extract() validates to the allowed fact vocabulary (disallowed kind / empty
    value dropped).
  * review() drops the facts the LLM rejects, keeps the rest, and FAILS OPEN
    (keeps everything) on a bad/empty response.
  * review() under "uncertain" scope does not spend a call on a high-confidence
    deterministic fact.

SABOTAGE PROOF
--------------
Make review() fail closed (return [] on error) and test_review_fails_open fails.
Make should_extract() ignore existing facts and
test_triage_skips_when_deterministic_facts_exist fails.

Run on demand:

    pytest tests/test_enumeration_llm_router.py -v
"""
import os
import sys
import types

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

mod = pytest.importorskip("etl.enumeration_llm_router")


class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload, self.status_code, self.text = payload, status, str(payload)

    def json(self):
        return self._payload


def _fake_requests(monkeypatch, content):
    calls = {"n": 0}

    def _post(url, json=None, timeout=None, verify=None, headers=None):
        calls["n"] += 1
        return _FakeResp({"message": {"content": content}})

    fake = types.ModuleType("requests")
    fake.post = _post
    monkeypatch.setitem(sys.modules, "requests", fake)
    return calls


class _FakeCur:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, *a, **k):
        pass

    def fetchall(self):
        return self._rows

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def __init__(self, rows):
        self._rows = rows

    def cursor(self):
        return _FakeCur(self._rows)

    def close(self):
        pass


def _router(rows=None):
    # Fresh instance per test so the settings cache does not bleed across tests.
    return mod.EnumerationLLMRouter(connect=(lambda: _FakeConn(rows or [])))


def test_route_defaults_and_override():
    r = _router()
    ex = r.route("extraction")
    assert ex["enabled"] is True and ex["model"] is None and ex["max_tokens"] == 600
    # override via app_settings
    r2 = _router(rows=[("enum_router.extraction.model", "gemma4:26b"),
                       ("enum_router.review.enabled", "false")])
    assert r2.route("extraction")["model"] == "gemma4:26b"
    assert r2.route("review")["enabled"] is False


def test_triage_skips_when_deterministic_facts_exist():
    r = _router()
    long_out = "x" * 200
    assert r.should_extract(long_out, [{"fact": "share"}]) is False
    assert r.should_extract(long_out, []) is True
    assert r.should_extract("tiny", []) is False          # below min_chars


def test_triage_respects_disabled():
    r = _router(rows=[("enum_router.extraction.enabled", "false")])
    assert r.should_extract("x" * 200, []) is False


def test_extract_validates(monkeypatch):
    _fake_requests(monkeypatch,
                   '{"facts":[{"fact":"secret","kind":"api_token","value":"tok_1"},'
                   '{"fact":"port","value":"8080"},'
                   '{"fact":"secret","value":""}]}')
    facts = _router().extract("x" * 100, target="10.0.0.7")
    assert [f["fact"] for f in facts] == ["secret"]
    assert facts[0]["source"] == "llm_fallback"


def test_review_drops_false_positives(monkeypatch):
    _fake_requests(monkeypatch,
                   '{"verdicts":[{"i":0,"keep":true,"confidence":"high","reason":"real"},'
                   '{"i":1,"keep":false,"confidence":"high","reason":"placeholder"}]}')
    facts = [
        {"fact": "secret", "kind": "generic", "value": "AbCdEf123456", "source": "llm_fallback"},
        {"fact": "secret", "kind": "generic", "value": "changeme", "source": "llm_fallback"},
    ]
    res = _router().review(facts, output="config dump", target="10.0.0.7")
    assert res["reviewed"] == 2 and res["dropped"] == 1
    assert len(res["facts"]) == 1 and res["facts"][0]["value"] == "AbCdEf123456"
    assert res["facts"][0]["review"]["kept"] is True


def test_review_fails_open(monkeypatch):
    _fake_requests(monkeypatch, "not json at all")
    facts = [{"fact": "secret", "kind": "generic", "value": "x", "source": "llm_fallback"}]
    res = _router().review(facts, output="ctx", target="10.0.0.7")
    # bad response => keep everything, drop nothing
    assert res["facts"] == facts and res["dropped"] == 0


def test_review_uncertain_scope_skips_high_confidence(monkeypatch):
    calls = _fake_requests(monkeypatch, '{"verdicts":[]}')
    # a deterministic, non-generic, non-llm fact is NOT uncertain -> not reviewed,
    # so no LLM call is made under the default "uncertain" scope.
    facts = [{"fact": "file", "kind": "private_key", "value": "/root/.ssh/id_rsa",
              "source": "extractor"}]
    res = _router().review(facts, output="ctx", target="10.0.0.7")
    assert res["reviewed"] == 0 and res["facts"] == facts
    assert calls["n"] == 0, "no LLM call for a high-confidence deterministic fact"


def test_review_all_scope_reviews_everything(monkeypatch):
    _fake_requests(monkeypatch, '{"verdicts":[{"i":0,"keep":true,"confidence":"high"}]}')
    r = _router(rows=[("enum_router.review.scope", "all")])
    facts = [{"fact": "file", "kind": "private_key", "value": "/root/.ssh/id_rsa",
              "source": "extractor"}]
    res = r.review(facts, output="ctx", target="10.0.0.7")
    assert res["reviewed"] == 1
