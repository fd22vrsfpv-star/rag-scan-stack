"""The LLM fallback classifies output that matched NO known extractor into
STRUCTURED facts, and it stays inside the vocabulary the rules speak.

WHY THIS EXISTS
---------------
Extractors + rules are deterministic and cover known shapes. Output that matches
nothing used to be stored and dropped. The fallback hands that output to the LLM
to classify into facts that re-enter the SAME rules -> scope gate -> pending
path. The risk is the LLM inventing fact kinds nothing consumes or values that
were never in the output; this pins the validation that prevents both, without a
live LLM (requests is faked) or a database.

WHAT IS PROVEN
--------------
  * A well-formed LLM response yields validated facts tagged source=llm_fallback.
  * A fact kind outside the allowed vocabulary is dropped (no hallucinated shape
    reaches the queue), and an empty value is dropped.
  * Output shorter than the minimum is not sent to the LLM at all (returns []).
  * _record_secret_facts records every `secret` fact as an observation even when
    no rule matched (a token must not vanish).

SABOTAGE PROOF
--------------
Add "port" to _LLM_ALLOWED_FACTS and test_disallowed_fact_kind_dropped fails.
Make _record_secret_facts skip secrets and test_secret_facts_recorded fails.

Run on demand:

    pytest tests/test_enumeration_llm_fallback.py -v
"""
import os
import sys
import types

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

pe = pytest.importorskip("etl.post_enumeration")


class _FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.text = str(payload)

    def json(self):
        return self._payload


def _install_fake_requests(monkeypatch, payload, status=200):
    captured = {}

    def _post(url, json=None, timeout=None, verify=None, headers=None):
        captured["url"] = url
        captured["body"] = json
        return _FakeResp(payload, status)

    fake = types.ModuleType("requests")
    fake.post = _post
    monkeypatch.setitem(sys.modules, "requests", fake)
    return captured


def test_wellformed_response_yields_validated_facts(monkeypatch):
    monkeypatch.setattr(pe, "LLM_FALLBACK_ENABLED", True)
    _install_fake_requests(monkeypatch, {"message": {"content":
        '{"facts":[{"fact":"secret","kind":"api_token","value":"tok_abc123",'
        '"why":"grants API access"}]}'}})
    facts = pe._llm_classify_output("some long unmatched output " * 3,
                                    tool="custom", target="10.0.0.7", service="http")
    assert len(facts) == 1
    f = facts[0]
    assert f["fact"] == "secret" and f["kind"] == "api_token"
    assert f["value"] == "tok_abc123"
    assert f["source"] == "llm_fallback" and f["target"] == "10.0.0.7"


def test_disallowed_fact_kind_dropped(monkeypatch):
    monkeypatch.setattr(pe, "LLM_FALLBACK_ENABLED", True)
    _install_fake_requests(monkeypatch, {"message": {"content":
        '{"facts":[{"fact":"port","value":"8080"},'
        '{"fact":"secret","value":""},'
        '{"fact":"host","kind":"lead","value":"192.168.5.5","why":"reachable"}]}'}})
    facts = pe._llm_classify_output("x" * 80, target="10.0.0.7")
    # port is not allowed; empty-value secret dropped; only the host survives.
    kinds = [(f["fact"]) for f in facts]
    assert kinds == ["host"]
    assert facts[0]["target"] == "192.168.5.5" and facts[0]["seen_on"] == "10.0.0.7"


def test_short_output_not_sent(monkeypatch):
    monkeypatch.setattr(pe, "LLM_FALLBACK_ENABLED", True)
    called = {"n": 0}

    def _post(*a, **k):
        called["n"] += 1
        return _FakeResp({"message": {"content": '{"facts":[]}'}})

    fake = types.ModuleType("requests")
    fake.post = _post
    monkeypatch.setitem(sys.modules, "requests", fake)
    assert pe._llm_classify_output("short", target="10.0.0.7") == []
    assert called["n"] == 0, "LLM must not be called for sub-minimum output"


def test_disabled_returns_empty(monkeypatch):
    monkeypatch.setattr(pe, "LLM_FALLBACK_ENABLED", False)
    assert pe._llm_classify_output("x" * 200, target="10.0.0.7") == []


class _FakeCur:
    def __init__(self):
        self.calls = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))


def test_secret_facts_recorded(monkeypatch):
    # _observe does the psycopg2 write; stub it so this tests the SELECTION logic
    # (which facts are recorded) without a database driver.
    observed = []
    monkeypatch.setattr(pe, "_observe",
                        lambda cur, rid, ex, fact, cmd, rec: observed.append((rid, fact)))
    cur = _FakeCur()
    facts = [
        {"fact": "secret", "kind": "jwt", "value": "eyJ...", "target": "10.0.0.7"},
        {"fact": "host", "target": "192.168.9.9"},          # not a secret
        {"fact": "secret", "kind": "aws_key", "value": "AKIA...", "target": "10.0.0.7"},
    ]
    n = pe._record_secret_facts(cur, facts, {"tool": "env", "target": "10.0.0.7"})
    assert n == 2, "both secret facts should be recorded, the host skipped"
    assert [rid for rid, _ in observed] == ["secret:jwt", "secret:aws_key"]
