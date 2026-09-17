"""Output→fact extraction is DATA (knowledge/enumeration_extractors.yaml), not
regexes hardcoded in facts_from().

WHY THIS EXISTS
---------------
knowledge/enumeration_rules.yaml already turns a FACT into a proposed next step
without a code change. But a rule only fires if a fact of the right shape was
produced first, and fact extraction from free-text output was three hardcoded
regexes — so a web token or an AWS key in a config dump produced NO fact and no
rule could ever match it. These extractors close that gap one layer down, and
they are data so a new secret shape is added without touching Python.

WHAT IS PROVEN
--------------
  * The YAML actually loads and compiles (more extractors than the 3-item
    fallback), so the file is wired in — not silently falling back.
  * The three behaviours carried over from the old hardcoded regexes are
    unchanged: a private-key block, an id_* key path, and a known_hosts IP LEAD
    (with self / loopback / broadcast skipped).
  * The new token/secret shapes the operator asked for produce `secret` facts
    with the right `kind` and the captured value.

SABOTAGE PROOF
--------------
Delete the `jwt` extractor from the YAML and `test_new_token_shapes` fails.
Break the `known-host-ip` `lead:` flag and `test_known_host_is_a_lead` fails
(self/loopback would leak through as a target).

Run on demand:

    pytest tests/test_enumeration_extractors.py -v
"""
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

pe = pytest.importorskip("etl.post_enumeration")


def _facts(output, *, target="10.0.0.5", service="ssh"):
    return pe.facts_from({}, output=output, target=target, service=service)


def _kinds(facts, fact_type):
    return {f.get("kind") for f in facts if f.get("fact") == fact_type}


def test_yaml_loads_and_is_more_than_fallback():
    ex = pe.load_extractors()
    ids = {e.get("id") for e in ex}
    # The 3-item hardcoded fallback would mean the YAML did not load.
    assert len(ex) > 3, f"extractor YAML not loaded — only {ids}"
    assert {"private-key-block", "known-host-ip", "jwt"} <= ids


def test_private_key_block_still_extracted():
    facts = _facts("-----BEGIN RSA PRIVATE KEY-----")
    assert any(f["fact"] == "file" and f.get("kind") == "private_key"
               for f in facts)


def test_ssh_key_path_captured():
    facts = _facts("found key at /home/msfadmin/.ssh/id_rsa on disk")
    paths = [f.get("path") for f in facts
             if f["fact"] == "file" and f.get("kind") == "private_key"]
    assert "/home/msfadmin/.ssh/id_rsa" in paths


def test_known_host_is_a_lead():
    # 10.0.0.5 is self (target), 127.0.0.1 loopback, 255.x broadcast → skipped.
    # 192.168.9.9 is a real lead.
    facts = _facts("known hosts: 10.0.0.5 127.0.0.1 255.255.255.255 192.168.9.9")
    leads = {f["target"] for f in facts
             if f["fact"] == "host" and f.get("source") == "known_hosts"}
    assert leads == {"192.168.9.9"}, leads
    for f in facts:
        if f["fact"] == "host":
            assert f.get("seen_on") == "10.0.0.5"


def test_new_token_shapes():
    facts = _facts(
        "Authorization: Bearer abcdef0123456789abcdef0123\n"
        "token=eyJhbGciOiJI.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4\n"
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "DATABASE_URL=postgres://app:s3cr3tpw@db.internal:5432/scans\n"
    )
    kinds = _kinds(facts, "secret")
    assert {"jwt", "aws_access_key", "bearer_token", "db_url"} <= kinds, kinds
    # the value is captured, not just the kind
    jwt = [f["value"] for f in facts if f.get("kind") == "jwt"]
    assert jwt and jwt[0].startswith("eyJ")


def test_generic_secret_assignment_low_confidence():
    facts = _facts('api_key: "AbCdEf123456ghij"')
    assert "generic" in _kinds(facts, "secret")


def test_no_output_no_crash():
    assert pe.facts_from({}, output="", target="10.0.0.5") == []
