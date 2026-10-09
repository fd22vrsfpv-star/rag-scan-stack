"""Tests for app/rag-api/scope_pivot_agent.py — cert-pivot + ASN-pivot.

Covers both the pure helpers and the two DB-writing entry points
(run_cert_pivot / run_asn_pivot), the latter driven through a FAKE
connection so the REAL generator logic executes end-to-end without a
live Postgres. Fixtures use the real stored shapes:

  * tlsx    recon_findings.data: {subject_cn, subject_an:[...], ...}
  * asnmap  recon_findings.data: {as_number, as_name, as_range:[...]}

Sabotage-proven:
  * Flip NEW_FOR_REVIEW_SCOPE to 'default' → test_cert_pivot_writes_new_for_review
    and test_asn_pivot_writes_new_for_review fail (wrong suggested_scope).
  * Drop the cloud/CDN filter in run_asn_pivot (suggest every range) →
    test_asn_pivot_drops_cloud_cdn fails (the AWS range leaks through).
  * Drop the "different registrable domain" guard in run_cert_pivot
    (keep same-org SANs) → test_cert_pivot_skips_same_domain fails.

Standalone: `pytest tests/test_scope_pivot_cert_asn.py`. Skips cleanly
if psycopg2 is not importable in this environment.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("psycopg2", reason="scope_pivot_agent imports psycopg2.extras")

_mod_path = Path(__file__).parent.parent / "app" / "rag-api" / "scope_pivot_agent.py"
_spec = importlib.util.spec_from_file_location("scope_pivot_agent", _mod_path)
scope_pivot_agent = importlib.util.module_from_spec(_spec)
sys.modules["scope_pivot_agent"] = scope_pivot_agent
_spec.loader.exec_module(scope_pivot_agent)

run_cert_pivot = scope_pivot_agent.run_cert_pivot
run_asn_pivot = scope_pivot_agent.run_asn_pivot
NEW_FOR_REVIEW_SCOPE = scope_pivot_agent.NEW_FOR_REVIEW_SCOPE
_registrable = scope_pivot_agent._registrable
_extract_cert_names = scope_pivot_agent._extract_cert_names
_as_range_list = scope_pivot_agent._as_range_list
_org_tokens = scope_pivot_agent._org_tokens

EID = "11111111-1111-1111-1111-111111111111"


# ─── fake connection ────────────────────────────────────────────────────────

class _FakeCursor:
    """Routes each SELECT by keyword to a canned result set; records
    INSERTed scope_suggestions so assertions can inspect them."""

    def __init__(self, store):
        self.store = store
        self._last = None
        self._result = []

    def execute(self, sql, params=None):
        self._last = sql
        s = " ".join(sql.split())
        if "FROM public.scope_targets" in s and "target_type = 'cidr'" in s:
            self._result = [{"target": c} for c in self.store["existing_cidrs"]]
        elif "FROM public.scope_targets" in s:
            self._result = self.store["scope_targets"]
        elif "FROM public.assets" in s:
            self._result = self.store["assets"]
        elif "FROM public.engagements" in s:
            self._result = [{"name": self.store.get("engagement_name", "")}]
        elif "FROM public.scope_suggestions" in s:
            self._result = [{"target": t} for t in self.store["existing_suggestions"]]
        elif "FROM public.recon_findings" in s and "source = 'asnmap'" in s:
            self._result = self.store["asnmap"]
        elif "FROM public.recon_findings" in s:
            self._result = self.store["certs"]
        elif s.startswith("INSERT INTO public.scope_suggestions"):
            target, scope, conf, reasoning, method = params[0], params[1], params[2], params[3], params[4]
            self.store["written"].append({
                "target": target, "suggested_scope": scope,
                "confidence": conf, "reasoning": reasoning, "method": method,
            })
            self.rowcount = 1
            self._result = []
        else:
            self._result = []

    @property
    def rowcount(self):
        return getattr(self, "_rowcount", 0)

    @rowcount.setter
    def rowcount(self, v):
        self._rowcount = v

    def fetchall(self):
        return list(self._result)

    def fetchone(self):
        return self._result[0] if self._result else None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def __init__(self, store):
        self.store = store
        self.committed = False

    def cursor(self, cursor_factory=None):
        return _FakeCursor(self.store)

    def commit(self):
        self.committed = True

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _make_get_db(store):
    store.setdefault("scope_targets", [])
    store.setdefault("assets", [])
    store.setdefault("existing_suggestions", [])
    store.setdefault("existing_cidrs", [])
    store.setdefault("certs", [])
    store.setdefault("asnmap", [])
    store.setdefault("written", [])
    store.setdefault("engagement_name", "")

    def _get_db():
        return _FakeConn(store)
    return _get_db


# ─── pure helpers ───────────────────────────────────────────────────────────

def test_new_for_review_scope_constant():
    assert NEW_FOR_REVIEW_SCOPE == "new_for_review"


def test_registrable_last_two_labels():
    assert _registrable("www.sub.testfire.net") == "testfire.net"
    assert _registrable("*.testfire.net") == "testfire.net"
    assert _registrable("TESTFIRE.NET.") == "testfire.net"
    assert _registrable("localhost") == ""


def test_extract_cert_names_tlsx_and_crtsh_shapes():
    # tlsx: subject_an is a list
    tlsx = {"subject_cn": "demo.testfire.net",
            "subject_an": ["demo.testfire.net", "altoro.example.org"]}
    names = set(_extract_cert_names(tlsx))
    assert "demo.testfire.net" in names
    assert "altoro.example.org" in names
    # crt.sh: name_value is newline-separated
    crtsh = {"common_name": "a.example.com", "name_value": "a.example.com\n*.b.example.com"}
    names2 = set(_extract_cert_names(crtsh))
    assert "a.example.com" in names2
    assert "b.example.com" in names2  # wildcard stripped


def test_as_range_list_accepts_list_and_string():
    assert _as_range_list({"as_range": ["10.0.0.0/24", "10.0.1.0/24"]}) == ["10.0.0.0/24", "10.0.1.0/24"]
    assert _as_range_list({"as_range": "192.168.0.0/16"}) == ["192.168.0.0/16"]
    assert _as_range_list({}) == []


def test_org_tokens_drops_short_labels():
    toks = _org_tokens({"testfire.net", "io"})
    assert "testfire" in toks
    assert "io" not in toks  # second-level label too short to be an org token


# ─── cert pivot (DB-driven, fake conn) ──────────────────────────────────────

def _cert_store():
    return {
        "scope_targets": [{"target": "testfire.net", "target_type": "domain"}],
        "assets": [{"hostname": "www.testfire.net", "ip_address": "1.2.3.4"}],
        "certs": [
            # cert observed ON our in-scope host, SAN names a different domain
            {"target": "www.testfire.net",
             "data": {"subject_cn": "www.testfire.net",
                      "subject_an": ["www.testfire.net", "altoromutual.example.org"]}},
            # a cert on our host whose SANs are all same-org (no pivot)
            {"target": "demo.testfire.net",
             "data": {"subject_an": ["demo.testfire.net", "api.testfire.net"]}},
        ],
    }


def test_cert_pivot_writes_new_for_review():
    store = _cert_store()
    out = run_cert_pivot(_make_get_db(store), EID)
    written = store["written"]
    assert out["suggestions_written"] == 1
    row = written[0]
    assert row["target"] == "altoromutual.example.org"
    assert row["method"] == "cert_pivot"
    assert row["suggested_scope"] == "new_for_review"  # literal, not the constant


def test_cert_pivot_skips_same_domain():
    """A SAN in the SAME registrable domain as a seed is not a pivot."""
    store = _cert_store()
    run_cert_pivot(_make_get_db(store), EID)
    targets = {w["target"] for w in store["written"]}
    assert "api.testfire.net" not in targets
    assert "demo.testfire.net" not in targets


def test_cert_pivot_no_domains_reports_error():
    store = {"scope_targets": [], "assets": []}
    out = run_cert_pivot(_make_get_db(store), EID)
    assert out["suggestions_written"] == 0
    assert out["errors"]


# ─── asn pivot (DB-driven, fake conn) ───────────────────────────────────────

def _asn_store():
    return {
        "scope_targets": [{"target": "testfire.net", "target_type": "domain"}],
        "assets": [{"hostname": "www.testfire.net", "ip_address": "203.0.113.10"}],
        "asnmap": [
            # our host in a corporate ASN whose name matches the org
            {"target": "www.testfire.net",
             "data": {"as_number": "64500", "as_name": "TESTFIRE-CORP",
                      "as_range": ["203.0.113.0/24"]}},
            # our host ALSO fronted by a CDN — must be dropped
            {"target": "www.testfire.net",
             "data": {"as_number": "16509", "as_name": "AMAZON-02",
                      "as_range": ["52.0.0.0/11"]}},
        ],
    }


def test_asn_pivot_writes_new_for_review():
    store = _asn_store()
    out = run_asn_pivot(_make_get_db(store), EID)
    rows = store["written"]
    assert out["suggestions_written"] >= 1
    corp = [r for r in rows if r["target"] == "203.0.113.0/24"]
    assert corp, "corporate ASN range should be suggested"
    assert corp[0]["method"] == "asn_pivot"
    assert corp[0]["suggested_scope"] == "new_for_review"  # literal, not the constant


def test_asn_pivot_drops_cloud_cdn():
    """An AWS range our host is fronted by is noise, not a pivot."""
    store = _asn_store()
    run_asn_pivot(_make_get_db(store), EID)
    targets = {r["target"] for r in store["written"]}
    assert "52.0.0.0/11" not in targets


def test_asn_pivot_no_scope_reports_error():
    store = {"scope_targets": [], "assets": []}
    out = run_asn_pivot(_make_get_db(store), EID)
    assert out["suggestions_written"] == 0
    assert out["errors"]


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
