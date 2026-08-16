"""Agent-output verification: extraction and the limits of what it proves.

Built because the models writing agent narrative are the same ones that produced
`smb-enum-links` and `smb proliferateate`. Nothing checked their prose.
"""
import importlib.util
import os

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "agent_claims",
    os.path.join(os.path.dirname(__file__), "..", "scan_recommender", "agent_claims.py"),
)
ac = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ac)

VOCAB = ["mysql", "vnc", "samba", "ssh", "http", "smb"]


def kinds(claims, kind):
    return [c["value"] for c in claims if c["kind"] == kind]


class TestExtraction:
    def test_port_forms(self):
        c = ac.extract_claims("port 3306 open, 5900/tcp listening, and 8080/udp too")
        assert set(kinds(c, "port")) == {3306, 5900, 8080}

    def test_cve(self):
        c = ac.extract_claims("vulnerable to CVE-2007-2447 and cve-2017-0144")
        assert set(kinds(c, "cve")) == {"CVE-2007-2447", "CVE-2017-0144"}

    def test_ipv4(self):
        c = ac.extract_claims("scanned 192.168.1.150 and 10.0.0.5")
        assert set(kinds(c, "host")) == {"192.168.1.150", "10.0.0.5"}

    def test_rejects_impossible_octets(self):
        """999.1.1.1 is not an address; claiming it would be a spurious alert."""
        assert kinds(ac.extract_claims("host 999.1.1.1 responded"), "host") == []

    def test_rejects_out_of_range_port(self):
        assert kinds(ac.extract_claims("port 99999 open"), "port") == []

    def test_services_only_from_vocab(self):
        """Matching arbitrary words would flood the report with noise."""
        c = ac.extract_claims("mysql was found; the weather was pleasant", service_vocab=VOCAB)
        assert kinds(c, "service") == ["mysql"]

    def test_no_vocab_means_no_service_claims(self):
        assert kinds(ac.extract_claims("mysql found"), "service") == []

    def test_deduplicates(self):
        c = ac.extract_claims("port 3306, again port 3306, and 3306/tcp")
        assert len(kinds(c, "port")) == 1

    def test_ignores_unverifiable_prose(self):
        """Judgements and recommendations have no database answer, so they are
        deliberately not extracted — flagging them as unsupported would be noise."""
        c = ac.extract_claims("I recommend prioritising this host; it looks weak.",
                              service_vocab=VOCAB)
        assert c == []

    def test_context_is_captured(self):
        c = ac.extract_claims("the scanner reported port 3306 as open on the target")
        assert "3306" in c[0]["context"]

    def test_empty_input(self):
        assert ac.extract_claims("") == []
        assert ac.extract_claims(None) == []


class _FakeCur:
    """Minimal cursor: returns a row when the queried value is in `present`."""
    def __init__(self, present):
        self.present, self._row = present, None

    def execute(self, sql, params=()):
        val = params[0] if params else None
        if isinstance(val, str) and val.startswith("%"):
            val = val.strip("%")
        self._row = {"service": "mysql", "port": 3306} if val in self.present else None

    def fetchone(self):
        return self._row


class TestVerification:
    def test_supported_claim(self):
        r = ac.verify_claims(_FakeCur({3306}), [{"kind": "port", "value": 3306, "context": ""}])
        assert r[0]["supported"]

    def test_unsupported_claim(self):
        r = ac.verify_claims(_FakeCur(set()), [{"kind": "port", "value": 31337, "context": ""}])
        assert not r[0]["supported"]

    def test_summary_counts_by_kind(self):
        results = [
            {"kind": "port", "value": 1, "supported": True},
            {"kind": "port", "value": 2, "supported": False},
            {"kind": "cve", "value": "CVE-2020-1", "supported": False},
        ]
        s = ac.summarise(results)
        assert s["claims_checked"] == 3
        assert s["unsupported_count"] == 2
        assert s["by_kind"]["port"] == {"total": 2, "unsupported": 1}

    def test_unsupported_is_not_the_same_as_false(self):
        """A claim can be true but unrecorded — ingestion may have dropped it.
        The field name and this test exist so that is not forgotten."""
        r = ac.verify_claims(_FakeCur(set()), [{"kind": "port", "value": 22, "context": ""}])
        assert "supported" in r[0] and r[0]["supported"] is False
        assert "false" not in r[0]


class TestNotability:
    """Severity crossed with support. Neither axis alone is enough:
    verification is negative-only, so a supported root shell was being filed
    silently as 'fine'."""

    def _claim(self, ctx, supported=True):
        return {"kind": "port", "value": 4444, "context": ctx, "supported": supported}

    def test_root_shell_is_notable(self):
        r = ac.score_notability(self._claim("obtained a root shell on the target"))
        assert r["notable"] and r["notable_score"] >= 5

    def test_credentials_are_notable(self):
        r = ac.score_notability(self._claim("recovered plaintext credentials from the config"))
        assert r["notable"] and "credentials" in r["notable_reason"]

    def test_ordinary_claim_is_not_notable(self):
        r = ac.score_notability(self._claim("the port responded to a TCP connect"))
        assert not r["notable"] and r["notable_score"] == 0

    def test_unsupported_high_impact_outranks_supported(self):
        """The worst case: a big claim with nothing behind it. It must sort
        ABOVE the same claim when the database backs it up."""
        sup = ac.score_notability(self._claim("got a root shell", supported=True))
        uns = ac.score_notability(self._claim("got a root shell", supported=False))
        assert uns["notable_score"] > sup["notable_score"]
        assert "NO SUPPORTING SCAN DATA" in uns["notable_reason"]

    def test_summary_separates_the_two_axes(self):
        results = [
            {"kind": "port", "value": 1, "supported": True,  "context": "root shell obtained"},
            {"kind": "port", "value": 2, "supported": False, "context": "just an open port"},
        ]
        s = ac.summarise(results)
        assert s["unsupported_count"] == 1     # port 2
        assert s["notable_count"] == 1         # port 1
        assert s["notable"][0]["value"] == 1   # different claims, different axes

    def test_notable_sorted_by_score(self):
        results = [
            {"kind": "port", "value": 1, "supported": True, "context": "sudo misconfiguration"},
            {"kind": "port", "value": 2, "supported": True, "context": "obtained a reverse shell"},
        ]
        s = ac.summarise(results)
        assert s["notable"][0]["value"] == 2
