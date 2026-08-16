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


class _CovCur(_FakeCur):
    """Cursor that can also answer the coverage probes."""
    def __init__(self, present, has_ports=True, has_assets=True, has_findings=True):
        super().__init__(present)
        self.has = {"ports": has_ports, "assets": has_assets, "findings": has_findings}

    def execute(self, sql, params=()):
        low = sql.lower()
        if "information_schema" in low:
            self._rows = []
            self._row = None
            return
        if "limit 1" in low and not params:
            table = ("ports" if " ports" in low else
                     "assets" if " assets" in low else "findings")
            self._row = {"x": 1} if self.has.get(table) else None
            return
        super().execute(sql, params)

    def fetchall(self):
        return []


class TestUnverifiable:
    """The distinction the first version got wrong.

    "The scan recorded 23 ports and none was 31337" is evidence of absence.
    "No ports were recorded" is absence of evidence. Reporting the second as
    unsupported manufactures a finding out of missing coverage — and today's
    ingestion bug (23 ports found, 0 stored) would have done exactly that to
    every true claim.
    """

    def test_absent_from_recorded_data_is_unsupported(self):
        cur = _CovCur(set(), has_ports=True)
        r = ac.verify_claims(cur, [{"kind": "port", "value": 31337, "context": ""}])
        assert r[0]["verdict"] == "unsupported"

    def test_no_data_at_all_is_unverifiable(self):
        cur = _CovCur(set(), has_ports=False)
        r = ac.verify_claims(cur, [{"kind": "port", "value": 22, "context": ""}])
        assert r[0]["verdict"] == "unverifiable"
        assert "absence of evidence" in r[0]["detail"]

    def test_unknown_kind_is_unverifiable_not_unsupported(self):
        """An LLM-proposed 'other' claim has no table to check — it goes to a
        human, it is not declared false."""
        cur = _CovCur(set())
        r = ac.verify_claims(cur, [{"kind": "other", "value": "writable share", "context": ""}])
        assert r[0]["verdict"] == "unverifiable"

    def test_supported_still_wins(self):
        cur = _CovCur({3306}, has_ports=True)
        r = ac.verify_claims(cur, [{"kind": "port", "value": 3306, "context": ""}])
        assert r[0]["verdict"] == "supported" and r[0]["supported"]

    def test_follow_up_collects_unverifiable_and_notable_unsupported(self):
        results = [
            {"kind": "other", "value": "writable share", "verdict": "unverifiable",
             "supported": False, "context": "world-readable export"},
            {"kind": "port", "value": 31337, "verdict": "unsupported",
             "supported": False, "context": "obtained a root shell"},
            {"kind": "port", "value": 80, "verdict": "unsupported",
             "supported": False, "context": "an open port"},
        ]
        s = ac.summarise(results)
        vals = [f["value"] for f in s["manual_follow_up"]]
        assert "writable share" in vals      # unverifiable
        assert 31337 in vals                 # unsupported AND notable
        assert 80 not in vals                # unsupported but unremarkable
        assert s["manual_follow_up"][0]["value"] == 31337   # highest impact first


class TestLlmExtraction:
    """The model proposes; SQL decides. It can widen recall but never clear a claim."""

    def test_parses_model_json(self):
        def fake(prompt, model=None):
            return {"response": '{"claims":[{"kind":"other","value":"smb share","assertion":"world writable"}]}'}
        out = ac.llm_extract_claims("notes", fake)
        assert out[0]["kind"] == "other" and out[0]["source"] == "llm"

    def test_tolerates_prose_wrapped_json(self):
        def fake(prompt, model=None):
            return "Sure!\n```json\n{\"claims\":[{\"kind\":\"port\",\"value\":\"445\"}]}\n```"
        out = ac.llm_extract_claims("notes", fake)
        assert out[0]["value"] == 445

    def test_model_failure_yields_nothing_not_an_error(self):
        def boom(prompt, model=None):
            raise RuntimeError("model down")
        assert ac.llm_extract_claims("notes", boom) == []

    def test_garbage_response_yields_nothing(self):
        assert ac.llm_extract_claims("notes", lambda p, model=None: "no json here") == []

    def test_regex_claims_win_on_collision(self):
        regex = [{"kind": "port", "value": 3306, "context": "literal match"}]
        llm = [{"kind": "port", "value": 3306, "context": "inferred", "source": "llm"}]
        merged = ac.merge_claims(regex, llm)
        assert len(merged) == 1 and merged[0]["context"] == "literal match"

    def test_llm_adds_what_regex_missed(self):
        regex = [{"kind": "port", "value": 3306, "context": ""}]
        llm = [{"kind": "other", "value": "anonymous ftp", "context": "", "source": "llm"}]
        assert len(ac.merge_claims(regex, llm)) == 2

    def test_rejects_absurd_port(self):
        def fake(prompt, model=None):
            return '{"claims":[{"kind":"port","value":"99999"}]}'
        assert ac.llm_extract_claims("notes", fake) == []


class TestRunFailureDiagnosis:
    """No data at all is a run failure, not a series of small mysteries.

    Claim by claim it looks like ambiguity; in aggregate it is one finding. The
    real ingestion bug — 23 ports found, 0 stored — would have produced exactly
    this shape.
    """

    def test_widespread_no_coverage_is_flagged(self):
        results = [{"kind": "port", "value": p, "verdict": "unverifiable",
                    "unverifiable_reason": "no_coverage", "supported": False, "context": ""}
                   for p in (22, 80, 443)]
        s = ac.summarise(results)
        assert s["probable_run_failure"]
        assert "ingest" in s["run_failure_hint"]

    def test_one_gap_among_findings_is_not_a_run_failure(self):
        results = [
            {"kind": "port", "value": 22, "verdict": "supported", "supported": True, "context": ""},
            {"kind": "port", "value": 80, "verdict": "supported", "supported": True, "context": ""},
            {"kind": "other", "value": "x", "verdict": "unverifiable",
             "unverifiable_reason": "unknown_kind", "supported": False, "context": ""},
        ]
        s = ac.summarise(results)
        assert not s["probable_run_failure"]

    def test_unknown_kind_alone_never_implies_run_failure(self):
        """LLM 'other' claims are unverifiable by nature — that says nothing
        about whether the scan worked."""
        results = [{"kind": "other", "value": f"c{i}", "verdict": "unverifiable",
                    "unverifiable_reason": "unknown_kind", "supported": False, "context": ""}
                   for i in range(4)]
        assert not ac.summarise(results)["probable_run_failure"]


class TestContextBounding:
    """Severity must not bleed between statements.

    The original ±45-character window made a host claim inherit "root shell"
    from the preceding sentence and score as an access finding.
    """

    def test_severity_does_not_bleed_across_sentences(self):
        text = "I obtained a root shell on the box. Host 10.1.2.3 also answered ping."
        host = [c for c in ac.extract_claims(text) if c["kind"] == "host"][0]
        assert "root shell" not in host["context"]
        assert not ac.score_notability({**host, "supported": True})["notable"]

    def test_severity_is_kept_within_its_own_sentence(self):
        text = "Port 4444 gave me a root shell."
        port = [c for c in ac.extract_claims(text) if c["kind"] == "port"][0]
        assert ac.score_notability({**port, "supported": True})["notable"]

    def test_bullet_lines_are_separate_statements(self):
        """Agent notes are often bullets with no full stops — a sentence-only
        split would lump the whole list into one context."""
        text = "- obtained a root shell\n- port 8080 is open\n"
        port = [c for c in ac.extract_claims(text) if c["kind"] == "port"][0]
        assert "root shell" not in port["context"]

    def test_unpunctuated_dump_is_still_bounded(self):
        text = "root shell " + ("filler " * 300) + "port 9999 open"
        port = [c for c in ac.extract_claims(text) if c["kind"] == "port"][0]
        assert len(port["context"]) < 400
