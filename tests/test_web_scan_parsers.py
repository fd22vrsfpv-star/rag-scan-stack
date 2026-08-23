"""
NOTE: _parse_xml/_parse_json now require enforce_scope and scope_rows.
# Scope is passed EXPLICITLY as False/None here because these tests exercise
parsing, not authorisation. The parameters are required rather than defaulted on
purpose: host_in_scope(..., enforce=False, ...) returns True, so a default would
let a forgotten call site disable the gate silently instead of failing.
Web scan report parser tests (Nikto + ZAP file import).

Format detection is tested with no DB at all. The ingest tests need a real
Postgres — they run against the live `scans` DB inside a transaction that is
ALWAYS rolled back, so they exercise the real SQL (column names, constraints,
the severity CHECK) without leaving rows behind. They skip cleanly when no DB
is reachable, so the suite still runs on a bare checkout.
"""
import json
import os
import sys

import pytest

REPO = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, REPO)

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

pytest.importorskip("psycopg2", reason="psycopg2 required for parser tests")

from etl import parse_nikto as nikto      # noqa: E402
from etl import parse_zap_file as zapf    # noqa: E402


# ── Format detection (no DB) ────────────────────────────────────────────────
class TestFormatDetection:
    def test_nikto_xml(self):
        assert nikto.detect_nikto_format(f"{FIXTURES}/sample_nikto.xml") == "xml"

    def test_nikto_json(self):
        assert nikto.detect_nikto_format(f"{FIXTURES}/sample_nikto.json") == "json"

    def test_zap_json(self):
        assert zapf.detect_zap_format(f"{FIXTURES}/sample_zap.json") == "json"

    def test_zap_xml(self):
        assert zapf.detect_zap_format(f"{FIXTURES}/sample_zap.xml") == "xml"

    def test_detection_is_content_based_not_extension_based(self, tmp_path):
        """A ZAP JSON report saved as .txt must still be recognised."""
        p = tmp_path / "report.txt"
        p.write_text(open(f"{FIXTURES}/sample_zap.json").read())
        assert zapf.detect_zap_format(str(p)) == "json"

    def test_cross_tool_reports_are_not_claimed(self):
        """Nikto's detector must not accept a ZAP report, and vice versa."""
        assert nikto.detect_nikto_format(f"{FIXTURES}/sample_zap.xml") == "unknown"
        assert zapf.detect_zap_format(f"{FIXTURES}/sample_nikto.xml") == "unknown"

    def test_empty_and_missing_files(self, tmp_path):
        empty = tmp_path / "empty.xml"
        empty.write_text("")
        assert nikto.detect_nikto_format(str(empty)) == "unknown"
        assert zapf.detect_zap_format("/nonexistent/report.json") == "unknown"


# ── Severity inference (no DB) ──────────────────────────────────────────────
class TestNiktoSeverityInference:
    @pytest.mark.parametrize("msg,expected", [
        ("Possible remote code execution vector detected.", "high"),
        ("SQL injection may be possible", "high"),
        ("Directory traversal found", "high"),
        ("/admin/: potential admin login page found", "medium"),
        ("Backup file found: possible source code disclosure", "medium"),
        ("Directory indexing found.", "low"),
        ("The anti-clickjacking X-Frame-Options header is not present.", "low"),
        ("Server banner changed", "low"),
        ("Something entirely unremarkable", "info"),
    ])
    def test_ladder(self, msg, expected):
        assert nikto._infer_severity(msg)[0] == expected

    def test_reason_is_recorded_for_audit(self):
        sev, reason = nikto._infer_severity("SQL injection may be possible")
        assert sev == "high" and reason == "sql injection"

    def test_default_reason(self):
        assert nikto._infer_severity("hello")[1] == "default"

    def test_severities_are_all_db_legal(self):
        """web_findings.severity has a CHECK constraint — stay inside it."""
        legal = {"info", "low", "medium", "high", "critical", "error", "recon"}
        for sev, _kw in nikto._SEVERITY_RULES:
            assert sev in legal


class TestZapSeverityMapping:
    @pytest.mark.parametrize("riskdesc,code,expected", [
        ("High (Medium)", "3", "high"),
        ("Medium", "2", "medium"),
        ("Low (Medium)", "1", "low"),
        ("Informational (Low)", "0", "info"),
        ("", "3", "high"),          # word form missing, fall back to riskcode
        ("", "0", "info"),
    ])
    def test_mapping(self, riskdesc, code, expected):
        assert zapf._map_severity(riskdesc, code) == expected

    def test_false_positive_is_skipped(self):
        assert zapf._map_severity("False Positive", "0") is None

    def test_html_is_stripped_from_descriptions(self):
        assert zapf._strip_html("<p>Use <b>parameterised</b> queries.</p>") == \
            "Use parameterised queries."


class TestNiktoUrlBuilding:
    def test_default_ports_omit_the_port(self):
        assert nikto._build_url("h.com", "80", "/a") == "http://h.com/a"
        assert nikto._build_url("h.com", "443", "/a") == "https://h.com/a"

    def test_non_default_port_is_kept(self):
        assert nikto._build_url("h.com", "8080", "/a") == "http://h.com:8080/a"

    def test_tls_inferred_for_https_ports(self):
        assert nikto._build_url("h.com", "8443", "/a").startswith("https://")

    def test_explicit_url_wins(self):
        assert nikto._build_url("h.com", "80", "/a", "http://other/x") == "http://other/x"

    def test_missing_leading_slash_is_added(self):
        assert nikto._build_url("h.com", "80", "a") == "http://h.com/a"


# ── Ingest against a real DB, always rolled back ────────────────────────────
DB_DSN = os.environ.get(
    "TEST_DB_DSN", "postgresql://app:app@127.0.0.1:5433/scans"
)


@pytest.fixture
def rollback_cur():
    """A cursor in a transaction that is unconditionally rolled back."""
    psycopg2 = pytest.importorskip("psycopg2")
    try:
        conn = psycopg2.connect(DB_DSN, connect_timeout=3)
    except Exception as e:
        pytest.skip(f"no test database reachable ({e})")
    try:
        cur = conn.cursor()
        yield cur
        cur.close()
    finally:
        conn.rollback()      # nothing this test wrote survives
        conn.close()


def _stats():
    return {"inserted": 0, "skipped_duplicate": 0, "skipped_no_url": 0,
            "skipped_false_positive": 0, "by_severity": {}, "errors": []}


class TestNiktoIngest:
    def test_xml_inserts_expected_rows(self, rollback_cur):
        st = _stats()
        nikto._parse_xml(f"{FIXTURES}/sample_nikto.xml", rollback_cur, st, dedupe=False, enforce_scope=False, scope_rows=None)
        assert st["errors"] == []
        assert st["inserted"] == 3
        # One of each rung of the ladder.
        assert st["by_severity"].get("high") == 1     # RCE vector
        assert st["by_severity"].get("medium") == 1   # admin login page
        assert st["by_severity"].get("low") == 1      # X-Frame-Options

    def test_json_inserts_expected_rows(self, rollback_cur):
        st = _stats()
        nikto._parse_json(f"{FIXTURES}/sample_nikto.json", rollback_cur, st, dedupe=False, enforce_scope=False, scope_rows=None)
        assert st["errors"] == []
        assert st["inserted"] == 3
        assert st["by_severity"].get("medium") == 1   # backup file / source disclosure
        assert st["by_severity"].get("low") == 1      # directory indexing

    def test_rows_land_with_correct_source_and_url(self, rollback_cur):
        st = _stats()
        nikto._parse_xml(f"{FIXTURES}/sample_nikto.xml", rollback_cur, st, dedupe=False, enforce_scope=False, scope_rows=None)
        rollback_cur.execute(
            "SELECT url, source, severity FROM web_findings "
            "WHERE source = 'nikto' AND url LIKE 'http://10.0.0.5%' ORDER BY url"
        )
        rows = rollback_cur.fetchall()
        assert len(rows) == 3
        assert {r[1] for r in rows} == {"nikto"}
        assert any(r[0].endswith("/admin/") for r in rows)

    def test_severity_reason_is_persisted(self, rollback_cur):
        st = _stats()
        nikto._parse_xml(f"{FIXTURES}/sample_nikto.xml", rollback_cur, st, dedupe=False, enforce_scope=False, scope_rows=None)
        # Scope to this fixture's own URLs. The DB legitimately holds nikto rows
        # from real scans, and an unscoped query picks one of those instead.
        rollback_cur.execute(
            "SELECT tags->>'severity_reason' FROM web_findings "
            "WHERE source='nikto' AND severity='high' "
            "  AND url LIKE 'http://10.0.0.5%' LIMIT 1"
        )
        assert rollback_cur.fetchone()[0] == "remote code execution"

    def test_dedupe_suppresses_a_second_pass(self, rollback_cur):
        first, second = _stats(), _stats()
        nikto._parse_xml(f"{FIXTURES}/sample_nikto.xml", rollback_cur, first, dedupe=True, enforce_scope=False, scope_rows=None)
        nikto._parse_xml(f"{FIXTURES}/sample_nikto.xml", rollback_cur, second, dedupe=True, enforce_scope=False, scope_rows=None)
        assert first["inserted"] == 3
        assert second["inserted"] == 0
        assert second["skipped_duplicate"] == 3


class TestZapFileIngest:
    def test_json_expands_instances_into_rows(self, rollback_cur):
        """One alert with 2 instances must become 2 findings, not 1."""
        st = _stats()
        zapf._parse_json(f"{FIXTURES}/sample_zap.json", rollback_cur, st, dedupe=False, enforce_scope=False, scope_rows=None)
        assert st["errors"] == []
        assert st["inserted"] == 3          # 2 SQLi instances + 1 header alert
        assert st["by_severity"].get("high") == 2
        assert st["by_severity"].get("low") == 1

    def test_false_positive_alert_is_skipped(self, rollback_cur):
        st = _stats()
        zapf._parse_json(f"{FIXTURES}/sample_zap.json", rollback_cur, st, dedupe=False, enforce_scope=False, scope_rows=None)
        assert st["skipped_false_positive"] == 1
        rollback_cur.execute(
            "SELECT count(*) FROM web_findings WHERE url = 'http://10.0.0.9/fp'"
        )
        assert rollback_cur.fetchone()[0] == 0

    def test_xml_inserts_and_maps_severity(self, rollback_cur):
        st = _stats()
        zapf._parse_xml(f"{FIXTURES}/sample_zap.xml", rollback_cur, st, dedupe=False, enforce_scope=False, scope_rows=None)
        assert st["errors"] == []
        assert st["inserted"] == 2
        assert st["by_severity"].get("high") == 1
        assert st["by_severity"].get("info") == 1

    def test_cwe_and_description_are_persisted(self, rollback_cur):
        st = _stats()
        zapf._parse_json(f"{FIXTURES}/sample_zap.json", rollback_cur, st, dedupe=False, enforce_scope=False, scope_rows=None)
        rollback_cur.execute(
            "SELECT cwe, description, solution FROM web_findings "
            "WHERE source='zap' AND name='SQL Injection' LIMIT 1"
        )
        cwe, desc, soln = rollback_cur.fetchone()
        assert cwe == ["CWE-89"]
        assert "<p>" not in (desc or "")          # HTML stripped
        assert "parameterised" in (soln or "")

    def test_dedupe_suppresses_a_second_pass(self, rollback_cur):
        first, second = _stats(), _stats()
        zapf._parse_json(f"{FIXTURES}/sample_zap.json", rollback_cur, first, dedupe=True, enforce_scope=False, scope_rows=None)
        zapf._parse_json(f"{FIXTURES}/sample_zap.json", rollback_cur, second, dedupe=True, enforce_scope=False, scope_rows=None)
        assert second["inserted"] == 0
        assert second["skipped_duplicate"] == first["inserted"]


class TestCrossToolDedup:
    def test_same_finding_from_two_tools_shares_a_fingerprint(self):
        """web_fingerprint excludes source, so ZAP and Nikto collapse."""
        from etl.fingerprint import web_fingerprint
        a = web_fingerprint(url="http://h/x", source="zap", name="XSS", issue_type="t")
        b = web_fingerprint(url="http://h/x", source="nikto", name="XSS", issue_type="t")
        assert a == b


class TestTopLevelErrors:
    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            nikto.parse_nikto("/nonexistent/report.xml")
        with pytest.raises(FileNotFoundError):
            zapf.parse_zap_file("/nonexistent/report.json")

    def test_unrecognised_format_raises_a_clear_error(self, tmp_path):
        junk = tmp_path / "junk.xml"
        junk.write_text("<somethingelse/>")
        with pytest.raises(ValueError, match="does not look like"):
            nikto.parse_nikto(str(junk))
        with pytest.raises(ValueError, match="does not look like"):
            zapf.parse_zap_file(str(junk))


# ── Cross-tool format detection (the /ingest/web-scan dispatcher) ───────────
class TestWebScanToolDetection:
    """Mirrors _detect_web_scan_tool in app/rag-api/api.py.

    The logic lives in rag-api (which can't be imported here without its full
    dependency tree), so this reimplements the same predicates and asserts them
    against the real fixtures. If the two drift, these fixtures are the contract
    both sides are written against.
    """

    @staticmethod
    def _detect(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(8192)
        if not head.strip():
            return None
        stripped = head.lstrip()
        low = stripped.lower()
        if stripped.startswith("<") or low.startswith("<?xml"):
            if "<owaspzapreport" in low or "<alertitem" in low:
                return "zap"
            if "<niktoscan" in low:
                return "nikto"
            if "<issues" in low or "<items" in low:
                return "burp"
            return None
        if stripped[0] in "{[":
            if '"site"' in head or '"alerts"' in head or '"@programName"' in head:
                return "zap"
            if '"vulnerabilities"' in head or '"niktoscan"' in head:
                return "nikto"
            if '"template-id"' in head or '"templateID"' in head or '"template_id"' in head:
                return "nuclei"
            return None
        return None

    @pytest.mark.parametrize("fixture,expected", [
        ("sample_zap.json", "zap"),
        ("sample_zap.xml", "zap"),
        ("sample_nikto.xml", "nikto"),
        ("sample_nikto.json", "nikto"),
    ])
    def test_detects_each_fixture(self, fixture, expected):
        assert self._detect(f"{FIXTURES}/{fixture}") == expected

    def test_detects_nuclei_jsonl(self):
        assert self._detect(f"{FIXTURES}/sample_nuclei.jsonl") == "nuclei"

    def test_detects_burp_xml(self, tmp_path):
        p = tmp_path / "burp.xml"
        p.write_text('<?xml version="1.0"?>\n<issues burpVersion="2023.1">\n<issue><name>X</name></issue>\n</issues>')
        assert self._detect(str(p)) == "burp"

    def test_unknown_file_returns_none(self, tmp_path):
        p = tmp_path / "notes.txt"
        p.write_text("just some notes about the engagement")
        assert self._detect(str(p)) is None

    def test_nmap_xml_is_not_claimed_as_a_web_report(self, tmp_path):
        """An nmap report must not be silently parsed as a web scan."""
        p = tmp_path / "nmap.xml"
        p.write_text('<?xml version="1.0"?>\n<nmaprun scanner="nmap"><host/></nmaprun>')
        assert self._detect(str(p)) is None

    def test_empty_file_returns_none(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text("   \n")
        assert self._detect(str(p)) is None
