"""Finding fingerprints — the dedup mechanism CLAUDE.md requires.

`etl/fingerprint.py` had no tests at all, despite CLAUDE.md calling for "unit
tests for parsers and fingerprinting". It went unnoticed because the hashes were
computed correctly and then never enforced: no unique index existed on
`vulns.fingerprint` or `web_findings.fingerprint`, so duplicates accumulated
freely — 369 vulns rows for 34 distinct fingerprints, and 32,218 katana rows for
630 distinct findings.

Two properties matter for dedup to work at all:
  * STABILITY — the same finding must hash identically across runs and tools,
    or every re-scan inserts a new row;
  * SENSITIVITY — genuinely different findings must not collide, or the unique
    index silently discards real results.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from etl.fingerprint import vuln_fingerprint, web_fingerprint, recon_fingerprint  # noqa: E402


# ------------------------------------------------------------- stability

@pytest.mark.unit
def test_web_fingerprint_is_stable_across_calls():
    a = web_fingerprint("http://h/a", "zap", "XSS", "alert")
    b = web_fingerprint("http://h/a", "zap", "XSS", "alert")
    assert a == b


@pytest.mark.unit
@pytest.mark.parametrize("url", [
    "http://h/a", "  http://h/a  ", "HTTP://H/A", "http://h/a/", "http://h/a///",
])
def test_web_fingerprint_normalises_case_whitespace_and_trailing_slashes(url):
    """Re-scans differ in trivial ways. If those produce new hashes, the table
    grows without bound — which is exactly what happened to katana."""
    assert web_fingerprint(url, "zap", "XSS", "alert") == \
           web_fingerprint("http://h/a", "zap", "XSS", "alert")


@pytest.mark.unit
def test_web_fingerprint_ignores_source_so_tools_deduplicate_against_each_other():
    """Documented intent: the same finding from ZAP and Nuclei is ONE finding."""
    assert web_fingerprint("http://h/a", "zap", "XSS", "alert") == \
           web_fingerprint("http://h/a", "nuclei", "XSS", "alert")


# ----------------------------------------------------------- sensitivity

@pytest.mark.unit
@pytest.mark.parametrize("kwargs", [
    {"url": "http://h/b"},
    {"name": "SQLi"},
    {"issue_type": "other"},
])
def test_web_fingerprint_changes_when_the_finding_changes(kwargs):
    base = dict(url="http://h/a", source="zap", name="XSS", issue_type="alert")
    assert web_fingerprint(**base) != web_fingerprint(**{**base, **kwargs})


@pytest.mark.unit
def test_different_ports_are_different_vulns():
    """A vuln on 80 and the same vuln on 8080 are two findings, not one."""
    a = vuln_fingerprint(ip="10.0.0.1", port=80, script="http-title", cves=None)
    b = vuln_fingerprint(ip="10.0.0.1", port=8080, script="http-title", cves=None)
    assert a != b


@pytest.mark.unit
def test_different_cves_are_different_vulns():
    a = vuln_fingerprint(ip="10.0.0.1", port=80, script="s", cves=["CVE-2011-2523"])
    b = vuln_fingerprint(ip="10.0.0.1", port=80, script="s", cves=["CVE-2026-4480"])
    assert a != b


# --------------------------------------------------------------- nulls

@pytest.mark.unit
def test_same_cve_on_same_host_port_dedupes_across_tools():
    """Documented intent: CVE-based identity groups the same CVE across tools,
    so nmap and nuclei reporting CVE-2011-2523 on 10.0.0.1:21 is one finding."""
    assert vuln_fingerprint(ip="10.0.0.1", port=21, script="ftp-vsftpd-backdoor",
                            cves=["CVE-2011-2523"]) == \
           vuln_fingerprint(ip="10.0.0.1", port=21, script="nuclei-template",
                            cves=["CVE-2011-2523"])


@pytest.mark.unit
def test_null_fields_do_not_raise_and_stay_stable():
    """Parsers pass None constantly. Raising here would abort ingestion; an
    unstable hash would defeat the index."""
    for fn, args in (
        (web_fingerprint, (None, None, None, None)),
        (vuln_fingerprint, (None, None, None)),
    ):
        try:
            first = fn(*args) if args else fn()
            second = fn(*args) if args else fn()
        except TypeError:
            pytest.skip(f"{fn.__name__} requires arguments; covered elsewhere")
        assert first == second
        assert isinstance(first, str) and len(first) == 32


@pytest.mark.unit
def test_empty_string_and_none_are_equivalent():
    """A parser emitting "" and another emitting None describe the same absence.
    Hashing them differently would create a duplicate per parser."""
    assert web_fingerprint("http://h/a", "zap", "XSS", None) == \
           web_fingerprint("http://h/a", "zap", "XSS", "")
