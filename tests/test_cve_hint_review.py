"""scripts/cve_hint_review.py: aggregation and resumability (pure parts).

Run standalone:  pytest tests/test_cve_hint_review.py -q
"""
import importlib.util
import json
import pathlib

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "cve_hint_review.py"


def _mod():
    spec = importlib.util.spec_from_file_location("cve_hint_review", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_aggregate_counts_keys_per_class_and_ignores_empties():
    m = _mod()
    rows = [
        {"cve": "A", "vuln_class": "privilege-escalation",
         "requirements": {"creates_state": True, "role_parameter": "reg_role"}},
        {"cve": "B", "vuln_class": "privilege-escalation",
         "requirements": {"creates_state": True, "auth_required": False}},
        {"cve": "C", "vuln_class": "privilege-escalation", "requirements": {}},
        {"cve": "D", "vuln_class": "sqli", "requirements": {"parameter": "id"}},
    ]
    a = m.aggregate(rows)
    pe = a["privilege-escalation"]
    assert pe["cves"] == 3 and pe["with_requirements"] == 2
    assert pe["keys"] == {"creates_state": 2, "role_parameter": 1}, (
        "a False/empty value must not count as a recurring requirement")
    assert a["sqli"]["samples"]["parameter"] == ["id"]


def test_done_set_makes_a_phase_resumable(tmp_path):
    m = _mod()
    p = tmp_path / "enrich.jsonl"
    m._append(str(p), {"cve": "CVE-2026-1"})
    p.write_text(p.read_text() + "not json\n")
    m._append(str(p), {"cve": "CVE-2026-2"})
    assert m._done(str(p)) == {"CVE-2026-1", "CVE-2026-2"}
    assert m._done(str(tmp_path / "missing.jsonl")) == set()


def test_failed_fetch_is_not_recorded_so_it_is_retried():
    """Unreachable is not absent: an errored enrich row must not be written,
    or the resume logic would skip that CVE forever with no class."""
    src = SCRIPT.read_text(encoding="utf-8")
    assert 'if row.get("error"):' in src and "_append(path, row)" in src
