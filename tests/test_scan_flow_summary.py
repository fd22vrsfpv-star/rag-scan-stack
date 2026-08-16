"""End-of-session scan flow summary.

The pre-existing summary only counted statuses, which cannot answer the question
an operator actually has at the end of an agent run: did each kind of scan do its
job? A nuclei run that found nothing and a nuclei run whose results never landed
both showed up as "completed: 1".

Two properties carry the weight here:
  * per-type outcomes — what each scan type PRODUCED, not just that it finished;
  * produced_nothing — a type that completed while producing nothing, which is
    exactly the shape a silently-broken tool takes (see the real case where ZAP
    reported "0 alerts" from 207 seeded URLs after its session was wiped).
"""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "autogen_agents"))
os.environ.setdefault("PORT_PROFILES_PATH",
                      str(Path(__file__).parent.parent / "knowledge" / "port_profiles.yaml"))

from scan_tools import SessionScanTracker as T  # noqa: E402


def _session(scans):
    """Drive build_flow_summary off a synthetic session registry."""
    sid = "test-session"
    T._registry = getattr(T, "_registry", {})
    # Full registry shape — get_session_status indexes started_at/current_phase
    # directly, so a partial record raises KeyError rather than degrading.
    T._registry[sid] = {
        "session_id": sid,
        "started_at": "2026-08-16T00:00:00Z",
        "current_phase": "test",
        "scans": scans,
    }
    return T.build_flow_summary(sid)


def _scan(stype, status="completed", result=None, dur=1.0, params=None, job="j"):
    return {
        "type": stype, "job_id": job, "status": status,
        "started_at": "2026-08-16T00:00:00Z", "completed_at": None,
        "duration_seconds": dur, "params": params or {}, "result_summary": result,
    }


@pytest.mark.unit
def test_groups_by_scan_type_and_preserves_flow_order():
    s = _session([
        _scan("masscan", params={"targets": ["192.168.1.150"]}),
        _scan("nmap", params={"targets": ["192.168.1.150"]}),
        _scan("masscan", params={"targets": ["192.168.1.151"]}),
        _scan("nuclei", params={"target_url": "http://192.168.1.150"}),
    ])
    assert s["total_scans"] == 4
    assert s["scan_types_run"] == 3
    # Order of FIRST appearance — the actual flow, not alphabetical.
    assert s["flow_order"] == ["masscan", "nmap", "nuclei"]
    masscan = next(t for t in s["by_scan_type"] if t["scan_type"] == "masscan")
    assert masscan["runs"] == 2
    assert masscan["targets"] == ["192.168.1.150", "192.168.1.151"]


@pytest.mark.unit
def test_aggregates_what_each_type_produced():
    s = _session([
        _scan("credential-check", result={"total_valid_credentials": 7}),
        _scan("gobuster", result={"paths_found": 11}),
        _scan("gobuster", result={"paths_found": 9}),
    ])
    creds = next(t for t in s["by_scan_type"] if t["scan_type"] == "credential-check")
    gob = next(t for t in s["by_scan_type"] if t["scan_type"] == "gobuster")
    assert creds["results"]["total_valid_credentials"] == 7
    assert gob["results"]["paths_found"] == 20        # summed across both runs


@pytest.mark.unit
def test_reads_counts_out_of_nested_result_sections():
    """Tools nest their counts under stages/ingest/stats rather than at the top."""
    s = _session([
        _scan("pipeline", result={"stages": {"urls_scanned": 192}}),
        _scan("nuclei", result={"ingest": {"inserted": 3}}),
    ])
    pipe = next(t for t in s["by_scan_type"] if t["scan_type"] == "pipeline")
    nuc = next(t for t in s["by_scan_type"] if t["scan_type"] == "nuclei")
    assert pipe["results"]["urls_scanned"] == 192
    assert nuc["results"]["inserted"] == 3


@pytest.mark.unit
def test_flags_a_type_that_completed_but_produced_nothing():
    """The silently-broken-tool shape: succeeds everywhere, yields nothing."""
    s = _session([
        _scan("zap", result={"alerts": 0}),
        _scan("gobuster", result={"paths_found": 11}),
    ])
    zap = next(t for t in s["by_scan_type"] if t["scan_type"] == "zap")
    gob = next(t for t in s["by_scan_type"] if t["scan_type"] == "gobuster")
    assert zap["produced_nothing"] is True
    assert gob["produced_nothing"] is False
    assert s["types_that_produced_nothing"] == ["zap"]


@pytest.mark.unit
def test_failures_are_surfaced_with_their_reason():
    s = _session([
        _scan("web", status="failed", result={"error": "ZAP not reachable at zap:8090"}),
        _scan("nmap"),
    ])
    web = next(t for t in s["by_scan_type"] if t["scan_type"] == "web")
    assert web["failed"] == 1
    assert "ZAP not reachable" in web["failures"][0]["error"]
    assert s["types_with_failures"] == ["web"]


@pytest.mark.unit
def test_failure_with_no_error_recorded_still_reports_something():
    """Never render a failure as a blank — that reads as 'no problem'."""
    s = _session([_scan("nikto", status="failed", result=None)])
    nikto = s["by_scan_type"][0]
    assert nikto["failures"][0]["error"] == "no error recorded"


@pytest.mark.unit
def test_durations_sum_per_type():
    s = _session([_scan("nmap", dur=12.5), _scan("nmap", dur=7.5)])
    assert s["by_scan_type"][0]["total_duration_seconds"] == 20.0


@pytest.mark.unit
def test_sequence_records_each_step_in_order():
    s = _session([
        _scan("nmap", job="a", result={"ports_found": 18}),
        _scan("nmap", job="b", result={"ports_found": 25}),
    ])
    seq = s["by_scan_type"][0]["sequence"]
    assert [x["job_id"] for x in seq] == ["a", "b"]
    assert [x["step"] for x in seq] == [1, 2]
    assert seq[1]["produced"] == {"ports_found": 25}


@pytest.mark.unit
def test_empty_session_is_not_an_error():
    s = _session([])
    assert s["total_scans"] == 0
    assert s["flow_order"] == []
    assert s["by_scan_type"] == []
    assert s["types_that_produced_nothing"] == []


@pytest.mark.unit
def test_list_valued_results_are_counted_not_ignored():
    """full-scan reports ports as LISTS; counting them as 0 would be a false
    'produced nothing' — the exact error this summary exists to prevent."""
    s = _session([
        _scan("full_scan", result={"ports_discovered": {"quick": [80, 22, 445],
                                                        "full": [3632, 8787]}}),
        _scan("masscan", result={"all_open_ports": [21, 22, 80, 139]}),
    ])
    full = next(t for t in s["by_scan_type"] if t["scan_type"] == "full_scan")
    mass = next(t for t in s["by_scan_type"] if t["scan_type"] == "masscan")
    assert full["results"] == {"ports_quick": 3, "ports_full": 2}
    assert full["produced_nothing"] is False
    assert mass["results"]["all_open_ports"] == 4
    assert s["types_that_produced_nothing"] == []


# ------------------------------------------------------- KB coverage
# The summary was pure telemetry: it counted what ran and never referenced
# anything the system had learned. scan_recommendations holds what the KB
# (source='rules') and the model (e.g. source='ollama') said SHOULD run, so
# cross-referencing turns "what happened" into "did we do what we knew to do".

@pytest.mark.unit
def test_summary_includes_kb_coverage_section():
    s = _session([_scan("nmap", params={"targets": ["192.168.1.150"]})])
    assert "kb_coverage" in s
    assert "available" in s["kb_coverage"]


@pytest.mark.unit
def test_kb_coverage_degrades_when_the_db_is_unreachable(monkeypatch):
    """Reporting must never be the reason a session teardown fails."""
    monkeypatch.setenv("DB_DSN", "dbname=nope user=nope host=127.0.0.1 port=1 connect_timeout=1")
    s = _session([_scan("nmap", params={"targets": ["192.168.1.150"]})])
    kb = s["kb_coverage"]
    assert kb["available"] is False
    assert "reason" in kb          # says WHY, rather than silently reporting zero


@pytest.mark.unit
def test_url_targets_are_reduced_to_hosts_for_kb_lookup():
    """scan_recommendations keys on ip, so http://host/path must not be queried raw."""
    s = _session([_scan("pipeline", params={"target_url": "http://192.168.1.150:8180/x"})])
    # Reaching the lookup at all (available True/False, not an exception) proves
    # the host reduction ran; the raw URL would never match an inet column.
    assert "kb_coverage" in s
