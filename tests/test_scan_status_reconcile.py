"""Guard the scan-status reconciliation that keeps a session from getting stuck.

A scanner job that finishes without its completion reaching session_scan_metrics
leaves the scan 'running' forever; the langgraph post-scan wait loop then blocks
until its 6h deadline and never runs final analysis/reporting — the session sits
at 'scanning'. Two concrete regressions caused this and each is guarded here:

  1. deep_port_scan (a first-class scan type) was MISSING from the scan-type ->
     scanner-URL maps used to refresh stale scans, so that scan never refreshed.
  2. the refresh persisted via update_scan_status(), which no-ops without a
     get_current_session() context (the background poller / API handlers) — so
     completion never reached the DB. persist_scan_status() + an explicit
     session_id argument fix that.

Source-level (ast/text) so it runs on a bare checkout with no DB or app deps.
Sabotage-proven: delete 'deep_port_scan' from a map, or the session_id param,
and the matching test fails.
"""
import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Every scan-type -> service-URL map that the stale-status refresh relies on.
# (file, a substring that uniquely anchors the map literal)
_MAP_SITES = [
    ("autogen_agents/scan_tools.py", '"credential_check": tools.nmap_url'),
    ("autogen_agents/autogen_service.py", '"credential_check": nmap'),
]

# scan types that constitute the slow full-range sweep — these are exactly the
# ones the wait loop blocks on, so a missing entry is the stall.
_REQUIRED_TYPES = ("full_scan", "deep_port_scan")


def _read(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        return f.read()


def test_deep_scan_types_in_every_refresh_map():
    missing = []
    for rel, anchor in _MAP_SITES:
        src = _read(rel)
        assert anchor in src, f"{rel}: refresh map anchor not found — did the map move?"
        # take a window around the anchor (the map literal)
        i = src.index(anchor)
        window = src[max(0, i - 1500):i + 1500]
        for t in _REQUIRED_TYPES:
            if f'"{t}"' not in window:
                missing.append(f"{rel}: '{t}' not in refresh map")
    assert not missing, (
        "deep full-range scan types missing from a stale-status refresh map — a "
        "stale scan of that type can never reconcile, stalling the session:\n  "
        + "\n  ".join(missing))


def test_persist_scan_status_exists():
    src = _read("autogen_agents/scan_tools.py")
    assert "def persist_scan_status(" in src, (
        "persist_scan_status() is gone — the by-(session,job) DB write that makes "
        "completion reliable from a background thread; without it the session "
        "stays 'scanning'.")


def test_update_scan_status_takes_session_id():
    src = _read("autogen_agents/scan_tools.py")
    m = re.search(r"def update_scan_status\(([^)]*)\)", src, re.S)
    assert m, "update_scan_status signature not found"
    assert "session_id" in m.group(1), (
        "update_scan_status must accept an explicit session_id — without it the "
        "call no-ops off the graph thread (get_current_session() unset) and the "
        "registry scan stays 'running'.")


def test_restore_from_db_sets_current_phase():
    src = _read("autogen_agents/scan_tools.py")
    m = re.search(r"def restore_from_db\(.*?(?=\n    @classmethod|\n    def )", src, re.S)
    assert m, "restore_from_db not found"
    assert "current_phase" in m.group(0), (
        "restore_from_db must set current_phase in the registry dict — "
        "get_session_status() requires it and raised KeyError on every DB "
        "restore (empty registry / after a restart) without it.")


def test_get_session_scan_status_handles_expired_job():
    """A scanner job that aged out of the scanner's memory (404) must be treated
    as terminal — otherwise a scan whose completion callback never landed stays
    'running' forever and the session sits at 'scanning'. This catches scan types
    that are absent from the refresh map too (e.g. asnmap/uncover once were)."""
    src = _read("autogen_agents/scan_tools.py")
    i = src.index("def get_session_scan_status(")
    j = src.index("def search_exploits_enhanced(", i)
    body = src[i:j]
    assert "status_code == 404" in body, (
        "get_session_scan_status must treat a 404 (expired scanner job) as "
        "completed; without it a stale 'running' scan lingers and the session "
        "stays 'scanning'.")


def test_agent_sessions_status_check_allows_scanning():
    """The engine writes the in-progress status 'scanning' (see _finish); the DB
    CHECK constraint MUST allow it, or every session that finishes with a scan
    still running fails the write and is marked 'failed'. Pin the db_init DDL."""
    import glob
    ddls = glob.glob(os.path.join(REPO, "db_init", "*.sql"))
    hits = []
    for f in ddls:
        with open(f, encoding="utf-8") as fh:
            txt = fh.read()
        if "agent_sessions_status_check" in txt or (
                "agent_sessions" in txt and "status" in txt and "CHECK" in txt):
            hits.append(txt)
    checks = [t for t in hits if "'scanning'" in t and "'awaiting_approval'" in t]
    assert checks, (
        "no db_init CHECK constraint for agent_sessions.status includes "
        "'scanning' — the engine writes that status and the constraint must "
        "permit it (a stale live constraint missing it marks finished sessions "
        "'failed').")
