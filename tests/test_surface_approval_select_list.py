"""The surface-test approval interrupt must expose a SELECT LIST (queued ids +
title/target), the same way the exploit approval does — otherwise the dashboard
banner has nothing to build a dropdown from and falls back to a free-text box,
where operators paste the session id from the approve URL and get a confusing
"Exploit not found".

These exercise langgraph_engine._surface_queued_detail with the DB lookup stubbed:
DB detail is used when present, and a DB miss falls back to the test's own name +
the surface target so the list is still usable (never a bare id). Skips cleanly
where the autogen deps are not importable.
"""
import importlib
import sys
from pathlib import Path

import pytest

AGENTS = Path(__file__).parent.parent / "autogen_agents"


@pytest.fixture()
def lge(monkeypatch):
    sys.path.insert(0, str(AGENTS))
    try:
        mod = importlib.import_module("langgraph_engine")
    except Exception as e:  # langgraph / db drivers absent here
        pytest.skip(f"langgraph_engine not importable: {e}")
    return mod


ID1 = "11111111-1111-1111-1111-111111111111"
ID2 = "22222222-2222-2222-2222-222222222222"


def test_db_detail_used_and_fallback(lge, monkeypatch):
    # DB returns detail for ID1 only; ID2 must fall back to the test's own name.
    monkeypatch.setattr(lge, "_queued_exploit_details",
                        lambda ids: [(ID1, "Tomcat WAR deploy", "10.0.0.1", 8080, "metasploit")])
    pending = [
        {"name": "WSTG webshell @ http://10.0.0.1:80", "pending_exploit_id": ID1},
        {"name": "vector cmdi @ 10.0.0.1:80", "pending_exploit_id": ID2},
        {"name": "a safe test with no id"},  # no pending_exploit_id -> skipped
    ]
    ids, detail = lge._surface_queued_detail(pending, "10.0.0.1")

    assert ids == [ID1, ID2]                     # safe test contributes no id
    assert len(detail) == 2
    d1 = next(d for d in detail if d["id"] == ID1)
    assert d1["title"] == "Tomcat WAR deploy" and d1["target"] == "10.0.0.1:8080"
    d2 = next(d for d in detail if d["id"] == ID2)
    assert d2["title"] == "vector cmdi @ 10.0.0.1:80"   # fell back to the test name
    assert d2["target"] == "10.0.0.1"                    # fell back to surface target


def test_db_miss_still_yields_usable_list(lge, monkeypatch):
    # Total DB miss (e.g. lookup failed) -> every entry falls back, none dropped.
    monkeypatch.setattr(lge, "_queued_exploit_details", lambda ids: [])
    pending = [{"name": "t1", "pending_exploit_id": ID1},
               {"name": "t2", "pending_exploit_id": ID2}]
    ids, detail = lge._surface_queued_detail(pending, "host:80")
    assert ids == [ID1, ID2]
    assert [d["id"] for d in detail] == [ID1, ID2]
    assert all(d["title"] and d["target"] == "host:80" for d in detail)


def test_empty_input(lge, monkeypatch):
    monkeypatch.setattr(lge, "_queued_exploit_details", lambda ids: [])
    assert lge._surface_queued_detail([], "") == ([], [])
    assert lge._surface_queued_detail(None, "") == ([], [])
