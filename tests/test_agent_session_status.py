"""Every agent-session status the code WRITES must be allowed by the DB CHECK.

Run on demand:

    pytest tests/test_agent_session_status.py -v

WHY THIS EXISTS
---------------
langgraph_engine._finish started writing status='scanning' (a session whose phase
graph finished but whose scans are still running), but the
`agent_sessions_status_check` constraint did not list it — so the write raised
`violates check constraint "agent_sessions_status_check"` and the whole LangGraph
run errored out. ast.parse passed, imports passed, the container was healthy; only
a live run hit it. This pins the code's status literals to the schema's CHECK.

SABOTAGE PROOF
--------------
Add `status="paused"` to an update_agent_session call without adding it to the
CHECK in db_init/ensure_all_tables.sql and this fails.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")
SCHEMA = os.path.join(REPO, "db_init", "ensure_all_tables.sql")


def _allowed_statuses():
    """The values in the agent_sessions_status_check CHECK, from the schema."""
    if not os.path.exists(SCHEMA):
        pytest.skip("ensure_all_tables.sql not present")
    sql = open(SCHEMA, encoding="utf-8").read()
    # The agent_sessions status CHECK is the one whose IN-list carries
    # 'awaiting_approval' (unique to this table among the schema's status CHECKs).
    for grp in re.findall(r"status\s+IN\s*\(([^)]*)\)", sql, re.I):
        vals = {v.strip().strip("'\"") for v in grp.split(",") if v.strip()}
        if "awaiting_approval" in vals:
            return vals
    pytest.fail("could not locate the agent_sessions status CHECK in ensure_all_tables.sql")


def _written_statuses():
    """Status string literals passed to update_agent_session(...) in the engine."""
    if not os.path.exists(ENGINE):
        pytest.skip("langgraph_engine.py not present")
    tree = ast.parse(open(ENGINE, encoding="utf-8").read())
    out = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "update_agent_session"):
            for kw in node.keywords:
                if kw.arg == "status" and isinstance(kw.value, ast.Constant) \
                        and isinstance(kw.value.value, str):
                    out.add(kw.value.value)
            # positional status (2nd arg after session_id)
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) \
                    and isinstance(node.args[1].value, str):
                out.add(node.args[1].value)
    return out


def test_scanning_is_allowed_by_the_check():
    assert "scanning" in _allowed_statuses(), (
        "agent_sessions_status_check must allow 'scanning' — _finish writes it")


def test_every_written_status_is_in_the_check():
    allowed = _allowed_statuses()
    written = _written_statuses()
    assert written, "no update_agent_session(status=...) literals found — guard too weak"
    bad = {s for s in written if s and s not in allowed}
    assert not bad, (
        f"langgraph_engine writes agent-session statuses the CHECK rejects: "
        f"{sorted(bad)} (allowed: {sorted(allowed)}). A live run will raise "
        f'violates check constraint "agent_sessions_status_check".')
