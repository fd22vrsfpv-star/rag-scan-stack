"""The session watchdog must see every status a WORKING session can hold.

Two sessions sat at `scanning` for 478 hours (2026-09-27 -> 2026-10-17). Their
metadata said `"phase": "done"` with the summary written, so the work had
finished; only the terminal status write was missing, because that write lives
inside the process (`langgraph_engine.py::update_agent_session`) and the
process had been restarted away.

A watchdog DID exist and was running the whole time. It asked for
`list_agent_sessions(status="active")` — one status — and a `scanning` session
is therefore invisible to it. The dashboard polls anything non-terminal, so the
dead rows produced steady `GET /pentest/{id}/scans` traffic and read as live
scans: the status caused the polling that made the status look justified.

The first fix attempt added a SECOND watchdog beside the existing one. That was
wrong — two sweepers over one table is the divergent-copy problem, and the real
defect was a one-word filter. These tests pin the filter instead.

    docker run --rm -v /opt/rag-scan-stack:/repo -w /repo python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=.:tests \
      python -m pytest tests/test_session_watchdog.py -v'
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SERVICE = REPO / "autogen_agents" / "autogen_service.py"
DB_UTILS = REPO / "autogen_agents" / "db_utils.py"

# Non-terminal AND backed by a process. `awaiting_approval` is non-terminal
# but waits on a HUMAN — sweeping it would destroy an operator queue.
WORKING_STATUSES = {"active", "scanning"}


def _func(path, name):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    pytest.fail(f"{name} not found in {Path(path).name}")


class TestTheWatchdogSeesScanningSessions:
    def test_it_asks_for_every_working_status(self):
        """The whole defect, in one assertion."""
        fn = _func(SERVICE, "session_watchdog")
        asked = set()
        for n in ast.walk(fn):
            if not (isinstance(n, ast.Call)
                    and getattr(n.func, "id", None) == "list_agent_sessions"):
                continue
            for kw in n.keywords:
                if kw.arg != "status":
                    continue
                if isinstance(kw.value, ast.Constant):
                    asked.add(kw.value.value)
                elif isinstance(kw.value, (ast.Tuple, ast.List, ast.Set)):
                    asked |= {e.value for e in kw.value.elts
                              if isinstance(e, ast.Constant)}
        assert asked, "the watchdog no longer lists sessions by status"
        missing = WORKING_STATUSES - asked
        assert not missing, (
            f"the watchdog cannot see {sorted(missing)} sessions, so one that "
            "dies in that state claims to be running forever — this is how "
            f"two sat at 'scanning' for 478 hours. It asks for: {sorted(asked)}")

    def test_it_does_not_sweep_the_human_queue(self):
        fn = _func(SERVICE, "session_watchdog")
        asked = set()
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "list_agent_sessions":
                for kw in n.keywords:
                    if kw.arg == "status":
                        if isinstance(kw.value, ast.Constant):
                            asked.add(kw.value.value)
                        elif isinstance(kw.value, (ast.Tuple, ast.List, ast.Set)):
                            asked |= {e.value for e in kw.value.elts
                                      if isinstance(e, ast.Constant)}
        assert "awaiting_approval" not in asked, (
            "awaiting_approval waits on a PERSON. Sweeping it would stall "
            "a real operator queue; 'nobody approved it yet' is not a dead "
            "process")


class TestTheListerSupportsASequence:
    def test_it_accepts_several_statuses(self):
        """Without this the fix above cannot be expressed at all."""
        fn = _func(DB_UTILS, "list_agent_sessions")
        src = ast.get_source_segment(
            DB_UTILS.read_text(encoding="utf-8"), fn) or ""
        assert "ANY(" in src, (
            "list_agent_sessions must support a sequence of statuses; with "
            "`status = %s` alone the watchdog can only ever watch one")

    def test_a_single_status_still_works(self):
        """Backward compatible: every other caller passes one string."""
        fn = _func(DB_UTILS, "list_agent_sessions")
        tests = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                 and getattr(n.func, "id", None) == "isinstance"]
        assert tests, (
            "the sequence branch must be chosen by an isinstance check, so a "
            "plain string keeps the original single-status query")

    def test_there_is_only_one_watchdog(self):
        """The first fix attempt added a second sweeper over the same table.

        Two watchdogs can reap the same row differently and neither owns the
        decision. The fix belongs in the one that already exists.
        """
        extra = (REPO / "autogen_agents" / "session_watchdog.py")
        assert not extra.exists(), (
            "a second watchdog module exists alongside session_watchdog() in "
            "autogen_service.py — one table, one sweeper")
