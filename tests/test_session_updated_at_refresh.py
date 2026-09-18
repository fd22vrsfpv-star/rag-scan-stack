"""A RUNNING session's updated_at must be refreshed as it makes progress.

WHY THIS EXISTS
---------------
agent_sessions.updated_at was only written on a STATUS change, so it froze at a
run's start. A healthy 30-minute run then read as "no update for 30 minutes" —
indistinguishable from a dead one — to the UI and to anything keying on
updated_at. add_agent_message (the single choke point every session message goes
through, sync and async) now also bumps updated_at, gated on running statuses so
a late message never rewrites a finished session's completion time.

WHAT IS PROVEN
--------------
Both add_agent_message implementations issue an UPDATE of agent_sessions'
updated_at, gated on a running status. Source-level (ast/text) so it runs on a
bare checkout without a database or asyncpg/psycopg2.

SABOTAGE PROOF
--------------
Delete the UPDATE from either writer and its assertion fails.

Run on demand:

    pytest tests/test_session_updated_at_refresh.py -v
"""
import os
import re

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SYNC = os.path.join(REPO, "autogen_agents", "db_utils.py")
ASYNC = os.path.join(REPO, "autogen_agents", "async_db_utils.py")


def _func_body(path, name):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    src = open(path, encoding="utf-8").read()
    # from the def to the next TOP-LEVEL def (or EOF). Not just `^\S`, because a
    # multi-line signature's closing `) -> ...:` line starts at column 0.
    m = re.search(
        rf"(?ms)^(?:async )?def {re.escape(name)}\(.*?(?=^(?:async )?def |\Z)", src)
    assert m, f"{name} not found in {path}"
    return m.group(0)


def _asserts_refresh(body):
    low = re.sub(r"\s+", " ", body).lower()
    return ("update agent_sessions set updated_at = now()" in low
            and "status in" in low
            and "'active'" in low)


def test_sync_writer_refreshes_updated_at():
    assert _asserts_refresh(_func_body(SYNC, "add_agent_message")), (
        "sync add_agent_message must UPDATE agent_sessions SET updated_at=now() "
        "gated on a running status")


def test_async_writer_refreshes_updated_at():
    assert _asserts_refresh(_func_body(ASYNC, "add_agent_message")), (
        "async add_agent_message must UPDATE agent_sessions SET updated_at=now() "
        "gated on a running status")
