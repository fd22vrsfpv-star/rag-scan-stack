"""Metasploit dispatches must be correlatable, and aimed at the right port.

Run on demand:

    pytest tests/test_msf_dispatch_identity.py -v

WHY THIS EXISTS
---------------
36 metasploit recommendations sat in `status='queued'` for 32 hours having
produced ZERO executions. The post-review agent reported them as "stuck"; the
real causes were two separate defects, both visible in the stored `extra`:

  "job_id": "msf"
  "dispatched_command": "msf auxiliary/gather/java_rmi_registry RHOSTS=... RPORT=21"
  "high_value": {"port": 1099, "service": "java-rmi"}

  1. `job_id` was the literal string "msf" for ALL 36 — one distinct value across
     the set. `ExecutionResult` had no `job_id` field at all, so the runner
     computed the MSF job id, wrote it into the output text as "Job started: N",
     and dropped it; the caller read only `session_id`, which an auxiliary module
     never sets. With no identifier, no dispatch could ever be correlated with a
     result.
  2. 16 of 36 carried a contradictory RPORT. An RMI module whose own metadata
     says 1099 was dispatched against port 21 — an RMI exploit aimed at FTP —
     because the row's `port` column is the TRIGGER port, not the module's.

These are pure functions precisely so they can be checked without dispatching a
real exploit.
"""
import importlib.util
import json
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
ASSETS = os.path.join(REPO, "dashboard", "bff", "routers", "assets.py")


@pytest.fixture(scope="module")
def mod():
    """Load assets.py without importing the whole BFF package."""
    if not os.path.exists(ASSETS):
        pytest.skip("BFF assets router not present")
    src = open(ASSETS, encoding="utf-8").read()
    ns = {"json": json}
    # Execute only the two helpers, which depend on nothing but json.
    # Pull the two functions out by AST, not regex. A regex bounded on the next
    # `^def ` ran to end-of-file — the next definition is INDENTED (nested in a
    # route handler) — and swallowed a module's worth of `await`s.
    import ast
    tree = ast.parse(src)
    wanted = {"msf_module_port", "msf_job_identifier"}
    picked = [n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name in wanted]
    missing = wanted - {n.name for n in picked}
    assert not missing, f"not defined at MODULE level in assets.py: {missing}"
    exec(compile(ast.Module(body=picked, type_ignores=[]), "<helpers>", "exec"), ns)
    return ns


# ── the port ────────────────────────────────────────────────────────────────

def test_the_module_port_beats_the_trigger_port(mod):
    """THE bug: an RMI exploit dispatched at FTP."""
    rec = {"id": "r1", "port": 21,
           "extra": {"port": 1099,
                     "high_value": {"port": 1099, "service": "java-rmi"}}}
    assert mod["msf_module_port"](rec) == 1099, \
        "the trigger port won again — this aims an RMI module at FTP"


def test_extra_as_a_json_string_is_still_read(mod):
    """psycopg2 hands jsonb back as a dict, but not every caller does."""
    rec = {"id": "r1", "port": 21,
           "extra": json.dumps({"high_value": {"port": 1099}})}
    assert mod["msf_module_port"](rec) == 1099


def test_the_row_port_is_used_when_extra_says_nothing(mod):
    assert mod["msf_module_port"]({"id": "r", "port": 445, "extra": {}}) == 445
    assert mod["msf_module_port"]({"id": "r", "port": 445}) == 445


def test_no_port_anywhere_returns_none_so_the_caller_can_resolve(mod):
    """None must not become 0 or a guess: the caller resolves from the DB."""
    assert mod["msf_module_port"]({"id": "r"}) is None
    assert mod["msf_module_port"]({"id": "r", "extra": {"high_value": {}}}) is None


def test_malformed_extra_does_not_raise(mod):
    for bad in ("not json at all", "[1,2,3]", None, 42):
        assert mod["msf_module_port"]({"id": "r", "port": 80, "extra": bad}) == 80


# ── the identifier ──────────────────────────────────────────────────────────

def test_job_id_is_preferred_over_session_id(mod):
    """An auxiliary module starts a job and never creates a session."""
    got = mod["msf_job_identifier"]({"job_id": 7, "session_id": None}, {"id": "r1"})
    assert got == "7"


def test_session_id_is_used_when_there_is_no_job(mod):
    assert mod["msf_job_identifier"]({"session_id": 3}, {"id": "r1"}) == "3"


def test_the_literal_msf_is_never_an_identifier(mod):
    """All 36 dispatches shared it, so nothing could be correlated."""
    got = mod["msf_job_identifier"]({"job_id": "msf", "session_id": None},
                                    {"id": "rec-abc"})
    assert got == "rec-abc", f"got {got!r} — 'msf' identifies nothing"


def test_an_empty_response_falls_back_to_the_unique_rec_id(mod):
    assert mod["msf_job_identifier"]({}, {"id": "rec-xyz"}) == "rec-xyz"
    assert mod["msf_job_identifier"](None, {"id": "rec-xyz"}) == "rec-xyz"


def test_two_dispatches_never_share_an_identifier(mod):
    """The property that actually matters."""
    a = mod["msf_job_identifier"]({}, {"id": "rec-1"})
    b = mod["msf_job_identifier"]({}, {"id": "rec-2"})
    assert a != b


# ── the runner must return what it computes ────────────────────────────────

@pytest.mark.unit
def test_execution_result_carries_the_job_id():
    """The model dropped it: the id was computed, written into the output text
    as "Job started: N", and never returned as a field."""
    path = os.path.join(REPO, "exploit_runner", "exploit_runner.py")
    if not os.path.exists(path):
        pytest.skip("exploit_runner not present")
    src = open(path, encoding="utf-8").read()
    import re
    m = re.search(r"class ExecutionResult\(BaseModel\):(.*?)(?=^class |\Z)",
                  src, re.S | re.M)
    assert m, "ExecutionResult not found"
    assert re.search(r"^\s*job_id\s*:", m.group(1), re.M), \
        "ExecutionResult has no job_id field again"
    assert "job_id=job_id" in src, \
        "the msf handler no longer populates job_id on the response"
