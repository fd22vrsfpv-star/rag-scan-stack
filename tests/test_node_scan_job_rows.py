"""A remote scan must leave a durable job row, not just a JSONL line.

`node_scan_jobs` was declared, indexed and triggered — and never written:

    SELECT count(*) FROM node_scan_jobs  ->  0

while the SAME code path was appending to `scan_audit/audit.jsonl` and filling
`scope_coverage`. No INSERT against the table existed anywhere in the repo. So
a remote scan's history was reconstructable only from a file on disk plus the
per-target coverage rows — neither of which records which node ran it, what
parameters it was given, or why it failed. The table had the full job shape
sitting unused.

Three things have to hold, and they are the three the table exists for:

  1. Dispatch writes `running` BEFORE the scan runs. A row written only on
     completion cannot describe a scan that hung, which is the case an
     operator most wants to look up.
  2. The failure path writes `failed` WITH the error. Same distinction
     `scope_coverage` draws: a scan that could not run is not a scan that
     found nothing.
  3. Every write is keyed by `job_id` and upserts. Dispatch INSERTs and the
     terminal paths UPDATE that same row, so `job_id` needs its unique index
     or a retried dispatch forks the history into two rows — and an
     `ON CONFLICT` whose expression does not match an index raises
     "no unique or exclusion constraint matching the ON CONFLICT
     specification" on every insert.

Structural (`ast` over source + the DDL text), so it runs with no database and
no node_manager import — that module needs sliver-py, boto3 and a live DSN.

Sabotage check: delete the dispatch call and
`test_dispatch_records_a_running_row` fails; change the failure call's status
to 'completed' and `test_failure_path_records_failed_with_the_error` fails;
drop the unique index from the DDL and
`test_job_id_has_a_unique_index_for_the_upsert` fails by index name.

    pytest tests/test_node_scan_job_rows.py -q
"""

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
NM = REPO / "node_manager" / "node_manager.py"
DDL = REPO / "db_init" / "ensure_all_tables.sql"
INDEX = "uq_node_scan_jobs_job_id"


def _tree() -> ast.Module:
    if not NM.exists():
        pytest.skip("node_manager.py not found")
    return ast.parse(NM.read_text(encoding="utf-8"))


def _calls() -> list[ast.Call]:
    return [n for n in ast.walk(_tree())
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == "_record_scan_job"]


def _status_of(call: ast.Call):
    """The 7th positional arg, or the `status=` keyword."""
    for kw in call.keywords:
        if kw.arg == "status" and isinstance(kw.value, ast.Constant):
            return kw.value.value
    if len(call.args) >= 7 and isinstance(call.args[6], ast.Constant):
        return call.args[6].value
    return None


def test_the_writer_exists():
    fns = [n for n in ast.walk(_tree())
           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
           and n.name == "_record_scan_job"]
    assert fns, (
        "node_manager has no _record_scan_job — node_scan_jobs stays at 0 rows "
        "and a remote scan's history lives only in a JSONL file")


def test_dispatch_records_a_running_row():
    statuses = [_status_of(c) for c in _calls()]
    assert "running" in statuses, (
        "nothing records a job as 'running'. A row written only at completion "
        "cannot describe a scan that hung — the case most worth looking up")


def test_terminal_states_are_recorded():
    statuses = [_status_of(c) for c in _calls()]
    assert "completed" in statuses, "no completion path records the job"
    assert "failed" in statuses, "no failure path records the job"
    assert all(s in ("running", "completed", "failed", "cancelled")
               for s in statuses), statuses


def test_failure_path_records_failed_with_the_error():
    """Found by sitting in the same block as the scan_failed audit write."""
    for node in ast.walk(_tree()):
        if not isinstance(node, ast.If):
            continue
        body = list(ast.walk(node))
        if not any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                   and n.func.id == "write_audit" and n.args
                   and isinstance(n.args[0], ast.Constant)
                   and n.args[0].value == "scan_failed" for n in body):
            continue
        local = [n for n in body if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == "_record_scan_job"]
        assert local, (
            "the failure path writes no job row — a failed remote scan leaves "
            "a row stuck at 'running' forever, which reads as a hung scan")
        for c in local:
            assert _status_of(c) == "failed", _status_of(c)
            assert any(kw.arg == "error" for kw in c.keywords), (
                "the failure row carries no error, so the table records THAT "
                "it failed and not WHY — the column exists for this")
        return
    pytest.fail("no scan_failed branch found")


def test_the_writer_upserts_on_job_id():
    fn = next(n for n in ast.walk(_tree())
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "_record_scan_job")
    sql = " ".join(" ".join(s.value.split()) for s in ast.walk(fn)
                   if isinstance(s, ast.Constant) and isinstance(s.value, str))
    assert re.search(r"ON\s+CONFLICT\s*\(\s*job_id\s*\)", sql, re.I), (
        "the writer does not upsert on job_id, so the dispatch row and the "
        "completion row are two different rows")
    assert re.search(r"INSERT\s+INTO\s+node_scan_jobs", sql, re.I), sql[:200]


def test_job_id_has_a_unique_index_for_the_upsert():
    """`ON CONFLICT (job_id)` without this raises on EVERY insert."""
    if not DDL.exists():
        pytest.skip("ensure_all_tables.sql not found")
    ddl = DDL.read_text(encoding="utf-8")
    m = re.search(r"CREATE\s+UNIQUE\s+INDEX[^;]*" + INDEX + r"[^;]*;", ddl, re.I)
    assert m, (
        f"{INDEX} is not declared. The ON CONFLICT (job_id) upsert in "
        "node_manager raises 'no unique or exclusion constraint matching the "
        "ON CONFLICT specification' on every write")
    stmt = " ".join(m.group(0).split())
    assert re.search(r"\(\s*job_id\s*\)", stmt), stmt
    assert " WHERE " not in stmt.upper(), (
        "the index is PARTIAL. Postgres requires the ON CONFLICT expression to "
        "repeat a partial index's predicate exactly, and node_manager's does "
        "not — so every insert would raise. See CLAUDE.md on partial unique "
        f"indexes.\n  {stmt}")


def test_the_job_row_carries_the_engagement():
    """Collected target data is engagement-attributable (CLAUDE.md)."""
    if not DDL.exists():
        pytest.skip("ensure_all_tables.sql not found")
    ddl = DDL.read_text(encoding="utf-8")
    assert re.search(r"node_scan_jobs\s+ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+engagement_id",
                     " ".join(ddl.split()), re.I), (
        "node_scan_jobs has no engagement_id, so a remote scan's history "
        "survives the purge of the engagement that ran it")
    fn = next(n for n in ast.walk(_tree())
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "_record_scan_job")
    assert any(a.arg == "engagement_id" for a in fn.args.args), (
        "the writer takes no engagement_id, so every row is NULL-attributed")


def test_every_call_passes_an_engagement():
    """`_eid` is resolved once per dispatch; no call may skip it."""
    for c in _calls():
        names = [a.id for a in list(c.args) + [k.value for k in c.keywords]
                 if isinstance(a, ast.Name)]
        assert "_eid" in names, (
            f"node_manager.py:{c.lineno} records a job row without the "
            "engagement — the purge cannot claim it")


def test_the_writer_fails_soft():
    """Bookkeeping must not refuse a scan that ran."""
    fn = next(n for n in ast.walk(_tree())
              if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == "_record_scan_job")
    handlers = [n for n in ast.walk(fn) if isinstance(n, ast.ExceptHandler)]
    assert handlers, (
        "_record_scan_job has no exception handler — a database hiccup would "
        "fail a scan that already ran")
    for h in handlers:
        assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr in ("warning", "error", "exception")
                   for n in ast.walk(h)), (
            "the handler is silent. A silent write failure is exactly how this "
            "table reached 0 rows without anyone noticing")
