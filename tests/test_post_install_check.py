"""Static guards for scripts/post-install-check.sh.

WHY THIS EXISTS
---------------
The install verifier was reporting ~25 tables as MISSING on a database where they
all existed, and then aborting partway with `f: unbound variable`. Three defects,
each invisible to any check that merely runs the script and reads its exit code:

  * the table/view loops called `docker exec rag-postgres psql` DIRECTLY, but in
    remote / remote_direct DB mode there is no such container — every query read
    empty and "could not query" was reported as "missing";
  * the one fallback path printed a literal 't'/'f' instead of the row value, so
    `SELECT count(*)` returned the string "f" and `[[ "$f" -eq 0 ]]` sent bash
    into arithmetic evaluation, where a bare word is a VARIABLE NAME — under
    `set -u` that kills the script;
  * a helper that set a global to report success was called as `x=$(_run_sql …)`,
    i.e. in a SUBSHELL, so the global never propagated to the caller.

These are all statically detectable, and none need a database, so they run on a
bare checkout.

Sabotage check: re-add `docker exec rag-postgres psql` to the table loop ->
test_no_hardcoded_db_container RED.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(REPO, "scripts", "post-install-check.sh")
LIB = os.path.join(REPO, "scripts", "lib", "compose-target.sh")
DDL = os.path.join(REPO, "db_init", "ensure_all_tables.sql")


def _src():
    if not os.path.exists(SCRIPT):
        pytest.skip("post-install-check.sh not present")
    with open(SCRIPT, encoding="utf-8") as fh:
        return fh.read()


def _lib_src():
    """The SQL resolver moved to scripts/lib/compose-target.sh (2026-09-09) so
    setup.sh's Phase 7 uses the same one instead of its own `docker exec
    rag-postgres`. The invariants below did not change — they follow the code."""
    if not os.path.exists(LIB):
        pytest.skip("scripts/lib/compose-target.sh not present")
    with open(LIB, encoding="utf-8") as fh:
        return fh.read()


def _function_body(src, name):
    """Crude but adequate: from `name() {` to the first line that is just `}`."""
    m = re.search(rf"^{re.escape(name)}\(\) \{{$", src, re.M)
    assert m, f"{name}() not found — this guard would pass vacuously"
    end = src.index("\n}\n", m.start())
    return src[m.start():end]


def test_no_hardcoded_db_container():
    """No call site in the verifier may name the postgres container.

    Originally this allowed _run_sql to do so; the resolver now lives in
    ct_sql, so the script itself should contain none at all. `docker exec
    rag-postgres` is doubly wrong now: it breaks when the database moves
    off-box, AND it addresses a GLOBAL name, so under a second compose project
    a fresh-install check verifies the LIVE database and passes.
    """
    offenders = []
    for i, line in enumerate(_src().splitlines(), 1):
        if "docker exec rag-postgres" not in line:
            continue
        if line.strip().startswith("#"):
            continue
        offenders.append(f"line {i}: {line.strip()[:90]}")
    assert not offenders, (
        "these call sites name the postgres container directly instead of going "
        f"through ct_sql / ct_exec: {offenders}"
    )


def test_only_ct_sql_names_the_db_container():
    """In the shared helper, exactly one function may name rag-postgres."""
    lib = _lib_src()
    body = _function_body(lib, "ct_sql")
    offenders = []
    for i, line in enumerate(lib.splitlines(), 1):
        if "rag-postgres" not in line or line.strip().startswith("#"):
            continue
        if line in body:
            continue
        offenders.append(f"line {i}: {line.strip()[:90]}")
    assert not offenders, (
        "only ct_sql may name the postgres container in compose-target.sh: "
        f"{offenders}"
    )


def test_run_sql_delegates_to_the_shared_resolver():
    """If _run_sql stopped delegating, the verifier and setup.sh Phase 7 would
    drift apart again — and the copy that lost the DSN fallback would report
    every table as missing in remote DB mode."""
    src = _src()
    m = re.search(r"^_run_sql\(\)\s*\{(.*?)\}", src, re.M | re.S)
    assert m, "_run_sql() not found in post-install-check.sh"
    assert "ct_sql" in m.group(1), (
        "_run_sql no longer calls ct_sql — it must not grow a second copy of "
        "the resolution logic"
    )


def test_sql_results_are_not_compared_arithmetically_unguarded():
    """`[[ "$X" -eq 0 ]]` on non-numeric text aborts the script under `set -u`."""
    src = _src()
    lines = src.splitlines()
    sql_vars = set(re.findall(r"^\s*(\w+)=\$\(_run_sql", src, re.M))
    assert sql_vars, "no _run_sql assignments found — guard would pass vacuously"
    bad = []
    for i, line in enumerate(lines, 1):
        for var in sql_vars:
            if re.search(rf'\[\[\s*"\$\{{?{var}\}}?"\s*-(eq|ne|gt|ge|lt|le)\b', line):
                window = "\n".join(lines[max(0, i - 6):i])
                if f'_is_num "${var}"' not in window:
                    bad.append(f"line {i}: {line.strip()[:80]}")
    assert not bad, (
        "these compare a _run_sql result arithmetically without a preceding "
        f"_is_num guard: {bad}"
    )


def test_run_sql_reports_failure_by_exit_status():
    """A global set inside `x=$(ct_sql …)` is lost — it runs in a subshell.

    Checked on ct_sql, where the logic now lives. It must also distinguish
    "ran but failed" (1) from "no database reachable" (2): _check_object turns
    a non-zero status into "could not query", and conflating that with
    "missing" is the defect this whole file exists for.
    """
    body = _function_body(_lib_src(), "ct_sql")
    assert "return 0" in body, "ct_sql must signal success with a zero status"
    assert "return 1" in body, "ct_sql must signal a failed query with status 1"
    assert "return 2" in body, (
        "ct_sql must signal 'no database reachable' with status 2 — distinct "
        "from a query that ran and failed"
    )
    for setter in ("_SQL_OK=", "_SQL_ERR="):
        assert setter not in body, (
            f"{setter} is set inside ct_sql, but callers invoke it in a command "
            "substitution (a subshell) where the assignment cannot propagate"
        )


def test_unreachable_database_is_not_reported_as_missing():
    """The distinction the whole fix rests on: 'could not query' != 'missing'."""
    body = _function_body(_src(), "_check_object")
    assert "rc" in body and "!= 0" in body, \
        "_check_object must branch on _run_sql's exit status"
    warn_i, fail_i = body.index("warn "), body.index("fail ")
    assert warn_i < fail_i, "the unreachable branch must come before the missing branch"


def test_expected_tables_are_actually_declared():
    """A name in EXPECTED_TABLES that no DDL creates is a permanent false FAIL."""
    src = _src()
    m = re.search(r"EXPECTED_TABLES=\((.*?)\n\)", src, re.S)
    assert m, "EXPECTED_TABLES not found"
    listed = [w for line in m.group(1).splitlines()
              for w in line.split("#", 1)[0].split()]
    assert len(listed) > 20, f"only {len(listed)} tables parsed — guard too weak"
    if not os.path.exists(DDL):
        pytest.skip("ensure_all_tables.sql not present")
    with open(DDL, encoding="utf-8") as fh:
        ddl = fh.read()
    declared = set(re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?(?:public\.)?(\w+)", ddl))
    declared |= set(re.findall(r"CREATE (?:OR REPLACE )?VIEW (?:public\.)?(\w+)", ddl))
    # Checkpoint tables are created by langgraph at runtime, not by our DDL.
    runtime = {"checkpoints", "checkpoint_blobs", "checkpoint_writes",
               "checkpoint_migrations"}
    missing = sorted(t for t in listed if t not in declared and t not in runtime)
    assert not missing, (
        f"EXPECTED_TABLES names tables that no DDL in db_init creates: {missing}"
    )


def test_the_wstg_review_table_is_checked():
    """PR #72 added wstg_manual_reviews to db_init, ensure_db_schema.sh and the
    health router, but not here — so the install check never verified it."""
    assert "wstg_manual_reviews" in _src(), \
        "wstg_manual_reviews is not in post-install-check.sh"
