"""Static guards for scripts/ensure_db_schema.sh.

WHY THIS EXISTS
---------------
This script is what REPAIRS a drifted database — it applies the idempotent DDL in
db_init/ensure_all_tables.sql. It used to require a local `rag-postgres` container
and `exit 1` without one. In remote / remote_direct mode Postgres lives on a VPS
and no such container exists, so the repairer could never run.

That is not a theoretical gap: `post_review_reports`, `scan_parameters` and the
view `v_identity_credential_state` were declared in the DDL yet ABSENT from the
live database, because every schema update since the move to a remote DB had
silently done nothing. A clean install was correct; only the long-lived
deployment drifted, and only a query that happened to touch one of them would
ever have revealed it.

Sabotage check: restore the `exit 1` when rag-postgres is absent ->
test_does_not_require_a_local_postgres_container RED.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(REPO, "scripts", "ensure_db_schema.sh")
DDL = os.path.join(REPO, "db_init", "ensure_all_tables.sql")

# Functions allowed to name the postgres container: they ARE the backend switch.
BACKEND_FUNCS = ("_psql", "_psql_db", "_psql_file", "_pg_ready")


def _src():
    if not os.path.exists(SCRIPT):
        pytest.skip("ensure_db_schema.sh not present")
    with open(SCRIPT, encoding="utf-8") as fh:
        return fh.read()


def _body(src, name):
    m = re.search(rf"^{re.escape(name)}\(\) \{{$", src, re.M)
    assert m, f"{name}() not found — this guard would pass vacuously"
    return src[m.start():src.index("\n}\n", m.start())]


def test_backend_helpers_exist():
    src = _src()
    for fn in BACKEND_FUNCS:
        assert re.search(rf"^{re.escape(fn)}\(\) \{{$", src, re.M), f"{fn}() is gone"


def test_no_hardcoded_postgres_container_outside_the_backend():
    """Every query must go through the backend switch, or it works only locally."""
    src = _src()
    allowed = "\n".join(_body(src, fn) for fn in BACKEND_FUNCS)
    offenders = []
    for i, line in enumerate(src.splitlines(), 1):
        if "docker exec rag-postgres" not in line or line.strip().startswith("#"):
            continue
        if line in allowed:
            continue
        offenders.append(f"line {i}: {line.strip()[:90]}")
    assert not offenders, (
        f"these bypass the backend switch and only work with a local Postgres: {offenders}"
    )


def test_does_not_require_a_local_postgres_container():
    """Absence of rag-postgres must select a remote backend, not abort the run."""
    src = _src()
    bad = re.search(
        r"if ! docker ps[^\n]*rag-postgres[^\n]*then\n(?:[^\n]*\n){0,4}?\s*exit 1", src)
    assert not bad, (
        "the script still exits when rag-postgres is absent — in remote DB mode "
        "that means schema updates can never be applied at all"
    )
    assert "DB_BACKEND" in src, "no backend selection present"
    for backend in ('"local"', '"psql"', '"python"'):
        assert backend in src, f"backend {backend} not offered"


def test_schema_file_is_applied_from_the_checkout_not_a_container_path():
    """/docker-entrypoint-initdb.d only exists inside the postgres container."""
    body = _body(_src(), "_psql_file")
    assert "ensure_all_tables" not in body or "PROJECT_ROOT" in _src(), \
        "the DDL path must come from the checkout on remote backends"
    m = re.search(r"_psql_file\s+\"\$\{PROJECT_ROOT\}/db_init/ensure_all_tables\.sql\"", _src())
    assert m, "ensure_all_tables.sql is not applied from ${PROJECT_ROOT}/db_init/"


def test_psql_meta_commands_are_stripped_on_the_remote_path():
    """The DDL opens with `\\connect scans`; letting psql re-connect can hang on a
    password prompt, with no output, forever."""
    if not os.path.exists(DDL):
        pytest.skip("ensure_all_tables.sql not present")
    with open(DDL, encoding="utf-8") as fh:
        metas = [l for l in fh.read().splitlines() if l.lstrip().startswith("\\")]
    if not metas:
        pytest.skip("DDL carries no meta-commands")
    body = _body(_src(), "_psql_file")
    assert "grep -v" in body and "\\\\" in body, (
        f"the DDL contains meta-commands {metas[:3]} but _psql_file does not strip them"
    )


def test_unreachable_is_not_reported_as_missing():
    """A pg_hba refusal on the `postgres` database is not evidence that the
    exploits database is absent."""
    src = _src()
    i = src.index("Verifying exploitdb")
    block = src[i:i + 2000]
    assert "pg_hba" in block, \
        "the exploitdb probe does not distinguish a refused connection from an absent database"
    assert "cannot verify" in block, "no 'cannot verify' branch for an unreachable probe"
    unreachable = block.index("cannot verify")
    missing = block.index("Missing exploits database")
    assert unreachable < missing, \
        "the unreachable branch must be tested before declaring the database missing"
