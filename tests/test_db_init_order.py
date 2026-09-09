"""The schema files must apply, in the order the postgres image runs them.

Run on demand:

    pytest tests/test_db_init_order.py -v

WHY THIS EXISTS
---------------
Found by the first rehearsal of install phases 6-10. A fresh install reported

    [OK] Schema applied: 114 tables (106 new)

and the post-install check then said `security_tests — table missing`,
`security_test_runs — table missing`, `assets_hostname_not_ip missing`. All
three ARE in db_init/ensure_all_tables.sql. Three separate defects, each
invisible to anything that only reads exit codes:

1. **Forward references inside a transaction.** A 378-line data-REPAIR block
   (asset dedup) sat near the top of the file and updated ~16 tables created
   further down. On a fresh database its first statement failed; because the
   block is one BEGIN/COMMIT, every statement to the COMMIT was skipped with
   "current transaction is aborted" — 24 of them, including the
   assets_hostname_not_ip CHECK that is the block's whole purpose.

2. **Forward references in a CREATE TABLE.** `security_tests` declared
   `engagement_id uuid REFERENCES public.engagements(id)` inline, and
   `engagements` is created ~1000 lines below. The CREATE failed outright, so
   the table, its 6 indexes, `security_test_runs` and its 5 all vanished.

3. **psql exits 0 anyway.** It runs without ON_ERROR_STOP, so it reports each
   error on stderr and carries on. Phase 7 redirected that to /dev/null. 43
   error lines were discarded and the phase recorded OK.

And in the container's own init directory:

4. **The entrypoint aborts on the first file.** It runs every top-level
   `*.sql` / `*.sh` in `/docker-entrypoint-initdb.d` alphabetically with
   `ON_ERROR_STOP=1`. `add_engagement_id_to_scan_tables.sql` sorted first and
   opened with `ALTER TABLE public.jobs`, so the container **exited 3** before
   any schema file ran — including `create_exploits.sh`, so the `exploits`
   database was missing from every fresh install. Compose restarted the
   container, PGDATA was already initialised, init never ran again, and nothing
   reported it.

The static checks here run anywhere. The apply test needs docker and skips
cleanly without it — a skip says "cannot run here", an error says "broken".
"""
import os
import re
import shutil
import subprocess
import time
import uuid

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
DB_INIT = os.path.join(REPO, "db_init")
SCHEMA = os.path.join(DB_INIT, "ensure_all_tables.sql")
SETUP_ALL = os.path.join(DB_INIT, "setup_alldb.sql")
SETUP_SH = os.path.join(REPO, "scripts", "setup.sh")

# The image the stack's postgres uses. The apply test must use the same one:
# a different major version can accept DDL this one rejects.
PG_IMAGE = "pgvector/pgvector:pg16"


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.relpath(path, REPO)} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# ── 1. Ordering inside ensure_all_tables.sql ───────────────────────────────
def _created_at(text):
    """table name -> line number of its CREATE TABLE."""
    out = {}
    for i, line in enumerate(text.splitlines(), 1):
        m = re.match(
            r"\s*CREATE TABLE (?:IF NOT EXISTS )?(?:public\.)?([a-z_][a-z0-9_]*)",
            line, re.I,
        )
        if m:
            out.setdefault(m.group(1).lower(), i)
    return out


def test_the_schema_file_declares_many_tables():
    """Otherwise every ordering assertion below passes for the wrong reason."""
    created = _created_at(_read(SCHEMA))
    assert len(created) > 100, (
        f"only {len(created)} CREATE TABLE statements parsed out of "
        "ensure_all_tables.sql — the scan is broken"
    )


def _exception_guarded_lines(text):
    """Line numbers inside a `DO $tag$ ... EXCEPTION ... END $tag$;` block.

    Swallowing a failure is a DELIBERATE pattern in this file: two ALTERs add
    `engagement_id` to assets and vulns before `engagements` exists, tolerate
    the failure, and the column is attached properly in the post-engagements
    block further down. A guard that cannot see the difference between a
    handled failure and an unhandled one would either flag those two forever or
    have to be switched off.
    """
    guarded = set()
    for m in re.finditer(r"DO\s+(\$[A-Za-z_]*\$)", text):
        tag = m.group(1)
        end = text.find(f"END {tag}", m.end())
        if end == -1:
            continue
        body = text[m.start():end]
        if "EXCEPTION" not in body.upper():
            continue
        first = text[:m.start()].count("\n") + 1
        last = text[:end].count("\n") + 1
        guarded.update(range(first, last + 1))
    return guarded


def test_no_statement_references_a_table_created_later():
    """A forward reference costs at least its own statement, and inside a
    transaction it costs every statement up to the COMMIT."""
    text = _read(SCHEMA)
    lines = text.splitlines()
    created = _created_at(text)
    guarded = _exception_guarded_lines(text)

    offenders = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("--") or i in guarded:
            continue
        # DML/DDL against a table, and inline foreign keys.
        for m in re.finditer(
            r"\b(?:UPDATE|INSERT INTO|DELETE FROM|ALTER TABLE|REFERENCES)\s+"
            r"(?:public\.)?([a-z_][a-z0-9_]*)",
            line, re.I,
        ):
            target = m.group(1).lower()
            born = created.get(target)
            if born is not None and born > i:
                offenders.append(
                    f"line {i} touches {target}, created at line {born}: "
                    f"{stripped[:64]}"
                )
    assert not offenders, (
        "these statements reference a table that ensure_all_tables.sql creates "
        "LATER, so they fail on a fresh database (and inside the BEGIN/COMMIT "
        "block they take every following statement with them):\n  "
        + "\n  ".join(offenders[:20])
        + (f"\n  ... and {len(offenders) - 20} more" if len(offenders) > 20 else "")
    )


def test_the_repair_block_comes_after_the_tables_it_repairs():
    """The BEGIN/COMMIT data-repair block belongs at the END of the file.

    Pinned separately from the check above because this is the arrangement that
    keeps it correct, and it is the one a future edit is most likely to undo by
    "tidying" the repair back up next to the assets table it starts from.
    """
    text = _read(SCHEMA)
    lines = text.splitlines()
    try:
        begin = next(i for i, l in enumerate(lines, 1) if l.strip() == "BEGIN;")
    except StopIteration:
        pytest.skip("no explicit transaction block in the schema file")
    created = _created_at(text)
    last_create = max(created.values())
    assert begin > last_create, (
        f"the transaction block opens at line {begin}, but the last CREATE "
        f"TABLE is at line {last_create}. Every table the block repairs must "
        "already exist, or the first failure aborts the whole block"
    )


# ── 2. The init directory the postgres image runs ──────────────────────────
def _top_level_init_files():
    if not os.path.isdir(DB_INIT):
        pytest.skip("db_init/ not present")
    return sorted(
        f for f in os.listdir(DB_INIT)
        if f.endswith((".sql", ".sh"))
        and os.path.isfile(os.path.join(DB_INIT, f))
    )


def test_no_migration_runs_as_an_init_script():
    """The entrypoint runs top-level files ALPHABETICALLY with ON_ERROR_STOP=1.

    A file whose first statement assumes an existing schema aborts the entire
    init — the container exits 3 and every later file, `create_exploits.sh`
    included, never runs. Migrations live in db_init/migrations/, which the
    entrypoint does not descend into.
    """
    offenders = []
    for name in _top_level_init_files():
        with open(os.path.join(DB_INIT, name), encoding="utf-8") as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("--") or s.startswith("\\"):
                    continue
                # First real statement decides.
                if re.match(r"(ALTER TABLE|UPDATE|DELETE FROM|INSERT INTO)\b", s, re.I):
                    offenders.append(f"{name}: opens with {s[:56]}")
                break
    assert not offenders, (
        "these files run as init scripts but open with a statement that needs "
        "the schema to exist already — move them to db_init/migrations/:\n  "
        + "\n  ".join(offenders)
    )


def test_create_database_is_conditional():
    """`POSTGRES_DB` has already created the database when these run, so a bare
    CREATE DATABASE fails and ON_ERROR_STOP kills the init."""
    text = _read(SETUP_ALL)
    bare = []
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith("--"):
            continue
        if re.match(r"CREATE DATABASE\b", s, re.I):
            bare.append(f"line {i}: {s[:64]}")
    assert not bare, (
        "these CREATE DATABASE statements are unconditional. Guard them with a "
        "`SELECT 'CREATE DATABASE ...' WHERE NOT EXISTS (SELECT FROM pg_database "
        "WHERE datname = '...')\\gexec` so re-running cannot abort the init:\n  "
        + "\n  ".join(bare)
    )


def test_every_include_path_resolves():
    """`\\i` respects ON_ERROR_STOP: a missing include is fatal to the whole
    init, and the path is written as it appears INSIDE the container."""
    missing = []
    for name in _top_level_init_files():
        path = os.path.join(DB_INIT, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for m in re.finditer(r"^\\i(?:r)?\s+(\S+)", text, re.M):
            inc = m.group(1)
            # Container path -> repo path
            rel = inc.replace("/docker-entrypoint-initdb.d/", "")
            if not os.path.exists(os.path.join(DB_INIT, rel)):
                missing.append(f"{name}: \\i {inc}")
    assert not missing, (
        "these includes do not resolve to a file under db_init/, so the init "
        "aborts where they are read:\n  " + "\n  ".join(missing)
    )


# ── 3. Phase 7 must not hide what psql says ────────────────────────────────
def test_phase_7_keeps_psqls_output():
    """psql reports failures on stderr and still exits 0. Discarding that is
    how "Schema applied: 114 tables" and OK coexisted with 43 error lines."""
    text = _read(SETUP_SH)
    m = re.search(r"# Apply schema\.?(.{0,2600})", text, re.S)
    assert m, "the phase-7 schema-apply block is gone"
    block = m.group(1)
    assert "ensure_all_tables.sql" in block, "phase 7 no longer applies the schema"
    # The invocation spans continuation lines, so join them before looking for
    # a redirect: matching a single line missed `psql ... \` + `-f ... >/dev/null`
    # and the guard failed with "could not find the psql invocation" instead of
    # checking anything.
    joined = re.sub(r"\\\n\s*", " ", block)
    apply_cmd = re.search(r"[^\n]*psql[^\n]*ensure_all_tables\.sql[^\n]*", joined)
    assert apply_cmd, "could not find the psql invocation"
    assert ">/dev/null" not in apply_cmd.group(0), (
        "phase 7 discards psql's output again — a partially applied schema will "
        "report OK, which is exactly how three missing objects shipped"
    )
    assert "ERROR:" in block, (
        "phase 7 does not count psql's ERROR lines, so it cannot tell a complete "
        "schema from a partial one"
    )


# ── 4. Does it actually apply? ─────────────────────────────────────────────
# The only check that would have caught all of the above on its own. Needs
# docker; skips (never fails) when it is unavailable, per CLAUDE.md.
def _docker_ok():
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "info"], capture_output=True, timeout=30
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@pytest.fixture(scope="module")
def fresh_postgres():
    if not _docker_ok():
        pytest.skip("docker is not available — cannot apply the schema")
    name = f"schema-order-test-{uuid.uuid4().hex[:8]}"
    up = subprocess.run(
        ["docker", "run", "-d", "--name", name,
         "-e", "POSTGRES_USER=app", "-e", "POSTGRES_PASSWORD=app",
         "-e", "POSTGRES_DB=scans", PG_IMAGE],
        capture_output=True, text=True,
    )
    if up.returncode != 0:
        pytest.skip(f"could not start {PG_IMAGE}: {up.stderr.strip()[:160]}")
    try:
        deadline = time.time() + 120
        while time.time() < deadline:
            ready = subprocess.run(
                ["docker", "exec", name, "pg_isready", "-U", "app", "-d", "scans"],
                capture_output=True,
            )
            if ready.returncode == 0:
                break
            time.sleep(2)
        else:
            pytest.skip("postgres did not become ready in 120s")
        yield name
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def test_the_schema_applies_with_no_errors(fresh_postgres):
    """Apply ensure_all_tables.sql to an empty database and read what psql says.

    Before the ordering fix this produced 43 ERROR lines and still exited 0.
    """
    name = fresh_postgres
    subprocess.run(["docker", "cp", SCHEMA, f"{name}:/tmp/schema.sql"],
                   capture_output=True, check=False)
    out = subprocess.run(
        ["docker", "exec", name, "psql", "-U", "app", "-d", "scans",
         "-f", "/tmp/schema.sql"],
        capture_output=True, text=True,
    )
    combined = out.stdout + out.stderr
    errors = [l for l in combined.splitlines() if "ERROR:" in l]
    causes = [l for l in errors if "current transaction is aborted" not in l]
    assert not errors, (
        f"applying ensure_all_tables.sql to an EMPTY database produced "
        f"{len(errors)} error line(s), {len(causes)} of them root causes:\n  "
        + "\n  ".join(causes[:10] or errors[:10])
    )


def test_the_schema_is_idempotent(fresh_postgres):
    """Applied twice, still silent: scripts/ensure_db_schema.sh re-runs this
    file on databases that already have most of it."""
    name = fresh_postgres
    out = subprocess.run(
        ["docker", "exec", name, "psql", "-U", "app", "-d", "scans",
         "-f", "/tmp/schema.sql"],
        capture_output=True, text=True,
    )
    errors = [l for l in (out.stdout + out.stderr).splitlines() if "ERROR:" in l]
    assert not errors, (
        "re-applying the schema produced errors, so a repair run cannot be "
        f"trusted:\n  " + "\n  ".join(errors[:10])
    )


def test_the_expected_tables_all_exist(fresh_postgres):
    """Every table post-install-check.sh asserts must come from this file.

    A name in EXPECTED_TABLES that no DDL creates is a permanent false FAIL;
    a table the DDL fails to create is a real one. This tells them apart.
    """
    check = _read(os.path.join(REPO, "scripts", "post-install-check.sh"))
    m = re.search(r"EXPECTED_TABLES=\((.*?)\n\)", check, re.S)
    assert m, "EXPECTED_TABLES not found in post-install-check.sh"
    expected = [w for line in m.group(1).splitlines()
                for w in line.split("#", 1)[0].split()]
    assert len(expected) > 90, f"only {len(expected)} expected tables parsed"

    name = fresh_postgres
    out = subprocess.run(
        ["docker", "exec", name, "psql", "-U", "app", "-d", "scans", "-tAc",
         "SELECT table_name FROM information_schema.tables "
         "WHERE table_schema='public'"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        pytest.skip(f"could not list tables: {out.stderr.strip()[:120]}")
    present = {l.strip() for l in out.stdout.splitlines() if l.strip()}
    missing = sorted(t for t in expected if t not in present)
    assert not missing, (
        "post-install-check.sh expects these tables but a fresh application of "
        "ensure_all_tables.sql does not create them:\n  " + "\n  ".join(missing)
    )


# ── The exploits database: two copies of one DDL ───────────────────────────
#
# db_init/create_exploits.sh runs INSIDE the postgres container on first init.
# It cannot run in remote DB mode at all: there is no local container, and the
# stack's role on a managed server has neither CREATEROLE nor CREATEDB
# (observed on this deployment: app | rolsuper=f | rolcreatedb=f |
# rolcreaterole=f). scripts/create-exploits-remote.sql is the superuser-side
# copy for that case.
#
# Two copies of the same DDL drift. CLAUDE.md: duplicated SQL needs an agreement
# test. This pins the parts that must match — if they diverge, the remote
# database gets a different edb.exploits from the local one and
# etl/edb_ingest_json.py starts failing on whichever it was not written for.
CREATE_SH = os.path.join(DB_INIT, "create_exploits.sh")
CREATE_REMOTE = os.path.join(REPO, "scripts", "create-exploits-remote.sql")

_EDB_COLUMNS = re.compile(
    r"CREATE TABLE IF NOT EXISTS edb\.exploits \((.*?)\n\);", re.S)


def _edb_column_names(text):
    m = _EDB_COLUMNS.search(text)
    assert m, "edb.exploits CREATE TABLE not found"
    names = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("--"):
            continue
        word = line.split()[0]
        if word.upper() in {"SETWEIGHT(TO_TSVECTOR('SIMPLE',", ")", "||"}:
            continue
        if re.match(r"^[a-z_][a-z0-9_]*$", word):
            names.append(word)
    return names


def test_the_two_exploits_ddls_agree():
    local = _read(CREATE_SH)
    remote = _read(CREATE_REMOTE)

    lc, rc = _edb_column_names(local), _edb_column_names(remote)
    assert lc == rc, (
        "edb.exploits has different columns in db_init/create_exploits.sh and "
        f"scripts/create-exploits-remote.sql:\n  local:  {lc}\n  remote: {rc}"
    )
    assert len(lc) >= 10, f"only {len(lc)} columns parsed — the scan is broken"

    # Compare EXTRACTED names, not substrings. `"idx_edb_exploits_cves" in
    # text` is satisfied by `idx_edb_exploits_cves_v2`, and a role renamed at
    # one of its several mentions leaves the old name elsewhere in the file —
    # both sabotages walked straight past the first version of this check.
    def roles(text):
        return set(re.findall(r"CREATE ROLE (edb_[a-z_]+)", text))

    def indexes(text):
        return set(re.findall(r"CREATE INDEX IF NOT EXISTS (\w+)\s+ON edb\.", text))

    assert roles(local) == roles(remote), (
        "the two scripts create different edb_* roles:\n"
        f"  local:  {sorted(roles(local))}\n  remote: {sorted(roles(remote))}"
    )
    assert roles(local) == {"edb_owner", "edb_rw", "edb_ro"}, (
        f"unexpected role set {sorted(roles(local))} — docker-compose.yml's "
        "PG_DSN authenticates as edb_rw, so that one is load-bearing"
    )
    assert indexes(local) == indexes(remote), (
        "the two scripts create different indexes on edb.exploits:\n"
        f"  local:  {sorted(indexes(local))}\n  remote: {sorted(indexes(remote))}"
    )
    assert len(indexes(local)) >= 2, (
        f"only {len(indexes(local))} index(es) parsed — the scan is broken"
    )
    # The generated FTS column is the part most likely to be copied wrongly.
    for frag in ("GENERATED ALWAYS AS", "setweight(to_tsvector"):
        assert frag in local and frag in remote, (
            f"the generated fts column differs: {frag!r} missing from one copy"
        )


def test_the_installer_says_the_exploit_corpus_is_not_loaded():
    """A completed install has an EMPTY exploit corpus and nothing used to say
    so: searchsploit-updater and exploitdb-etl are one-shot services that no
    phase runs, because the updater apt-installs exploitdb inside a Kali image.
    """
    text = _read(SETUP_SH)
    code = "\n".join(l for l in text.splitlines()
                     if not l.strip().startswith("#"))
    assert "exploitdb-etl" in code, (
        "scripts/setup.sh never mentions exploitdb-etl, so an operator finishes "
        "the install with no exploit corpus and no way to know it"
    )
    assert "searchsploit-updater" in code, (
        "the corpus load needs searchsploit-updater too — it writes the JSON "
        "that exploitdb-etl ingests"
    )


# ── rag_documents belongs to the scans schema ──────────────────────────────
#
# It was created in setup_alldb.sql under `\connect n8n` — the workflow
# automation database — while its only writer, app/load_all.py, connects with
# DB_DSN like every other ETL module, i.e. `scans`. The INSERT could only ever
# fail with "relation rag_documents does not exist", and on the live deployment
# (which has no n8n database at all) the table existed nowhere.
#
# Moved 2026-09-09. These pin the arrangement, because re-adding it to
# setup_alldb.sql would recreate the exact confusion: two declarations, in two
# databases, one of which nothing can reach.
LOAD_ALL = os.path.join(REPO, "app", "load_all.py")


def _connect_sections(text):
    """Map each `\\connect <db>` region of a psql script to its SQL."""
    parts = re.split(r"^\\connect\s+(\w+)\s*$", text, flags=re.M)
    out = {}
    # parts = [preamble, db1, sql1, db2, sql2, ...]
    for i in range(1, len(parts) - 1, 2):
        out.setdefault(parts[i], "")
        out[parts[i]] += parts[i + 1]
    return out


def test_rag_documents_is_declared_in_the_scans_schema():
    schema = _read(SCHEMA)
    # \b matters: without it this matched `rag_documents_disabled` and the
    # sabotage that renamed the table walked straight past — the third time
    # this exact substring trap has bitten in this session.
    assert re.search(r"CREATE TABLE IF NOT EXISTS public\.rag_documents\b", schema), (
        "rag_documents is not declared in ensure_all_tables.sql, so it is not "
        "created on a fresh install and scripts/ensure_db_schema.sh cannot "
        "repair it either"
    )
    for want in ("vector(384)", "GENERATED ALWAYS AS", "rag_recent_high"):
        assert want in schema, f"rag_documents moved without its {want!r}"


def test_rag_documents_is_not_declared_in_another_database():
    """One declaration, one database."""
    sections = _connect_sections(_read(SETUP_ALL))
    offenders = [db for db, sql in sections.items()
                 if re.search(r"CREATE TABLE (?:IF NOT EXISTS )?public\.rag_documents\b", sql)]
    assert not offenders, (
        "rag_documents is declared in setup_alldb.sql under these databases: "
        f"{offenders}. It belongs only in ensure_all_tables.sql (the scans "
        "schema) — a second copy in `n8n` is what made it unreachable to its "
        "own writer"
    )
    # The view has to move with it, or it silently disappears.
    view_owners = [db for db, sql in sections.items() if "rag_recent_high" in sql
                   and "CREATE OR REPLACE VIEW" in sql]
    assert not view_owners, (
        f"the rag_recent_high view is still created in {view_owners}"
    )


def test_the_rag_writer_can_actually_connect():
    """app/load_all.py imported `etl.db`, which does not exist — so the module
    raised ModuleNotFoundError and the backfill had never once run."""
    if not os.path.exists(LOAD_ALL):
        pytest.skip("app/load_all.py not present")
    src = _read(LOAD_ALL)
    code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
    assert "from etl.db import" not in code, (
        "app/load_all.py imports etl.db, which is not a module in this repo — "
        "the file cannot be imported at all"
    )
    assert "psycopg2.connect(DB_DSN)" in code, (
        "the backfill does not open its own connection with DB_DSN, the way "
        "every other ETL module does"
    )
    assert re.search(r"^DB_DSN\s*=", code, re.M), (
        "DB_DSN is used but never defined in app/load_all.py"
    )
