"""Every column a query names must exist on the table it reads or writes.

Run on demand:

    pytest tests/test_sql_columns.py -v
    python3 tests/test_sql_columns.py      # standalone, no pytest needed

WHY THIS EXISTS
---------------
This is the one defect class the other endpoint guards structurally cannot
catch. A query naming a column its table lacks:

  * passes ast.parse — the file is valid Python,
  * imports fine — the SQL is just a string until it executes,
  * reports a healthy container,
  * and 500s only when that specific code path runs.

It had already happened three times before this test existed:

  * pe.module_path      — pending_exploits keeps the module in exploit_id, so
                          /api/exploits/results/all 500'd AND an approved
                          Metasploit module could never resolve its path.
  * dp.method,
    dp.location         — discovered_params has http_method / param_location,
                          making /scope/{name}/analysis a guaranteed 500.
  * p.state, f.source,
    f.template_id,
    wf.tool, wf.title,
    wf.finding_type,
    wf.target_url       — seven in one function, build_existing_target_context(),
                          whose caller logs the failure as a warning. So agents
                          silently lost the "here is what we already know about
                          this target" context and re-ran scans whose data was
                          already in the database.

And Postgres reports only the FIRST bad column, so fixing the one in the
traceback can simply reveal the next.

TWO TIERS
---------
1. alias.column — `FROM ports p ... p.state`. Binds aliases from FROM/JOIN and
   checks each qualified reference.
2. INSERT INTO t (cols) — checks each named column.

PRECISION OVER COMPLETENESS
---------------------------
This is deliberately not a SQL parser. Anything it cannot resolve with
confidence it SKIPS, because a guard with false positives gets disabled and
then protects nothing:

  * unknown table or alias (CTEs, subqueries, views) — skipped,
  * column lists containing an interpolation — skipped,
  * SQL keywords and `excluded.` (upsert pseudo-table) — skipped,
  * `--` and block comments stripped, since prose describing a column is not a
    reference to one. (Without this the test flagged its own comment.)

Measured on this tree: 2,219 qualified references and 2,264 INSERT columns
checked, zero false positives.
"""
import ast
import glob
import os
import re

try:
    import pytest
except ImportError:  # pragma: no cover
    class _NoPytest:
        @staticmethod
        def fixture(*args, **kwargs):
            def wrap(fn):
                return fn
            return wrap(args[0]) if args and callable(args[0]) else wrap

    pytest = _NoPytest()

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))

SKIP_DIRS = {"__pycache__", "node_modules", ".git", "tests", "venv", ".venv"}

IDENT = r"[a-zA-Z_][a-zA-Z0-9_]*"

TYPE_WORDS = (
    r"(?:uuid|text|varchar|char|integer|int|bigint|smallint|serial|bigserial"
    r"|boolean|bool|timestamptz|timestamp|date|time|numeric|decimal|real"
    r"|double|jsonb|json|bytea|inet|cidr|macaddr|tsvector|interval|float)"
)

SQL_HINT = re.compile(r"\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b", re.I)
BIND = re.compile(rf"\b(?:FROM|JOIN)\s+(?:public\.)?({IDENT})(?:\s+AS)?\s+({IDENT})\b", re.I)
BARE = re.compile(rf"\b(?:FROM|JOIN)\s+(?:public\.)?({IDENT})", re.I)
REF = re.compile(rf"\b({IDENT})\.({IDENT})\b")
CTE = re.compile(rf"\b({IDENT})\s+AS\s*\(", re.I)
INSERT = re.compile(rf"INSERT\s+INTO\s+(?:public\.)?({IDENT})\s*\(([^)]*)\)", re.I | re.S)

# Reserved words and pseudo-tables that must never be read as a table alias or
# a column name. `excluded` is the upsert pseudo-table; its columns mirror the
# insert and are not checkable here.
SQL_WORDS = {
    "select", "from", "where", "join", "left", "right", "inner", "outer", "full",
    "cross", "on", "and", "or", "not", "in", "is", "null", "as", "group", "by",
    "order", "having", "limit", "offset", "insert", "into", "values", "update",
    "set", "delete", "returning", "union", "all", "distinct", "case", "when",
    "then", "else", "end", "with", "recursive", "asc", "desc", "using", "exists",
    "between", "like", "ilike", "coalesce", "count", "sum", "avg", "min", "max",
    "now", "interval", "cast", "excluded", "lateral", "natural", "true", "false",
    "only", "conflict", "do", "nothing", "for", "of", "fetch", "filter", "over",
    "partition", "window", "array", "any", "some", "both", "leading", "trailing",
}

# Queries that legitimately cannot be checked, and known-bad code that still
# ships. RATCHETS: a new violation fails by name, and a fixed entry must be
# deleted (test_no_stale_sql_debt enforces that).
#
# Each key is (relative path, table, column).
SQL_DEBT = {
    ("etl/parse_subdomain_takeover.py", "recon_findings", "scan_id"):
        "parser writes a bespoke shape; recon_findings keeps payload in data jsonb",
    ("etl/parse_subdomain_takeover.py", "recon_findings", "domain"):
        "same INSERT — needs a schema-mapping decision, not a rename",
    ("etl/parse_subdomain_takeover.py", "recon_findings", "subdomain"):
        "same INSERT",
    ("etl/parse_subdomain_takeover.py", "recon_findings", "title"):
        "same INSERT",
    ("etl/parse_subdomain_takeover.py", "recon_findings", "description"):
        "same INSERT",
    ("etl/parse_subdomain_takeover.py", "recon_findings", "evidence_data"):
        "same INSERT",
    ("etl/parse_subdomain_takeover.py", "recon_findings", "discovered_at"):
        "same INSERT",
    ("etl/parse_subdomain_takeover.py", "recon_findings", "metadata"):
        "same INSERT",
    ("etl/parse_pacu.py", "credential_findings", "target"):
        "pacu findings need mapping onto ip/port/username/secret_type",
    ("etl/parse_pacu.py", "credential_findings", "finding_type"):
        "same INSERT",
    ("etl/parse_pacu.py", "credential_findings", "data"):
        "same INSERT — credential_findings uses metadata jsonb",
}


def _strip_sql_comments(sql):
    """Remove -- and /* */ comments.

    Load-bearing: a comment mentioning dp.get("method") is prose, not a column
    reference, and without this the guard flagged its own documentation.
    """
    sql = re.sub(r"--[^\n]*", " ", sql)
    return re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)


def _python_files():
    out = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        out.extend(os.path.join(dirpath, f) for f in filenames if f.endswith(".py"))
    return sorted(out)


def _parse_ddl(paths):
    """table -> {columns}, from CREATE TABLE and ALTER TABLE ADD COLUMN.

    Python files are scanned too, not just .sql: scan_recommender/exploits_rag.py
    creates exploit_chunks and ALTERs in section_header at runtime. Missing those
    sources is what makes this kind of guard emit false positives.
    """
    tables = {}
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            src = fh.read()
        if "CREATE TABLE" not in src.upper() and "ADD COLUMN" not in src.upper():
            continue
        src = re.sub(r"--[^\n]*", " ", src)

        for m in re.finditer(
            rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?[\"']?({IDENT})[\"']?\s*\(",
            src, re.I,
        ):
            start = m.end() - 1
            depth = 0
            body = None
            for j in range(start, len(src)):
                if src[j] == "(":
                    depth += 1
                elif src[j] == ")":
                    depth -= 1
                    if depth == 0:
                        body = src[start + 1:j]
                        break
            if body is None:
                continue
            cols = tables.setdefault(m.group(1).lower(), set())
            for part in re.split(r",(?![^()]*\))", body):
                part = part.strip()
                if not part:
                    continue
                first = part.split()[0].strip('"').lower()
                if first in ("constraint", "primary", "unique", "foreign",
                             "check", "exclude", "like"):
                    continue
                if re.match(rf"^[\"']?{IDENT}[\"']?\s+{TYPE_WORDS}\b", part, re.I) or \
                   re.match(rf"^[\"']?{IDENT}[\"']?\s+[A-Za-z]", part):
                    cols.add(first)

        for m in re.finditer(
            rf"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:public\.)?[\"']?({IDENT})[\"']?\s+"
            rf"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"']?({IDENT})",
            src, re.I,
        ):
            tables.setdefault(m.group(1).lower(), set()).add(m.group(2).lower())
    return tables


def _sql_literals(path):
    """(lineno, sql) for every string in a file that looks like SQL.

    f-strings are reassembled with each interpolation replaced by a spacer, so
    a dynamic table or column list becomes unresolvable and gets skipped rather
    than guessed at.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            tree = ast.parse(fh.read())
    except SyntaxError:
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if SQL_HINT.search(node.value):
                yield node.lineno, node.value
        elif isinstance(node, ast.JoinedStr):
            parts = [
                v.value if isinstance(v, ast.Constant) and isinstance(v.value, str)
                else " {} "
                for v in node.values
            ]
            joined = "".join(parts)
            if SQL_HINT.search(joined):
                yield node.lineno, joined


def _scan(tables):
    """Return (problems, refs_checked, insert_cols_checked)."""
    problems = []
    refs_checked = 0
    inserts_checked = 0

    for path in _python_files():
        rel = os.path.relpath(path, REPO)
        for lineno, raw in _sql_literals(path):
            sql = _strip_sql_comments(raw)

            ctes = {m.group(1).lower() for m in CTE.finditer(sql)}

            aliases = {}
            for m in BIND.finditer(sql):
                table, alias = m.group(1).lower(), m.group(2).lower()
                if alias in SQL_WORDS or table in SQL_WORDS:
                    continue
                aliases[alias] = table
            for m in BARE.finditer(sql):
                table = m.group(1).lower()
                if table not in SQL_WORDS:
                    aliases.setdefault(table, table)

            for m in REF.finditer(sql):
                alias, col = m.group(1).lower(), m.group(2).lower()
                if alias in ctes or alias in SQL_WORDS or col in SQL_WORDS:
                    continue
                table = aliases.get(alias)
                if not table or table in ctes or table not in tables:
                    continue
                refs_checked += 1
                if col not in tables[table]:
                    problems.append((rel, lineno, table, col, f"{alias}.{col}"))

            for m in INSERT.finditer(sql):
                table, collist = m.group(1).lower(), m.group(2)
                if table not in tables or "{" in collist or "%" in collist:
                    continue
                for col in collist.split(","):
                    col = col.strip().strip('"').lower()
                    if not col or not re.fullmatch(IDENT, col) or col in SQL_WORDS:
                        continue
                    inserts_checked += 1
                    if col not in tables[table]:
                        problems.append((rel, lineno, table, col, f"INSERT {table}({col})"))
    return problems, refs_checked, inserts_checked


@pytest.fixture(scope="module")
def schema():
    sources = sorted(glob.glob(os.path.join(REPO, "db_init", "*.sql"))) + _python_files()
    return _parse_ddl(sources)


@pytest.fixture(scope="module")
def scanned(schema):
    return _scan(schema)


def test_schema_extraction_is_not_vacuous(schema):
    """A guard whose schema map is empty passes everything.

    Two earlier guards in this repo silently checked nothing — one scanned zero
    files, one skipped 20 assertions — and both looked green. Assert the inputs.
    """
    assert len(schema) >= 90, f"only {len(schema)} tables parsed"
    # Spot-check tables whose real columns are known and were involved in the
    # bugs above. A rename here should break this test loudly.
    assert "is_open" in schema["ports"], "ports.is_open missing from parse"
    assert "state" not in schema["ports"], "ports.state should not exist"
    assert "http_method" in schema["discovered_params"]
    assert "param_location" in schema["discovered_params"]
    assert "exploit_id" in schema["pending_exploits"]
    assert "module_path" not in schema["pending_exploits"]
    assert "section_header" in schema["exploit_chunks"], \
        "runtime ALTER in scan_recommender/exploits_rag.py not picked up"


def test_scan_reaches_the_queries(scanned):
    """Prove the scanner actually found SQL to check."""
    _, refs, inserts = scanned
    assert refs >= 1500, f"only {refs} qualified column references checked"
    assert inserts >= 1500, f"only {inserts} INSERT columns checked"


def test_comments_are_not_read_as_references():
    """Prose in a SQL comment is not a column reference."""
    sql = """
        -- dp.get("method") and dp.location are described here
        /* wf.target_url too */
        SELECT dp.param_name FROM discovered_params dp
    """
    stripped = _strip_sql_comments(sql)
    assert "param_name" in stripped
    for gone in ("get", "location", "target_url"):
        assert gone not in stripped, f"{gone} survived comment stripping"


def test_interpolated_column_lists_are_skipped(schema):
    """A dynamic column list is unresolvable and must not be guessed at."""
    assert "{" in " {} ", "spacer convention changed"
    problems, _, _ = _scan(schema)
    # The scan must complete without treating "{}" as a column name.
    assert not any(col == "{}" for _, _, _, col, _ in problems)


def test_every_sql_column_exists(scanned):
    """The guard. Every resolvable column reference must exist on its table."""
    problems, _, _ = scanned
    unexpected = [
        (rel, lineno, table, col, shown)
        for rel, lineno, table, col, shown in problems
        if (rel, table, col) not in SQL_DEBT
    ]
    assert not unexpected, (
        f"{len(unexpected)} SQL reference(s) name a column their table does not have.\n"
        "Postgres reports only the FIRST bad column per query — check the whole\n"
        "statement against the DDL, not just the one in a traceback:\n  "
        + "\n  ".join(f"{r}:{ln}  {shown}  (table {t} has no {c})"
                      for r, ln, t, c, shown in sorted(unexpected))
    )


def test_no_stale_sql_debt(scanned):
    """A fixed debt entry must be deleted, or the list stops meaning anything."""
    problems, _, _ = scanned
    live = {(rel, table, col) for rel, _, table, col, _ in problems}
    stale = sorted(k for k in SQL_DEBT if k not in live)
    assert not stale, (
        "SQL_DEBT entries no longer violate anything — delete them:\n  "
        + "\n  ".join(f"{r}: {t}.{c}" for r, t, c in stale)
    )


def _main():
    """Standalone entry point for scripts/post-install-check.sh (no pytest)."""
    sources = sorted(glob.glob(os.path.join(REPO, "db_init", "*.sql"))) + _python_files()
    tables = _parse_ddl(sources)
    problems, refs, inserts = _scan(tables)

    cols = sum(len(c) for c in tables.values())
    print(f"Schema: {len(tables)} tables, {cols} columns "
          f"(db_init/*.sql + runtime DDL in .py)")
    print(f"Checked {refs} qualified reference(s) and {inserts} INSERT column(s)")

    unexpected = [p for p in problems if (p[0], p[2], p[3]) not in SQL_DEBT]
    known = len(problems) - len(unexpected)
    print(f"  {known} known debt entr(ies) tolerated, {len(SQL_DEBT)} listed")

    if unexpected:
        print(f"\n{len(unexpected)} SQL reference(s) name a nonexistent column:")
        for rel, lineno, table, col, shown in sorted(unexpected):
            print(f"  ✗ {rel}:{lineno}  {shown}  (table {table} has no {col})")
        return 1
    print("\n✅ every resolvable SQL column reference exists")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
