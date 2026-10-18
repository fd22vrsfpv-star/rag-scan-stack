"""Guard: discovered_params identity is per-ENGAGEMENT, and the writers agree.

Why this exists
---------------
`discovered_params.url_pattern` carries only `scheme://netloc/path`. The old key
was `UNIQUE(url_pattern, param_name, http_method, param_location)`, so two
engagements pointed at the SAME address -- a benchmark harness that reuses one
IP for every target, or a host re-purposed between engagements -- produced the
identical key. The second engagement's crawl took the `ON CONFLICT ... DO UPDATE`
branch and bumped the FIRST engagement's row: one `occurrence_count` and one
`sample_values` shared by two unrelated applications. `asset_id` did not save it
either, because a reused IP resolves to the same asset.

Three things have to hold together, and each is checked here:

1. the identity index is engagement-scoped and COALESCEs every NULLABLE key
   column. A partial index (or a plain multi-column UNIQUE) would not: in
   Postgres a NULL in any indexed column makes two rows non-equal, so rows whose
   engagement could not be resolved would be unconstrained ALTOGETHER -- dedup
   silently off for exactly the rows that need it.
2. every `ON CONFLICT` targeting that index repeats the expression EXACTLY.
   A mismatch is not a silent fallback: Postgres raises "no unique or exclusion
   constraint matching the ON CONFLICT specification" on EVERY row.
3. the writers attribute the row through the ONE shared resolver
   (`etl.identity_upsert.resolve_engagement_for_host`), not a second copy of the
   question "which engagement does this host belong to?".

Everything is read with `ast` / regex rather than imported: `etl/parse_katana.py`
and `playwright_scanner/param_extractor.py` import psycopg2 and `db_utils`,
which are not installed on the host or in the test image.

Run standalone:
    python -m pytest tests/test_discovered_params_engagement.py -q
"""
import ast
import os
import re

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DDL = os.path.join(REPO, "db_init", "ensure_all_tables.sql")
WRITERS = (
    os.path.join(REPO, "etl", "parse_katana.py"),
    os.path.join(REPO, "playwright_scanner", "param_extractor.py"),
)
INDEX_NAME = "uq_discovered_params_identity"
TABLE = "discovered_params"


def _read(path):
    if not os.path.exists(path):
        pytest.skip("%s not present in this checkout" % os.path.relpath(path, REPO))
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _balanced(src, open_at):
    """The text inside the parenthesis group starting at src[open_at] == '('."""
    depth = 0
    for i in range(open_at, len(src)):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return src[open_at + 1:i]
    return None


def _normalise(expr):
    """Collapse whitespace so formatting differences are not false mismatches."""
    expr = re.sub(r"--[^\n]*", " ", expr)
    expr = re.sub(r"\s+", " ", expr).strip()
    expr = re.sub(r"\s*,\s*", ", ", expr)
    expr = re.sub(r"\(\s+", "(", expr)
    expr = re.sub(r"\s+\)", ")", expr)
    return expr


def _split_top_level(expr):
    """Split a key list on top-level commas only (COALESCE(...) stays whole)."""
    parts, depth, cur = [], 0, []
    for ch in expr:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def _index_expression():
    sql = _read(DDL)
    m = re.search(
        r"CREATE\s+UNIQUE\s+INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?" + INDEX_NAME
        + r"\s+ON\s+(?:public\.)?" + TABLE + r"\s*\(",
        sql, re.I)
    assert m, (
        INDEX_NAME + " is not declared in db_init/ensure_all_tables.sql. "
        "Without it the ON CONFLICT in every discovered_params writer matches "
        "no index and each insert raises instead of storing."
    )
    body = _balanced(sql, m.end() - 1)
    assert body is not None, INDEX_NAME + " key list has unbalanced parentheses"
    tail = sql[m.end() + len(body) + 1:m.end() + len(body) + 60]
    assert not re.match(r"\s*WHERE\b", tail, re.I), (
        INDEX_NAME + " is PARTIAL. A WHERE predicate does not constrain the "
        "rows it excludes at all -- COALESCE the nullable column instead."
    )
    return _normalise(body)


def _table_columns():
    """column -> is_nullable, from the CREATE TABLE body and later ALTERs."""
    sql = _read(DDL)
    m = re.search(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?" + TABLE + r"\s*\(",
        sql, re.I)
    assert m, "no CREATE TABLE for " + TABLE
    body = re.sub(r"--[^\n]*", " ", _balanced(sql, m.end() - 1))
    cols = {}
    for part in _split_top_level(body):
        part = part.strip()
        if not part:
            continue
        first = part.split()[0].strip('"').lower()
        if first in ("constraint", "primary", "unique", "foreign", "check",
                     "exclude", "like"):
            continue
        cols[first] = not re.search(r"\bNOT\s+NULL\b", part, re.I)
    for a in re.finditer(
            r"ALTER\s+TABLE\s+(?:public\.)?" + TABLE
            + r"\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)([^;]*)", sql, re.I):
        cols.setdefault(a.group(1).lower(),
                        not re.search(r"\bNOT\s+NULL\b", a.group(2), re.I))
    return cols


def _discovered_param_inserts(path):
    """[(lineno, normalised ON CONFLICT list, sql)] for every writer statement."""
    src = _read(path)
    found = []
    for node in ast.walk(ast.parse(src)):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        text = node.value
        if not re.search(r"INSERT\s+INTO\s+(?:public\.)?" + TABLE + r"\b", text, re.I):
            continue
        m = re.search(r"ON\s+CONFLICT\s*\(", text, re.I)
        assert m, (
            "%s:%d inserts into %s with no ON CONFLICT clause -- a repeat crawl "
            "would raise or fork a second row instead of updating."
            % (os.path.relpath(path, REPO), node.lineno, TABLE)
        )
        body = _balanced(text, m.end() - 1)
        assert body is not None, (
            "%s:%d ON CONFLICT list has unbalanced parentheses"
            % (os.path.relpath(path, REPO), node.lineno))
        found.append((node.lineno, _normalise(body), text))
    assert found, "%s no longer writes to %s" % (os.path.relpath(path, REPO), TABLE)
    return found


def test_identity_index_is_engagement_scoped():
    """The key must carry the engagement, COALESCEd for the unresolved case."""
    expr = _index_expression()
    keys = _split_top_level(expr)
    eng = [k for k in keys if re.search(r"\bengagement_id\b", k)]
    assert eng, (
        "%s does not mention engagement_id: %r. Two engagements on one address "
        "would share a row again." % (INDEX_NAME, expr)
    )
    assert re.match(r"(?i)^coalesce\s*\(\s*engagement_id\s*,", eng[0]), (
        "engagement_id is in %s as a BARE column (%r). A NULL in an indexed "
        "column makes rows non-equal in Postgres, so every row whose engagement "
        "could not be resolved would be unconstrained -- unlimited duplicates "
        "with dedup silently off. COALESCE it." % (INDEX_NAME, eng[0])
    )


def test_every_nullable_key_column_is_coalesced():
    """Generic form of the rule: no bare NULLABLE column in a unique key."""
    cols = _table_columns()
    bare = []
    for key in _split_top_level(_index_expression()):
        name = key.strip().lower()
        if not re.match(r"^\w+$", name):
            continue          # an expression (COALESCE(...)) -- already handled
        if cols.get(name, True):
            bare.append(name)
    assert not bare, (
        "%s indexes nullable column(s) %s bare. Postgres treats two rows as "
        "non-equal when either side is NULL, so those rows are not deduplicated "
        "at all. COALESCE them (and update every ON CONFLICT)."
        % (INDEX_NAME, bare)
    )


def test_legacy_engagement_blind_unique_is_gone():
    """The old 4-column key must not be re-declared anywhere in the DDL."""
    sql = re.sub(r"--[^\n]*", " ", _read(DDL))
    offenders = []
    for m in re.finditer(r"UNIQUE\s*\(([^)]*)\)", sql, re.I):
        cols = set(c.strip().lower() for c in m.group(1).split(","))
        if cols == {"url_pattern", "param_name", "http_method", "param_location"}:
            offenders.append(sql[:m.start()].count("\n") + 1)
    assert not offenders, (
        "the engagement-blind UNIQUE(url_pattern, param_name, http_method, "
        "param_location) is declared again at line(s) %s -- it is what let a "
        "second engagement's crawl update the first engagement's row."
        % (offenders,)
    )


@pytest.mark.parametrize("path", WRITERS, ids=lambda p: os.path.basename(p))
def test_writer_on_conflict_matches_the_index_exactly(path):
    """A near-miss raises on EVERY row; it does not quietly degrade."""
    index_expr = _index_expression()
    for lineno, conflict_expr, _sql in _discovered_param_inserts(path):
        assert conflict_expr == index_expr, (
            "%s:%d ON CONFLICT does not repeat %s exactly.\n  index:       %s\n"
            "  on conflict: %s\nPostgres answers a mismatch with \"no unique or "
            "exclusion constraint matching the ON CONFLICT specification\" on "
            "every row -- 0 params stored, which is not a fallback."
            % (os.path.relpath(path, REPO), lineno, INDEX_NAME,
               index_expr, conflict_expr)
        )


@pytest.mark.parametrize("path", WRITERS, ids=lambda p: os.path.basename(p))
def test_writer_supplies_the_engagement(path):
    """engagement_id is in the INSERT column list, with a placeholder for it."""
    for lineno, _expr, text in _discovered_param_inserts(path):
        m = re.search(
            r"INSERT\s+INTO\s+(?:public\.)?" + TABLE + r"\s*\(", text, re.I)
        collist = _balanced(text, m.end() - 1)
        names = [c.strip().lower() for c in collist.split(",") if c.strip()]
        assert "engagement_id" in names, (
            "%s:%d inserts into %s without engagement_id (%s). The row lands in "
            "the shared \"no engagement\" bucket and collides with every other "
            "engagement on that address -- and collected data must carry its "
            "engagement." % (os.path.relpath(path, REPO), lineno, TABLE, names)
        )
        vm = re.search(r"VALUES\s*\(", text, re.I)
        assert vm, "%s:%d INSERT has no VALUES" % (os.path.relpath(path, REPO), lineno)
        n_values = len(_split_top_level(_balanced(text, vm.end() - 1)))
        assert n_values == len(names), (
            "%s:%d has %d columns but %d VALUES entries -- adding engagement_id "
            "to the column list without its placeholder shifts every parameter."
            % (os.path.relpath(path, REPO), lineno, len(names), n_values)
        )


@pytest.mark.parametrize("path", WRITERS, ids=lambda p: os.path.basename(p))
def test_writer_uses_the_shared_engagement_resolver(path):
    """One answer to 'which engagement is this host?', not a per-writer copy."""
    tree = ast.parse(_read(path))
    imported = any(
        isinstance(n, ast.ImportFrom)
        and (n.module or "").endswith("identity_upsert")
        and any(a.name == "resolve_engagement_for_host" for a in n.names)
        for n in ast.walk(tree)
    )
    assert imported, (
        "%s does not import resolve_engagement_for_host from etl.identity_upsert. "
        "Resolving the engagement a second way is how the question comes to mean "
        "two different things in two places." % os.path.relpath(path, REPO)
    )
    called = any(
        isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        and n.func.id == "resolve_engagement_for_host"
        for n in ast.walk(tree)
    )
    assert called, (
        "%s imports resolve_engagement_for_host but never calls it -- an unused "
        "import attributes nothing." % os.path.relpath(path, REPO)
    )


def test_install_and_health_scripts_assert_the_column():
    """A column the installer does not check is one a fresh stack can miss."""
    checks = (
        ("scripts/ensure_db_schema.sh",
         (r"discovered_params:engagement_id", INDEX_NAME)),
        ("scripts/post-install-check.sh",
         (r"table_name='discovered_params'\s+AND\s+column_name='engagement_id'",
          INDEX_NAME)),
    )
    for rel, needles in checks:
        text = _read(os.path.join(REPO, rel))
        for needle in needles:
            assert re.search(needle, text), (
                "%s does not assert %r for %s. A missing engagement_id makes "
                "every param upsert raise, and nothing would catch it before "
                "the first crawl." % (rel, needle, TABLE)
            )
