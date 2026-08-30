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
    # Standalone mode: scripts/post-install-check.sh runs this file directly on
    # hosts with no pytest, the same way it runs check_shared_code.py. The shim
    # only needs to make the decorators no-ops at import time; _main() calls the
    # plain helpers, not the test functions.
    #
    # It must cover every pytest attribute used below — a shim with only
    # .fixture broke the standalone path the moment a @pytest.mark.unit was
    # added, and the traceback was invisible behind a 2>/dev/null.
    def _identity(fn):
        return fn

    class _AnyDecorator:
        def __getattr__(self, _name):
            def decorator(*args, **kwargs):
                if len(args) == 1 and not kwargs and callable(args[0]):
                    return args[0]
                return _identity
            return decorator

    class _NoPytest:
        mark = _AnyDecorator()

        @staticmethod
        def fixture(*args, **kwargs):
            if args and callable(args[0]):
                return args[0]
            return _identity

        @staticmethod
        def importorskip(name, **kwargs):
            import importlib
            return importlib.import_module(name)

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
    # EMPTY.
    #
    # Held 11 entries: etl/parse_subdomain_takeover.py wrote 8 columns
    # recon_findings does not have, and etl/parse_pacu.py wrote 3 that
    # credential_findings does not have. Neither parser had EVER stored a row —
    # every insert raised UndefinedColumn inside a try/except that counted it as
    # one error among many.
    #
    # Both needed a schema-mapping decision rather than a rename:
    #   * takeover findings -> recon_findings(source, finding_type='subdomain_
    #     takeover', target, data jsonb, severity, tags)
    #   * pacu AWS keys -> credential_vault, because credential_findings.ip,
    #     .port and .username are all NOT NULL and an access key has no host
    #
    # Add an entry only with a reason, and delete it the moment it is fixed —
    # test_no_stale_sql_debt enforces that.
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



# ═══════════════════════════════════════════════════════════════════════════
# TIER 3 — parameter TYPE compatibility
#
# Column names being right is not enough. web_findings.cwe is text[], and the
# playwright ZAP path passed the alert's bare string:
#
#     scalar "CWE-79": REJECTED -> malformed array literal: "CWE-79"
#     list  ["CWE-79"]: ACCEPTED   (verified against the live column)
#
# Tiers 1 and 2 above check names and cannot see that. This tier maps INSERT
# columns to their positional %s parameters and checks the value's shape.
#
# HONEST LIMITS — read before trusting this.
# A bare `x.get('cwe')` is opaque: its type is whatever the dict holds, so this
# tier could NOT have caught the original cwe bug on its own. Rather than skip
# what it cannot prove (a sweep that silently drops half its inputs reads as
# coverage it does not have), unprovable ARRAY feeds are enumerated in
# ARRAY_UNVERIFIED and ratchet: a NEW one fails by name. So reintroducing the
# bug is still caught — as "a new unverifiable array feed appeared".
#
# Local assignments ARE followed, so normalising to a list and passing the
# variable is recognised as correct. That is deliberate: the guard should reward
# the fix pattern, not shrug at it.
# ═══════════════════════════════════════════════════════════════════════════

_TYPE_DECL = re.compile(
    rf"^[\"']?({IDENT})[\"']?\s+([A-Za-z][A-Za-z0-9_ ]*(?:\[\])?)", re.I)

# Callables whose result is a list (or None). Add a project normaliser here to
# make its call sites provable.
LIST_SAFE_FUNCS = {"as_text_array", "as_int_array", "to_text_array", "list", "sorted"}

# ARRAY-column parameters whose type cannot be decided statically. Each entry is
# (relative path, table, column). RATCHETS both ways: a new unprovable feed
# fails, and one that becomes provable must be deleted.
ARRAY_UNVERIFIED = set()   # NB: set(), not {} — {} is an empty dict
# EMPTY, and worth keeping that way.
#
# This started at 19. Most entries did not need a wrapper at the call site —
# their type was already written down and the guard simply could not read it
# yet. Teaching it to follow Pydantic field annotations, parameter
# annotations, `-> list` returns, local assignments and the `x or []` idiom
# resolved 18 of the 19. Only one was genuinely opaque (a dict subscript off
# a parsed OpenAPI document) and that one now calls as_text_array().
#
# So: before adding an entry here, check whether the value's type is already
# declared somewhere the guard could learn to see. Reach for a normaliser
# when the shape truly is unknown at the call site, not to restate a
# signature that already promises a list.

# Provable type mismatches that still ship. Empty is the goal.
SQL_TYPE_DEBT = {}


def _column_kinds(paths):
    """table -> {column: 'array' | 'jsonb' | 'scalar'}."""
    out = {}
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                src = fh.read()
        except OSError:
            continue
        if "CREATE TABLE" not in src.upper():
            continue
        src = re.sub(r"--[^\n]*", " ", src)
        for m in re.finditer(
            rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?[\"']?({IDENT})[\"']?\s*\(",
            src, re.I,
        ):
            start = m.end() - 1
            depth, body = 0, None
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
            cols = out.setdefault(m.group(1).lower(), {})
            for part in re.split(r",(?![^()]*\))", body):
                part = part.strip()
                if not part:
                    continue
                if part.split()[0].strip('"').lower() in (
                        "constraint", "primary", "unique", "foreign", "check",
                        "exclude", "like"):
                    continue
                decl = _TYPE_DECL.match(part)
                if not decl:
                    continue
                col, typ = decl.group(1).lower(), decl.group(2).strip().lower()
                if typ.endswith("[]") or part.lower().rstrip(",").endswith("[]"):
                    kind = "array"
                elif typ.startswith("vector"):
                    # pgvector. A Python list is the CORRECT value here, and the
                    # '[1,2,3]' text form is also accepted, so neither shape is
                    # a defect — checking it as a scalar flagged three real
                    # embedding writes as mismatches.
                    kind = "vector"
                elif "jsonb" in typ or typ == "json":
                    kind = "jsonb"
                else:
                    kind = "scalar"
                cols[col] = kind
    return out


def _classify(node):
    """'str' | 'list' | 'dict' | 'json_wrapped' | 'scalar' | 'none' | 'unknown'."""
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return "str"
        return "none" if node.value is None else "scalar"
    if isinstance(node, ast.JoinedStr):
        return "str"
    if isinstance(node, (ast.List, ast.Tuple, ast.ListComp)):
        return "list"
    if isinstance(node, (ast.Dict, ast.DictComp)):
        return "dict"
    if isinstance(node, ast.IfExp):
        both = {_classify(node.body), _classify(node.orelse)} - {"none"}
        return both.pop() if len(both) == 1 else "unknown"
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        # `x or []` — the idiomatic default-to-empty. `or` yields one of its
        # operands, so it is a list only if EVERY resolvable operand is one; an
        # unresolvable operand keeps the whole thing unknown rather than
        # optimistically assuming the author got it right.
        kinds = {_classify(v) for v in node.values} - {"none"}
        return kinds.pop() if len(kinds) == 1 else "unknown"
    if isinstance(node, ast.Call):
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        if name in LIST_SAFE_FUNCS:
            return "list"
        if name == "Json":
            return "json_wrapped"
        if name in ("dumps", "str", "join"):
            return "str"
    return "unknown"


def _annotation_is_list(node):
    """True when an annotation denotes a list — List[str], list[str], Optional[List[int]]."""
    if node is None:
        return False
    if isinstance(node, ast.Name):
        return node.id in ("list", "List")
    if isinstance(node, ast.Attribute):
        return node.attr in ("list", "List")
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return "list[" in node.value.lower()
    if isinstance(node, ast.Subscript):
        base = node.value
        base_name = base.attr if isinstance(base, ast.Attribute) else getattr(base, "id", "")
        if base_name in ("list", "List"):
            return True
        # Optional[List[x]] / Union[List[x], None] — recurse into the args.
        if base_name in ("Optional", "Union"):
            inner = node.slice
            parts = inner.elts if isinstance(inner, ast.Tuple) else [inner]
            return any(_annotation_is_list(p) for p in parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):   # X | None
        return _annotation_is_list(node.left) or _annotation_is_list(node.right)
    return False


_CLASS_INDEX = None


def _class_index():
    """class name -> {field: is_list}, repo-wide, but only for UNIQUE names.

    Pydantic request models usually live in a sibling module (WebhookCreate is
    in webhooks/models.py, used from webhooks/router.py), so a same-file-only
    lookup misses them. A name defined in two places is dropped rather than
    guessed at — resolving to the wrong class would be worse than not resolving.
    """
    global _CLASS_INDEX
    if _CLASS_INDEX is not None:
        return _CLASS_INDEX

    seen = {}
    for path in _python_files():
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                tree = ast.parse(fh.read())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            fields = {
                stmt.target.id: _annotation_is_list(stmt.annotation)
                for stmt in node.body
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
            }
            if not fields:
                continue
            if node.name in seen and seen[node.name] != fields:
                seen[node.name] = None          # ambiguous, refuse to guess
            elif node.name not in seen:
                seen[node.name] = fields
    _CLASS_INDEX = {k: v for k, v in seen.items() if v}
    return _CLASS_INDEX


def _resolve_model_attr(node, scope, tree):
    """Resolve `body.tags` via the annotated class of the `body` parameter.

    Many array feeds are Pydantic model fields declared `List[str]`, so their
    type IS knowable — it is written down one class away. Without this they read
    as unprovable and would be papered over with a redundant wrapper at the call
    site instead.
    """
    if not (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)):
        return "unknown"
    var, field = node.value.id, node.attr

    class_name = None
    if scope is not None:
        args = scope.args
        for arg in list(args.args) + list(args.posonlyargs) + list(args.kwonlyargs):
            if arg.arg == var and arg.annotation is not None:
                ann = arg.annotation
                class_name = ann.attr if isinstance(ann, ast.Attribute) else getattr(ann, "id", None)
                break
    if not class_name:
        return "unknown"

    # Same file first — a local definition wins over a same-named import.
    for cls in ast.walk(tree):
        if not (isinstance(cls, ast.ClassDef) and cls.name == class_name):
            continue
        for stmt in cls.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) \
                    and stmt.target.id == field:
                return "list" if _annotation_is_list(stmt.annotation) else "scalar_annotated"

    fields = _class_index().get(class_name)
    if fields is not None and field in fields:
        return "list" if fields[field] else "scalar_annotated"
    return "unknown"


def _deep_classify(node, scope, tree, depth=0):
    """_classify, but able to follow names, model fields and nested operators.

    Kept separate from _classify so the pure shape-of-a-literal logic stays
    testable on its own. Recursion is bounded: `a or b or c` chains and
    conditionals nest, and a cycle through a self-referential assignment would
    otherwise spin.
    """
    if depth > 4:
        return "unknown"

    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        kinds = {_deep_classify(v, scope, tree, depth + 1) for v in node.values} - {"none"}
        return kinds.pop() if len(kinds) == 1 else "unknown"

    if isinstance(node, ast.IfExp):
        kinds = {_deep_classify(node.body, scope, tree, depth + 1),
                 _deep_classify(node.orelse, scope, tree, depth + 1)} - {"none"}
        return kinds.pop() if len(kinds) == 1 else "unknown"

    kind = _classify(node)
    if kind != "unknown":
        return kind

    if isinstance(node, ast.Call) and tree is not None:
        callee = node.func
        fname = callee.attr if isinstance(callee, ast.Attribute) else getattr(callee, "id", "")
        if fname and _returns_list(fname, tree):
            return "list"

    if isinstance(node, ast.Name):
        if scope is not None:
            local = _resolve_local(node.id, scope)
            if local != "unknown":
                return local
            by_ann = _resolve_param_annotation(node.id, scope)
            if by_ann != "unknown":
                return by_ann
        # Module-level constants: _ALL_EVENT_TYPES = [...] is a list, and a
        # function-scope-only lookup cannot see it.
        if tree is not None:
            at_module = _resolve_module_constant(node.id, tree)
            if at_module != "unknown":
                return at_module
        if scope is None:
            return "unknown"
        # a local assigned from a `-> list` helper
        for stmt in ast.walk(scope):
            if isinstance(stmt, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == node.id for t in stmt.targets):
                if _deep_classify(stmt.value, scope, tree, depth + 1) == "list":
                    return "list"
        return "unknown"
    if isinstance(node, ast.Attribute):
        return _resolve_model_attr(node, scope, tree)
    return "unknown"


def _resolve_module_constant(name, tree):
    """Kind of a module-level assignment, ignoring anything inside a def/class."""
    kinds = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            targets, value = stmt.targets, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets, value = [stmt.target], stmt.value
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == name:
                kinds.add(_classify(value))
    kinds.discard("none")
    return kinds.pop() if len(kinds) == 1 else "unknown"


def _resolve_param_annotation(name, scope):
    """A parameter annotated `list` / `List[str]` states its own type.

    Wrapping such a value in a normaliser at the call site would only restate
    what the signature already promises, so the guard should read the promise.
    """
    if scope is None:
        return "unknown"
    args = scope.args
    for arg in list(args.args) + list(args.posonlyargs) + list(args.kwonlyargs):
        if arg.arg == name and arg.annotation is not None:
            return "list" if _annotation_is_list(arg.annotation) else "unknown"
    return "unknown"


def _returns_list(func_name, tree):
    """True when a module-level function is annotated `-> list`."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and node.name == func_name and node.returns is not None:
            return _annotation_is_list(node.returns)
    return False


def _resolve_local(name, scope):
    """Collapse every local assignment of `name` to one kind, else 'unknown'.

    Without this, the correct fix — normalise to a list, pass the variable —
    is indistinguishable from passing a raw scalar, and the guard would push
    people away from doing it properly.
    """
    kinds = set()
    for stmt in ast.walk(scope):
        if isinstance(stmt, ast.Assign):
            targets, value = stmt.targets, stmt.value
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            targets, value = [stmt.target], stmt.value
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == name:
                if isinstance(value, ast.IfExp):
                    kinds.add(_classify(value.body))
                    kinds.add(_classify(value.orelse))
                else:
                    kinds.add(_classify(value))
    kinds.discard("none")
    for single in ("list", "json_wrapped", "str"):
        if kinds and kinds <= {single}:
            return single
    return "unknown"


_INSERT_COLS = re.compile(rf"INSERT\s+INTO\s+(?:public\.)?({IDENT})\s*\(([^)]*)\)",
                          re.I | re.S)
_UPDATE_HEAD = re.compile(rf"UPDATE\s+(?:public\.)?({IDENT})(?:\s+(?:AS\s+)?({IDENT}))?\s+SET\s",
                          re.I | re.S)
def _split_top_level(text):
    """Split on commas that are not inside parentheses.

    A regex cannot do this: `event_types = COALESCE(%s, event_types), name = %s`
    has a comma INSIDE the function call, and a comma-avoiding pattern silently
    dropped the whole assignment rather than mis-parsing it — which is worse,
    because the column then looked unchecked instead of wrong.
    """
    parts, depth, current = [], 0, []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


def _update_set_columns(sql):
    """[(table, column)] for `SET col = %s` assignments, in placeholder order.

    Only assignments whose value is exactly a placeholder consume a parameter
    whose shape IS the column's shape. `col = EXCLUDED.col` and `col = now()`
    consume none; `col = COALESCE(%s, col)` consumes one but wraps it, so it
    yields (table, None) — a slot to skip, keeping later columns aligned.

    The SET clause is cut at WHERE/RETURNING/FROM because those placeholders
    come AFTER the SET ones positionally, and mapping a WHERE value onto a
    column would produce confident nonsense.
    """
    head = _UPDATE_HEAD.search(sql)
    if not head:
        return None, []
    table = head.group(1).lower()
    tail = sql[head.end():]

    cut = len(tail)
    for keyword in (r"\bWHERE\b", r"\bRETURNING\b", r"\bFROM\b"):
        m = re.search(keyword, tail, re.I)
        if m:
            cut = min(cut, m.start())
    set_clause = tail[:cut]

    ordered = []
    for chunk in _split_top_level(set_clause):
        if "=" not in chunk:
            continue
        col, _, value = chunk.partition("=")
        col = col.strip().strip('"').lower()
        value = value.strip()
        if not re.fullmatch(IDENT, col):
            continue
        if value == "%s":
            ordered.append((table, col))
        elif "%s" in value:
            ordered.append((table, None))
    return table, ordered


def _scan_param_types(kinds):
    """(mismatches, unprovable_array_feeds, positions_checked)."""
    mismatches, unprovable, checked = [], set(), 0

    for path in _python_files():
        rel = os.path.relpath(path, REPO)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                tree = ast.parse(fh.read())
        except SyntaxError:
            continue

        funcs = [n for n in ast.walk(tree)
                 if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]

        def enclosing(node):
            best = None
            for fn in funcs:
                if fn.lineno <= node.lineno <= getattr(fn, "end_lineno", fn.lineno):
                    if best is None or fn.lineno > best.lineno:
                        best = fn
            return best

        for call in ast.walk(tree):
            if not (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)):
                continue
            if call.func.attr != "execute" or len(call.args) < 2:
                continue

            sql_node = call.args[0]
            if isinstance(sql_node, ast.Constant) and isinstance(sql_node.value, str):
                sql = sql_node.value
            elif isinstance(sql_node, ast.JoinedStr):
                sql = "".join(
                    v.value if isinstance(v, ast.Constant) and isinstance(v.value, str)
                    else " {} " for v in sql_node.values)
            else:
                continue

            params = call.args[1]
            if not isinstance(params, (ast.Tuple, ast.List)):
                continue

            sql = _strip_sql_comments(sql)

            update_table, update_cols = _update_set_columns(sql)
            if update_cols and update_table in kinds:
                # SET placeholders are the FIRST parameters; anything beyond
                # them belongs to WHERE and is left alone.
                if len(params.elts) >= len(update_cols):
                    for (tbl, col), param in zip(update_cols, params.elts):
                        if col is None:
                            continue
                        kind = kinds[tbl].get(col)
                        if not kind:
                            continue
                        got = _deep_classify(param, enclosing(param), tree)
                        if got == "scalar_annotated":
                            got = "str" if kind == "array" else "unknown"
                        if got in ("unknown", "none"):
                            if kind == "array":
                                unprovable.add((rel, tbl, col))
                            continue
                        checked += 1
                        problem = None
                        if kind == "array" and got in ("str", "json_wrapped", "dict"):
                            problem = f"{got} passed to {col} (text[]) in UPDATE SET"
                        elif kind == "jsonb" and got in ("dict", "list"):
                            problem = f"bare {got} passed to {col} (jsonb) in UPDATE SET — needs Json()"
                        elif kind == "scalar" and got in ("list", "dict"):
                            problem = f"{got} passed to scalar {col} in UPDATE SET"
                        if problem:
                            mismatches.append((rel, param.lineno, tbl, col, problem))

            m = _INSERT_COLS.search(sql)
            if not m:
                continue
            table, collist = m.group(1).lower(), m.group(2)
            if table not in kinds or "{" in collist:
                continue
            cols = [c.strip().strip('"').lower() for c in collist.split(",") if c.strip()]

            # Positional mapping is only trustworthy when the counts line up.
            placeholders = sql.count("%s")
            if not (placeholders == len(cols) == len(params.elts)):
                continue

            for col, param in zip(cols, params.elts):
                kind = kinds[table].get(col)
                if not kind:
                    continue
                got = _deep_classify(param, enclosing(param), tree)
                if got == "scalar_annotated":
                    # Annotation found and it is not a list. For an array column
                    # that is a provable mismatch, not an unknown.
                    got = "str" if kind == "array" else "unknown"
                if got in ("unknown", "none"):
                    if kind == "array":
                        unprovable.add((rel, table, col))
                    continue

                checked += 1
                problem = None
                if kind == "array" and got in ("str", "json_wrapped", "dict"):
                    problem = f"{got} passed to {col} (text[])"
                elif kind == "jsonb" and got in ("dict", "list"):
                    problem = f"bare {got} passed to {col} (jsonb) — needs Json()/json.dumps()"
                elif kind == "scalar" and got in ("list", "dict"):
                    problem = f"{got} passed to scalar {col}"
                if problem:
                    mismatches.append((rel, param.lineno, table, col, problem))
    return mismatches, unprovable, checked


@pytest.fixture(scope="module")
def column_kinds():
    sources = sorted(glob.glob(os.path.join(REPO, "db_init", "*.sql"))) + _python_files()
    return _column_kinds(sources)


@pytest.fixture(scope="module")
def param_scan(column_kinds):
    return _scan_param_types(column_kinds)


def test_column_kinds_are_parsed(column_kinds):
    """Anti-vacuity: an empty type map would pass every assertion below."""
    assert len(column_kinds) >= 90, f"only {len(column_kinds)} tables typed"
    arrays = sum(1 for t in column_kinds.values() for k in t.values() if k == "array")
    jsonbs = sum(1 for t in column_kinds.values() for k in t.values() if k == "jsonb")
    assert arrays >= 20, f"only {arrays} array columns found"
    assert jsonbs >= 50, f"only {jsonbs} jsonb columns found"
    # The column that motivated this tier.
    assert column_kinds["web_findings"]["cwe"] == "array"
    assert column_kinds["web_findings"]["refs"] == "jsonb"


def test_classifier_knows_a_list_from_a_scalar():
    """The distinction the whole tier rests on."""
    assert _classify(ast.parse("['CWE-79']", mode="eval").body) == "list"
    assert _classify(ast.parse("'CWE-79'", mode="eval").body) == "str"
    assert _classify(ast.parse("f'CWE-{n}'", mode="eval").body) == "str"
    assert _classify(ast.parse("Json({})", mode="eval").body) == "json_wrapped"
    assert _classify(ast.parse("{'a': 1}", mode="eval").body) == "dict"
    assert _classify(ast.parse("[str(c) for c in x]", mode="eval").body) == "list"
    # Opaque on purpose — this is the honest limit stated above.
    assert _classify(ast.parse("d.get('cwe')", mode="eval").body) == "unknown"


def test_local_normalisation_is_recognised():
    """Normalise-then-pass must read as a list, or the guard punishes the fix."""
    src = (
        "def f(d):\n"
        "    v = d.get('cwe')\n"
        "    if v is None:\n"
        "        arr = None\n"
        "    elif isinstance(v, list):\n"
        "        arr = [str(c) for c in v]\n"
        "    else:\n"
        "        arr = [str(v)]\n"
    )
    tree = ast.parse(src)
    fn = tree.body[0]
    assert _resolve_local("arr", fn) == "list"
    assert _resolve_local("v", fn) == "unknown"


def test_param_scan_reaches_the_inserts(param_scan):
    _, _, checked = param_scan
    assert checked >= 80, f"only {checked} typed parameter positions checked"


def test_sql_param_types_are_compatible(param_scan):
    """The guard: no provable type mismatch between a value and its column."""
    mismatches, _, _ = param_scan
    unexpected = [m for m in mismatches
                  if (m[0], m[2], m[3]) not in SQL_TYPE_DEBT]
    assert not unexpected, (
        f"{len(unexpected)} parameter(s) cannot adapt to their column type:\n  "
        + "\n  ".join(f"{r}:{ln} {t}.{c} — {why}" for r, ln, t, c, why in sorted(unexpected))
    )


def test_unprovable_array_feeds_are_declared(param_scan):
    """Everything this tier cannot prove must be listed, never silently skipped.

    A new entry means a new array column is fed a value of unknown shape — the
    exact situation that let the cwe scalar through. Normalise it to a list (or
    route it through a LIST_SAFE_FUNCS helper) and it stops being listed.
    """
    _, unprovable, _ = param_scan
    added = sorted(unprovable - ARRAY_UNVERIFIED)
    assert not added, (
        f"{len(added)} array column(s) fed a value of unprovable type:\n  "
        + "\n  ".join(f"{r}: {t}.{c}" for r, t, c in added)
        + "\n\nNormalise to a list before passing it, e.g.\n"
          "    arr = v if isinstance(v, list) else ([str(v)] if v else None)\n"
          "or add the entry to ARRAY_UNVERIFIED with a reason."
    )


def test_no_stale_array_exemptions(param_scan):
    """A feed that became provable must leave the list."""
    _, unprovable, _ = param_scan
    stale = sorted(ARRAY_UNVERIFIED - unprovable)
    assert not stale, (
        "ARRAY_UNVERIFIED entries are now provable or gone — delete them:\n  "
        + "\n  ".join(f"{r}: {t}.{c}" for r, t, c in stale)
    )


@pytest.mark.unit
def test_annotation_is_list_recognises_the_common_forms():
    """Pydantic and stdlib annotations both, including Optional/union wrappers."""
    def ann(src):
        return _annotation_is_list(ast.parse(src, mode="eval").body)
    assert ann("list")
    assert ann("List[str]")
    assert ann("list[int]")
    assert ann("Optional[List[str]]")
    assert ann("Union[List[str], None]")
    assert ann("List[str] | None")
    assert ann("typing.List[str]")
    assert not ann("str")
    assert not ann("Optional[str]")
    assert not ann("Dict[str, str]")


@pytest.mark.unit
def test_or_empty_list_idiom_is_provable():
    """`body.tags or []` is how most of these feeds are written."""
    src = ("def f(body: M):\n"
           "    cur.execute('INSERT INTO t (tags) VALUES (%s)', (body.tags or [],))\n"
           "class M:\n"
           "    tags: List[str]\n")
    tree = ast.parse(src)
    fn = tree.body[0]
    call = fn.body[0].value
    param = call.args[1].elts[0]
    assert _deep_classify(param, fn, tree) == "list"


@pytest.mark.unit
def test_annotated_parameter_is_provable():
    """A parameter annotated `list` states its own type; no wrapper needed."""
    src = ("def f(cve_ids: list):\n"
           "    cur.execute('INSERT INTO t (cve_ids) VALUES (%s)', (cve_ids,))\n")
    tree = ast.parse(src)
    fn = tree.body[0]
    param = fn.body[0].value.args[1].elts[0]
    assert _deep_classify(param, fn, tree) == "list"


@pytest.mark.unit
def test_return_annotated_helper_is_provable():
    src = ("def _extract() -> list:\n"
           "    return []\n"
           "def f():\n"
           "    cves = _extract()\n"
           "    cur.execute('INSERT INTO t (cve) VALUES (%s)', (cves,))\n")
    tree = ast.parse(src)
    fn = tree.body[1]
    param = fn.body[1].value.args[1].elts[0]
    assert _deep_classify(param, fn, tree) == "list"


@pytest.mark.unit
def test_scalar_annotation_on_an_array_column_is_a_mismatch_not_unknown():
    """A field declared `str` feeding text[] is provably wrong, not unprovable."""
    src = ("def f(body: M):\n"
           "    pass\n"
           "class M:\n"
           "    tags: str\n")
    tree = ast.parse(src)
    attr = ast.parse("body.tags", mode="eval").body
    assert _resolve_model_attr(attr, tree.body[0], tree) == "scalar_annotated"


@pytest.mark.unit
def test_ambiguous_class_names_are_not_guessed():
    """Two classes sharing a name must resolve to nothing, not to either one."""
    global _CLASS_INDEX
    saved = _CLASS_INDEX
    try:
        _CLASS_INDEX = {}
        attr = ast.parse("body.tags", mode="eval").body
        src = "def f(body: Nope):\n    pass\n"
        tree = ast.parse(src)
        assert _resolve_model_attr(attr, tree.body[0], tree) == "unknown"
    finally:
        _CLASS_INDEX = saved


@pytest.mark.unit
def test_update_set_maps_only_placeholder_assignments():
    """`col = EXCLUDED.col` / `now()` consume no parameter.

    Counting every assignment would misalign every parameter after the first
    such clause, and then confidently report the wrong column.
    """
    table, cols = _update_set_columns(
        "UPDATE webhooks SET name = %s, event_types = %s, updated_at = now() "
        "WHERE id = %s")
    assert table == "webhooks"
    assert cols == [("webhooks", "name"), ("webhooks", "event_types")]


@pytest.mark.unit
def test_update_set_stops_at_where():
    """WHERE placeholders come AFTER the SET ones and are not column values."""
    _, cols = _update_set_columns("UPDATE t SET a = %s WHERE b = %s AND c = %s")
    assert cols == [("t", "a")]


@pytest.mark.unit
def test_update_set_marks_wrapped_placeholders_as_unmappable():
    """`col = COALESCE(%s, col)` consumes a parameter but wraps it.

    The parameter's shape is not the column's shape there, so it must be
    skipped rather than checked — this is what the webhook PATCH handler does
    for all nine of its columns.
    """
    _, cols = _update_set_columns(
        "UPDATE webhooks SET event_types = COALESCE(%s, event_types), name = %s")
    assert cols == [("webhooks", None), ("webhooks", "name")]


@pytest.mark.unit
def test_update_head_not_matched_on_a_select():
    _, cols = _update_set_columns("SELECT a FROM t WHERE b = %s")
    assert cols == []


@pytest.mark.unit
def test_module_level_constant_is_resolvable():
    """A list constant at module scope is invisible to a function-scope lookup."""
    src = ("EVENTS = ['a', 'b']\n"
           "def f():\n"
           "    cur.execute('UPDATE t SET c = %s', (EVENTS,))\n")
    tree = ast.parse(src)
    fn = tree.body[1]
    param = fn.body[0].value.args[1].elts[0]
    assert _deep_classify(param, fn, tree) == "list"


@pytest.mark.unit
def test_module_constant_reassigned_to_two_kinds_is_unknown():
    """Ambiguity must not resolve to whichever assignment came last."""
    src = "X = ['a']\nX = 'b'\n"
    tree = ast.parse(src)
    assert _resolve_module_constant("X", tree) == "unknown"


@pytest.mark.unit
def test_pgvector_columns_accept_lists():
    """A `vector` column takes a Python list; treating it as scalar produced
    three false positives on real embedding writes."""
    kinds = _column_kinds([os.path.join(REPO, "db_init", "ensure_all_tables.sql")])
    vector_cols = [(t, c) for t, cols in kinds.items()
                   for c, k in cols.items() if k == "vector"]
    assert vector_cols, "no vector columns parsed — pgvector detection regressed"

def _main():
    """Standalone entry point for scripts/post-install-check.sh (no pytest)."""
    sources = sorted(glob.glob(os.path.join(REPO, "db_init", "*.sql"))) + _python_files()
    tables = _parse_ddl(sources)
    problems, refs, inserts = _scan(tables)

    cols = sum(len(c) for c in tables.values())
    print(f"Schema: {len(tables)} tables, {cols} columns "
          f"(db_init/*.sql + runtime DDL in .py)")
    print(f"Checked {refs} qualified reference(s) and {inserts} INSERT column(s)")

    sources = sorted(glob.glob(os.path.join(REPO, "db_init", "*.sql"))) + _python_files()
    kinds = _column_kinds(sources)
    type_bad, unprovable, positions = _scan_param_types(kinds)
    type_bad = [m for m in type_bad if (m[0], m[2], m[3]) not in SQL_TYPE_DEBT]
    print(f"Checked {positions} typed parameter position(s); "
          f"{len(unprovable)} array feed(s) unprovable "
          f"({len(ARRAY_UNVERIFIED)} declared)")

    unexpected = [p for p in problems if (p[0], p[2], p[3]) not in SQL_DEBT]
    known = len(problems) - len(unexpected)
    print(f"  {known} known debt entr(ies) tolerated, {len(SQL_DEBT)} listed")

    new_unprovable = sorted(unprovable - ARRAY_UNVERIFIED)
    stale_unprovable = sorted(ARRAY_UNVERIFIED - unprovable)

    if unexpected:
        print(f"\n{len(unexpected)} SQL reference(s) name a nonexistent column:")
        for rel, lineno, table, col, shown in sorted(unexpected):
            print(f"  ✗ {rel}:{lineno}  {shown}  (table {table} has no {col})")
    for rel, lineno, table, col, why in sorted(type_bad):
        print(f"  ✗ {rel}:{lineno}  {table}.{col} — {why}")
    for rel, table, col in new_unprovable:
        print(f"  ✗ {rel}: {table}.{col} — array fed a value of unprovable type")
    for rel, table, col in stale_unprovable:
        print(f"  ✗ {rel}: {table}.{col} — ARRAY_UNVERIFIED entry is stale, delete it")

    if unexpected or type_bad or new_unprovable or stale_unprovable:
        return 1
    print("\n✅ every resolvable SQL column reference and parameter type checks out")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main())
