"""Every scope_targets writer must name the REAL unique index, and attribute it.

WHY THIS EXISTS
---------------
`scope_targets` has exactly one unique index besides the primary key:

    ux_scope_targets_eng_name_target  (engagement_id, name, target)

Five INSERT sites said `ON CONFLICT (name, target)`. In Postgres an ON CONFLICT
target must match an existing unique index EXACTLY, so those five did not dedupe
— they RAISED, every time:

    there is no unique or exclusion constraint matching the ON CONFLICT specification

Verified against the live database before the fix. So scope auto-discovery,
scope-move, auto-classify and swagger-import could not add a single row, and the
move path deleted from the source scope before the failing insert. This was
recorded in OPEN_ITEMS as "writers omit engagement_id", which understated it:
the column was missing AND the statement could never run.

The second half matters on its own. A scope row with a NULL `engagement_id` is
an orphan an engagement data-purge cannot claim (CLAUDE.md), with one deliberate
exception: the global `not_in_scope` deny-list is cross-engagement by design.

Sabotage: change any ON CONFLICT back to (name, target), or drop engagement_id
from a non-not_in_scope insert -> the matching test fails by line number.
"""
import ast
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")

# The only unique index on scope_targets, per db_init.
INDEX_COLS = ("engagement_id", "name", "target")

# Inserts that legitimately carry no engagement_id: the global deny-list.
GLOBAL_SCOPE = "not_in_scope"


def _api_src():
    if not os.path.exists(API):
        pytest.skip("api.py not present")
    return open(API, encoding="utf-8").read()


def _scope_inserts(src):
    """(line, sql, statement_source) for every INSERT INTO scope_targets.

    Read from string CONSTANTS via ast, so a statement mentioned in a comment or
    a docstring is not mistaken for one that runs.

    The third element is the source of the enclosing CALL, because the scope name
    is not always inside the SQL: execute_values() puts it in `template=`, so a
    not_in_scope insert can look unattributed while being the global deny-list.
    """
    tree = ast.parse(src)
    # map each INSERT constant to the call that executes it
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)]
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        v = node.value
        if not re.search(r"INSERT\s+INTO\s+(public\.)?scope_targets", v, re.I):
            continue
        stmt = v
        for c in calls:
            if any(a is node for a in ast.walk(c)):
                seg = ast.get_source_segment(src, c)
                if seg and len(seg) >= len(stmt):
                    stmt = seg
                    break
        out.append((node.lineno, v, stmt))
    return out


def test_the_index_is_what_we_think_it_is():
    """Guard the premise: if db_init's index changes, this whole file is wrong."""
    ddl = os.path.join(REPO, "db_init", "ensure_all_tables.sql")
    if not os.path.exists(ddl):
        pytest.skip("ensure_all_tables.sql not present")
    sql = open(ddl, encoding="utf-8").read()
    m = re.search(r"CREATE UNIQUE INDEX[^;]*ux_scope_targets_eng_name_target[^;]*;", sql, re.I)
    assert m, "ux_scope_targets_eng_name_target is not declared in db_init"
    cols = m.group(0)
    for c in INDEX_COLS:
        assert c in cols, f"the unique index no longer covers {c}: {cols[:160]}"


def test_on_conflict_matches_the_unique_index():
    """An ON CONFLICT target that names no index raises on every execution."""
    bad = []
    for lineno, sql, _stmt in _scope_inserts(_api_src()):
        m = re.search(r"ON\s+CONFLICT\s*\(([^)]*)\)", sql, re.I)
        if not m:
            continue                      # no upsert clause is fine
        cols = tuple(c.strip() for c in m.group(1).split(","))
        if cols != INDEX_COLS:
            bad.append((lineno, cols))
    assert not bad, (
        "these scope_targets inserts name an ON CONFLICT target that matches no "
        f"unique index, so they raise instead of deduping: {bad}\n"
        f"The only unique index is {INDEX_COLS}; ON CONFLICT must repeat it exactly.")


def test_non_global_inserts_carry_the_engagement():
    """A NULL-engagement scope row is an orphan a purge cannot claim."""
    missing = []
    for lineno, sql, _stmt in _scope_inserts(_api_src()):
        m = re.search(r"INSERT\s+INTO\s+(?:public\.)?scope_targets\s*\(([^)]*)\)", sql, re.I)
        if not m:
            continue
        cols = {c.strip() for c in m.group(1).split(",")}
        if "engagement_id" in cols:
            continue
        if GLOBAL_SCOPE in _stmt:
            continue                      # the global deny-list, by design
        missing.append(lineno)
    assert not missing, (
        f"scope_targets inserts at lines {missing} omit engagement_id and are not "
        f"the global {GLOBAL_SCOPE!r} deny-list, so they create orphan rows an "
        "engagement purge cannot remove")


def test_the_global_deny_list_is_still_exempt():
    """The exemption must stay REAL, not become a way to skip the check.

    If no insert targets not_in_scope any more, the exemption above is dead and
    should be deleted rather than left as a hole.
    """
    src = _api_src()
    assert any(GLOBAL_SCOPE in stmt for _ln, _sql, stmt in _scope_inserts(src)), (
        f"no scope_targets insert mentions {GLOBAL_SCOPE!r} — the exemption in "
        "test_non_global_inserts_carry_the_engagement is now dead code")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
