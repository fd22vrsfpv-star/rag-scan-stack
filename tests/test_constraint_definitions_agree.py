"""A named CHECK constraint defined in more than one place must AGREE everywhere.

Run on demand:

    pytest tests/test_constraint_definitions_agree.py -v

WHY THIS EXISTS
---------------
The live DB has more than one thing that applies DDL. `db_init/ensure_all_tables.sql`
(via scripts/ensure_db_schema.sh) is one; but several long-running SERVICES also run
`DROP CONSTRAINT ... ADD CONSTRAINT ...` migrations on every startup
(autogen_agents/db_utils.py, node_manager/node_manager.py, ...). Whoever runs LAST
wins. So if two of them define the SAME named constraint with DIFFERENT value sets,
a service restart silently re-narrows the constraint the schema file had widened, and
the next write of the dropped value fails with `violates check constraint`.

This already bit us twice:
  * agent_sessions_status_check lost 'scanning' on every autogen-agents restart.
  * remote_nodes_status_check dropped 'disabled' on every node_manager restart, while
    node_manager.py:450 itself writes status='disabled'.

Both were invisible to ast.parse, imports, and a healthy container — only a live run
(or a restart) hit them. This pins every named CHECK-IN constraint so all of its
definitions carry the SAME set of allowed values, whatever the run order.

SABOTAGE PROOF
--------------
Remove a value from one definition of any multiply-defined named constraint (e.g. drop
'disabled' from node_manager.py's remote_nodes_status_check) and this fails by name.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))

# ALTER TABLE ... ADD CONSTRAINT <name> CHECK ( <col> IN ( <values> ) )
# Works for both the SQL files and the Python-embedded DDL strings, single- or
# multi-line (re.S), since the value list is captured up to its closing paren.
_ADD = re.compile(
    r"ADD\s+CONSTRAINT\s+(\w+)\s+CHECK\s*\(\s*\w+\s+IN\s*\(([^)]*)\)",
    re.I | re.S,
)


def _values(group: str) -> frozenset:
    return frozenset(v.strip().strip("'\"") for v in group.split(",") if v.strip())


def _collect():
    """{constraint_name: {frozenset(values): [files...]}} across the whole repo."""
    out = {}
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")]
        # tests/ describe constraints in prose/sabotage notes; don't scan them.
        if os.path.relpath(root, REPO).split(os.sep)[0] == "tests":
            continue
        for fn in files:
            if not (fn.endswith(".py") or fn.endswith(".sql")):
                continue
            path = os.path.join(root, fn)
            try:
                text = open(path, encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for name, grp in _ADD.findall(text):
                vals = _values(grp)
                if not vals:
                    continue
                rel = os.path.relpath(path, REPO)
                out.setdefault(name, {}).setdefault(vals, [])
                if rel not in out[name][vals]:
                    out[name][vals].append(rel)
    return out


def test_multiply_defined_constraints_agree():
    collected = _collect()
    assert collected, "no ADD CONSTRAINT ... CHECK definitions found — guard too weak"
    disagreements = {
        name: variants
        for name, variants in collected.items()
        if len(variants) > 1
    }
    if disagreements:
        lines = []
        for name, variants in sorted(disagreements.items()):
            lines.append(f"  {name}:")
            for vals, files in variants.items():
                lines.append(f"    {sorted(vals)}  <- {sorted(files)}")
        pytest.fail(
            "Named CHECK constraints with DISAGREEING value sets across files "
            "(a service restart will re-narrow the live constraint and break "
            "writes of the dropped value):\n" + "\n".join(lines))
