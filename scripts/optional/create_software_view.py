#!/usr/bin/env python3
"""Apply the detected_software view from its ONE canonical definition.

This script used to carry its own copy of the view SQL. It had drifted badly:
10 source branches where `db_init/ensure_all_tables.sql` has 15, and no
deduplication at all. Running it would have silently reverted the dedup fix AND
dropped five whole sources of software detection — the classic second-DDL-source
problem (see Docs/Memories.md: "A second DDL source can undo schema repair").

So it no longer holds any SQL. It extracts the `CREATE OR REPLACE VIEW
public.detected_software` statement out of `db_init/ensure_all_tables.sql` and
applies exactly that. The view cannot drift from the schema file because there
is nothing here to drift.

    python3 scripts/optional/create_software_view.py          # apply
    python3 scripts/optional/create_software_view.py --print  # show, apply nothing
"""
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCHEMA = REPO / "db_init" / "ensure_all_tables.sql"
HEAD = "CREATE OR REPLACE VIEW public.detected_software AS"


def extract_view_sql(schema_text: str) -> str:
    """The view statement, from its header to the terminating semicolon.

    Semicolon-splitting the file would not work: the view's branches contain
    regex literals and the file contains `DO $$ ... $$` blocks. Scan forward
    from the header for the first line that ENDS a statement, honouring the
    dollar-quoted blocks on the way.
    """
    start = schema_text.find(HEAD)
    if start < 0:
        raise SystemExit(f"{SCHEMA}: no '{HEAD}' found — has the view moved?")
    rest = schema_text[start:]
    depth = 0
    for m in re.finditer(r"\$\$|;", rest):
        if m.group(0) == "$$":
            depth ^= 1
        elif depth == 0:
            return rest[:m.end()]
    raise SystemExit(f"{SCHEMA}: the view statement is not terminated")


def main() -> int:
    sql = extract_view_sql(SCHEMA.read_text(encoding="utf-8"))
    branches = sql.count("UNION ALL") + 1
    if "--print" in sys.argv:
        print(sql)
        return 0
    if "GROUP BY" not in sql:
        # Loud, not silent: applying an un-deduplicated view is the exact
        # regression this script exists to not cause.
        print("REFUSING: the extracted view has no GROUP BY, so it would "
              "reintroduce one software row per scan run (measured 2026-10-14: "
              "15,407 rows for 11,268 distinct software, 27% copies).",
              file=sys.stderr)
        return 2
    import psycopg2
    dsn = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(sql)
        cur.execute("SELECT count(*) FROM detected_software")
        total = cur.fetchone()[0]
        cur.execute("""SELECT count(*) FROM (
                         SELECT asset_id, ip, hostname, port, protocol, product,
                                version, source, detection_type
                           FROM detected_software
                          GROUP BY 1,2,3,4,5,6,7,8,9 HAVING count(*) > 1) x""")
        dupes = cur.fetchone()[0]
    conn.close()
    print(f"detected_software applied from {SCHEMA.relative_to(REPO)} "
          f"({branches} source branches)")
    print(f"  rows: {total}   duplicate groups: {dupes}")
    if dupes:
        print("  WARNING: duplicates remain — the GROUP BY key may be wrong",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
