#!/usr/bin/env python3
"""Backfill engagement_id on identities that were written with none.

WHY THIS EXISTS
---------------
Enumerated / MSF-dumped accounts were inserted into `identities` with no
`engagement_id` (the writer omitted the column). The Users page filters by the
active engagement only when one resolves, so those NULL-engagement rows leaked
into every engagement's view — MSF-host accounts showed up under an unrelated
scope like `testfire`. CLAUDE.md ("Engagement attribution is mandatory") requires
collected target data to carry its engagement. The writer is fixed to set it
going forward (app/rag-api/target_wordlists.py); this claims the rows already
written.

WHAT IT DOES
------------
For each identity with engagement_id IS NULL it derives the host — from the
`domain` column (the enumerated writer stores the host there), else a `host:<h>`
tag, else raw->>'host', else the part after the last '@' in the identifier — and
resolves it to an engagement with the SAME shared resolver the writer uses
(identity_upsert.resolve_engagement_for_host: asset first, then IP scope entry).
A host that resolves gets its engagement stamped; a host that does not is left
NULL and reported (it cannot be attributed without inventing an engagement — the
attribution stays fail-closed). Idempotent: only NULL rows are touched, and a
second run with the same DB state is a no-op.

RUN
---
    # inside a container with DB access (e.g. rag-api), or with DB_DSN set:
    python3 etl/backfill_identities_engagement.py            # dry run (default)
    python3 etl/backfill_identities_engagement.py --apply    # write changes
"""
import argparse
import json
import os
import sys

import psycopg2
from psycopg2.extras import RealDictCursor

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

try:
    from etl.identity_upsert import resolve_engagement_for_host
except ImportError:  # flat layout / run from repo root
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from identity_upsert import resolve_engagement_for_host  # type: ignore


def _host_for_identity(row) -> str:
    """Best available host for an identity row, most reliable source first."""
    # 1) the `domain` column — the enumerated writer stores the host here
    dom = (row.get("domain") or "").strip()
    if dom:
        return dom
    # 2) a `host:<h>` tag
    for t in (row.get("tags") or []):
        if isinstance(t, str) and t.startswith("host:"):
            h = t[len("host:"):].strip()
            if h:
                return h
    # 3) raw JSON `host`
    raw = row.get("raw")
    if isinstance(raw, dict):
        h = str(raw.get("host") or "").strip()
        if h:
            return h
    # 4) the part after the last '@' in name@host identifiers
    ident = (row.get("identifier") or "")
    if "@" in ident:
        h = ident.rsplit("@", 1)[1].strip()
        # Skip obvious email/UPN domains for cloud identities — those are not
        # hosts and will never resolve; returning them is harmless (they just
        # fall into "unresolved") but this keeps the intent clear.
        if h:
            return h
    return ""


def _emit_webhook(applied: int, unresolved: int, examined: int) -> None:
    """Best-effort event so external tools can observe the backfill. Never
    raises: absence of config or a dead endpoint must not fail the backfill."""
    url = os.environ.get("RAG_API_URL") or os.environ.get("API_BASE")
    if not url:
        return
    try:
        import httpx  # optional
        httpx.post(
            f"{url.rstrip('/')}/webhooks/emit",
            headers={"x-api-key": os.environ.get("API_KEY", "")},
            json={
                "source": "backfill",
                "event_type": "identities_engagement_backfill_completed",
                "data": {"attributed": applied, "unresolved": unresolved,
                         "examined": examined},
            },
            verify=False, timeout=5,
        )
    except Exception as e:  # noqa: BLE001
        print(f"[warn] webhook emit skipped: {type(e).__name__}: {e}",
              file=sys.stderr)


def backfill(apply: bool = False) -> dict:
    conn = psycopg2.connect(DB_DSN)
    conn.autocommit = False
    examined = attributed = unresolved = 0
    unresolved_hosts: dict = {}
    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(
            "SELECT id, identifier, domain, tags, raw, provider "
            "FROM identities WHERE engagement_id IS NULL")
        rows = cur.fetchall()
        examined = len(rows)
        wcur = conn.cursor()
        for row in rows:
            host = _host_for_identity(row)
            eid = resolve_engagement_for_host(wcur, host) if host else None
            if not eid:
                unresolved += 1
                key = host or "(no host)"
                unresolved_hosts[key] = unresolved_hosts.get(key, 0) + 1
                continue
            if apply:
                # Re-check IS NULL in the UPDATE so a concurrent writer that has
                # since attributed the row is not overwritten.
                wcur.execute(
                    "UPDATE identities SET engagement_id = %s::uuid, "
                    "updated_at = now() "
                    "WHERE id = %s AND engagement_id IS NULL",
                    (eid, row["id"]))
            attributed += 1
        if apply:
            conn.commit()
        else:
            conn.rollback()
    finally:
        conn.close()

    result = {
        "examined": examined,
        "attributed": attributed,
        "unresolved": unresolved,
        "unresolved_by_host": dict(sorted(unresolved_hosts.items(),
                                          key=lambda kv: -kv[1])[:20]),
        "applied": bool(apply),
    }
    if apply and attributed:
        _emit_webhook(attributed, unresolved, examined)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true",
                    help="write changes (default: dry run, no writes)")
    args = ap.parse_args()
    res = backfill(apply=args.apply)
    print(json.dumps(res, indent=2, default=str))
    mode = "APPLIED" if res["applied"] else "DRY RUN (no writes)"
    print(f"\n{mode}: {res['attributed']} of {res['examined']} NULL-engagement "
          f"identities attributable; {res['unresolved']} could not be resolved "
          f"to an engagement.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
