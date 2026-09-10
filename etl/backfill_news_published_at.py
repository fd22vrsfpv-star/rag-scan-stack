#!/usr/bin/env python3
"""Backfill news_items.published_at from the dates already in articles[].

The column was added 2026-09-10. Every row ingested before that already
carries the feed's raw date string in `articles[].published` -- it was stored
but never promoted to a column -- so this recovers the real publication dates
instead of leaving 876 rows sorting as "no date".

Uses news_agent._parse_published, the SAME parser the live ingest path uses, so
a backfilled row is indistinguishable from a freshly-ingested one. It is not
re-implemented here on purpose: a second date parser would drift.

For a multi-article item the EARLIEST date wins -- that is when the story
broke, which is what the Published sort is for.

Idempotent: only touches rows where published_at IS NULL. Safe to re-run.

Run inside the news-runner container, which has psycopg2 AND news_agent:

    docker exec news-runner python /tmp/backfill_news_published_at.py
    docker exec news-runner python /tmp/backfill_news_published_at.py --dry-run
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "news_runner"))

import psycopg2  # noqa: E402
from psycopg2.extras import RealDictCursor  # noqa: E402

try:
    import news_agent  # type: ignore # noqa: E402
except ImportError:
    sys.exit("news_agent not importable — run this inside the news-runner container")

DSN = os.environ.get("DB_DSN") or getattr(news_agent, "DB_DSN", None)
if not DSN:
    sys.exit("DB_DSN not set")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--batch", type=int, default=500)
    args = ap.parse_args()

    conn = psycopg2.connect(DSN)
    scanned = filled = unparseable = 0

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT id, articles
                 FROM news_items
                WHERE published_at IS NULL
                  AND articles IS NOT NULL
                ORDER BY first_seen"""
        )
        rows = cur.fetchall()

    print(f"{len(rows)} rows with no published_at")
    updates = []
    for row in rows:
        scanned += 1
        dates = []
        for a in (row["articles"] or []):
            raw = (a or {}).get("published") or ""
            # articles[].published_at exists only on rows written after the
            # change; prefer it, then fall back to re-parsing the raw string.
            pre = (a or {}).get("published_at")
            if pre:
                raw = pre
            dt = news_agent._parse_published({}, raw)
            if dt:
                dates.append(dt)
        if dates:
            updates.append((min(dates), str(row["id"])))
        else:
            unparseable += 1

    print(f"  {len(updates)} parseable, {unparseable} with no usable date")
    if args.dry_run:
        for dt, iid in updates[:5]:
            print(f"  would set {iid} -> {dt.isoformat()}")
        conn.close()
        return 0

    with conn.cursor() as cur:
        for i in range(0, len(updates), args.batch):
            chunk = updates[i:i + args.batch]
            cur.executemany(
                "UPDATE news_items SET published_at = %s WHERE id = %s::uuid "
                "AND published_at IS NULL",
                chunk,
            )
            conn.commit()
            filled += len(chunk)
            print(f"  committed {filled}/{len(updates)}")

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM news_items WHERE published_at IS NOT NULL")
        total = cur.fetchone()[0]
    conn.close()
    print(f"done: scanned {scanned}, filled {filled}, "
          f"{unparseable} left null (feed gave no date); "
          f"{total} rows now have published_at")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
