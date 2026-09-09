#!/usr/bin/env python3
"""Embed findings into rag_documents.

    docker exec autogen-agents python3 /app/etl/backfill_rag_documents.py --dry-run
    docker exec autogen-agents python3 /app/etl/backfill_rag_documents.py --sources vulns
    docker exec autogen-agents python3 /app/etl/backfill_rag_documents.py            # default sources

WHY THIS EXISTS
---------------
`app/load_all.py::backfill_findings_into_rag` was the delivered backfill and
could never have worked. Four separate reasons, none of which the code could
report because it failed at import:

  1. `from etl.db import get_conn` — there is no etl/db.py in this repo, so the
     module raised ModuleNotFoundError. (Fixed 2026-09-09.)
  2. It selected `f.description`, `f.evidence` and ordered by `f.observed_at`.
     `findings` has none of those columns: it is
     `id, title, severity, asset_id, port, created_at, updated_at, details,
     engagement_id`.
  3. It read `findings`, which holds **0 rows**. The findings in this deployment
     live in the specialised tables — web_findings 13,342, recon_findings
     22,278, playwright_findings 780, vulns 297.
  4. It loaded SentenceTransformer in-process, and **no container has both
     sentence_transformers and psycopg2** — the embedder image has the model but
     no database driver, everything else has the driver but no model.

So it lives here instead: `etl/` is bind-mounted into the containers that have
psycopg2 and requests, which is the only place this can actually run.

Embeddings come from the stack's own embedder service (`POST /embed`), the same
way scan_recommender/exploits_rag.py gets them. That is not just convenience:
the service runs `sentence-transformers/all-MiniLM-L6-v2`, which is exactly the
384 dimensions `rag_documents.embedding` declares, so there is one source of
truth for the model instead of two that can drift.

IDEMPOTENT, unlike its predecessor: every chunk carries
`metadata->>'source'` and `metadata->>'row_id'`, and each row's existing chunks
are deleted before its new ones are written. Re-running updates in place rather
than doubling the corpus.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import psycopg2
import requests
from psycopg2.extras import Json, execute_values

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
EMBEDDER_URL = os.environ.get("EMBEDDER_URL", "https://embedder:8030")
CHUNK_CHARS = int(os.environ.get("RAG_CHUNK_CHARS", "3000"))
EMBED_BATCH = int(os.environ.get("RAG_EMBED_BATCH", "64"))

# The API the webhook allow-list has to know about, or the event is answered 200
# and discarded (see app/rag-api/webhooks/router.py::_ALL_EVENT_TYPES).
RAG_API_URL = os.environ.get("RAG_API_URL", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "")


# ── Sources ────────────────────────────────────────────────────────────────
# Each source names the table, the SQL that produces one row per finding, and
# how to turn that row into a document. Columns are listed explicitly rather
# than SELECT * so a schema change fails loudly here instead of silently
# embedding the wrong field.
#
# `recon_findings` is deliberately NOT in the default set: 22,278 rows of
# subdomain/host enumeration is the bulk of the database and almost none of it
# is prose. Embedding it buries the 297 vulns in noise. Ask for it explicitly.
SOURCES: Dict[str, Dict] = {
    "vulns": {
        "sql": """
            SELECT id, asset_id, port_id, title, script, output, severity,
                   cve, cvss, created_at
              FROM public.vulns
             ORDER BY created_at DESC NULLS LAST
             LIMIT %s
        """,
        "build": lambda r: (
            r[3] or r[4] or "vuln",
            "\n".join(filter(None, [
                f"TITLE: {r[3]}" if r[3] else None,
                f"SCRIPT: {r[4]}" if r[4] else None,
                f"CVE: {', '.join(r[7])}" if r[7] else None,
                f"CVSS: {r[8]}" if r[8] is not None else None,
                f"OUTPUT:\n{r[5]}" if r[5] else None,
            ])),
            {"severity": r[6], "cve": list(r[7] or []), "cvss": float(r[8]) if r[8] is not None else None},
            r[1], r[2],
        ),
    },
    "web_findings": {
        # record_kind separates real findings from inventory rows (the
        # technology/software catalogue). Inventory has no prose worth
        # embedding, and it is what would otherwise dominate the corpus.
        "sql": """
            SELECT id, asset_id, NULL::uuid, name, url, issue_type, description,
                   evidence, solution, severity, cwe, created_at
              FROM public.web_findings
             WHERE coalesce(record_kind, 'finding') <> 'inventory'
             ORDER BY created_at DESC NULLS LAST
             LIMIT %s
        """,
        "build": lambda r: (
            r[3] or r[5] or "web finding",
            "\n".join(filter(None, [
                f"NAME: {r[3]}" if r[3] else None,
                f"URL: {r[4]}" if r[4] else None,
                f"TYPE: {r[5]}" if r[5] else None,
                f"CWE: {', '.join(r[10])}" if r[10] else None,
                f"DESCRIPTION:\n{r[6]}" if r[6] else None,
                f"EVIDENCE:\n{r[7]}" if r[7] else None,
                f"SOLUTION:\n{r[8]}" if r[8] else None,
            ])),
            {"severity": r[9], "url": r[4], "issue_type": r[5], "cwe": list(r[10] or [])},
            r[1], None,
        ),
    },
    "playwright_findings": {
        "sql": """
            SELECT id, asset_id, NULL::uuid, title, description, severity,
                   evidence, created_at
              FROM public.playwright_findings
             ORDER BY created_at DESC NULLS LAST
             LIMIT %s
        """,
        "build": lambda r: (
            r[3] or "playwright finding",
            "\n".join(filter(None, [
                f"TITLE: {r[3]}" if r[3] else None,
                f"DESCRIPTION:\n{r[4]}" if r[4] else None,
                f"EVIDENCE:\n{r[6]}" if r[6] else None,
            ])),
            {"severity": r[5]},
            r[1], None,
        ),
    },
    # Columns verified against the live schema: recon_findings is
    # (source, finding_type, target, data jsonb) — NOT (kind, value), which is
    # what a first pass assumed. A wrong column name here is exactly the defect
    # class that made the original backfill unrunnable, so it is checked rather
    # than guessed.
    "recon_findings": {
        "sql": """
            SELECT id, asset_id, NULL::uuid, finding_type, target, source,
                   severity, data, created_at
              FROM public.recon_findings
             ORDER BY created_at DESC NULLS LAST
             LIMIT %s
        """,
        "build": lambda r: (
            f"{r[3]}: {r[4]}" if r[3] else (r[4] or "recon finding"),
            "\n".join(filter(None, [
                f"TYPE: {r[3]}" if r[3] else None,
                f"TARGET: {r[4]}" if r[4] else None,
                f"SOURCE: {r[5]}" if r[5] else None,
                f"DATA:\n{json.dumps(r[7], ensure_ascii=False)[:2000]}" if r[7] else None,
            ])),
            {"severity": r[6], "finding_type": r[3], "recon_source": r[5]},
            r[1], None,
        ),
    },
}

DEFAULT_SOURCES = ["vulns", "web_findings", "playwright_findings"]


def chunk(text: str, size: int = CHUNK_CHARS) -> List[str]:
    text = (text or "").strip()
    if not text:
        return []
    return [text[i:i + size] for i in range(0, len(text), size)]


def embed(texts: Sequence[str], timeout: int = 180) -> List[List[float]]:
    """Vectors for `texts`, in input order, from the embedder service.

    verify=False matches every other caller: the stack's TLS is self-signed and
    the CA bundle is not present in every image. The traffic never leaves the
    compose network.
    """
    resp = requests.post(f"{EMBEDDER_URL.rstrip('/')}/embed",
                         json={"texts": list(texts)}, timeout=timeout, verify=False)
    resp.raise_for_status()
    vectors = resp.json()["embeddings"]
    if len(vectors) != len(texts):
        raise RuntimeError(
            f"embedder returned {len(vectors)} vectors for {len(texts)} texts — "
            "refusing to write misaligned embeddings"
        )
    return vectors


def emit_webhook(event_type: str, data: Dict) -> None:
    """Audit event for a corpus rewrite. Best effort, but LOUDLY best effort.

    Two things this has to get right, both learned the hard way here:

      * `source` is REQUIRED by /webhooks/emit. Without it the endpoint answers
        **422** and nothing is recorded — the first version of this function
        omitted it.
      * a non-2xx has to be REPORTED. `requests.post` does not raise on 422, so
        the 422 above looked like a success and the missing audit trail was only
        found by querying webhook_events. CLAUDE.md: silence around an HTTP call
        turns a broken endpoint into "it returned zero results".

    The event TYPE must also be in the router's allow-list (`_ALL_EVENT_TYPES`),
    or it is accepted with 200 and silently discarded — and the running rag-api
    image must be new enough to contain it.
    """
    if not API_KEY:
        print("  [warn] API_KEY unset — audit event not emitted", file=sys.stderr)
        return
    try:
        resp = requests.post(
            f"{RAG_API_URL.rstrip('/')}/webhooks/emit",
            json={"event_type": event_type, "source": "rag-backfill", "data": data},
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            timeout=15, verify=False,
        )
        if resp.status_code >= 300:
            print(f"  [warn] webhook {event_type} rejected: HTTP "
                  f"{resp.status_code} {resp.text[:200]}", file=sys.stderr)
        else:
            print(f"  audit event {event_type} emitted")
    except Exception as exc:                      # noqa: BLE001 - audit only
        print(f"  [warn] webhook {event_type} not emitted: {exc}", file=sys.stderr)


def backfill_source(conn, name: str, limit: int, dry_run: bool) -> Tuple[int, int]:
    """Embed one source. Returns (rows_seen, chunks_written)."""
    spec = SOURCES[name]
    cur = conn.cursor()
    cur.execute(spec["sql"], (limit,))
    rows = cur.fetchall()
    print(f"  {name}: {len(rows)} row(s) to consider")

    # Grouped BY ROW, not flattened into a list of chunks.
    #
    # The first version flattened every chunk into one list and sliced it into
    # fixed-size batches. Each batch DELETEs the rows it is about to insert, so
    # a row whose chunks straddled a batch boundary had its earlier chunks
    # deleted by the later batch: 8,284 chunks were written and only 8,274
    # survived, with rows that should have had 3 chunks left holding 1 or 2.
    # Silent, and invisible unless you compare the count you wrote against the
    # count in the table.
    #
    # A row's chunks now always travel together, so the delete can never
    # outrun the insert.
    groups: List[Tuple[str, List[Tuple]]] = []   # (row_id, [(title, part, md, asset, port)])
    for row in rows:
        title, body, meta, asset_id, port_id = spec["build"](row)
        chunks = chunk(body)
        if not chunks:
            continue
        items = []
        for i, part in enumerate(chunks):
            md = dict(meta)
            md.update({"source": name, "row_id": str(row[0]), "chunk": i,
                       "chunks": len(chunks)})
            items.append((title, part, md, asset_id, port_id))
        groups.append((str(row[0]), items))

    total_chunks = sum(len(items) for _, items in groups)
    print(f"  {name}: {total_chunks} chunk(s) to embed")
    if dry_run or not groups:
        return len(rows), 0

    written = 0
    batch: List[Tuple] = []
    batch_rows: List[str] = []

    def flush() -> int:
        """Embed, replace and insert one batch. Returns chunks written."""
        if not batch:
            return 0
        vectors = embed([b[1] for b in batch])
        # Delete-then-insert, so a re-run REPLACES a finding's chunks rather
        # than appending a second copy (the predecessor appended, which is why
        # it was documented as "not idempotent"). Safe now that every chunk of
        # a row is in this same batch.
        cur.execute(
            "DELETE FROM public.rag_documents "
            " WHERE metadata->>'source' = %s AND metadata->>'row_id' = ANY(%s)",
            (name, sorted(set(batch_rows))),
        )
        execute_values(
            cur,
            "INSERT INTO public.rag_documents "
            "  (asset_id, port_id, title, text_chunk, metadata, embedding) VALUES %s",
            [(b[3], b[4], b[0], b[1], Json(b[2]), vec)
             for b, vec in zip(batch, vectors)],
        )
        conn.commit()
        return len(batch)

    for row_id, items in groups:
        # A single row bigger than the batch size goes on its own rather than
        # being split.
        if batch and len(batch) + len(items) > EMBED_BATCH:
            written += flush()
            print(f"    {name}: {written}/{total_chunks} chunks", flush=True)
            batch, batch_rows = [], []
        batch.extend(items)
        batch_rows.append(row_id)

    written += flush()
    print(f"    {name}: {written}/{total_chunks} chunks", flush=True)
    return len(rows), written


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sources", nargs="+", choices=sorted(SOURCES),
                    default=DEFAULT_SOURCES,
                    help=f"default: {' '.join(DEFAULT_SOURCES)} "
                         "(recon_findings is opt-in: 22k rows of enumeration)")
    ap.add_argument("--limit", type=int, default=100000,
                    help="max rows per source")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be embedded and write nothing")
    args = ap.parse_args(argv)

    print(f"embedder: {EMBEDDER_URL}")
    print(f"sources:  {' '.join(args.sources)}"
          f"{'   [DRY RUN]' if args.dry_run else ''}")

    conn = psycopg2.connect(DB_DSN)
    try:
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM public.rag_documents")
        before = cur.fetchone()[0]
        print(f"rag_documents before: {before} row(s)\n")

        total_rows = total_chunks = 0
        for name in args.sources:
            seen, written = backfill_source(conn, name, args.limit, args.dry_run)
            total_rows += seen
            total_chunks += written

        cur.execute("SELECT count(*) FROM public.rag_documents")
        after = cur.fetchone()[0]
        print(f"\nrag_documents after: {after} row(s)  (+{after - before})")
        print(f"sources read: {total_rows} row(s) -> {total_chunks} chunk(s) written")
    finally:
        conn.close()

    if not args.dry_run:
        emit_webhook("maintenance_rag_backfilled", {
            "sources": list(args.sources),
            "rows_read": total_rows,
            "chunks_written": total_chunks,
            "rag_documents_total": after,
        })
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
