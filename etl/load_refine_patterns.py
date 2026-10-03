"""Idempotent loader for knowledge/refine_error_patterns.yaml.

Reads the YAML, embeds each (title, body) pair, and replaces every row in
rag_documents under source='refine_error_pattern'. Also mirrors the
structured trigger spec into refine_error_patterns table so the fast
substring matcher in api.py can read it without re-parsing YAML on each
refine iter.

Idempotent: wipes source='refine_error_pattern' then re-inserts. Safe to
run on every YAML change.

    docker exec rag-api python3 /app/etl/load_refine_patterns.py
"""
import logging
import os
import sys

import httpx
import psycopg2
import psycopg2.extras as ex
import yaml

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("load_refine_patterns")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
EMBEDDER_URL = os.environ.get("EMBEDDER_URL", "https://embedder:8030")
YAML_PATH = os.environ.get(
    "REFINE_PATTERNS_YAML", "/knowledge/refine_error_patterns.yaml")
SOURCE = "refine_error_pattern"


def _embed(texts):
    r = httpx.post(f"{EMBEDDER_URL.rstrip('/')}/embed",
                   json={"texts": texts}, timeout=180, verify=False)
    r.raise_for_status()
    vecs = r.json()["embeddings"]
    if len(vecs) != len(texts):
        raise RuntimeError(f"embedder returned {len(vecs)} for {len(texts)} texts")
    return vecs


def _ensure_table(cur):
    """Table carries the STRUCTURED triggers so the refine matcher doesn't
    re-parse YAML on every iter. The RAG embedding (title + body) lives in
    rag_documents like other knowledge; this table is the fast lookup."""
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.refine_error_patterns (
            id text PRIMARY KEY,
            title text NOT NULL,
            guidance text NOT NULL,
            triggers jsonb NOT NULL,
            source text NOT NULL DEFAULT 'yaml',  -- 'yaml' | 'learned'
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now(),
            approved_by text,
            approved_at timestamptz
        )
    """)


def main():
    with open(YAML_PATH) as f:
        doc = yaml.safe_load(f) or {}
    patterns = doc.get("patterns") or []
    if not patterns:
        log.error("no patterns in %s", YAML_PATH)
        return 1

    docs = []  # (title, embed-body) for rag_documents
    rows = []  # (id, title, guidance, triggers_json) for refine_error_patterns
    for p in patterns:
        pid = p.get("id")
        title = p.get("title") or pid
        guidance = (p.get("guidance") or "").strip()
        triggers = p.get("triggers") or {}
        if not pid or not guidance:
            log.warning("skipping malformed pattern: %r", p)
            continue
        # RAG document: title + guidance so the planner's semantic search can
        # retrieve the pattern by error signal in natural language.
        docs.append((f"Refine fix: {title}", guidance))
        rows.append((pid, title, guidance, ex.Json(triggers)))

    vectors = _embed([f"{t}\n{x}" for t, x in docs])

    conn = psycopg2.connect(DB_DSN)
    try:
        cur = conn.cursor()
        _ensure_table(cur)
        # Wipe source='yaml' only — operator-approved learned patterns are
        # kept across reloads (source='learned', approved_by not null).
        cur.execute("DELETE FROM public.refine_error_patterns WHERE source = 'yaml'")
        cur.execute("DELETE FROM public.rag_documents WHERE metadata->>'source' = %s",
                    (SOURCE,))
        # Insert into refine_error_patterns
        ex.execute_values(
            cur,
            "INSERT INTO public.refine_error_patterns "
            "(id, title, guidance, triggers, source) VALUES %s "
            "ON CONFLICT (id) DO UPDATE SET "
            " title = EXCLUDED.title, guidance = EXCLUDED.guidance, "
            " triggers = EXCLUDED.triggers, updated_at = now()",
            [(pid, title, guidance, trig, "yaml") for pid, title, guidance, trig in rows]
        )
        # Insert into rag_documents for semantic retrieval
        embed_rows = []
        for (title, text), vec in zip(docs, vectors):
            vec_str = "[" + ",".join(repr(float(x)) for x in vec) + "]"
            embed_rows.append(
                (title, text,
                 ex.Json({"source": SOURCE, "kind": "refine_pattern"}),
                 vec_str))
        ex.execute_values(
            cur,
            "INSERT INTO rag_documents (title, text_chunk, metadata, embedding) "
            "VALUES %s",
            embed_rows, template="(%s, %s, %s, %s::vector)")
        conn.commit()
    finally:
        conn.close()
    log.info("loaded %d refine-error patterns (YAML)", len(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
