"""Idempotent loader for knowledge/build_poc_research_patterns.yaml.

Embeds each pattern (title + guidance [+ recipe]) into rag_documents under
metadata.source='build_poc_research_pattern' so the planner / decomposed
extractor can recall it via /rag/knowledge/search, and mirrors the
structured `triggers` + `recipe` into build_poc_research_patterns so the
deterministic artifact gate can read them without re-parsing YAML.

Idempotent: wipes source='build_poc_research_pattern' then re-inserts.
Mirrors etl/load_refine_patterns.py. Added 2026-10-07.

    docker exec rag-api python3 /app/etl/load_research_patterns.py
"""
import json
import logging
import os

import httpx
import psycopg2
import psycopg2.extras as ex
import yaml

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("load_research_patterns")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
EMBEDDER_URL = os.environ.get("EMBEDDER_URL", "https://embedder:8030")
YAML_PATH = os.environ.get("RESEARCH_PATTERNS_YAML", "/knowledge/build_poc_research_patterns.yaml")
SOURCE = "build_poc_research_pattern"


def _embed(texts):
    r = httpx.post(f"{EMBEDDER_URL.rstrip('/')}/embed", json={"texts": texts}, timeout=180, verify=False)
    r.raise_for_status()
    vecs = r.json()["embeddings"]
    if len(vecs) != len(texts):
        raise RuntimeError(f"embedder returned {len(vecs)} for {len(texts)} texts")
    return vecs


def _ensure_table(cur):
    cur.execute("""
        CREATE TABLE IF NOT EXISTS public.build_poc_research_patterns (
            id text PRIMARY KEY,
            title text NOT NULL,
            guidance text NOT NULL,
            triggers jsonb NOT NULL DEFAULT '{}'::jsonb,
            recipe jsonb,
            source text NOT NULL DEFAULT 'yaml',
            created_at timestamptz NOT NULL DEFAULT now(),
            updated_at timestamptz NOT NULL DEFAULT now()
        )
    """)


def load(yaml_path: str = YAML_PATH) -> int:
    with open(yaml_path) as f:
        doc = yaml.safe_load(f) or {}
    patterns = doc.get("patterns") or []
    if not patterns:
        log.error("no patterns in %s", yaml_path)
        return 0
    docs, rows = [], []
    for p in patterns:
        pid, title = p.get("id"), p.get("title") or p.get("id")
        guidance = (p.get("guidance") or "").strip()
        if not pid or not guidance:
            log.warning("skipping malformed pattern: %r", p)
            continue
        recipe = p.get("recipe")
        body = guidance + (("\n\nRECIPE:\n" + json.dumps(recipe, indent=1)) if recipe else "")
        docs.append((f"Build-PoC research: {title}", body))
        rows.append((pid, title, guidance, ex.Json(p.get("triggers") or {}),
                     ex.Json(recipe) if recipe is not None else None))
    vectors = _embed([f"{t}\n{x}" for t, x in docs])
    conn = psycopg2.connect(DB_DSN)
    try:
        cur = conn.cursor()
        _ensure_table(cur)
        cur.execute("DELETE FROM public.build_poc_research_patterns WHERE source='yaml'")
        cur.execute("DELETE FROM public.rag_documents WHERE metadata->>'source' = %s", (SOURCE,))
        ex.execute_values(
            cur,
            "INSERT INTO public.build_poc_research_patterns (id, title, guidance, triggers, recipe, source) VALUES %s "
            "ON CONFLICT (id) DO UPDATE SET title=EXCLUDED.title, guidance=EXCLUDED.guidance, "
            "triggers=EXCLUDED.triggers, recipe=EXCLUDED.recipe, updated_at=now()",
            [(pid, t, g, trig, rec, "yaml") for pid, t, g, trig, rec in rows])
        embed_rows = []
        for (title, text), vec in zip(docs, vectors):
            vec_str = "[" + ",".join(repr(float(x)) for x in vec) + "]"
            embed_rows.append((title, text, ex.Json({"source": SOURCE, "kind": "research_pattern"}), vec_str))
        ex.execute_values(cur, "INSERT INTO rag_documents (title, text_chunk, metadata, embedding) VALUES %s",
                          embed_rows, template="(%s, %s, %s, %s::vector)")
        conn.commit()
        log.info("loaded %d research patterns (%d rag_documents)", len(rows), len(embed_rows))
        return len(rows)
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(0 if load() else 1)
