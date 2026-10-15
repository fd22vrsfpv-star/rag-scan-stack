#!/usr/bin/env python3
"""Embed knowledge/gap_tools.yaml into rag_documents.

CLAUDE.md: "Every knowledge/*.yaml that defines scans or actions MUST have an
idempotent loader that embeds it into rag_documents, run on change... A file
that is read deterministically but never embedded is retrievable by nobody."

gap_tools.yaml defines actions — tools build-poc may run to answer a gap — so
it needs to be recallable, not only read by the resolver. One document per
tool, phrased as the question it answers ("how do I obtain <gap>"), because
that is the form `_solutions_for_gaps` searches with.

Idempotent: deletes this source's rows and reinserts, so re-running after an
edit replaces rather than duplicates.

    python3 etl/load_gap_tools.py
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

import yaml

# psycopg2 is imported inside main(), not at module scope, so `load_specs` and
# `as_documents` — which are pure and are what the tests exercise — can be
# imported anywhere. The test container has yaml but no database driver, and a
# module-level import made the whole validation suite skip rather than run.

log = logging.getLogger("load_gap_tools")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

SOURCE = "gap_tools"
REPO = Path(__file__).resolve().parents[1]


def _find_yaml() -> Path:
    """knowledge/ is bind-mounted at a different place in each container.

    In the repo it is ./knowledge; inside rag-api the mount is /knowledge, NOT
    /app/knowledge — deriving it from this file's location gives the wrong
    answer there and the loader dies with FileNotFoundError. Try the known
    locations in order and let GAP_TOOLS_YAML override.
    """
    env = os.environ.get("GAP_TOOLS_YAML")
    if env:
        return Path(env)
    for cand in (REPO / "knowledge" / "gap_tools.yaml",
                 Path("/knowledge/gap_tools.yaml"),
                 Path("knowledge/gap_tools.yaml")):
        if cand.is_file():
            return cand
    # Nothing found: return the repo-relative path so the error names the
    # location a reader expects rather than the last candidate tried.
    return REPO / "knowledge" / "gap_tools.yaml"


YAML_PATH = _find_yaml()
DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
EMBEDDER_URL = os.environ.get("EMBEDDER_URL", "http://embedder:8080")


def load_specs(path: Path = None) -> list:
    """The tool entries, validated. Raises on a malformed file rather than
    loading half of it — a partially embedded vocabulary is worse than none,
    because the gap it silently cannot answer looks like a gap with no tool."""
    path = Path(path) if path else _find_yaml()
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    tools = doc.get("tools") or []
    required = ("id", "gaps", "yields", "command", "why")
    for t in tools:
        missing = [k for k in required if not t.get(k)]
        if missing:
            raise ValueError(f"gap_tools entry {t.get('id', '?')!r} missing {missing}")
        if not isinstance(t["gaps"], list):
            raise ValueError(f"gap_tools entry {t['id']!r}: `gaps` must be a list")
    ids = [t["id"] for t in tools]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate gap_tools ids: {sorted(dupes)}")
    return tools


def as_documents(tools: list) -> list:
    """(title, text) per tool, phrased as the question the planner asks."""
    docs = []
    for t in tools:
        gaps = ", ".join(t["gaps"])
        ind = t.get("indicators") or []
        body = (
            f"To obtain {gaps} for an exploit build, run the tool `{t['id']}`. "
            f"It yields {t['yields']}. Command template: {t['command']}. "
            f"{str(t.get('why') or '').strip()} "
            + (f"Only suggest this when one of these indicators is observed: "
               f"{', '.join(ind)}. " if ind else "")
            + (f"Estimated cost {t.get('cost')}s. " if t.get("cost") else "")
            + ("This tool is NOISY — prefer a quieter option first. "
               if t.get("noisy") else "")
            + ("This runs locally and sends no traffic to the target. "
               if t.get("local_only") else "")
        )
        docs.append((f"Gap tool: {t['id']} (answers {gaps})", " ".join(body.split())))
    return docs


def _embed(texts: list) -> list:
    import requests
    r = requests.post(f"{EMBEDDER_URL.rstrip('/')}/embed",
                      json={"texts": texts}, timeout=120)
    r.raise_for_status()
    data = r.json()
    return data.get("embeddings") or data.get("vectors") or data


def main() -> int:
    try:
        tools = load_specs()
    except Exception as e:  # noqa: BLE001
        log.error("gap_tools.yaml is not loadable: %s", e)
        return 1
    docs = as_documents(tools)
    if not docs:
        log.error("no gap-tool documents to load")
        return 1
    try:
        vectors = _embed([f"{t}\n{x}" for t, x in docs])
    except Exception as e:  # noqa: BLE001
        log.error("embedding failed (%s) — nothing loaded, so the previous "
                  "corpus is left intact rather than half-replaced", e)
        return 1
    import psycopg2
    import psycopg2.extras as ex
    conn = psycopg2.connect(DB_DSN)
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM rag_documents WHERE metadata->>'source' = %s", (SOURCE,))
        rows = []
        for (title, text), vec in zip(docs, vectors):
            vec_str = "[" + ",".join(repr(float(x)) for x in vec) + "]"
            rows.append((title, text,
                         ex.Json({"source": SOURCE, "kind": "gap_tool"}), vec_str))
        ex.execute_values(
            cur,
            "INSERT INTO rag_documents (title, text_chunk, metadata, embedding) VALUES %s",
            rows, template="(%s, %s, %s, %s::vector)")
        conn.commit()
        cur.close()
    finally:
        conn.close()
    log.info("loaded %d gap-tool documents", len(docs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
