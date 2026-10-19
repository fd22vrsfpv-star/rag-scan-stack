import os, glob, json
from sentence_transformers import SentenceTransformer
import psycopg2
from psycopg2.extras import Json
from etl.parse_nmap import parse_nmap
from etl.parse_nessus import parse_nessus
from etl.parse_nuclei import parse_nuclei
from etl.parse_burp import parse_burp

# `from etl.db import get_conn` — there is no etl/db.py, and there never has
# been, so this module raised ModuleNotFoundError on import and the findings
# backfill has never once run. Every other ETL module opens its own connection
# with psycopg2.connect(DB_DSN); do the same.
DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

MODEL_NAME = os.environ.get("EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")

def embed_chunks(model, text, step=3000):
    parts = [text[i:i+step] for i in range(0, len(text), step)] or ['']
    embs = model.encode(parts, normalize_embeddings=True)
    return list(zip(parts, embs))

def backfill_findings_into_rag(limit=5000):
    """Embed recent findings into rag_documents.

    rag_documents lives in the `scans` database (db_init/ensure_all_tables.sql).
    It used to be declared in the `n8n` database while this function connected
    to `scans`, so the INSERT below could only ever fail — on the rare occasion
    the import let it get this far.

    Re-runnable, but NOT idempotent: it appends chunks for the findings it sees,
    so running it twice doubles them. Delete by finding_id first if that
    matters.
    """
    model = SentenceTransformer(MODEL_NAME)
    # 2026-10-17: autocommit (below) already bounds each INSERT to its own
    # transaction, so this loop never held one across the embedding calls. What
    # was missing were the session caps every other DB writer carries
    # (etl/access.py::_connect): fail the connect fast rather than hanging on an
    # unreachable Postgres, and let the server kill this session if it ever does
    # go idle in a transaction or queue behind a lock — which is what turned a
    # slow writer into a stalled reader for everyone during the
    # four-hour-transaction incident.
    with psycopg2.connect(
        DB_DSN, connect_timeout=5,
        options="-c idle_in_transaction_session_timeout=120000 -c lock_timeout=5000",
    ) as conn:
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute("SELECT f.id, f.title, f.description, f.evidence, f.severity, f.asset_id FROM findings f ORDER BY f.observed_at DESC LIMIT %s", (limit,))
        rows = cur.fetchall()
        for fid, title, desc, evidence, sev, asset_id in rows:
            body = (desc or '') + "\n\nEVIDENCE:\n" + json.dumps(evidence or {}, ensure_ascii=False)
            for text, emb in embed_chunks(model, body):
                cur.execute(
                    """
                    INSERT INTO rag_documents (asset_id, finding_id, title, text_chunk, metadata, embedding)
                    VALUES (%s,%s,%s,%s,%s,%s)
                    """ ,
                    (asset_id, fid, title, text, Json({'severity': sev, 'source':'findings'}), emb.tolist())
                )

def main():
    in_dir = os.environ.get("INGEST_DIR", "./ingest_in")
    os.makedirs(in_dir, exist_ok=True)

    for path in glob.glob(os.path.join(in_dir, "*.xml")):
        try:
            parse_nmap(path, profile='default')
        except Exception:
            try:
                parse_burp(path, profile='default')
            except Exception:
                pass

    for path in glob.glob(os.path.join(in_dir, "*.nessus")):
        parse_nessus(path, profile='default')

    for path in glob.glob(os.path.join(in_dir, "*.jsonl")):
        parse_nuclei(path, profile='default')

    backfill_findings_into_rag()
    print("ETL complete. Findings embedded into rag_documents.")

if __name__ == "__main__":
    main()
