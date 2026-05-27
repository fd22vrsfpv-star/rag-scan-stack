import os, json, logging
import psycopg2
from psycopg2.extras import Json, RealDictCursor

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
log = logging.getLogger(__name__)


def _load_jsonl(path):
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return results


def parse_cvemap(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, cves_upserted=0, vulns_updated=0, skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path)
    stats["records_seen"] = len(records)
    if not records:
        return stats

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    cve_id = rec.get("cve_id", "").strip()
                    if not cve_id:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    summary = rec.get("cve_description", "") or ""
                    cvss = rec.get("cvss_score") or rec.get("cvss")
                    published = rec.get("published_at")
                    refs_list = rec.get("references") or []
                    refs = Json(refs_list) if refs_list else Json([])

                    cur.execute("""
                        INSERT INTO cve (id, summary, cvss, published, refs, last_modified)
                        VALUES (%s, %s, %s, %s, %s, now())
                        ON CONFLICT (id) DO UPDATE SET
                            summary = EXCLUDED.summary,
                            cvss = EXCLUDED.cvss,
                            refs = EXCLUDED.refs,
                            last_modified = now()
                    """, (cve_id, summary, cvss, published, refs))
                    stats["cves_upserted"] += 1

                    # Cross-reference: update vulns that reference this CVE but lack CVSS
                    if cvss is not None:
                        cur.execute("""
                            UPDATE vulns SET cvss = %s, updated_at = now()
                            WHERE %s = ANY(cve) AND cvss IS NULL
                        """, (cvss, cve_id))
                        stats["vulns_updated"] += cur.rowcount

                    cur.execute("RELEASE SAVEPOINT rec_sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5:
                        stats["error_examples"].append(f"{type(e).__name__}: {e}")

            conn.commit()
    finally:
        conn.close()

    log.info(f"[cvemap] Parsed {stats['records_seen']} records, upserted {stats['cves_upserted']} CVEs, "
             f"updated {stats['vulns_updated']} vulns")
    return stats
