import os, json, uuid, ipaddress
import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

def _load_jsonl(path):
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: results.append(json.loads(line))
            except json.JSONDecodeError: pass
    return results

def parse_subfinder(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, assets_upserted=0, recon_findings_inserted=0, skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    host = rec.get("host", "").strip()
                    if not host:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue
                    asset_id = None
                    try:
                        ip = str(ipaddress.ip_address(host))
                        cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
                        row = cur.fetchone()
                        if row:
                            asset_id = str(row["id"])
                            cur.execute("UPDATE assets SET updated_at=now() WHERE id=%s", (asset_id,))
                        else:
                            asset_id = str(uuid.uuid4())
                            cur.execute("INSERT INTO assets (id, ip) VALUES (%s,%s)", (asset_id, ip))
                            stats["assets_upserted"] += 1
                    except ValueError:
                        # It's a hostname — try to link to existing asset
                        cur.execute("SELECT id FROM assets WHERE hostname = %s", (host,))
                        row = cur.fetchone()
                        if row:
                            asset_id = str(row["id"])
                            cur.execute("UPDATE assets SET updated_at=now() WHERE id=%s", (asset_id,))
                        # else: leave asset_id=None; assets table requires ip NOT NULL

                    # Also insert into recon_findings for Burp export / dashboard
                    source_name = rec.get("source", "subfinder")
                    parent_domain = rec.get("input", "")
                    data = {"host": host, "source": source_name, "input": parent_domain}
                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'subfinder', 'subdomain', %s, %s, 'info')
                        ON CONFLICT DO NOTHING
                    """, (str(uuid.uuid4()), asset_id, host, Json(data)))
                    if cur.rowcount > 0:
                        stats["recon_findings_inserted"] += 1

                    cur.execute("RELEASE SAVEPOINT rec_sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5: stats["error_examples"].append(f"{type(e).__name__}: {e}")
            conn.commit()
    finally:
        conn.close()
    return stats
