import os, json, uuid
import psycopg2
from psycopg2.extras import RealDictCursor

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

def parse_naabu(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, assets_upserted=0, ports_inserted=0, ports_updated=0, skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    # naabu uses 'host' or 'ip' field
                    ip = rec.get("ip") or rec.get("host")
                    if not ip:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue
                    port = rec.get("port")
                    if port is None:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue
                    port = int(port)
                    proto = (rec.get("protocol") or rec.get("proto") or "tcp").lower()

                    # Upsert asset
                    cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
                    row = cur.fetchone()
                    if row:
                        asset_id = str(row["id"])
                        cur.execute("UPDATE assets SET updated_at=now() WHERE id=%s", (asset_id,))
                    else:
                        asset_id = str(uuid.uuid4())
                        cur.execute("INSERT INTO assets (id, ip) VALUES (%s,%s)", (asset_id, ip))
                        stats["assets_upserted"] += 1

                    # Upsert port
                    cur.execute("SELECT id FROM ports WHERE asset_id=%s AND proto=%s AND port=%s", (asset_id, proto, port))
                    prow = cur.fetchone()
                    if prow:
                        cur.execute("""
                            UPDATE ports
                            SET is_open=true,
                                updated_at=now()
                            WHERE id=%s
                        """, (prow["id"],))
                        stats["ports_updated"] += 1
                    else:
                        pid = str(uuid.uuid4())
                        cur.execute("""
                            INSERT INTO ports
                            (id, asset_id, proto, port, is_open)
                            VALUES (%s,%s,%s,%s,%s)
                        """, (pid, asset_id, proto, port, True))
                        stats["ports_inserted"] += 1
                    cur.execute("RELEASE SAVEPOINT rec_sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5:
                        stats["error_examples"].append(f"{type(e).__name__}: {e}")
            conn.commit()
    finally:
        conn.close()
    return stats
