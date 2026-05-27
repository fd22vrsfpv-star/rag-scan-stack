import os, json, uuid, sys
import psycopg2
from psycopg2.extras import RealDictCursor

# Add ETL directory to Python path
sys.path.append('/app/etl')
from asset_utils import ensure_asset

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

def _load_masscan(path: str):
    with open(path, "r") as f:
        raw = f.read().strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, dict): data = [data]
        if not isinstance(data, list): raise ValueError("Unexpected JSON format")
        return data
    except (json.JSONDecodeError, ValueError):
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if not line: continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return items

def parse_masscan(path: str, profile: str = "upload"):
    stats = dict(records_seen=0, assets_upserted=0, ports_inserted=0, ports_updated=0, skipped=0, errors=0, error_examples=[])
    records = _load_masscan(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    ip = rec.get("ip") or rec.get("addr")
                    if not ip:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue
                    ports = rec.get("ports", []) or []
                    # Use standardized asset creation to prevent duplicates
                    asset_id = ensure_asset(cur, ip=ip)
                    stats["assets_upserted"] += 1
                    for p in ports:
                        port = p.get("port")
                        if port is None: stats["skipped"] += 1; continue
                        port = int(port)
                        proto = (p.get("proto") or "tcp").lower()
                        is_open = (p.get("status", "open").lower() == "open")
                        service = p.get("service"); product = p.get("product"); version = p.get("version"); banner = p.get("banner")
                        cur.execute("SELECT id FROM ports WHERE asset_id=%s AND proto=%s AND port=%s", (asset_id, proto, port))
                        prow = cur.fetchone()
                        if prow:
                            cur.execute("""
                                UPDATE ports
                                SET is_open=%s,
                                    service=COALESCE(%s, service),
                                    product=COALESCE(%s, product),
                                    version=COALESCE(%s, version),
                                    banner =COALESCE(%s, banner),
                                    updated_at=now()
                                WHERE id=%s
                            """, (is_open, service, product, version, banner, prow["id"]))
                            stats["ports_updated"] += 1
                        else:
                            pid = str(uuid.uuid4())
                            cur.execute("""
                                INSERT INTO ports
                                (id, asset_id, proto, port, service, product, version, banner, is_open)
                                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                            """, (pid, asset_id, proto, port, service, product, version, banner, is_open))
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
