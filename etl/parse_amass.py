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

def _ensure_asset(cur, ip_str):
    """Find or create an asset by IP, return asset_id or None."""
    try:
        ip = str(ipaddress.ip_address(ip_str))
    except ValueError:
        return None
    cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
    row = cur.fetchone()
    if row:
        asset_id = str(row["id"])
        cur.execute("UPDATE assets SET updated_at=now() WHERE id=%s", (asset_id,))
        return asset_id
    asset_id = str(uuid.uuid4())
    cur.execute("INSERT INTO assets (id, ip) VALUES (%s,%s)", (asset_id, ip))
    return asset_id

def parse_amass(path: str, profile: str = "upload", job_id: str = None):
    """Parse Amass JSON output and store subdomains in recon_findings.

    Amass JSON format (one per line):
    {"name": "sub.example.com", "domain": "example.com", "addresses": [{"ip": "1.2.3.4", "cidr": "1.2.3.0/24", "asn": 12345}], "tag": "dns", "sources": ["DNS"]}
    """
    stats = dict(records_seen=0, assets_upserted=0, recon_findings_inserted=0, skipped=0, errors=0, error_examples=[])
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
                    name = rec.get("name", "").strip()
                    if not name:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    domain = rec.get("domain", "")
                    addresses = rec.get("addresses") or []
                    sources = rec.get("sources") or []
                    tag = rec.get("tag", "")

                    # Link to asset by first resolved IP
                    asset_id = None
                    for addr in addresses:
                        ip_str = addr.get("ip", "")
                        if ip_str:
                            asset_id = _ensure_asset(cur, ip_str)
                            if asset_id:
                                stats["assets_upserted"] += 1
                                break

                    data = {
                        "name": name,
                        "domain": domain,
                        "addresses": addresses,
                        "tag": tag,
                        "sources": sources,
                    }

                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'amass', 'subdomain', %s, %s, 'info')
                        ON CONFLICT DO NOTHING
                    """, (str(uuid.uuid4()), asset_id, name, Json(data)))
                    if cur.rowcount > 0:
                        stats["recon_findings_inserted"] += 1

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
