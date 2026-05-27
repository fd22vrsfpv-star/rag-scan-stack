import os, json, uuid, ipaddress
from urllib.parse import urlparse
import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

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

def parse_gau(path: str, source: str = "gau", profile: str = "upload", job_id: str = None):
    """Parse GAU / Waybackurls plain-text URL output.

    Input: one URL per line (plain text).
    Stores unique URLs in recon_findings with finding_type='historical_url'.
    The `source` param allows reuse for both gau and waybackurls.
    """
    stats = dict(records_seen=0, assets_upserted=0, recon_findings_inserted=0, skipped=0, duplicates=0, errors=0, error_examples=[])

    urls = set()
    with open(path) as f:
        for line in f:
            url = line.strip()
            if url:
                stats["records_seen"] += 1
                urls.add(url)

    stats["duplicates"] = stats["records_seen"] - len(urls)
    if not urls:
        return stats

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for url in urls:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    parsed = urlparse(url)
                    hostname = parsed.hostname or ""
                    if not hostname:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    # Try to link to asset by hostname (if it's an IP)
                    asset_id = None
                    try:
                        asset_id = _ensure_asset(cur, hostname)
                        if asset_id:
                            stats["assets_upserted"] += 1
                    except ValueError:
                        pass

                    # If hostname isn't an IP, try to find asset by hostname field
                    if not asset_id:
                        cur.execute("SELECT id FROM assets WHERE hostname = %s", (hostname,))
                        row = cur.fetchone()
                        if row:
                            asset_id = str(row["id"])

                    data = {
                        "url": url,
                        "hostname": hostname,
                        "path": parsed.path,
                        "scheme": parsed.scheme,
                        "query": parsed.query or None,
                    }

                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, %s, 'historical_url', %s, %s, 'info')
                        ON CONFLICT DO NOTHING
                    """, (str(uuid.uuid4()), asset_id, source, hostname, Json(data)))
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
