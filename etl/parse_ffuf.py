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

def parse_ffuf(path: str, profile: str = "upload", job_id: str = None):
    """Parse ffuf JSON output and store discovered paths in recon_findings.

    ffuf JSON format:
    {
      "commandline": "ffuf -u http://target/FUZZ ...",
      "results": [
        {"input": {"FUZZ": "admin"}, "position": 1, "status": 200,
         "length": 1234, "words": 56, "lines": 12, "content-type": "text/html",
         "redirectlocation": "", "url": "http://target/admin", "host": "target"}
      ]
    }
    """
    stats = dict(records_seen=0, assets_upserted=0, recon_findings_inserted=0, skipped=0, errors=0, error_examples=[])

    try:
        with open(path) as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        stats["errors"] = 1
        stats["error_examples"] = [f"Failed to load file: {e}"]
        return stats

    results = raw.get("results", [])
    stats["records_seen"] = len(results)
    if not results:
        return stats

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in results:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    url = rec.get("url", "")
                    status_code = rec.get("status", 0)
                    if not url:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    parsed = urlparse(url)
                    hostname = parsed.hostname or ""

                    # Try to link to asset
                    asset_id = None
                    if hostname:
                        try:
                            asset_id = _ensure_asset(cur, hostname)
                            if asset_id:
                                stats["assets_upserted"] += 1
                        except ValueError:
                            pass
                        if not asset_id:
                            cur.execute("SELECT id FROM assets WHERE hostname = %s", (hostname,))
                            row = cur.fetchone()
                            if row:
                                asset_id = str(row["id"])

                    fuzz_input = rec.get("input", {})
                    data = {
                        "url": url,
                        "status": status_code,
                        "length": rec.get("length", 0),
                        "words": rec.get("words", 0),
                        "lines": rec.get("lines", 0),
                        "content_type": rec.get("content-type", ""),
                        "redirect": rec.get("redirectlocation", ""),
                        "input": fuzz_input,
                        "host": rec.get("host", hostname),
                    }

                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'ffuf', 'web_path', %s, %s, 'info')
                        ON CONFLICT DO NOTHING
                    """, (str(uuid.uuid4()), asset_id, hostname, Json(data)))
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
