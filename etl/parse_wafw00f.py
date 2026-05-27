import os, json, uuid, ipaddress
from urllib.parse import urlparse
import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _load_json(path):
    """Load wafw00f JSON output (array of objects)."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def parse_wafw00f(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, skipped=0, errors=0, error_examples=[])
    records = _load_json(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    url = rec.get("url", "").strip()
                    if not url:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    detected = rec.get("detected", False)
                    firewall = rec.get("firewall", "").strip()
                    manufacturer = rec.get("manufacturer", "").strip()

                    # Extract host from URL
                    parsed = urlparse(url)
                    host = parsed.hostname or url

                    # Lookup asset_id by hostname or IP
                    asset_id = None
                    if host:
                        try:
                            ip_str = str(ipaddress.ip_address(host))
                            cur.execute("SELECT id FROM assets WHERE ip = %s OR hostname = %s", (ip_str, host))
                        except ValueError:
                            cur.execute("SELECT id FROM assets WHERE hostname = %s", (host,))
                        row = cur.fetchone()
                        if row: asset_id = str(row["id"])

                    # Build data payload
                    data = {"url": url, "detected": detected, "firewall": firewall, "manufacturer": manufacturer}

                    # Build evidence and name
                    if detected and firewall:
                        evidence = f"WAF Detected: {firewall}"
                        if manufacturer: evidence += f" ({manufacturer})"
                        name = f"WAF: {firewall}"
                    elif detected:
                        evidence = "WAF Detected (unknown type)"
                        name = "WAF: Unknown"
                    else:
                        evidence = "No WAF detected"
                        name = "No WAF"
                    severity = "info"

                    # Insert into recon_findings (OSINT Explorer)
                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'wafw00f', 'waf_detection', %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (str(uuid.uuid4()), asset_id, host, Json(data), severity))

                    # Insert into web_findings (Findings Explorer)
                    cur.execute("""
                        INSERT INTO web_findings (id, asset_id, url, source, evidence, refs, name, severity)
                        VALUES (%s, %s, %s, 'wafw00f', %s, %s, %s, %s)
                    """, (str(uuid.uuid4()), asset_id, url, evidence, Json(data), name, severity))

                    stats["findings_inserted"] += 1
                    cur.execute("RELEASE SAVEPOINT rec_sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5: stats["error_examples"].append(f"{type(e).__name__}: {e}")
            conn.commit()
    finally:
        conn.close()
    return stats
