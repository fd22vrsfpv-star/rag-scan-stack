import os, json, uuid, ipaddress
from datetime import datetime
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

def parse_crtsh(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, expired_certs=0, wildcard_certs=0, skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    common_name = rec.get("common_name", "").strip()
                    if not common_name:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    # Look up asset by common_name — only query ip column if it's a valid IP
                    try:
                        ipaddress.ip_address(common_name)
                        cur.execute("SELECT id FROM assets WHERE ip = %s OR hostname = %s", (common_name, common_name))
                    except ValueError:
                        cur.execute("SELECT id FROM assets WHERE hostname = %s", (common_name,))
                    row = cur.fetchone()
                    asset_id = str(row["id"]) if row else None

                    # Determine severity
                    severity = "info"
                    is_expired = False
                    is_wildcard = common_name.startswith("*.")

                    if is_wildcard:
                        severity = "low"
                        stats["wildcard_certs"] += 1

                    # Check expiration
                    not_after = rec.get("not_after")
                    if not_after:
                        try:
                            expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                            if expiry < datetime.now(expiry.tzinfo):
                                severity = "medium"
                                is_expired = True
                                stats["expired_certs"] += 1
                        except Exception:
                            pass

                    # Build target from queried domain or common_name
                    target = rec.get("queried_domain", common_name)

                    # Build metadata
                    metadata = {
                        "common_name": common_name,
                        "name_value": rec.get("name_value", ""),
                        "issuer_name": rec.get("issuer_name", ""),
                        "not_before": rec.get("not_before"),
                        "not_after": not_after,
                        "serial_number": rec.get("serial_number", ""),
                        "is_expired": is_expired,
                        "is_wildcard": is_wildcard,
                        "entry_timestamp": rec.get("entry_timestamp", ""),
                    }
                    if job_id:
                        metadata["job_id"] = job_id

                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'crtsh', 'ct_cert', %s, %s, %s)
                    """, (str(uuid.uuid4()), asset_id, target, json.dumps(metadata), severity))
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
