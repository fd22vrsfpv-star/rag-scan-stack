import os, json, uuid, ipaddress
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor

try:
    from _provider_detect import tag_asset as _tag_provider
except ImportError:
    from etl._provider_detect import tag_asset as _tag_provider

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

def parse_tlsx(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, expired_certs=0, self_signed_certs=0, skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    host = rec.get("host")
                    if not host:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue
                    # Look up asset — only query ip column if host is a valid IP
                    try:
                        ipaddress.ip_address(host)
                        cur.execute("SELECT id FROM assets WHERE ip = %s OR hostname = %s", (host, host))
                    except ValueError:
                        cur.execute("SELECT id FROM assets WHERE hostname = %s", (host,))
                    row = cur.fetchone()
                    asset_id = str(row["id"]) if row else None
                    # Determine severity
                    severity = "info"
                    is_expired = False
                    is_self_signed = False
                    # Check expiration
                    not_after = rec.get("not_after")
                    if not_after:
                        try:
                            expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
                            if expiry < datetime.now(expiry.tzinfo):
                                severity = "medium"
                                is_expired = True
                                stats["expired_certs"] += 1
                        except:
                            pass
                    # Check self-signed (issuer == subject)
                    issuer = rec.get("issuer", "")
                    subject_cn = rec.get("subject_cn", "")
                    if issuer and subject_cn and issuer == subject_cn:
                        severity = "medium"
                        is_self_signed = True
                        stats["self_signed_certs"] += 1
                    # Build metadata
                    metadata = {
                        "subject_cn": rec.get("subject_cn"),
                        "subject_an": rec.get("subject_an", []),
                        "issuer": rec.get("issuer"),
                        "not_before": rec.get("not_before"),
                        "not_after": rec.get("not_after"),
                        "serial": rec.get("serial"),
                        "is_expired": is_expired,
                        "is_self_signed": is_self_signed,
                        "port": rec.get("port")
                    }
                    if job_id:
                        metadata["job_id"] = job_id
                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'tlsx', 'tls_cert', %s, %s, %s)
                    """, (str(uuid.uuid4()), asset_id, host, json.dumps(metadata), severity))
                    stats["findings_inserted"] += 1
                    # Tag asset provider from cert evidence — issuer / subject CN
                    # / SAN list often reveal Amazon-issued or Microsoft-issued
                    # certs even when the hostname doesn't.
                    if asset_id:
                        san_blob = " ".join(metadata.get("subject_an") or [])
                        _tag_provider(cur, asset_id,
                                      " ".join([metadata.get("issuer") or "",
                                                metadata.get("subject_cn") or "",
                                                san_blob]))
                    cur.execute("RELEASE SAVEPOINT rec_sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5: stats["error_examples"].append(f"{type(e).__name__}: {e}")
            conn.commit()
    finally:
        conn.close()
    return stats
