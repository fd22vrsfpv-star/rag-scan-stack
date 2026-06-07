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

VALID_SECRET_TYPES = {"password", "aws_key", "azure_key", "ssh_key", "api_token", "ntlm_hash", "kerberos_ticket", "certificate", "other"}

def parse_brutus(path: str, profile: str = "upload", job_id: str = None, secret_type: str = "password"):
    if secret_type not in VALID_SECRET_TYPES:
        secret_type = "password"
    stats = dict(records_seen=0, credentials_found=0, skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    ip = rec.get("host") or rec.get("ip")
                    port = rec.get("port")
                    protocol = rec.get("protocol", "unknown")
                    username = rec.get("username", "")
                    success = rec.get("success", False)
                    if not ip or not port or not success:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue
                    # Look up asset
                    cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
                    row = cur.fetchone()
                    asset_id = str(row["id"]) if row else None
                    # Look up port
                    port_id = None
                    if asset_id:
                        cur.execute("SELECT id FROM ports WHERE asset_id=%s AND port=%s", (asset_id, int(port)))
                        prow = cur.fetchone()
                        if prow: port_id = str(prow["id"])
                    # Insert - do NOT store password.
                    # Metadata captures the audit trail when present:
                    #   - job_id : ties row back to the scan
                    #   - audit  : per-attempt list (users tried, passwords
                    #              masked, failure modes, KEX-legacy detection,
                    #              summary).  Populated by the credential-check
                    #              path (nmap_scanner/cred_checker.py).
                    #              Optional -- the brutus runner JSONL omits
                    #              it, in which case the row just has no
                    #              audit panel in the UI.
                    meta = {}
                    if job_id:
                        meta["job_id"] = job_id
                    rec_audit = rec.get("audit")
                    if rec_audit:
                        meta["audit"] = rec_audit
                    cur.execute("""
                        INSERT INTO credential_findings (id, asset_id, port_id, ip, port, protocol, username, valid_cred, auth_type, secret_type, source, metadata, discovered_at, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, true, %s, %s, 'brutus', %s, now(), 'valid')
                    """, (str(uuid.uuid4()), asset_id, port_id, ip, int(port), protocol, username,
                          secret_type, secret_type, json.dumps(meta)))
                    stats["credentials_found"] += 1
                    cur.execute("RELEASE SAVEPOINT rec_sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5: stats["error_examples"].append(f"{type(e).__name__}: {e}")
            conn.commit()
    finally:
        conn.close()
    return stats
