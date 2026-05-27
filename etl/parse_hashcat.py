import os, json, uuid
import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

def parse_hashcat(path: str, hash_type: str = "unknown", profile: str = "upload", job_id: str = None):
    """Parse Hashcat output file (cracked hashes).

    Hashcat output format: one cracked result per line
    hash:plaintext

    For NTLM (mode 1000): nthash:plaintext
    For MD5 (mode 0): md5hash:plaintext
    For Kerberoast (mode 13100): $krb5tgs$...:plaintext
    """
    stats = dict(records_seen=0, recon_findings_inserted=0, skipped=0, errors=0, error_examples=[])

    lines = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(line)
    stats["records_seen"] = len(lines)
    if not lines:
        return stats

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for line in lines:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    # Split on last colon for hash:plaintext
                    # Use rsplit with maxsplit=1 since hashes can contain colons
                    parts = line.rsplit(":", 1)
                    if len(parts) != 2:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    hash_value = parts[0]
                    plaintext = parts[1]

                    if not hash_value or not plaintext:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    data = {
                        "hash_type": hash_type,
                        "cracked": True,
                        "hash_prefix": hash_value[:16] + "..." if len(hash_value) > 16 else hash_value,
                        "plaintext_length": len(plaintext),
                    }

                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, NULL, 'hashcat', 'cracked_hash', %s, %s, 'critical')
                        ON CONFLICT DO NOTHING
                    """, (str(uuid.uuid4()), hash_type, Json(data)))
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
