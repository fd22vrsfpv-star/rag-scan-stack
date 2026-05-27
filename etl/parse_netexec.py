import os, json, uuid, re, ipaddress
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

# NetExec output markers
SUCCESS_RE = re.compile(r'^\[[\+\*]\]\s+(.+)')
FAILURE_RE = re.compile(r'^\[\-\]\s+(.+)')
# e.g. SMB  192.168.1.100  445  DC01  [+] domain\user:password (Pwn3d!)
CRED_SUCCESS_RE = re.compile(
    r'(\S+)\s+'          # protocol
    r'(\d+\.\d+\.\d+\.\d+)\s+'  # IP
    r'(\d+)\s+'          # port
    r'(\S+)\s+'          # hostname
    r'\[\+\]\s+'         # success marker
    r'(\S+?)\\(\S+?):(\S+)'     # domain\user:password or hash
)
PWNED_RE = re.compile(r'\(Pwn3d!\)', re.IGNORECASE)

def parse_netexec(path: str, profile: str = "upload", job_id: str = None):
    r"""Parse NetExec log output.

    NetExec output format (line-based):
    SMB  192.168.1.100  445  DC01  [+] DOMAIN\admin:Password123 (Pwn3d!)
    SMB  192.168.1.100  445  DC01  [-] DOMAIN\user:wrongpass STATUS_LOGON_FAILURE
    SMB  192.168.1.100  445  DC01  [*] Windows Server 2019
    """
    stats = dict(records_seen=0, assets_upserted=0, recon_findings_inserted=0,
                 credential_successes=0, skipped=0, errors=0, error_examples=[])

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
                    # Try to parse credential success lines
                    m = CRED_SUCCESS_RE.search(line)
                    if m:
                        protocol = m.group(1).lower()
                        ip = m.group(2)
                        port = int(m.group(3))
                        host_name = m.group(4)
                        domain = m.group(5)
                        username = m.group(6)
                        secret = m.group(7)
                        pwned = bool(PWNED_RE.search(line))

                        asset_id = _ensure_asset(cur, ip)
                        if asset_id:
                            stats["assets_upserted"] += 1

                        data = {
                            "protocol": protocol,
                            "ip": ip,
                            "port": port,
                            "hostname": host_name,
                            "domain": domain,
                            "username": username,
                            "pwned": pwned,
                            "raw_line": line,
                        }

                        severity = "critical" if pwned else "high"
                        finding_type = "credential_valid"

                        cur.execute("""
                            INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                            VALUES (%s, %s, 'netexec', %s, %s, %s, %s)
                            ON CONFLICT DO NOTHING
                        """, (str(uuid.uuid4()), asset_id, finding_type, ip, Json(data), severity))
                        if cur.rowcount > 0:
                            stats["recon_findings_inserted"] += 1
                            stats["credential_successes"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    # Parse informational/enumeration lines
                    sm = SUCCESS_RE.match(line)
                    if sm:
                        # Extract IP if present
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        asset_id = None
                        target = ""
                        if ip_match:
                            target = ip_match.group(1)
                            asset_id = _ensure_asset(cur, target)
                            if asset_id:
                                stats["assets_upserted"] += 1

                        data = {"raw_line": line}
                        cur.execute("""
                            INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                            VALUES (%s, %s, 'netexec', 'enumeration', %s, %s, 'info')
                            ON CONFLICT DO NOTHING
                        """, (str(uuid.uuid4()), asset_id, target, Json(data)))
                        if cur.rowcount > 0:
                            stats["recon_findings_inserted"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    # Failure lines — skip (not interesting for findings)
                    if FAILURE_RE.match(line):
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    stats["skipped"] += 1
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
