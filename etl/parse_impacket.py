import os, json, uuid, re
import psycopg2
from psycopg2.extras import RealDictCursor, Json
import ipaddress

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

# secretsdump: user:rid:lmhash:nthash:::
SECRETSDUMP_RE = re.compile(r'^(.+?):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::$')

# GetUserSPNs / GetNPUsers: $krb5tgs$ or $krb5asrep$ hashes
KERBEROAST_RE = re.compile(r'(\$krb5tgs\$\d+\$\*?[^$]+\$[^$]+\$[^$]+\$[a-fA-F0-9]+)')
ASREPROAST_RE = re.compile(r'(\$krb5asrep\$\d+\$[^:]+:[a-fA-F0-9]+)')

def parse_impacket(path: str, tool: str = "secretsdump", target: str = "", profile: str = "upload", job_id: str = None):
    """Parse Impacket tool output based on the tool type.

    Supported tools:
    - secretsdump: Parse NTLM hashes (user:rid:lmhash:nthash:::)
    - GetUserSPNs: Parse Kerberoast TGS tickets ($krb5tgs$)
    - GetNPUsers: Parse AS-REP roast hashes ($krb5asrep$)
    - Other: Store raw output as recon finding
    """
    stats = dict(records_seen=0, assets_upserted=0, recon_findings_inserted=0, skipped=0, errors=0, error_examples=[])

    lines = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                lines.append(line)
    stats["records_seen"] = len(lines)
    if not lines:
        return stats

    # Try to link to asset from target
    asset_id_for_target = None

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Resolve target to asset
            if target:
                asset_id_for_target = _ensure_asset(cur, target)
                if asset_id_for_target:
                    stats["assets_upserted"] += 1

            if tool == "secretsdump":
                _parse_secretsdump(cur, lines, asset_id_for_target, target, stats)
            elif tool in ("GetUserSPNs", "getUserSPNs"):
                _parse_kerberoast(cur, lines, asset_id_for_target, target, stats)
            elif tool in ("GetNPUsers", "getNPUsers"):
                _parse_asreproast(cur, lines, asset_id_for_target, target, stats)
            else:
                _parse_generic(cur, lines, tool, asset_id_for_target, target, stats)

            conn.commit()
    finally:
        conn.close()
    return stats


def _parse_secretsdump(cur, lines, asset_id, target, stats):
    """Parse secretsdump NTLM hash output."""
    for line in lines:
        try:
            cur.execute("SAVEPOINT rec_sp")
            m = SECRETSDUMP_RE.match(line)
            if not m:
                stats["skipped"] += 1
                cur.execute("RELEASE SAVEPOINT rec_sp")
                continue

            username = m.group(1)
            rid = m.group(2)
            lm_hash = m.group(3)
            nt_hash = m.group(4)

            # Skip machine accounts with empty hashes
            if nt_hash == "31d6cfe0d16ae931b73c59d7e0c089c0" and username.endswith("$"):
                stats["skipped"] += 1
                cur.execute("RELEASE SAVEPOINT rec_sp")
                continue

            data = {
                "username": username,
                "rid": rid,
                "lm_hash": lm_hash,
                "nt_hash": nt_hash,
                "secret_type": "ntlm_hash",
                "target": target,
            }

            cur.execute("""
                INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                VALUES (%s, %s, 'impacket', 'credential_hash', %s, %s, 'critical')
                ON CONFLICT DO NOTHING
            """, (str(uuid.uuid4()), asset_id, target, Json(data)))
            if cur.rowcount > 0:
                stats["recon_findings_inserted"] += 1

            cur.execute("RELEASE SAVEPOINT rec_sp")
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
            stats["errors"] += 1
            if len(stats["error_examples"]) < 5:
                stats["error_examples"].append(f"{type(e).__name__}: {e}")


def _parse_kerberoast(cur, lines, asset_id, target, stats):
    """Parse GetUserSPNs Kerberoast output."""
    full_text = "\n".join(lines)
    matches = KERBEROAST_RE.findall(full_text)
    for ticket in matches:
        try:
            cur.execute("SAVEPOINT rec_sp")
            # Extract SPN name from ticket string
            spn_match = re.search(r'\$krb5tgs\$\d+\$\*?([^$]+)\$', ticket)
            spn_name = spn_match.group(1) if spn_match else "unknown"

            data = {
                "spn": spn_name,
                "secret_type": "kerberos_ticket",
                "ticket_type": "krb5tgs",
                "hash_length": len(ticket),
                "target": target,
            }

            cur.execute("""
                INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                VALUES (%s, %s, 'impacket', 'credential_hash', %s, %s, 'high')
                ON CONFLICT DO NOTHING
            """, (str(uuid.uuid4()), asset_id, target, Json(data)))
            if cur.rowcount > 0:
                stats["recon_findings_inserted"] += 1

            cur.execute("RELEASE SAVEPOINT rec_sp")
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
            stats["errors"] += 1
            if len(stats["error_examples"]) < 5:
                stats["error_examples"].append(f"{type(e).__name__}: {e}")


def _parse_asreproast(cur, lines, asset_id, target, stats):
    """Parse GetNPUsers AS-REP roast output."""
    full_text = "\n".join(lines)
    matches = ASREPROAST_RE.findall(full_text)
    for ticket in matches:
        try:
            cur.execute("SAVEPOINT rec_sp")
            # Extract username from ticket string
            user_match = re.search(r'\$krb5asrep\$\d+\$([^:]+):', ticket)
            username = user_match.group(1) if user_match else "unknown"

            data = {
                "username": username,
                "secret_type": "kerberos_ticket",
                "ticket_type": "krb5asrep",
                "hash_length": len(ticket),
                "target": target,
            }

            cur.execute("""
                INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                VALUES (%s, %s, 'impacket', 'credential_hash', %s, %s, 'high')
                ON CONFLICT DO NOTHING
            """, (str(uuid.uuid4()), asset_id, target, Json(data)))
            if cur.rowcount > 0:
                stats["recon_findings_inserted"] += 1

            cur.execute("RELEASE SAVEPOINT rec_sp")
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
            stats["errors"] += 1
            if len(stats["error_examples"]) < 5:
                stats["error_examples"].append(f"{type(e).__name__}: {e}")


def _parse_generic(cur, lines, tool, asset_id, target, stats):
    """Store raw Impacket output as a single recon finding."""
    output = "\n".join(lines[:200])  # Cap at 200 lines
    data = {
        "tool": tool,
        "output": output,
        "line_count": len(lines),
        "target": target,
    }

    cur.execute("""
        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
        VALUES (%s, %s, 'impacket', 'tool_output', %s, %s, 'info')
        ON CONFLICT DO NOTHING
    """, (str(uuid.uuid4()), asset_id, target, Json(data)))
    if cur.rowcount > 0:
        stats["recon_findings_inserted"] += 1
