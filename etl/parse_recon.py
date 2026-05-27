import os, json, uuid, ipaddress
import psycopg2
from psycopg2.extras import RealDictCursor

try:
    from _provider_detect import tag_asset as _tag_provider
except ImportError:
    from etl._provider_detect import tag_asset as _tag_provider

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _is_ip(value: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(value.split("/")[0])
        return True
    except (ValueError, AttributeError):
        return False


def _load_jsonl(path):
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: results.append(json.loads(line))
            except json.JSONDecodeError: pass
    return results

def parse_recon(path: str, source: str = "recon", profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    # Savepoint so one bad record doesn't abort the whole tx
                    cur.execute("SAVEPOINT recon_rec")

                    # Determine finding type based on source and record content
                    finding_type = "unknown"
                    target = None

                    if source == "asnmap":
                        finding_type = "asn_mapping"
                        target = rec.get("input") or rec.get("ip") or rec.get("asn") or rec.get("as_number") or rec.get("org")
                    elif source == "uncover":
                        finding_type = "search_result"
                        target = rec.get("host") or rec.get("ip") or rec.get("url")
                    elif source == "cloudlist":
                        finding_type = "cloud_asset"
                        target = rec.get("hostname") or rec.get("ip") or rec.get("id")
                    else:
                        # Generic recon
                        target = rec.get("target") or rec.get("host") or rec.get("ip") or rec.get("hostname")
                        finding_type = rec.get("type", "generic_recon")

                    if not target:
                        cur.execute("RELEASE SAVEPOINT recon_rec")
                        stats["skipped"] += 1; continue

                    # Try to find matching asset — only query ip column with valid IPs
                    asset_id = None
                    if _is_ip(target):
                        cur.execute("SELECT id FROM assets WHERE ip = %s", (target,))
                        row = cur.fetchone()
                        asset_id = str(row["id"]) if row else None
                    else:
                        cur.execute("SELECT id FROM assets WHERE hostname = %s", (target,))
                        row = cur.fetchone()
                        asset_id = str(row["id"]) if row else None

                    # Build metadata
                    metadata = dict(rec)
                    if job_id:
                        metadata["job_id"] = job_id

                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, %s, %s, %s, %s, 'info')
                    """, (str(uuid.uuid4()), asset_id, source, finding_type, target, json.dumps(metadata)))
                    # Tag asset provider from asnmap org/ASN ("Amazon", "AS16509",
                    # "Microsoft Corporation", "Cloudflare, Inc.") and from
                    # cloudlist (already provider-keyed).
                    if asset_id and source in ("asnmap", "cloudlist", "uncover"):
                        signal = " ".join(str(v) for v in [
                            metadata.get("org"), metadata.get("as_number"),
                            metadata.get("asn"), metadata.get("provider"),
                            metadata.get("service"), metadata.get("hostname"),
                        ] if v)
                        _tag_provider(cur, asset_id, signal)
                    cur.execute("RELEASE SAVEPOINT recon_rec")
                    stats["findings_inserted"] += 1
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT recon_rec")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5: stats["error_examples"].append(f"{type(e).__name__}: {e}")
            conn.commit()
    finally:
        conn.close()
    return stats
