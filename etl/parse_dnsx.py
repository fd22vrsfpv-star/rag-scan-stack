import os, json, uuid, ipaddress
import psycopg2
from psycopg2.extras import RealDictCursor

try:
    from _provider_detect import tag_asset as _tag_provider
except ImportError:  # pragma: no cover — etl/ may be on PYTHONPATH already
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

def _ensure_asset(cur, ip_str: str, hostname: str = None):
    """Create or find an asset by IP, optionally setting hostname. Returns asset_id."""
    cur.execute("SELECT id FROM assets WHERE ip = %s", (ip_str,))
    row = cur.fetchone()
    if row:
        asset_id = str(row["id"])
        if hostname:
            cur.execute("UPDATE assets SET hostname = COALESCE(hostname, %s), updated_at = now() WHERE id = %s",
                        (hostname, asset_id))
        return asset_id
    asset_id = str(uuid.uuid4())
    cur.execute("INSERT INTO assets (id, ip, hostname) VALUES (%s, %s, %s)",
                (asset_id, ip_str, hostname))
    return asset_id


def parse_dnsx(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, assets_linked=0, subfinder_updated=0,
                 skipped=0, errors=0, error_examples=[])
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

                    # If dnsx resolved A records, create/link asset from the first IP
                    asset_id = None
                    a_records = rec.get("a")
                    if a_records:
                        ips = a_records if isinstance(a_records, list) else [a_records]
                        first_ip = next((ip for ip in ips if ip), None)
                        if first_ip:
                            try:
                                ip_str = str(ipaddress.ip_address(first_ip))
                                asset_id = _ensure_asset(cur, ip_str, hostname=host)
                                stats["assets_linked"] += 1
                            except ValueError:
                                pass

                    # Fallback: look up asset by IP or hostname
                    if not asset_id:
                        try:
                            ip = str(ipaddress.ip_address(host))
                            cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
                            row = cur.fetchone()
                            if row: asset_id = str(row["id"])
                        except ValueError:
                            cur.execute("SELECT id FROM assets WHERE hostname = %s", (host,))
                            row = cur.fetchone()
                            if row: asset_id = str(row["id"])

                    # Back-update subfinder findings with asset_id so resolved_ip shows up
                    if asset_id:
                        cur.execute("""
                            UPDATE recon_findings SET asset_id = %s
                            WHERE source = 'subfinder' AND target = %s AND asset_id IS NULL
                        """, (asset_id, host))
                        stats["subfinder_updated"] += cur.rowcount

                    # Process each DNS record type
                    record_types = [
                        ("a", "dns_a"),
                        ("aaaa", "dns_aaaa"),
                        ("cname", "dns_cname"),
                        ("mx", "dns_mx"),
                        ("ns", "dns_ns"),
                        ("txt", "dns_txt"),
                        ("ptr", "dns_ptr"),
                        ("soa", "dns_soa")
                    ]
                    for field, finding_type in record_types:
                        value = rec.get(field)
                        if value:
                            # Handle both single values and arrays
                            values = value if isinstance(value, list) else [value]
                            for v in values:
                                if not v: continue
                                data_obj = {"record": v, "host": host}
                                if job_id: data_obj["job_id"] = job_id
                                # Include all DNS records in data for context
                                for rt_field, _ in record_types:
                                    rt_val = rec.get(rt_field)
                                    if rt_val: data_obj[rt_field] = rt_val
                                cur.execute("""
                                    INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                                    VALUES (%s, %s, 'dnsx', %s, %s, %s, 'info')
                                """, (str(uuid.uuid4()), asset_id, finding_type, host,
                                      json.dumps(data_obj)))
                                stats["findings_inserted"] += 1
                                # CNAME targets carry the cloud-hosting signal — tag the
                                # parent asset so vanity domains like cdn.example.com
                                # become discoverable via assets.provider = 'aws'.
                                if finding_type == "dns_cname" and asset_id:
                                    _tag_provider(cur, asset_id, str(v))
                    cur.execute("RELEASE SAVEPOINT rec_sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5: stats["error_examples"].append(f"{type(e).__name__}: {e}")
            conn.commit()
    finally:
        conn.close()
    return stats
