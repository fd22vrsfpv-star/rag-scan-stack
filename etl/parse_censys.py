import os, json, uuid, ipaddress
import psycopg2
from psycopg2.extras import RealDictCursor, Json

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

def _ensure_asset_by_hostname(cur, hostname):
    """Find or create an asset by hostname, return asset_id or None."""
    if not hostname:
        return None
    cur.execute("SELECT id FROM assets WHERE hostname = %s", (hostname,))
    row = cur.fetchone()
    if row:
        asset_id = str(row["id"])
        cur.execute("UPDATE assets SET updated_at=now() WHERE id=%s", (asset_id,))
        return asset_id
    asset_id = str(uuid.uuid4())
    cur.execute("INSERT INTO assets (id, hostname) VALUES (%s,%s)", (asset_id, hostname))
    return asset_id


def parse_censys(path: str, search_type: str = "hosts", profile: str = "upload", job_id: str = None):
    """Parse Censys JSONL output (hosts, certs, or subdomains)."""
    stats = dict(records_seen=0, assets_upserted=0, recon_findings_inserted=0,
                 ports_inserted=0, skipped=0, errors=0, error_examples=[])

    records = _load_jsonl(path)
    stats["records_seen"] = len(records)
    if not records:
        return stats

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    rec_type = rec.get("type", search_type)

                    if rec_type == "host":
                        ip = rec.get("ip", "")
                        if not ip:
                            stats["skipped"] += 1
                            cur.execute("RELEASE SAVEPOINT rec_sp")
                            continue

                        asset_id = _ensure_asset(cur, ip)
                        if asset_id:
                            stats["assets_upserted"] += 1

                        # Store services as port findings
                        services = rec.get("services", [])
                        for svc in services:
                            port = svc.get("port", 0)
                            if not port:
                                continue
                            svc_data = {
                                "ip": ip,
                                "port": port,
                                "service_name": svc.get("service_name", ""),
                                "transport_protocol": svc.get("transport_protocol", "tcp"),
                                "banner": svc.get("banner", "")[:500],
                                "location": rec.get("location", {}),
                                "autonomous_system": rec.get("autonomous_system", {}),
                                "operating_system": rec.get("operating_system", {}),
                            }

                            cur.execute("""
                                INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                                VALUES (%s, %s, 'censys', 'service', %s, %s, 'info')
                                ON CONFLICT DO NOTHING
                            """, (str(uuid.uuid4()), asset_id, ip, Json(svc_data)))
                            if cur.rowcount > 0:
                                stats["recon_findings_inserted"] += 1

                            # Also insert into ports table if it exists
                            try:
                                cur.execute("""
                                    INSERT INTO ports (id, asset_id, port, protocol, service, banner)
                                    VALUES (%s, %s, %s, %s, %s, %s)
                                    ON CONFLICT DO NOTHING
                                """, (str(uuid.uuid4()), asset_id, port,
                                      svc.get("transport_protocol", "tcp"),
                                      svc.get("service_name", ""),
                                      svc.get("banner", "")[:500]))
                                if cur.rowcount > 0:
                                    stats["ports_inserted"] += 1
                            except Exception:
                                pass  # ports table may not exist

                    elif rec_type == "subdomain":
                        name = rec.get("name", "")
                        if not name:
                            stats["skipped"] += 1
                            cur.execute("RELEASE SAVEPOINT rec_sp")
                            continue

                        asset_id = _ensure_asset_by_hostname(cur, name)
                        if asset_id:
                            stats["assets_upserted"] += 1

                        data = {
                            "subdomain": name,
                            "count": rec.get("count", 0),
                            "query": rec.get("query", ""),
                        }

                        cur.execute("""
                            INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                            VALUES (%s, %s, 'censys', 'subdomain', %s, %s, 'info')
                            ON CONFLICT DO NOTHING
                        """, (str(uuid.uuid4()), asset_id, name, Json(data)))
                        if cur.rowcount > 0:
                            stats["recon_findings_inserted"] += 1

                    elif rec_type == "certificate":
                        fingerprint = rec.get("fingerprint", "")
                        names = rec.get("names", [])
                        target = names[0] if names else fingerprint

                        asset_id = None
                        if names:
                            asset_id = _ensure_asset_by_hostname(cur, names[0])
                            if asset_id:
                                stats["assets_upserted"] += 1

                        data = {
                            "fingerprint": fingerprint,
                            "names": names,
                            "issuer": rec.get("issuer", ""),
                            "not_before": rec.get("not_before", ""),
                            "not_after": rec.get("not_after", ""),
                            "query": rec.get("query", ""),
                        }

                        cur.execute("""
                            INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                            VALUES (%s, %s, 'censys', 'certificate', %s, %s, 'info')
                            ON CONFLICT DO NOTHING
                        """, (str(uuid.uuid4()), asset_id, target, Json(data)))
                        if cur.rowcount > 0:
                            stats["recon_findings_inserted"] += 1

                    else:
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
