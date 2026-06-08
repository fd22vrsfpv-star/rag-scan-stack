import os, json, uuid, ipaddress
import psycopg2
import requests
from psycopg2.extras import RealDictCursor

try:
    from _provider_detect import tag_asset as _tag_provider
except ImportError:  # pragma: no cover — etl/ may be on PYTHONPATH already
    from etl._provider_detect import tag_asset as _tag_provider

try:
    from scope_gate import load_engagement_scope, is_in_scope
except ImportError:  # pragma: no cover
    from etl.scope_gate import load_engagement_scope, is_in_scope

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
API_BASE = os.environ.get("API_BASE", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "true").lower() == "true"


def emit_webhook_event(event_type: str, source: str, data: dict, severity: str = None):
    """Emit a webhook event via the RAG API (mirrors other etl parsers)."""
    if not WEBHOOK_ENABLED:
        return
    try:
        payload = {"event_type": event_type, "source": source, "data": data}
        if severity:
            payload["severity"] = severity
        requests.post(
            f"{API_BASE}/webhooks/emit",
            headers={"x-api-key": API_KEY, "Content-Type": "application/json"},
            json=payload, timeout=5,
        )
    except Exception:
        pass

def _load_jsonl(path):
    results = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try: results.append(json.loads(line))
            except json.JSONDecodeError: pass
    return results

def _ensure_asset(cur, ip_str: str, hostname: str = None, engagement_id: str = None):
    """Create or find an asset by IP, optionally setting hostname.

    When `engagement_id` is set (caller already confirmed the host is
    in-scope), stamp it on the asset so the Recon Agent will scan it.
    Returns asset_id.
    """
    cur.execute("SELECT id FROM assets WHERE ip = %s", (ip_str,))
    row = cur.fetchone()
    if row:
        asset_id = str(row["id"])
        if engagement_id:
            cur.execute("UPDATE assets SET hostname = COALESCE(hostname, %s), "
                        "engagement_id = COALESCE(engagement_id, %s), updated_at = now() WHERE id = %s",
                        (hostname, engagement_id, asset_id))
        elif hostname:
            cur.execute("UPDATE assets SET hostname = COALESCE(hostname, %s), updated_at = now() WHERE id = %s",
                        (hostname, asset_id))
        return asset_id
    asset_id = str(uuid.uuid4())
    cur.execute("INSERT INTO assets (id, ip, hostname, engagement_id) VALUES (%s, %s, %s, %s)",
                (asset_id, ip_str, hostname, engagement_id))
    return asset_id


def parse_dnsx(path: str, profile: str = "upload", job_id: str = None,
               engagement_id: str = None):
    """Ingest dnsx JSONL.

    When `engagement_id` is provided, a record is in-scope if either the
    queried hostname OR its resolved A-record IP matches the engagement's
    scope (G3).  In-scope records stamp the engagement on the asset +
    recon_findings so the Recon Agent scans the host; out-of-scope records
    are recorded but left unscoped.
    """
    stats = dict(records_seen=0, findings_inserted=0, assets_linked=0, subfinder_updated=0,
                 in_scope=0, out_of_scope=0, assets_scoped=0,
                 skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            scope_rows = load_engagement_scope(cur, engagement_id)
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
                    first_ip = None
                    if a_records:
                        ips = a_records if isinstance(a_records, list) else [a_records]
                        first_ip = next((ip for ip in ips if ip), None)

                    # Scope gate: in-scope if the hostname OR the resolved IP matches.
                    in_scope = bool(engagement_id) and (
                        is_in_scope(host, scope_rows)
                        or (first_ip is not None and is_in_scope(str(first_ip), scope_rows))
                    )
                    eid = engagement_id if in_scope else None
                    if engagement_id:
                        stats["in_scope" if in_scope else "out_of_scope"] += 1

                    if first_ip:
                        try:
                            ip_str = str(ipaddress.ip_address(first_ip))
                            asset_id = _ensure_asset(cur, ip_str, hostname=host, engagement_id=eid)
                            stats["assets_linked"] += 1
                            if eid:
                                stats["assets_scoped"] += 1
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
                        # Stamp engagement on the matched asset when in-scope.
                        if asset_id and eid:
                            cur.execute("UPDATE assets SET engagement_id = COALESCE(engagement_id, %s), "
                                        "updated_at = now() WHERE id = %s", (eid, asset_id))
                            stats["assets_scoped"] += 1

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
                                    INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity, engagement_id)
                                    VALUES (%s, %s, 'dnsx', %s, %s, %s, 'info', %s)
                                """, (str(uuid.uuid4()), asset_id, finding_type, host,
                                      json.dumps(data_obj), eid))
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

    if engagement_id:
        emit_webhook_event("recon_discovery_scoped", "dnsx", {
            "engagement_id": engagement_id,
            "in_scope": stats["in_scope"], "out_of_scope": stats["out_of_scope"],
            "assets_scoped": stats["assets_scoped"], "records_seen": stats["records_seen"],
        })
    return stats
