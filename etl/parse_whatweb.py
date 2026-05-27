import os, json, uuid, ipaddress
from urllib.parse import urlparse
import psycopg2
from psycopg2.extras import RealDictCursor, Json

try:
    from _provider_detect import tag_asset as _tag_provider
except ImportError:
    from etl._provider_detect import tag_asset as _tag_provider

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _load_json(path):
    """Load WhatWeb JSON output (array of objects)."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    return []


def parse_whatweb(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, skipped=0, errors=0, error_examples=[])
    records = _load_json(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    target = rec.get("target", "").strip()
                    if not target:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    http_status = rec.get("http_status")
                    plugins = rec.get("plugins", {})

                    # Extract host from target URL
                    parsed = urlparse(target)
                    host = parsed.hostname or ""
                    port = parsed.port

                    # Lookup asset_id by hostname or IP
                    asset_id = None
                    if host:
                        try:
                            ip_str = str(ipaddress.ip_address(host))
                            cur.execute("SELECT id FROM assets WHERE ip = %s OR hostname = %s", (ip_str, host))
                        except ValueError:
                            cur.execute("SELECT id FROM assets WHERE hostname = %s", (host,))
                        row = cur.fetchone()
                        if row: asset_id = str(row["id"])

                    # Build tech list from plugins
                    tech_list = []
                    for plugin_name, plugin_data in plugins.items():
                        version = ""
                        if isinstance(plugin_data, dict):
                            ver_list = plugin_data.get("version", [])
                            if ver_list and isinstance(ver_list, list):
                                version = ver_list[0]
                            elif isinstance(ver_list, str):
                                version = ver_list
                        if version:
                            tech_list.append(f"{plugin_name}/{version}")
                        else:
                            tech_list.append(plugin_name)

                    # Build evidence string
                    evidence_parts = []
                    if http_status: evidence_parts.append(f"Status: {http_status}")
                    if tech_list: evidence_parts.append(f"Tech: {', '.join(tech_list)}")
                    evidence = " | ".join(evidence_parts) if evidence_parts else None

                    # Build refs jsonb
                    refs = {}
                    if tech_list: refs["tech"] = tech_list
                    if http_status: refs["http_status"] = http_status
                    if port: refs["port"] = port
                    if plugins: refs["plugins"] = {k: v for k, v in plugins.items() if isinstance(v, dict)}

                    # Derive a title from the most interesting plugins
                    title_parts = [t for t in tech_list[:5]]
                    title = ", ".join(title_parts) if title_parts else None

                    # Determine severity: error state (no evidence) vs successful probe
                    is_error = http_status is None and not evidence
                    severity = "error" if is_error else "recon"

                    finding_id = str(uuid.uuid4())
                    cur.execute("""
                        INSERT INTO web_findings
                        (id, asset_id, url, source, status_code, evidence, refs, name, severity)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (finding_id, asset_id, target, "whatweb", http_status, evidence, json.dumps(refs), title, severity))

                    # Also insert into recon_findings for OSINT Explorer
                    recon_data = {"url": target, "host": host}
                    if http_status is not None:
                        recon_data["http_status"] = http_status
                    if tech_list:
                        recon_data["tech"] = tech_list
                    if port:
                        recon_data["port"] = port
                    recon_target = host or target
                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'whatweb', 'web_service', %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (str(uuid.uuid4()), asset_id, recon_target, Json(recon_data), severity))

                    # Tag provider from detected tech stack — whatweb plugin
                    # names like "CloudFront", "Amazon-CloudFront", "Cloudflare"
                    # appear in tech_list verbatim.
                    if asset_id and tech_list:
                        _tag_provider(cur, asset_id, " ".join(tech_list))

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
