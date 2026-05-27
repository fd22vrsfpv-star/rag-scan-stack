import os, json, uuid, ipaddress
import psycopg2
from psycopg2.extras import RealDictCursor, Json

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

def parse_httpx(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    url = rec.get("url", "").strip()
                    if not url:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    # Extract fields from httpx output
                    status_code = rec.get("status_code") or rec.get("status-code")
                    title = rec.get("title", "")
                    tech = rec.get("tech", [])
                    webserver = rec.get("webserver", "")
                    content_length = rec.get("content_length") or rec.get("content-length")
                    host = rec.get("host", "")
                    port = rec.get("port")

                    # Lookup or create asset by hostname or IP
                    asset_id = None
                    if host:
                        try:
                            ip_str = str(ipaddress.ip_address(host))
                            cur.execute("SELECT id FROM assets WHERE ip = %s::inet LIMIT 1", (ip_str,))
                            row = cur.fetchone()
                            if row:
                                asset_id = str(row["id"])
                            else:
                                asset_id = str(uuid.uuid4())
                                cur.execute("INSERT INTO assets (id, ip) VALUES (%s, %s::inet) ON CONFLICT DO NOTHING RETURNING id",
                                            (asset_id, ip_str))
                                r = cur.fetchone()
                                if not r:
                                    cur.execute("SELECT id FROM assets WHERE ip = %s::inet LIMIT 1", (ip_str,))
                                    r = cur.fetchone()
                                if r: asset_id = str(r["id"])
                        except ValueError:
                            # host is a hostname, not an IP — look up by hostname
                            cur.execute("SELECT id FROM assets WHERE hostname = %s LIMIT 1", (host,))
                            row = cur.fetchone()
                            if row:
                                asset_id = str(row["id"])
                            else:
                                # Resolve hostname and create asset
                                import socket as _socket
                                try:
                                    resolved_ip = _socket.gethostbyname(host)
                                except _socket.gaierror:
                                    resolved_ip = "0.0.0.0"
                                asset_id = str(uuid.uuid4())
                                cur.execute("""INSERT INTO assets (id, ip, hostname)
                                              VALUES (%s, %s::inet, %s)
                                              ON CONFLICT (ip, COALESCE(hostname, '')) DO UPDATE SET last_seen = now()
                                              RETURNING id""",
                                            (asset_id, resolved_ip, host))
                                r = cur.fetchone()
                                if r: asset_id = str(r["id"])

                    # Ensure port record exists for this web service
                    if asset_id and port:
                        svc = 'https' if url.startswith('https') else 'http'
                        try:
                            cur.execute("SAVEPOINT port_sp")
                            cur.execute("""INSERT INTO ports (id, asset_id, proto, port, service, product, is_open)
                                          VALUES (%s, %s, 'tcp', %s, %s, %s, true)
                                          ON CONFLICT DO NOTHING""",
                                        (str(uuid.uuid4()), asset_id, port, svc, webserver or None))
                            cur.execute("RELEASE SAVEPOINT port_sp")
                        except Exception:
                            cur.execute("ROLLBACK TO SAVEPOINT port_sp")

                    # Build evidence from available data
                    evidence_parts = []
                    if title: evidence_parts.append(f"Title: {title}")
                    if webserver: evidence_parts.append(f"Server: {webserver}")
                    if tech: evidence_parts.append(f"Tech: {', '.join(tech) if isinstance(tech, list) else tech}")
                    if content_length: evidence_parts.append(f"Content-Length: {content_length}")
                    evidence = " | ".join(evidence_parts) if evidence_parts else None

                    # Build refs jsonb
                    refs = {}
                    if tech: refs["tech"] = tech if isinstance(tech, list) else [tech]
                    if webserver: refs["webserver"] = webserver
                    if content_length: refs["content_length"] = content_length
                    if port: refs["port"] = port

                    # Determine severity: error state (no evidence) vs successful probe
                    is_error = rec.get("failed", False) or (status_code is None and not evidence)
                    severity = "error" if is_error else "recon"

                    finding_id = str(uuid.uuid4())
                    cur.execute("""
                        INSERT INTO web_findings
                        (id, asset_id, url, source, status_code, evidence, refs, name, severity)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (finding_id, asset_id, url, "httpx", status_code, evidence, json.dumps(refs), title or None, severity))

                    # Also insert into recon_findings so it appears in OSINT Explorer
                    recon_data = {"url": url, "host": host}
                    if status_code is not None:
                        recon_data["status_code"] = status_code
                    if title:
                        recon_data["title"] = title
                    if webserver:
                        recon_data["webserver"] = webserver
                    if tech:
                        recon_data["tech"] = tech if isinstance(tech, list) else [tech]
                    if port:
                        recon_data["port"] = port
                    if content_length:
                        recon_data["content_length"] = content_length
                    recon_target = host or url
                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'httpx', 'web_service', %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (str(uuid.uuid4()), asset_id, recon_target, Json(recon_data), severity))

                    # Tag asset provider from server header + tech stack — covers
                    # CloudFront / AWSALB / AmazonS3 / nginx-via-Cloudflare / etc.
                    if asset_id:
                        tech_blob = " ".join(tech) if isinstance(tech, list) else (tech or "")
                        _tag_provider(cur, asset_id, f"{webserver or ''} {tech_blob}")

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
