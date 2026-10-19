import os, json, uuid, ipaddress
import psycopg2
from psycopg2.extras import RealDictCursor, Json

try:
    from scope_gate import load_ingest_scope, host_in_scope
except ImportError:  # pragma: no cover — etl/ may already be on PYTHONPATH
    from etl.scope_gate import load_ingest_scope, host_in_scope


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

# Documented "we could not resolve this hostname" sentinel. A hostname asset
# still has to carry an inet, and inventing one would make it look scanned.
UNRESOLVED_IP = "0.0.0.0"


def _sanitize_resolved_ip(resolved_ip: str) -> str:
    """Reject resolver answers that are not a host.

    A bad DNS record can hand back a multicast/broadcast/reserved address, or
    an all-zeros answer. Storing it makes the address look like a scanned host
    and, because host views group by ip, collapses every such hostname onto one
    pseudo-host. Fall back to the documented sentinel instead of inventing a
    target.
    """
    try:
        _r = ipaddress.ip_address(resolved_ip)
        if (_r.is_multicast or _r.is_reserved
                or _r.is_unspecified
                or resolved_ip == "255.255.255.255"):
            return UNRESOLVED_IP
    except ValueError:
        return UNRESOLVED_IP
    return resolved_ip


def _prefetch_host_ips(records) -> dict:
    """Resolve every distinct non-IP hostname in the batch, deduplicated.

    Called BEFORE the database connection is opened — see the comment in
    parse_httpx(). Resolution failures are not an error: they become the
    UNRESOLVED_IP sentinel exactly as the inline lookup did.
    """
    import socket as _socket
    out: dict = {}
    for rec in records:
        host = rec.get("host", "")
        if not host or host in out:
            continue
        try:
            ipaddress.ip_address(host)
            continue  # already an IP — nothing to resolve
        except ValueError:
            pass
        try:
            resolved = _socket.gethostbyname(host)
        except Exception:
            # gaierror is the common case, but herror/UnicodeError/timeout are
            # all "no answer" too, and none of them should abort the batch.
            resolved = UNRESOLVED_IP
        out[host] = _sanitize_resolved_ip(resolved)
    return out


def parse_httpx(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(out_of_scope=0, records_seen=0, findings_inserted=0, skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats

    # 2026-10-17 — the four-hour-transaction class, in an ingest path.
    #
    # Two things used to let ONE batch hold ONE transaction open for an
    # unbounded time, and both are fixed here:
    #
    #  1. DNS. The hostname lookup for an unknown asset ran INSIDE the record
    #     loop, i.e. inside the open transaction. gethostbyname() goes through
    #     the C resolver, so it honours neither socket.setdefaulttimeout() nor
    #     any Postgres setting — a black-holed resolver blocks for the system
    #     resolver's own timeout (tens of seconds, per hostname) while the
    #     transaction sits idle holding row locks. Resolving every distinct
    #     hostname BEFORE the connection is opened was chosen over committing
    #     around each lookup: a per-record commit does NOT fix this, because
    #     the lookup happens part-way through a record, after that record's
    #     statements have already opened the transaction. The only way the
    #     network call cannot hold a transaction is for there to be no
    #     transaction while it runs. The cost is resolving hostnames whose
    #     asset is already in the database; the lookups are deduplicated and
    #     the OS resolver cache absorbs the repeats.
    #  2. Batch-wide commit. See the per-record commit at the end of the loop.
    #
    # The connection also carries the standard caps (etl/access.py::_connect):
    # fail the connect fast, and let Postgres kill us if we ever do go idle in
    # a transaction or queue on a lock.
    host_ips = _prefetch_host_ips(records)
    conn = psycopg2.connect(
        DB_DSN, connect_timeout=5,
        options="-c idle_in_transaction_session_timeout=120000 -c lock_timeout=5000",
    )
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            _enforce_scope, _scope_rows = load_ingest_scope(cur)
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    url = rec.get("url", "").strip()
                    # Ingest scope gate: never record a host the engagement
                    # does not cover, whatever the tool reported.
                    if not host_in_scope(url, _enforce_scope, _scope_rows):
                        stats["out_of_scope"] = stats.get("out_of_scope", 0) + 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue
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
                                # Create the asset from the address resolved in
                                # the pre-pass. No network call here: a DNS
                                # lookup inside this transaction is the bug
                                # this parser is being fixed for.
                                resolved_ip = host_ips.get(host) or UNRESOLVED_IP
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
                            # A successful httpx fingerprint (we got an HTTP
                            # response + Server banner) is PROOF the port is open,
                            # so assert is_open=true even if a prior port scan
                            # recorded it closed/filtered — that commonly happens
                            # when the network scan is routed through a proxy that
                            # can't reach the host while the web scan went direct.
                            cur.execute("""INSERT INTO ports (id, asset_id, proto, port, service, product, is_open)
                                          VALUES (%s, %s, 'tcp', %s, %s, %s, true)
                                          ON CONFLICT (asset_id, proto, port) DO UPDATE SET
                                            is_open = true,
                                            service = EXCLUDED.service,
                                            product = COALESCE(EXCLUDED.product, ports.product),
                                            last_seen = now()""",
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
                    # informational, not a separate "recon" severity.
                    severity = "error" if is_error else "info"

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
                finally:
                    # One transaction per RECORD, not one per batch. A 40k-line
                    # httpx file used to be a single transaction; now the
                    # longest-lived one is a handful of statements. In a
                    # `finally` so the `continue` paths (out-of-scope, skipped)
                    # and the exception path close their transaction too —
                    # after ROLLBACK TO SAVEPOINT the transaction is still open
                    # and would otherwise sit idle until the next record.
                    conn.commit()
    finally:
        conn.close()
    return stats
