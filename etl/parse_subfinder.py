import os, json, uuid, ipaddress
import psycopg2
import requests
from psycopg2.extras import RealDictCursor, Json

try:
    from scope_gate import load_engagement_scope, is_in_scope
except ImportError:  # pragma: no cover — etl/ may be on PYTHONPATH already
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

def parse_subfinder(path: str, profile: str = "upload", job_id: str = None,
                    engagement_id: str = None):
    """Ingest subfinder JSONL.

    When `engagement_id` is provided, each discovered host is checked
    against that engagement's scope (G3).  In-scope hosts get their asset
    + recon_finding stamped with the engagement_id so the Recon Agent
    picks them up and scans them next cycle.  Out-of-scope hosts are still
    recorded but left engagement-unscoped (and therefore unscannable).
    """
    stats = dict(records_seen=0, assets_upserted=0, recon_findings_inserted=0,
                 in_scope=0, out_of_scope=0, assets_scoped=0,
                 skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Load the engagement scope once (empty list if no engagement).
            scope_rows = load_engagement_scope(cur, engagement_id)
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    host = rec.get("host", "").strip()
                    if not host:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue
                    # Scope gate: only stamp/scan a host we've confirmed in-scope.
                    in_scope = bool(engagement_id) and is_in_scope(host, scope_rows)
                    eid = engagement_id if in_scope else None
                    if engagement_id:
                        stats["in_scope" if in_scope else "out_of_scope"] += 1
                    asset_id = None
                    try:
                        ip = str(ipaddress.ip_address(host))
                        cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
                        row = cur.fetchone()
                        if row:
                            asset_id = str(row["id"])
                            if eid:
                                cur.execute("UPDATE assets SET updated_at=now(), "
                                            "engagement_id=COALESCE(engagement_id,%s) WHERE id=%s",
                                            (eid, asset_id))
                                stats["assets_scoped"] += 1
                            else:
                                cur.execute("UPDATE assets SET updated_at=now() WHERE id=%s", (asset_id,))
                        else:
                            asset_id = str(uuid.uuid4())
                            cur.execute("INSERT INTO assets (id, ip, engagement_id) VALUES (%s,%s,%s)",
                                        (asset_id, ip, eid))
                            stats["assets_upserted"] += 1
                            if eid:
                                stats["assets_scoped"] += 1
                    except ValueError:
                        # It's a hostname — try to link to existing asset
                        cur.execute("SELECT id FROM assets WHERE hostname = %s", (host,))
                        row = cur.fetchone()
                        if row:
                            asset_id = str(row["id"])
                            if eid:
                                cur.execute("UPDATE assets SET updated_at=now(), "
                                            "engagement_id=COALESCE(engagement_id,%s) WHERE id=%s",
                                            (eid, asset_id))
                                stats["assets_scoped"] += 1
                            else:
                                cur.execute("UPDATE assets SET updated_at=now() WHERE id=%s", (asset_id,))
                        # else: leave asset_id=None; assets table requires ip NOT NULL

                    # Also insert into recon_findings for Burp export / dashboard
                    source_name = rec.get("source", "subfinder")
                    parent_domain = rec.get("input", "")
                    data = {"host": host, "source": source_name, "input": parent_domain}
                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity, engagement_id)
                        VALUES (%s, %s, 'subfinder', 'subdomain', %s, %s, 'info', %s)
                        ON CONFLICT DO NOTHING
                    """, (str(uuid.uuid4()), asset_id, host, Json(data), eid))
                    if cur.rowcount > 0:
                        stats["recon_findings_inserted"] += 1

                    cur.execute("RELEASE SAVEPOINT rec_sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5: stats["error_examples"].append(f"{type(e).__name__}: {e}")
            conn.commit()
    finally:
        conn.close()

    # Webhook so external tools learn which hosts entered (or were excluded
    # from) the engagement scan loop.
    if engagement_id:
        emit_webhook_event("recon_discovery_scoped", "subfinder", {
            "engagement_id": engagement_id,
            "in_scope": stats["in_scope"], "out_of_scope": stats["out_of_scope"],
            "assets_scoped": stats["assets_scoped"], "records_seen": stats["records_seen"],
        })
    return stats
