"""ETL parser for cloud-tenant discovery output (osint-runner /jobs/cloud-tenant).

Each JSONL line is one provider record for a single domain. Inserts a row
into `cloud_tenants` (upsert on (LOWER(domain), provider)) plus a record
into `recon_findings` so the result surfaces in the existing recon UI.
Cross-references existing identities.tenant_id and
cloud_scan_recommendations.account_id when matching data is on file.
"""
import os
import json
import uuid
from datetime import datetime
from typing import Optional

import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _load_jsonl(path: str) -> list:
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def _cross_ref(cur, domain: str, provider: str, tenant_id: Optional[str]) -> dict:
    """Pull related rows already in the DB so the operator can pivot:
    - matching identities for an Azure tenant_id
    - cloud_scan_recommendations whose trigger_summary mentions the domain"""
    refs: dict = {}
    if provider == "azure" and tenant_id:
        cur.execute(
            "SELECT count(*) AS n FROM identities WHERE tenant_id = %s",
            (tenant_id,),
        )
        n = cur.fetchone()["n"]
        if n:
            refs["identities_in_tenant"] = n
    cur.execute(
        """SELECT count(*) AS n FROM cloud_scan_recommendations
           WHERE provider = %s
             AND (trigger_summary ILIKE %s OR command_hint ILIKE %s)""",
        (provider, f"%{domain}%", f"%{domain}%"),
    )
    n = cur.fetchone()["n"]
    if n:
        refs["scan_recommendations_for_domain"] = n
    return refs


def parse_cloud_tenant(path: str, profile: str = "upload", job_id: Optional[str] = None) -> dict:
    stats = dict(records_seen=0, tenants_upserted=0, findings_inserted=0, errors=0,
                 error_examples=[])
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
                    domain = (rec.get("domain") or "").strip().lower()
                    provider = (rec.get("provider") or "").strip().lower()
                    if not domain or provider not in ("azure", "aws", "gcp"):
                        stats["errors"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    tenant_id = rec.get("tenant_id")
                    federation_type = rec.get("federation_type") or rec.get("name_space_type")
                    sts_auth_url = rec.get("sts_auth_url")
                    name_space_type = rec.get("name_space_type")
                    cloud_instance = rec.get("cloud_instance")
                    indicators = rec.get("indicators") or {}
                    # Stash any extra keys (e.g. openid_issuer, federation_brand_name)
                    for k in ("openid_issuer", "tenant_region_scope",
                              "federation_brand_name"):
                        if rec.get(k) is not None:
                            indicators[k] = rec[k]

                    engagement_id = rec.get("engagement_id")

                    cross = _cross_ref(cur, domain, provider, tenant_id)
                    if cross:
                        indicators["cross_reference"] = cross

                    # Upsert into cloud_tenants — refresh last_seen + indicators each run
                    cur.execute(
                        """INSERT INTO cloud_tenants
                            (domain, provider, tenant_id, federation_type, sts_auth_url,
                             name_space_type, cloud_instance, indicators, engagement_id)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                           ON CONFLICT (LOWER(domain), provider) DO UPDATE SET
                              tenant_id       = COALESCE(EXCLUDED.tenant_id, cloud_tenants.tenant_id),
                              federation_type = COALESCE(EXCLUDED.federation_type, cloud_tenants.federation_type),
                              sts_auth_url    = COALESCE(EXCLUDED.sts_auth_url, cloud_tenants.sts_auth_url),
                              name_space_type = COALESCE(EXCLUDED.name_space_type, cloud_tenants.name_space_type),
                              cloud_instance  = COALESCE(EXCLUDED.cloud_instance, cloud_tenants.cloud_instance),
                              indicators      = cloud_tenants.indicators || EXCLUDED.indicators,
                              engagement_id   = COALESCE(EXCLUDED.engagement_id, cloud_tenants.engagement_id),
                              last_seen       = now()
                           RETURNING id""",
                        (domain, provider, tenant_id, federation_type, sts_auth_url,
                         name_space_type, cloud_instance, Json(indicators), engagement_id),
                    )
                    stats["tenants_upserted"] += 1

                    # Surface the discovery as a recon_finding so it shows up
                    # in the existing Recon Explorer / follow-ups UI.
                    finding_type = (
                        "azure_tenant_id" if provider == "azure"
                        else "aws_hosting_indicator"
                    )
                    title = (
                        f"Azure tenant {tenant_id} ({federation_type or 'unknown'}) for {domain}"
                        if provider == "azure" and tenant_id
                        else f"{provider.upper()} indicators for {domain}"
                    )
                    fingerprint = f"cloud-tenant:{provider}:{domain}:{tenant_id or ''}"
                    payload = {**rec, "title": title, "cross_reference": cross}
                    cur.execute(
                        """INSERT INTO recon_findings
                            (id, source, finding_type, target, data, severity,
                             fingerprint, engagement_id, created_at)
                           VALUES (%s, %s, %s, %s, %s, 'info', %s, %s, now())""",
                        (str(uuid.uuid4()), "cloud-tenant", finding_type, domain,
                         Json(payload), fingerprint, engagement_id),
                    )
                    stats["findings_inserted"] += 1

                    cur.execute("RELEASE SAVEPOINT rec_sp")
                except Exception as e:
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5:
                        stats["error_examples"].append(f"{type(e).__name__}: {e}")
                    try:
                        cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    except Exception:
                        pass

            conn.commit()
    finally:
        conn.close()
    return stats
