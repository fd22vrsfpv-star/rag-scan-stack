"""
ETL parser for Prowler OCSF JSON output.

Parses AWS/Azure/GCP security posture findings into recon_findings.
Supported input formats:
  - OCSF JSON array
  - OCSF JSONL (one JSON object per line)
"""

import os
import json
import uuid

import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


def _load_records(path):
    """Load records from JSON array or JSONL."""
    with open(path) as f:
        text = f.read().strip()

    if not text:
        return []

    # JSON array
    if text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

    # JSONL
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def parse_prowler(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, skipped=0, errors=0, error_examples=[])
    records = _load_records(path)
    stats["records_seen"] = len(records)
    if not records:
        return stats

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    # OCSF format fields
                    status_code = rec.get("status_code", rec.get("status", ""))
                    # Skip PASS findings — only import failures
                    if str(status_code).upper() == "PASS":
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    # Severity from OCSF severity_id or severity text
                    raw_sev = rec.get("severity", rec.get("severity_text", "info"))
                    if isinstance(raw_sev, str):
                        severity = SEVERITY_MAP.get(raw_sev.lower(), "info")
                    else:
                        # severity_id: 1=info, 2=low, 3=medium, 4=high, 5=critical
                        sev_id_map = {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}
                        severity = sev_id_map.get(int(raw_sev), "info")

                    # Extract key fields from OCSF structure
                    finding = rec.get("finding_info", rec.get("finding", {})) or {}
                    resources = rec.get("resources", []) or []
                    resource = resources[0] if resources else {}
                    cloud = rec.get("cloud", {}) or {}
                    account = cloud.get("account", {}) or {}
                    region = cloud.get("region", resource.get("region", ""))
                    provider = cloud.get("provider", rec.get("provider", "aws"))

                    check_id = rec.get("check_id", finding.get("uid", ""))
                    title = finding.get("title", rec.get("check_title", rec.get("status_extended", "")))
                    description = finding.get("desc", rec.get("description", ""))
                    resource_arn = resource.get("uid", rec.get("resource_arn", rec.get("resource_id", "")))
                    service = rec.get("service_name", resource.get("type", ""))
                    account_id = account.get("uid", rec.get("account_id", ""))
                    compliance = rec.get("compliance", {}) or {}
                    risk = rec.get("risk", finding.get("risk", ""))

                    target = resource_arn or account_id or provider

                    data = {
                        "check_id": check_id,
                        "title": title,
                        "description": description,
                        "resource_arn": resource_arn,
                        "service": service,
                        "region": region,
                        "account_id": account_id,
                        "provider": provider,
                        "compliance": compliance,
                        "risk": risk,
                        "status_code": str(status_code),
                    }
                    if rec.get("remediation"):
                        data["remediation"] = rec["remediation"]

                    # Asset lookup
                    asset_id = None
                    if target:
                        cur.execute(
                            "SELECT id FROM assets WHERE hostname = %s LIMIT 1",
                            (target,),
                        )
                        row = cur.fetchone()
                        if row:
                            asset_id = str(row["id"])

                    cur.execute("""
                        INSERT INTO recon_findings
                            (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'prowler', 'cloud_misconfiguration', %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (
                        str(uuid.uuid4()), asset_id,
                        target, Json(data), severity,
                    ))
                    stats["findings_inserted"] += 1
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
