"""
ETL parser for ScoutSuite results JSON.

ScoutSuite outputs a nested JSON structure:
  services.<name>.findings.<rule>.items[]
Each item is a flagged resource with a danger_level.
"""

import os
import json
import uuid

import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

DANGER_MAP = {
    "danger": "critical",
    "warning": "medium",
    "info": "info",
}


def _load_scoutsuite(path):
    """Load ScoutSuite results — handle both raw JSON and JS variable assignment."""
    with open(path) as f:
        text = f.read().strip()

    if not text:
        return {}

    # ScoutSuite sometimes wraps output as: scoutsuite_results = {...}
    if text.startswith("scoutsuite_results"):
        eq_idx = text.index("=")
        text = text[eq_idx + 1:].strip().rstrip(";")

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def parse_scoutsuite(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, skipped=0, errors=0, error_examples=[])
    data = _load_scoutsuite(path)
    if not data:
        return stats

    services = data.get("services", data) if isinstance(data, dict) else {}
    provider = data.get("provider_name", data.get("provider", "aws"))

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for svc_name, svc_data in services.items():
                if not isinstance(svc_data, dict):
                    continue
                findings = svc_data.get("findings", {})
                if not isinstance(findings, dict):
                    continue

                for rule_name, rule_data in findings.items():
                    if not isinstance(rule_data, dict):
                        continue
                    items = rule_data.get("items", rule_data.get("flagged_items", []))
                    if not isinstance(items, list):
                        items = list(items) if items else []
                    danger = rule_data.get("level", rule_data.get("danger_level", "warning"))
                    severity = DANGER_MAP.get(str(danger).lower(), "medium")
                    description = rule_data.get("description", rule_data.get("rationale", ""))

                    for item in items:
                        stats["records_seen"] += 1
                        try:
                            cur.execute("SAVEPOINT rec_sp")
                            if isinstance(item, str):
                                target = item
                                item_data = {}
                            elif isinstance(item, dict):
                                target = item.get("arn", item.get("id", item.get("name", svc_name)))
                                item_data = item
                            else:
                                stats["skipped"] += 1
                                cur.execute("RELEASE SAVEPOINT rec_sp")
                                continue

                            finding_type = f"{svc_name}_misconfiguration"

                            rec_data = {
                                "service": svc_name,
                                "rule": rule_name,
                                "description": description,
                                "provider": provider,
                                "danger_level": str(danger),
                            }
                            if isinstance(item_data, dict):
                                rec_data["resource"] = item_data

                            asset_id = None
                            if target:
                                cur.execute(
                                    "SELECT id FROM assets WHERE hostname = %s LIMIT 1",
                                    (str(target),),
                                )
                                row = cur.fetchone()
                                if row:
                                    asset_id = str(row["id"])

                            cur.execute("""
                                INSERT INTO recon_findings
                                    (id, asset_id, source, finding_type, target, data, severity)
                                VALUES (%s, %s, 'scoutsuite', %s, %s, %s, %s)
                                ON CONFLICT DO NOTHING
                            """, (
                                str(uuid.uuid4()), asset_id,
                                finding_type, str(target), Json(rec_data), severity,
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
