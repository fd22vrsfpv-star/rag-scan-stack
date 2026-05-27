"""
ETL parser for CloudFox CSV/text loot files.

CloudFox outputs CSV files with privilege escalation paths,
role trusts, and other AWS enumeration data.
Supports: CSV files and JSON output.
"""

import os
import csv
import json
import uuid
import io

import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

# Map CloudFox output filenames/headers to finding types
FINDING_TYPE_MAP = {
    "privesc": "privesc_path",
    "role-trust": "role_trust",
    "role-trusts": "role_trust",
    "principals": "iam_enumeration",
    "permissions": "iam_enumeration",
    "access-keys": "access_key_enum",
    "buckets": "s3_enumeration",
    "endpoints": "endpoint_enum",
    "instances": "ec2_enumeration",
    "secrets": "secret_enum",
    "env-vars": "env_var_exposure",
    "lambdas": "lambda_enum",
}


def _detect_type_from_headers(headers):
    """Infer finding type from CSV column headers."""
    header_str = " ".join(h.lower() for h in headers)
    if "privesc" in header_str or "escalation" in header_str:
        return "privesc_path"
    if "trust" in header_str:
        return "role_trust"
    if "principal" in header_str or "policy" in header_str:
        return "iam_enumeration"
    if "bucket" in header_str:
        return "s3_enumeration"
    if "instance" in header_str or "ec2" in header_str:
        return "ec2_enumeration"
    if "lambda" in header_str or "function" in header_str:
        return "lambda_enum"
    if "secret" in header_str:
        return "secret_enum"
    return "cloud_enumeration"


def _load_records(path):
    """Load records from CSV, JSON array, or JSONL."""
    with open(path) as f:
        text = f.read().strip()

    if not text:
        return [], "cloud_enumeration"

    # Try JSON
    if text.startswith("[") or text.startswith("{"):
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data, "cloud_enumeration"
            if isinstance(data, dict):
                return [data], "cloud_enumeration"
        except json.JSONDecodeError:
            pass

    # CSV
    try:
        reader = csv.DictReader(io.StringIO(text))
        headers = reader.fieldnames or []
        finding_type = _detect_type_from_headers(headers)
        records = []
        for row in reader:
            rec = {k.strip(): (v or "").strip() for k, v in row.items() if k is not None}
            records.append(rec)
        return records, finding_type
    except (csv.Error, KeyError):
        pass

    # Plain text lines (one item per line)
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return [{"value": l} for l in lines], "cloud_enumeration"


def parse_cloudfox(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, skipped=0, errors=0, error_examples=[])
    records, default_type = _load_records(path)
    stats["records_seen"] = len(records)
    if not records:
        return stats

    # Try to detect type from filename
    basename = os.path.basename(path).lower().replace(".csv", "").replace(".json", "").replace(".txt", "")
    for key, ftype in FINDING_TYPE_MAP.items():
        if key in basename:
            default_type = ftype
            break

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    if isinstance(rec, dict):
                        # Extract a meaningful target
                        target = (rec.get("arn") or rec.get("ARN")
                                  or rec.get("principal") or rec.get("Principal")
                                  or rec.get("resource") or rec.get("name")
                                  or rec.get("value") or rec.get("Role")
                                  or "unknown")
                        data = rec
                    else:
                        target = str(rec)
                        data = {"value": str(rec)}

                    severity = "medium"
                    if default_type == "privesc_path":
                        severity = "high"
                    elif default_type in ("secret_enum", "env_var_exposure"):
                        severity = "high"

                    data["provider"] = "aws"

                    asset_id = None
                    cur.execute("""
                        INSERT INTO recon_findings
                            (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'cloudfox', %s, %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (
                        str(uuid.uuid4()), asset_id,
                        default_type, str(target)[:500], Json(data), severity,
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
