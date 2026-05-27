"""
ETL parser for GreyHatWarfare (GHW) output.

Parses bucket_exposure and file_exposure findings into recon_findings.
Supported input formats:
  - JSONL (one JSON object per line) — from GHW API
  - JSON array — from GHW API
  - CSV — from GHW web UI export (manual search results)
"""

import os
import csv
import json
import uuid
import io

import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _load_records(path):
    """Load records from JSONL, JSON array, or CSV."""
    with open(path) as f:
        text = f.read().strip()

    if not text:
        return []

    # Try JSON array first
    if text.startswith("["):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

    # Try JSONL (first non-empty line starts with {)
    first_line = text.split("\n", 1)[0].strip()
    if first_line.startswith("{"):
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if records:
            return records

    # Try CSV (GHW web export format)
    # GHW CSV typically has headers like: bucket,fileCount,url,provider
    # or: filename,bucket,url,size,lastModified
    try:
        reader = csv.DictReader(io.StringIO(text))
        records = []
        for row in reader:
            # Normalize CSV column names to match our expected keys
            rec = {}
            for k, v in row.items():
                if k is None:
                    continue
                key = k.strip().lower().replace(" ", "_")
                rec[key] = (v or "").strip()
            # Determine type from available columns
            if rec.get("filename") or rec.get("file_name"):
                rec["type"] = "file"
            else:
                rec["type"] = "bucket"
            # Normalize common CSV column variations
            if "bucket_name" in rec and "bucket" not in rec:
                rec["bucket"] = rec["bucket_name"]
            # CSV lowercases "fileCount" → "filecount"; map all variants
            for fc_key in ("filecount", "file_count", "files"):
                if fc_key in rec and "fileCount" not in rec:
                    rec["fileCount"] = rec[fc_key]
                    break
            if "cloud_provider" in rec and "provider" not in rec:
                rec["provider"] = rec["cloud_provider"]
            if "lastmodified" in rec and "lastModified" not in rec:
                rec["lastModified"] = rec["lastmodified"]
            if "file_name" in rec and "filename" not in rec:
                rec["filename"] = rec["file_name"]
            records.append(rec)
        if records:
            return records
    except (csv.Error, KeyError):
        pass

    return []


def parse_greyhatwarfare(path: str, profile: str = "upload", job_id: str = None):
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
                    # Determine record type
                    rec_type = rec.get("type", "bucket")
                    if rec_type == "file":
                        finding_type = "file_exposure"
                    else:
                        finding_type = "bucket_exposure"

                    # Extract key fields
                    bucket_name = rec.get("bucket", rec.get("bucketName", ""))
                    url = rec.get("url", "")
                    file_count = rec.get("fileCount", rec.get("file_count", 0))
                    cloud_provider = rec.get("provider", rec.get("cloudProvider", "unknown"))
                    keywords = rec.get("keywords", rec.get("keyword", ""))
                    filename = rec.get("filename", rec.get("fileName", ""))

                    if not bucket_name and not url:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    # Determine target (use bucket name or extracted hostname)
                    target = bucket_name or url

                    # Severity: medium for buckets with files, info for empty/restricted
                    if finding_type == "bucket_exposure":
                        severity = "medium" if (file_count and int(file_count) > 0) else "info"
                    else:
                        severity = "medium"  # file exposures are always at least medium

                    # Build data payload
                    data = {
                        "bucket": bucket_name,
                        "url": url,
                        "file_count": file_count,
                        "cloud_provider": cloud_provider,
                        "keywords": keywords,
                        "record_type": rec_type,
                    }
                    if filename:
                        data["filename"] = filename
                    if rec.get("size"):
                        data["size"] = rec["size"]
                    if rec.get("lastModified") or rec.get("last_modified"):
                        data["last_modified"] = rec.get("lastModified") or rec.get("last_modified")

                    # Try to find asset by target
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
                        VALUES (%s, %s, 'greyhatwarfare', %s, %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (
                        str(uuid.uuid4()), asset_id,
                        finding_type, target, Json(data), severity,
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
