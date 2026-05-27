import os, json, uuid
import psycopg2
from psycopg2.extras import RealDictCursor, Json

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

def parse_trufflehog(path: str, profile: str = "upload", job_id: str = None):
    """Parse TruffleHog JSON output and store leaked secret metadata in recon_findings.

    TruffleHog JSON format (one per line):
    {
      "SourceMetadata": {"Data": {"Git": {"repository": "...", "file": "...", "line": 42}}},
      "SourceID": 0,
      "SourceType": 16,
      "SourceName": "trufflehog - git",
      "DetectorType": 17,
      "DetectorName": "AWS",
      "DecoderName": "PLAIN",
      "Verified": true,
      "Raw": "<redacted>",
      "RawV2": "<redacted>",
      "Redacted": "AKIA...XXXX",
      "ExtraData": {"account": "123456789"},
      "StructuredData": null
    }

    IMPORTANT: We do NOT store Raw/RawV2 secret values — only metadata.
    """
    stats = dict(records_seen=0, recon_findings_inserted=0, skipped=0, verified=0, unverified=0, errors=0, error_examples=[])
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
                    detector_name = rec.get("DetectorName", "unknown")
                    verified = rec.get("Verified", False)
                    redacted = rec.get("Redacted", "")

                    # Extract source metadata
                    source_meta = rec.get("SourceMetadata", {}).get("Data", {})
                    # Git metadata
                    git_meta = source_meta.get("Git", {})
                    repo = git_meta.get("repository", "")
                    file_path = git_meta.get("file", "")
                    line_num = git_meta.get("line", None)
                    commit = git_meta.get("commit", "")

                    # GitHub metadata (org scan)
                    gh_meta = source_meta.get("Github", {})
                    if not repo and gh_meta:
                        repo = gh_meta.get("repository", "")
                        file_path = gh_meta.get("file", "")
                        line_num = gh_meta.get("line", None)

                    # Filesystem metadata
                    fs_meta = source_meta.get("Filesystem", {})
                    if not file_path and fs_meta:
                        file_path = fs_meta.get("file", "")
                        line_num = fs_meta.get("line", None)

                    source_name = rec.get("SourceName", "trufflehog")
                    target = repo or file_path or source_name

                    if not target or target == "trufflehog":
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    severity = "critical" if verified else "high"
                    if verified:
                        stats["verified"] += 1
                    else:
                        stats["unverified"] += 1

                    # Store metadata only — never raw secrets
                    data = {
                        "detector": detector_name,
                        "verified": verified,
                        "redacted": redacted,
                        "repository": repo,
                        "file": file_path,
                        "line": line_num,
                        "commit": commit,
                        "source_name": source_name,
                        "decoder": rec.get("DecoderName", ""),
                        "extra": rec.get("ExtraData") or {},
                    }

                    cur.execute("""
                        INSERT INTO recon_findings (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, NULL, 'trufflehog', 'leaked_secret', %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (str(uuid.uuid4()), target, Json(data), severity))
                    if cur.rowcount > 0:
                        stats["recon_findings_inserted"] += 1

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
