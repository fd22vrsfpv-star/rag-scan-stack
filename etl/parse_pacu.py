"""
ETL parser for Pacu session export JSON.

Pacu is an AWS exploitation framework. This parses its session export
which contains module execution results, discovered credentials, etc.
"""

import os
import json
import uuid

import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

# Map Pacu module categories to finding types
MODULE_TYPE_MAP = [
    ("privesc", "privesc_path"),
    ("escalate", "privesc_path"),
    ("persist", "persistence"),
    ("lambda", "lambda_enum"),
    ("s3", "s3_enumeration"),
    ("ec2", "ec2_enumeration"),
    ("iam", "iam_enumeration"),
    ("enum", "iam_enumeration"),
]


def _classify_module(module_name: str) -> str:
    """Classify a Pacu module name into a finding type."""
    name_lower = module_name.lower()
    for key, ftype in MODULE_TYPE_MAP:
        if key in name_lower:
            return ftype
    return "aws_enumeration"


def _load_records(path):
    """Load Pacu session export JSON."""
    with open(path) as f:
        text = f.read().strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


def parse_pacu(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, credentials_inserted=0,
                 skipped=0, errors=0, error_examples=[])
    data = _load_records(path)
    if not data:
        return stats

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Process module executions
            modules = data.get("modules", data.get("module_data", {}))
            if isinstance(modules, list):
                modules = {m.get("module", f"module_{i}"): m for i, m in enumerate(modules)}

            for mod_name, mod_data in (modules or {}).items():
                if not isinstance(mod_data, dict):
                    continue
                stats["records_seen"] += 1

                try:
                    cur.execute("SAVEPOINT rec_sp")
                    finding_type = _classify_module(mod_name)
                    severity = "medium"

                    # Privesc findings are high severity
                    if "privesc" in mod_name.lower() or "escalat" in mod_name.lower():
                        severity = "high"

                    # Extract results summary
                    results = mod_data.get("results", mod_data.get("data", mod_data))
                    account_id = data.get("account_id", data.get("aws_account_id", ""))

                    target = account_id or mod_name
                    rec_data = {
                        "module": mod_name,
                        "account_id": account_id,
                        "provider": "aws",
                    }
                    if isinstance(results, dict):
                        rec_data["results"] = results
                    elif isinstance(results, list):
                        rec_data["results"] = results[:50]  # cap large results
                    else:
                        rec_data["results_summary"] = str(results)[:2000]

                    asset_id = None
                    cur.execute("""
                        INSERT INTO recon_findings
                            (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'pacu', %s, %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (
                        str(uuid.uuid4()), asset_id,
                        finding_type, target, Json(rec_data), severity,
                    ))
                    stats["findings_inserted"] += 1
                    cur.execute("RELEASE SAVEPOINT rec_sp")

                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5:
                        stats["error_examples"].append(f"{type(e).__name__}: {e}")

            # Process discovered credentials
            creds = data.get("credentials", data.get("aws_keys", []))
            if isinstance(creds, dict):
                creds = [creds]
            for cred in (creds or []):
                stats["records_seen"] += 1
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    access_key = cred.get("access_key_id", cred.get("AccessKeyId", ""))
                    secret_key = cred.get("secret_access_key", cred.get("SecretAccessKey", ""))
                    session_token = cred.get("session_token", cred.get("SessionToken", ""))
                    user_name = cred.get("user_name", cred.get("UserName", access_key))

                    if not access_key:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    cred_type = "aws_sts" if session_token else "aws_access_key"
                    cred_value = access_key
                    if secret_key:
                        cred_value = f"{access_key}:{secret_key}"

                    # credential_vault, not credential_findings.
                    #
                    # This used to write (target, finding_type, data) into
                    # credential_findings — the recon_findings shape, and three
                    # columns that table does not have — so every insert raised
                    # UndefinedColumn and this parser had never stored a row.
                    #
                    # credential_findings is also the wrong table on its merits:
                    # its ip, port and username are all NOT NULL, and an AWS
                    # access key has no host or port. credential_vault is built
                    # for exactly this — username/credential_type/source plus a
                    # cloud_metadata jsonb.
                    #
                    # source_entity_id is a DETERMINISTIC uuid5 of the access key
                    # id, because the key id IS the credential's identity. That
                    # makes ux_credvault_source_entity a real dedup key, so a
                    # re-import updates rather than duplicating. The WHERE
                    # predicate has to be repeated: the index is PARTIAL, and
                    # ON CONFLICT must match it exactly or Postgres refuses with
                    # "no unique or exclusion constraint matching".
                    entity_id = str(uuid.uuid5(uuid.NAMESPACE_URL,
                                               f"pacu:aws-access-key:{access_key}"))
                    cur.execute("""
                        INSERT INTO credential_vault
                            (id, username, credential_type, credential_value,
                             source, source_entity_id, status, cloud_metadata, notes)
                        VALUES (%s, %s, %s, %s, 'pacu', %s, 'active', %s, %s)
                        ON CONFLICT (source, source_entity_id)
                          WHERE source_entity_id IS NOT NULL
                          DO UPDATE SET
                            credential_value = EXCLUDED.credential_value,
                            cloud_metadata   = EXCLUDED.cloud_metadata,
                            updated_at       = now()
                    """, (
                        str(uuid.uuid4()), user_name, cred_type, cred_value,
                        entity_id,
                        Json({
                            "access_key_id": access_key,
                            "has_secret": bool(secret_key),
                            "has_session_token": bool(session_token),
                            "user_name": user_name,
                            "account_id": data.get("account_id", ""),
                        }),
                        # Stored in the clear, which is the operator's stated
                        # choice for this tool. Flagged here so it is visible at
                        # the point of storage rather than only in a doc.
                        "CAUTION: credential material is stored unencrypted in "
                        "this database. Restrict access accordingly.",
                    ))
                    stats["credentials_inserted"] += 1
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
