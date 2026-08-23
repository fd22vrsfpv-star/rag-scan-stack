import os, json, uuid
import psycopg2
from psycopg2.extras import RealDictCursor

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

VALID_SECRET_TYPES = {"password", "aws_key", "azure_key", "ssh_key", "api_token", "ntlm_hash", "kerberos_ticket", "certificate", "other"}

def parse_brutus(path: str, profile: str = "upload", job_id: str = None, secret_type: str = "password"):
    if secret_type not in VALID_SECRET_TYPES:
        secret_type = "password"
    stats = dict(records_seen=0, credentials_found=0, skipped=0, errors=0, error_examples=[])
    records = _load_jsonl(path); stats["records_seen"] = len(records)
    if not records: return stats
    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    # Field-name compatibility across brutus + credential-check
                    # producers.  Two schemas show up here:
                    #
                    # Legacy brutus / nmap-api credential-check JSONL:
                    #   {"host":"1.2.3.4","port":22,"protocol":"ssh",
                    #    "username":"x","success":true}
                    #
                    # Current brutus (multi-subcommand v9+) only emits rows
                    # for SUCCESSFUL attempts, with no `success` field and
                    # a combined target string:
                    #   {"target":"1.2.3.4:22","protocol":"ssh",
                    #    "username":"x","password":"y","duration":"..."}
                    #
                    # Treat absence-of-success-field-with-password-present as
                    # implicit success (matches current brutus semantics), and
                    # fall back to splitting `target` when host/port aren't
                    # provided separately.
                    ip = rec.get("host") or rec.get("ip")
                    port = rec.get("port")
                    if (not ip or not port) and rec.get("target"):
                        tgt = rec["target"]
                        if ":" in tgt:
                            tgt_host, _, tgt_port = tgt.rpartition(":")
                            ip = ip or tgt_host
                            try:
                                port = port or int(tgt_port)
                            except ValueError:
                                pass
                        else:
                            ip = ip or tgt
                    protocol = rec.get("protocol", "unknown")
                    username = rec.get("username", "")
                    # success: honour explicit value; otherwise infer from
                    # the row's presence + a password being captured (the
                    # current-brutus contract).
                    if "success" in rec:
                        success = bool(rec["success"])
                    else:
                        success = bool(rec.get("password") or rec.get("username"))
                    if not ip or not port or not success:
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue
                    # Look up asset
                    cur.execute("SELECT id FROM assets WHERE ip = %s", (ip,))
                    row = cur.fetchone()
                    asset_id = str(row["id"]) if row else None
                    # Look up port
                    port_id = None
                    if asset_id:
                        cur.execute("SELECT id FROM ports WHERE asset_id=%s AND port=%s", (asset_id, int(port)))
                        prow = cur.fetchone()
                        if prow: port_id = str(prow["id"])
                    # The recovered secret IS stored, in PLAINTEXT, by operator
                    # decision: a password nobody can read is useless for the
                    # lateral movement this phase exists to enable. See the
                    # CAUTION on credential_findings.secret_value in
                    # db_init/ensure_all_tables.sql for what that implies.
                    #
                    # Not logged here. nmap_scanner/nmap-api.py already prints
                    # valid credentials at INFO for the operator's job log; adding
                    # a second copy in the ingest log widens the blast radius of
                    # a shipped log bundle for no extra information.
                    secret_value = rec.get("password")
                    if secret_value is not None:
                        secret_value = str(secret_value)
                        # An empty password is a REAL finding (anonymous FTP), so
                        # "" is stored as-is and only a missing key becomes NULL.
                    # Metadata captures the audit trail when present:
                    #   - job_id : ties row back to the scan
                    #   - audit  : per-attempt list (users tried, passwords
                    #              masked, failure modes, KEX-legacy detection,
                    #              summary).  Populated by the credential-check
                    #              path (nmap_scanner/cred_checker.py).
                    #              Optional -- the brutus runner JSONL omits
                    #              it, in which case the row just has no
                    #              audit panel in the UI.
                    meta = {}
                    if job_id:
                        meta["job_id"] = job_id
                    rec_audit = rec.get("audit")
                    if rec_audit:
                        meta["audit"] = rec_audit
                    cur.execute("""
                        INSERT INTO credential_findings (id, asset_id, port_id, ip, port, protocol, username, valid_cred, auth_type, secret_type, source, metadata, secret_value, discovered_at, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, true, %s, %s, 'brutus', %s, %s, now(), 'valid')
                        -- NOTE: this clause is UNREACHABLE in the deployed
                        -- schema. trg_credential_findings_dedup is a BEFORE
                        -- INSERT trigger that updates the existing row and
                        -- RETURNs NULL, so the statement is cancelled before any
                        -- conflict can be raised — an INSERT of a known
                        -- credential reports "INSERT 0 0". The re-verification
                        -- (including carrying a newly recovered secret_value onto
                        -- the existing row) therefore happens IN THE TRIGGER, and
                        -- that is the place to change it.
                        --
                        -- Kept rather than deleted because it is the correct
                        -- fallback if the trigger is ever dropped, and because
                        -- uq_credential_findings_identity still exists: the
                        -- COALESCE must match that index EXPRESSION exactly, since
                        -- auth_type is nullable and a NULL makes rows non-equal
                        -- for a unique index.
                        ON CONFLICT (ip, port, username, COALESCE(auth_type, ''))
                          DO UPDATE SET
                            valid_cred       = EXCLUDED.valid_cred,
                            status           = EXCLUDED.status,
                            last_verified_at = now(),
                            metadata         = COALESCE(EXCLUDED.metadata,
                                                        credential_findings.metadata),
                            -- Never overwrite a stored secret with a NULL: a
                            -- re-verification run that did not capture the
                            -- password must not erase the one we already have.
                            secret_value     = COALESCE(EXCLUDED.secret_value,
                                                        credential_findings.secret_value)
                    """, (str(uuid.uuid4()), asset_id, port_id, ip, int(port), protocol, username,
                          secret_type, secret_type, json.dumps(meta), secret_value))
                    stats["credentials_found"] += 1
                    cur.execute("RELEASE SAVEPOINT rec_sp")
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT rec_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5: stats["error_examples"].append(f"{type(e).__name__}: {e}")
            conn.commit()
    finally:
        conn.close()
    return stats
