"""Bridge verified service credentials into the vault and the identity directory.

WHY THIS EXISTS
---------------
Brutus (hydra/medusa/ncrack) and the credential-check path write **verified**
service credentials to `credential_findings`. The Users page reads `identities`
and badges a row when a matching `credential_vault` entry exists. Nothing
connected the two, so seven confirmed valid credentials on 192.168.1.150 were
invisible to every consumer that reads the vault:

  * `GET /identities` — `has_credential` is `EXISTS (… FROM credential_vault …)`
  * `GET /identities/{id}` — the `credentials` block on the detail panel
  * `/cloud/posture`, the MCP credential tools, the exploit recommenders

`vault_import_agent.import_secrets_from_recon` already bridges *recon_findings*
→ vault, but only for cloud-secret finding types; it has never read
`credential_findings`. This module is the missing half.

Both halves are documented design intent, not invention. From the DDL:

    Identities — unified directory of detected user / SP / guest accounts.
    Populated by parsers (microburst, azurehound, netexec, impacket, ...) via
    upsert; one row per (provider, identifier). Links to credential_vault when
    credentials for the same username/UPN are discovered.

`netexec`/`impacket` are host-account tools, so host-local accounts always
belonged in `identities` — only the cloud parsers were ever wired up.

GRAIN — one vault row per (source, host, username), NOT per finding
------------------------------------------------------------------
`credential_findings` is per service: `msfadmin` on 192.168.1.150 appears three
times (ftp/21, telnet/23, ftp/2121). `credential_vault` has no service column,
so one row per finding would store three rows differing only in
`source_entity_id` — indistinguishable duplicates in every UI that reads them.

That is the same duplication this codebase has spent real effort removing, so
the grain here is the **account**: one row per (source, host, username), with
the services it was proven against recorded in `grants_access_to` (the port
ids — a column nothing had ever fed) and spelled out in `notes`.

IDEMPOTENCY
-----------
`source_entity_id` is a deterministic `uuid5` of `{source}:{host}:{username}` —
the account *is* the identity, so re-running the bridge updates in place. That
makes the existing `ux_credvault_source_entity` a real dedup key. It is a
**partial** index (`WHERE source_entity_id IS NOT NULL`, so hand-added creds
without one don't collide), and Postgres requires `ON CONFLICT` to repeat that
predicate exactly or it refuses with "no unique or exclusion constraint matching
the ON CONFLICT specification".

THE SECRET ITSELF IS NOT COPIED, BECAUSE IT WAS NEVER STORED
------------------------------------------------------------
`etl/parse_brutus.py` records the *username* and, in `metadata.audit`, only
**masked** passwords (`msf*****`). There is no plaintext to bridge, so
`credential_value` stays NULL and `notes` says so outright.

Writing the masked string into `credential_value` would be worse than leaving it
empty: a downstream tool would treat `msf*****` as a usable password and every
authentication attempt with it would fail for a reason nobody could see. A NULL
is honestly empty; a mask is a plausible lie. Changing brutus to retain
plaintext is a separate, deliberate decision — the vault row is still worth
having without it, because "this account is confirmed valid on these services"
is the fact an operator plans lateral movement from.
"""
import logging
import uuid
from typing import Any, Optional

__all__ = ["bridge_credential_findings", "vault_credential_type", "BRIDGE_PROVIDER"]

log = logging.getLogger("credential_bridge")

# The identity namespace for host-local accounts. `identities.provider` holds a
# directory/cloud namespace ('azure', 'on_prem_ad', 'aws', 'gcp'); an account
# that exists on one host and no directory is 'local'. `principal_type` stays
# within the existing vocabulary ('user') rather than inventing a value the
# frontend filter has never heard of.
BRIDGE_PROVIDER = "local"
BRIDGE_PRINCIPAL_TYPE = "user"

# credential_findings.secret_type and credential_vault.credential_type are two
# different CHECK-constrained vocabularies that overlap but are NOT equal. These
# three have no direct counterpart:
#
#   kerberos_ticket -> krb_tgt      (the vault splits TGT from TGS; a captured
#                                    ticket without a service name is a TGT)
#   aws_key         -> aws_access_key
#   azure_key       -> other        (the vault offers azure_oauth and azure_sp;
#                                    "azure_key" does not say which, and naming
#                                    the wrong one is a worse record than 'other')
#
# Unmapped values fall through to 'other' rather than raising: a CHECK violation
# would abort the row, and losing a verified credential to a vocabulary mismatch
# is the failure mode this whole module exists to fix.
_SECRET_TYPE_TO_VAULT = {
    "password": "password",
    "ntlm_hash": "ntlm_hash",
    "ssh_key": "ssh_key",
    "api_token": "api_token",
    "certificate": "certificate",
    "kerberos_ticket": "krb_tgt",
    "aws_key": "aws_access_key",
    "azure_key": "other",
    "other": "other",
}
_VAULT_FALLBACK_TYPE = "other"

# credential_findings.status is free-form observation ('valid', 'unknown', ...);
# credential_vault.status is CHECK-constrained lifecycle. A credential we hold
# and have not retired is 'active'; 'revoked' is the only other honest outcome.
_STATUS_TO_VAULT = {
    "valid": "active",
    "unknown": "active",
    "invalid": "revoked",
    "revoked": "revoked",
    "expired": "expired",
}

# Account names that ARE privileged by definition on the platform that has them,
# so the Users page can sort them first (`ORDER BY is_admin DESC`). Deliberately
# narrow and name-based: 'msfadmin' and 'admin' are only conventionally
# privileged, and flagging a guess would push the wrong row to the top of the
# operator's list.
_ALWAYS_PRIVILEGED = {"root", "administrator"}

_NOTE_NO_SECRET = (
    "Verified valid by credential testing; the secret itself was NOT retained "
    "(parse_brutus stores only masked passwords in metadata.audit), so "
    "credential_value is empty by design rather than by omission."
)


def vault_credential_type(secret_type: Optional[str]) -> str:
    """Map a credential_findings.secret_type onto the vault's CHECK vocabulary."""
    if not secret_type:
        return "password"      # credential_findings' own column default
    return _SECRET_TYPE_TO_VAULT.get(
        str(secret_type).strip().lower(), _VAULT_FALLBACK_TYPE)


def _vault_status(status: Optional[str]) -> str:
    if not status:
        return "active"
    return _STATUS_TO_VAULT.get(str(status).strip().lower(), "active")


def _account_uuid(source: str, host: str, username: str) -> str:
    """Stable identity for an account, so re-running updates instead of adding."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL,
                          f"credfinding:{source}:{host}:{username.lower()}"))


def bridge_credential_findings(cur,
                               engagement_id: Optional[str] = None,
                               only_valid: bool = True,
                               dry_run: bool = True,
                               limit: int = 1000,
                               sources: Optional[list] = None) -> dict:
    """`credential_findings` → `credential_vault` + `identities`.

    Groups findings by (source, host, username) so one account produces one
    vault row and one identity regardless of how many services it was proven
    on. `dry_run=True` returns the proposals and writes nothing.

    `sources` restricts the sweep to specific `credential_findings.source`
    values. Without it the default is every source, which is what a post-ingest
    run wants — but it also means a caller experimenting against a live database
    rewrites every account in it. Tests MUST pass their own source so their
    writes cannot reach real engagement data.

    Returns counts plus `proposals` (dry run) or `errors` (commit).
    """
    conds = []
    args: list[Any] = []
    if only_valid:
        # A credential that failed verification is not a credential we hold.
        conds.append("cf.valid_cred IS TRUE")
    if engagement_id:
        conds.append("cf.engagement_id = %s::uuid")
        args.append(engagement_id)
    if sources:
        conds.append("COALESCE(cf.source, 'brutus') = ANY(%s)")
        args.append(list(sources))
    where = (" WHERE " + " AND ".join(conds)) if conds else ""
    args.append(limit)

    cur.execute(f"""
        SELECT cf.id::text            AS id,
               host(cf.ip)            AS host,
               cf.port, cf.protocol, cf.username,
               COALESCE(cf.source, 'brutus') AS source,
               cf.secret_type, cf.auth_type, cf.status, cf.valid_cred,
               -- Resolve the service by ADDRESS, falling back from the finding's
               -- own port_id, which is NULL on every row that exists today:
               -- parse_brutus looks the port up under the finding's asset_id, and
               -- this host is stored as TWO asset rows -- one carrying the
               -- hostname and zero ports, one carrying 57 ports and no hostname.
               -- The finding attached to the former, so the lookup found nothing.
               -- Keying on (ip, port) survives that split.
               COALESCE(cf.port_id::text, (
                   SELECT p.id::text FROM ports p
                     JOIN assets a ON a.id = p.asset_id
                    WHERE a.ip = cf.ip AND p.port = cf.port
                    ORDER BY p.last_seen DESC NULLS LAST
                    LIMIT 1
               ))                     AS port_id,
               cf.asset_id::text      AS asset_id,
               cf.engagement_id::text AS engagement_id,
               cf.discovered_at, cf.last_verified_at
        FROM credential_findings cf
        {where}
        ORDER BY cf.discovered_at DESC NULLS LAST, cf.id
        LIMIT %s
    """, args)
    findings = cur.fetchall()

    # ── group into accounts ────────────────────────────────────────────────
    accounts: dict[tuple, dict] = {}
    for f in findings:
        username = (f["username"] or "").strip()
        host = f["host"]
        if not username or not host:
            continue
        key = (f["source"], host, username.lower())
        acct = accounts.get(key)
        if acct is None:
            acct = accounts[key] = {
                "source": f["source"],
                "host": host,
                "username": username,
                "secret_type": f["secret_type"],
                "status": f["status"],
                "engagement_id": f["engagement_id"] or engagement_id,
                "services": [],
                "port_ids": [],
                "finding_ids": [],
            }
        svc = (f["protocol"] or "tcp", int(f["port"]))
        if svc not in acct["services"]:
            acct["services"].append(svc)
        if f["port_id"] and f["port_id"] not in acct["port_ids"]:
            acct["port_ids"].append(f["port_id"])
        acct["finding_ids"].append(f["id"])

    proposals = []
    for (source, host, uname_lc), acct in accounts.items():
        # sort on the tuple so 23 precedes 2121; render after, or
        # string ordering puts "ftp/2121" before "telnet/23"
        services = [f"{proto}/{port}" for proto, port
                    in sorted(acct["services"], key=lambda s: (s[0], s[1]))]
        proposals.append({
            "source": source,
            "source_entity_id": _account_uuid(source, host, acct["username"]),
            "username": acct["username"],
            "domain": host,          # identifier becomes username@host
            "credential_type": vault_credential_type(acct["secret_type"]),
            "status": _vault_status(acct["status"]),
            "engagement_id": acct["engagement_id"],
            "grants_access_to": acct["port_ids"],
            "services": services,
            "finding_count": len(acct["finding_ids"]),
            "identity_identifier": f"{acct['username']}@{host}",
            "is_admin": uname_lc in _ALWAYS_PRIVILEGED,
            "notes": (f"Valid on {', '.join(services)} at {host} "
                      f"(source: {source}). {_NOTE_NO_SECRET}"),
        })
    proposals.sort(key=lambda p: (p["domain"], p["username"]))

    if dry_run:
        return {
            "dry_run": True,
            "findings_examined": len(findings),
            "accounts": len(proposals),
            "proposals": proposals,
            "credentials_upserted": 0,
            "identities_upserted": 0,
            "errors": [],
        }

    # ── commit ─────────────────────────────────────────────────────────────
    try:
        from etl.identity_upsert import upsert_identity
    except ImportError:                     # rag-api imports etl as a top-level pkg
        from identity_upsert import upsert_identity   # type: ignore

    creds = idents = 0
    errors: list[str] = []
    for p in proposals:
        try:
            cur.execute("SAVEPOINT cred_bridge_sp")
            cur.execute("""
                INSERT INTO credential_vault
                    (engagement_id, username, domain, credential_type,
                     credential_value, source, source_entity_id, status,
                     grants_access_to, notes)
                VALUES (%s::uuid, %s, %s, %s, NULL, %s, %s::uuid, %s, %s::uuid[], %s)
                -- ux_credvault_source_entity is PARTIAL; the WHERE clause must be
                -- repeated verbatim or Postgres refuses the ON CONFLICT outright.
                ON CONFLICT (source, source_entity_id) WHERE source_entity_id IS NOT NULL
                  DO UPDATE SET status           = EXCLUDED.status,
                                credential_type  = EXCLUDED.credential_type,
                                -- a later scan can prove MORE services; never fewer
                                grants_access_to = EXCLUDED.grants_access_to,
                                notes            = EXCLUDED.notes,
                                updated_at       = now()
            """, (p["engagement_id"], p["username"], p["domain"],
                  p["credential_type"], p["source"], p["source_entity_id"],
                  p["status"], p["grants_access_to"] or None, p["notes"]))
            creds += 1

            upsert_identity(
                cur,
                provider=BRIDGE_PROVIDER,
                identifier=p["identity_identifier"],
                source=p["source"],
                display_name=p["username"],
                principal_type=BRIDGE_PRINCIPAL_TYPE,
                status="active",
                domain=p["domain"],
                is_admin=p["is_admin"] or None,   # None leaves an existing true alone
                tags=[f"service:{s}" for s in p["services"]] + [f"host:{p['domain']}"],
                raw={"services": p["services"], "host": p["domain"],
                     "bridged_from": "credential_findings"},
                engagement_id=p["engagement_id"],
            )
            idents += 1
            cur.execute("RELEASE SAVEPOINT cred_bridge_sp")
        except Exception as e:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT cred_bridge_sp")
            except Exception:
                pass
            if len(errors) < 10:
                errors.append(f"{p['username']}@{p['domain']}: {type(e).__name__}: {e}")

    return {
        "dry_run": False,
        "findings_examined": len(findings),
        "accounts": len(proposals),
        "credentials_upserted": creds,
        "identities_upserted": idents,
        "errors": errors,
    }
