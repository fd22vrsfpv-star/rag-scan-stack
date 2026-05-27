"""
ETL parser for MicroBurst (NetSPI) Azure AD / Entra ID enumeration output.

MicroBurst is a PowerShell toolkit (https://github.com/NetSPI/MicroBurst) that
emits a directory of CSVs per tenant — typically zipped by the operator before
hand-off. This parser accepts either a `.zip` archive OR a directory path,
walks every CSV inside, classifies it by filename pattern, and inserts a row
per record into `recon_findings` with `source='microburst'`.

Finding-type taxonomy mirrors AzureHound so dedup/delta works cross-tool:
    azure_user, azure_group, azure_role_assignment, azure_app_registration,
    azure_service_principal, azure_device, azure_conditional_access,
    azure_domain, azure_directory_role, azure_secret_exposure
"""

import csv
import hashlib
import io
import logging
import os
import re
import uuid
import zipfile
from typing import Iterator, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor, Json, execute_values

log = logging.getLogger("parse_microburst")
log.setLevel(logging.INFO)

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

# Order matters: more specific patterns first (e.g. RoleMembers before Roles).
# Patterns are matched against the basename via re.search, so unanchored
# patterns work for both `AzureADUsers.csv` and `contoso-AzureADUsers.csv`.
# The Get-AzDomainInfo / Get-AzureADGroupMembers patterns at the bottom
# match files like `Users.CSV`, `Groups.CSV`, `<GroupName>_Users.CSV`.
FILENAME_RULES = [
    (re.compile(r"AzureADRoleMembers?", re.I),      "azure_role_assignment"),
    (re.compile(r"AzureADDirectoryRoles?", re.I),   "azure_directory_role"),
    (re.compile(r"AzureADRoles?", re.I),            "azure_directory_role"),
    (re.compile(r"AzureADConditionalAccess", re.I), "azure_conditional_access"),
    (re.compile(r"AzureADServicePrincipals?", re.I),"azure_service_principal"),
    (re.compile(r"AzureADApplications?", re.I),     "azure_app_registration"),
    (re.compile(r"AzureADAppRegistrations?", re.I), "azure_app_registration"),
    (re.compile(r"AzureADDevices?", re.I),          "azure_device"),
    (re.compile(r"AzureADGroups?", re.I),           "azure_group"),
    (re.compile(r"AzureADUsers?", re.I),            "azure_user"),
    (re.compile(r"AzureADDomains?", re.I),          "azure_domain"),
    (re.compile(r"AzureADTenants?", re.I),          "azure_tenant"),
    # Get-AzPasswords / Get-AzKeyVaultSecrets / etc. — credential exposures
    (re.compile(r"Get-?AzPasswords?", re.I),        "azure_secret_exposure"),
    (re.compile(r"KeyVaultSecrets?", re.I),         "azure_secret_exposure"),
    (re.compile(r"AppServiceCreds?", re.I),         "azure_secret_exposure"),
    (re.compile(r"AutomationAccounts?", re.I),      "azure_secret_exposure"),
    (re.compile(r"StorageAccountKeys?", re.I),      "azure_secret_exposure"),
    # Get-AzDomainInfo / Get-AzureADGroupMembers structure:
    #   Users.CSV               → master tenant users list
    #   Groups.CSV              → master tenant groups list
    #   <GroupName>_Users.CSV   → membership of one specific group (per-row = a user)
    # The membership pattern must come BEFORE the master pattern so the leading
    # underscore is required to claim a row as group-membership rather than
    # user-enumeration.
    (re.compile(r"_Users\.csv$", re.I),             "azure_group_member"),
    (re.compile(r"^Users\.csv$", re.I),             "azure_user"),
    (re.compile(r"^Groups\.csv$", re.I),            "azure_group"),
]

# Severity per finding_type. Refined types (Pass 1) carry the privilege signal
# in the type itself, so rule matching is schema-aware instead of regex-over-jsonb.
DEFAULT_SEVERITY = {
    # Secrets always critical
    "azure_secret_exposure":          "critical",
    # Role-assignment tiers (refined from base azure_role_assignment)
    "azure_role_global_admin":        "critical",  # Global/Privileged Role/Privileged Auth Admin
    "azure_role_app_admin":           "high",      # Application/Cloud App/Hybrid Identity Admin
    "azure_role_service_principal":   "high",      # SP holding any role (no MFA path)
    "azure_role_assignment":          "medium",    # other roles; bumped to high if keyword-priv
    # User subtypes
    "azure_user_dirsync":             "critical",  # AAD Connect / on-prem sync identity
    "azure_user_guest":               "info",      # info on its own; cross-rule with role catches privilege
    "azure_user":                     "info",
    # App / SP / CA / domain / device subtypes
    "azure_app_with_secret":          "high",      # App registration with stored credential
    "azure_app_registration":         "medium",
    "azure_service_principal":        "medium",
    "azure_ca_disabled":              "high",
    "azure_conditional_access":       "info",
    "azure_domain_federated":         "high",
    "azure_domain":                   "info",
    "azure_device_unmanaged":         "medium",
    "azure_device":                   "info",
    # Group membership (from <GroupName>_Users.CSV) — info by default,
    # bumped to medium in _row_to_tuple if the group name suggests privilege
    # (admin / owner / global / contributor / privileged keyword match).
    "azure_group_member":             "info",
    # Untiered / passive
    "azure_directory_role":           "info",
    "azure_group":                    "info",
    "azure_tenant":                   "info",
}

PRIVILEGED_ROLE_KEYWORDS = ("owner", "contributor", "admin", "global", "privileged")

# Specific Entra role names that warrant tier-0 / tier-1 promotion.
GLOBAL_ADMIN_ROLES = (
    "global administrator",
    "privileged role administrator",
    "privileged authentication administrator",
)
APP_ADMIN_ROLES = (
    "application administrator",
    "cloud application administrator",
    "hybrid identity administrator",
)
DIRSYNC_NAME_RE = re.compile(
    r"On-Premises Directory Synchronization Service Account"
    r"|^MSOL_[A-Fa-f0-9]+"
    r"|^Sync_[A-Za-z0-9_-]+"
    r"|^AAD_[A-Fa-f0-9]+",
)


def _row_role_text(row: dict) -> str:
    """Concatenate all 'role'-named columns into a single lower-cased string."""
    parts = [str(v) for k, v in row.items() if "role" in k.lower() and v]
    return " ".join(parts).lower()


def _row_get_ci(row: dict, *keys: str):
    """Case-insensitive get-first-of for column names that vary across MicroBurst versions."""
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return row[k]
        # case-insensitive fallback
        for rk, rv in row.items():
            if rk.lower() == k.lower() and rv not in (None, ""):
                return rv
    return None


def _refine_finding_type(row: dict, base_type: str) -> str:
    """Promote a base finding_type to a more specific subtype based on row content.

    This pushes the privilege signal into the type itself so rules can do simple
    `where: {finding_type: azure_role_global_admin}` instead of regex-matching jsonb.
    """
    if not isinstance(row, dict):
        return base_type

    if base_type == "azure_role_assignment":
        role_text = _row_role_text(row)
        if any(r in role_text for r in GLOBAL_ADMIN_ROLES):
            return "azure_role_global_admin"
        if any(r in role_text for r in APP_ADMIN_ROLES):
            return "azure_role_app_admin"
        ptype = str(_row_get_ci(row, "PrincipalType") or "").lower()
        if ptype == "serviceprincipal":
            return "azure_role_service_principal"
        return base_type

    if base_type == "azure_app_registration":
        for key in ("PasswordCredentials", "KeyCredentials"):
            v = _row_get_ci(row, key)
            if v and str(v).strip() not in ("", "[]", "null", "None"):
                return "azure_app_with_secret"
        return base_type

    if base_type == "azure_conditional_access":
        state = str(_row_get_ci(row, "State", "Enabled") or "").lower()
        if state in ("disabled", "false", "0"):
            return "azure_ca_disabled"
        return base_type

    if base_type == "azure_domain":
        atype = str(_row_get_ci(row, "AuthenticationType", "Type") or "").lower()
        if atype == "federated":
            return "azure_domain_federated"
        return base_type

    if base_type == "azure_user":
        name_blob = " ".join(
            str(_row_get_ci(row, k) or "")
            for k in ("DisplayName", "UserPrincipalName")
        )
        if DIRSYNC_NAME_RE.search(name_blob):
            return "azure_user_dirsync"
        utype = str(_row_get_ci(row, "UserType") or "").lower()
        if utype == "guest":
            return "azure_user_guest"
        return base_type

    if base_type == "azure_device":
        managed = str(_row_get_ci(row, "IsManaged") or "").lower()
        mdm = str(_row_get_ci(row, "MDMAppId") or "").lower()
        if managed in ("false", "0", "none", "") and mdm in ("", "none", "null"):
            return "azure_device_unmanaged"
        return base_type

    return base_type


def _classify(filename: str) -> str:
    """Map a CSV filename to a finding_type. Returns 'azure_entity' if unknown."""
    base = os.path.basename(filename)
    for pat, ftype in FILENAME_RULES:
        if pat.search(base):
            return ftype
    return "azure_entity"


def _row_target(row: dict, finding_type: str) -> str:
    """Pick the most identifying column for the `target` field."""
    # Refined subtypes inherit their base type's target preferences.
    USER_KEYS = ("UserPrincipalName", "userPrincipalName", "Mail", "DisplayName", "Id")
    ROLE_KEYS = ("PrincipalDisplayName", "RoleDisplayName", "PrincipalId")
    APP_KEYS  = ("DisplayName", "AppId", "Id")
    DEV_KEYS  = ("DisplayName", "DeviceId", "Id")
    DOM_KEYS  = ("Name", "DomainName", "Id")
    CA_KEYS   = ("DisplayName", "PolicyId", "Id")
    candidates_by_type = {
        "azure_user":                    USER_KEYS,
        "azure_user_dirsync":            USER_KEYS,
        "azure_user_guest":              USER_KEYS,
        "azure_group":                   ("DisplayName", "MailNickname", "Id"),
        "azure_role_assignment":         ROLE_KEYS,
        "azure_role_global_admin":       ROLE_KEYS,
        "azure_role_app_admin":          ROLE_KEYS,
        "azure_role_service_principal":  ROLE_KEYS,
        "azure_directory_role":          ("DisplayName", "RoleTemplateId", "Id"),
        "azure_app_registration":        APP_KEYS,
        "azure_app_with_secret":         APP_KEYS,
        "azure_service_principal":       ("DisplayName", "AppId", "ServicePrincipalNames", "Id"),
        "azure_device":                  DEV_KEYS,
        "azure_device_unmanaged":        DEV_KEYS,
        "azure_conditional_access":      CA_KEYS,
        "azure_ca_disabled":             CA_KEYS,
        "azure_domain":                  DOM_KEYS,
        "azure_domain_federated":        DOM_KEYS,
        "azure_tenant":                  ("DisplayName", "TenantId", "Id"),
        "azure_secret_exposure":         ("Name", "VaultName", "ResourceName", "AccountName", "Id"),
    }
    for key in candidates_by_type.get(finding_type, ("DisplayName", "Name", "Id")):
        v = row.get(key)
        if v:
            return str(v)
    # Fallback: first non-empty value
    for v in row.values():
        if v:
            return str(v)
    return finding_type


def _row_severity(row: dict, finding_type: str) -> str:
    sev = DEFAULT_SEVERITY.get(finding_type, "info")
    # For un-refined role assignments, still bump severity if a privileged keyword
    # appears in any role-named column. Refined types already encode the tier.
    if finding_type == "azure_role_assignment":
        role_text = _row_role_text(row)
        if any(kw in role_text for kw in PRIVILEGED_ROLE_KEYWORDS):
            return "high"
    return sev


def _hash_file_bytes(full_path: str) -> str:
    """MD5 of file contents in 1MB chunks. Cheap (~500MB/s), 32 hex chars,
    plenty for "did this CSV change" detection."""
    h = hashlib.md5()
    try:
        with open(full_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def _iter_csvs(path: str):
    """Yield (filename, content_hash, rows_loader) for every CSV under `path`.

    `rows_loader` is a zero-arg callable that returns the materialized list
    of rows. The body is NOT read until the caller invokes it — this lets
    the resume check decide to skip cheaply.

    `content_hash` is a short identity for the CSV's bytes:
      - Zip mode: hex(CRC32) from the zip header (zero extra I/O — already
        computed when the zip was created).
      - Directory / single-file mode: MD5 over the file bytes.
    Both are non-cryptographic but ample for "did this file change since
    last ingest" detection. Caller compares to the asset's stored
    `content_hash` to decide whether a same-named re-upload counts as new
    data or a redundant reload.

    Files are processed largest-first.
    """
    if zipfile.is_zipfile(path):
        zf = zipfile.ZipFile(path)
        try:
            csvs = [info for info in zf.infolist()
                    if not info.is_dir() and info.filename.lower().endswith(".csv")]
            csvs.sort(key=lambda i: i.file_size, reverse=True)
            for info in csvs:
                # CRC32 from zip header — no body read needed
                content_hash = f"crc32:{info.CRC:08x}"

                def _load(info=info, zf=zf):
                    with zf.open(info) as fh:
                        text = io.TextIOWrapper(fh, encoding="utf-8-sig", errors="replace")
                        return list(csv.DictReader(text))
                yield info.filename, content_hash, _load
        finally:
            zf.close()
        return

    if os.path.isdir(path):
        entries: list[tuple[int, str, str]] = []
        for root, _dirs, files in os.walk(path):
            for fn in files:
                if not fn.lower().endswith(".csv"):
                    continue
                full = os.path.join(root, fn)
                try:
                    sz = os.path.getsize(full)
                except OSError:
                    sz = 0
                entries.append((sz, fn, full))
        entries.sort(key=lambda t: t[0], reverse=True)
        for _sz, fn, full in entries:
            content_hash = f"md5:{_hash_file_bytes(full)}"

            def _load(full=full):
                with open(full, encoding="utf-8-sig", errors="replace", newline="") as fh:
                    return list(csv.DictReader(fh))
            yield fn, content_hash, _load
        return

    if path.lower().endswith(".csv") and os.path.isfile(path):
        content_hash = f"md5:{_hash_file_bytes(path)}"

        def _load(p=path):
            with open(p, encoding="utf-8-sig", errors="replace", newline="") as fh:
                return list(csv.DictReader(fh))
        yield os.path.basename(path), content_hash, _load
        return

    return


_IDENTITY_TYPES = {
    "azure_user", "azure_user_guest", "azure_user_dirsync",
    "azure_service_principal",
    "azure_role_assignment", "azure_role_global_admin",
    "azure_role_app_admin", "azure_role_service_principal",
    "azure_group_member",
}


def _identity_from_row(row: dict, finding_type: str) -> dict | None:
    """Extract the identity (user / SP / principal) implied by this row.

    Returns kwargs for `upsert_identity`, or None if the row carries no usable
    identity (e.g. groups, devices, domains).
    """
    if finding_type not in _IDENTITY_TYPES:
        return None

    raw_clean = {k: v for k, v in row.items() if v not in (None, "")}
    tenant_id = _row_get_ci(row, "TenantId", "tenantId")

    if finding_type == "azure_group_member":
        # Each row in <GroupName>_Users.CSV is a user who is a member of that
        # group. Treat them as user identities; the group context is added as
        # a `member_of:<group>` tag at the call site (where source_file is in
        # scope).
        identifier = (_row_get_ci(row, "UserPrincipalName")
                      or _row_get_ci(row, "Mail")
                      or _row_get_ci(row, "Id", "ObjectId"))
        if not identifier:
            return None
        utype = str(_row_get_ci(row, "UserType") or "").lower()
        return dict(
            provider="azure",
            identifier=str(identifier),
            display_name=_row_get_ci(row, "DisplayName"),
            principal_type="guest" if utype == "guest" else "user",
            is_guest=(utype == "guest"),
            tenant_id=tenant_id,
            raw={"microburst_group_member": raw_clean},
            source="microburst",
        )

    if finding_type in ("azure_user", "azure_user_guest", "azure_user_dirsync"):
        identifier = (_row_get_ci(row, "UserPrincipalName")
                      or _row_get_ci(row, "Mail")
                      or _row_get_ci(row, "Id", "ObjectId"))
        if not identifier:
            return None
        enabled = str(_row_get_ci(row, "AccountEnabled", "Enabled") or "").lower()
        if enabled in ("true", "1"):
            status = "active"
        elif enabled in ("false", "0"):
            status = "disabled"
        else:
            status = "unknown"
        return dict(
            provider="azure",
            identifier=str(identifier),
            display_name=_row_get_ci(row, "DisplayName"),
            principal_type="guest" if finding_type == "azure_user_guest" else "user",
            status=status,
            is_guest=(finding_type == "azure_user_guest"),
            is_dirsync=(finding_type == "azure_user_dirsync"),
            tenant_id=tenant_id,
            raw={"microburst_user": raw_clean},
            source="microburst",
        )

    if finding_type == "azure_service_principal":
        identifier = (_row_get_ci(row, "AppId")
                      or _row_get_ci(row, "ServicePrincipalNames")
                      or _row_get_ci(row, "Id", "ObjectId"))
        if not identifier:
            return None
        return dict(
            provider="azure",
            identifier=str(identifier),
            display_name=_row_get_ci(row, "DisplayName"),
            principal_type="service_principal",
            tenant_id=tenant_id,
            raw={"microburst_sp": raw_clean},
            source="microburst",
        )

    # Role assignment: identity is the principal, admin flag set if role is privileged.
    if finding_type.startswith("azure_role_"):
        ptype = (_row_get_ci(row, "PrincipalType") or "User").lower()
        if ptype == "serviceprincipal":
            principal_type = "service_principal"
        elif ptype == "group":
            principal_type = "group"
        else:
            principal_type = "user"
        identifier = (_row_get_ci(row, "PrincipalUPN")
                      or _row_get_ci(row, "PrincipalEmail")
                      or _row_get_ci(row, "PrincipalId")
                      or _row_get_ci(row, "PrincipalDisplayName"))
        if not identifier:
            return None
        is_admin = finding_type in (
            "azure_role_global_admin", "azure_role_app_admin",
            "azure_role_service_principal",
        )
        if finding_type == "azure_role_assignment":
            role_text = _row_role_text(row)
            is_admin = any(kw in role_text for kw in PRIVILEGED_ROLE_KEYWORDS)
        return dict(
            provider="azure",
            identifier=str(identifier),
            display_name=_row_get_ci(row, "PrincipalDisplayName"),
            principal_type=principal_type,
            is_admin=is_admin,
            tenant_id=tenant_id,
            raw={"microburst_role": raw_clean},
            source="microburst",
        )

    return None


def _row_to_tuple(row: dict, finding_type: str, source_file: str,
                  asset_id=None, engagement_id=None):
    """Build the parameter tuple for a single recon_findings INSERT.

    Order matches _VALUES_TEMPLATE: (id, asset_id, finding_type, target, data,
    severity, engagement_id). When asset_id / engagement_id are None the row
    stays unscoped — same behavior as before.
    """
    target = _row_target(row, finding_type)
    severity = _row_severity(row, finding_type)
    # Group-membership severity bump: when the group name (encoded in the CSV
    # filename, e.g. `Tenant_Admins_Users.CSV`) suggests a privileged group,
    # promote `info` → `medium` so triage surfaces sensitive memberships.
    if finding_type == "azure_group_member" and source_file:
        gname = source_file.lower()
        if any(kw in gname for kw in PRIVILEGED_ROLE_KEYWORDS):
            severity = "medium"
    data = {
        "provider": "azure",
        "source_file": source_file,
        "row": {k: v for k, v in row.items() if v not in (None, "")},
    }
    return (
        str(uuid.uuid4()),
        asset_id,
        finding_type,
        str(target)[:500],
        Json(data),
        severity,
        engagement_id,
    )


_INSERT_SQL = """
    INSERT INTO recon_findings
        (id, asset_id, source, finding_type, target, data, severity, engagement_id)
    VALUES %s
    ON CONFLICT DO NOTHING
"""

# execute_values template: 'microburst' is a literal so it doesn't bloat the args list.
_VALUES_TEMPLATE = "(%s, %s, 'microburst', %s, %s, %s, %s, %s)"

# Synthetic IP marker for cloud-import assets (no real network meaning, just a
# placeholder so the assets table's NOT NULL ip column is satisfied).
_CLOUD_IMPORT_IP = "127.0.1.1"


def _ensure_cloud_import_asset(cur, engagement_id: str | None,
                               filename: str,
                               content_hash: str | None = None) -> str | None:
    """Find-or-create an asset row for this CSV file under the engagement.

    Stores `content_hash` so the resume check can detect when the same
    filename has been re-uploaded with different bytes. Updates the hash
    on conflict so a re-ingest of changed content refreshes the marker.

    Returns the asset's UUID, or None if no engagement_id was provided.
    """
    if not engagement_id:
        return None
    eng_short = str(engagement_id).split("-")[0]
    hostname = f"{eng_short}/{filename}"
    cur.execute("""
        INSERT INTO assets (ip, hostname, env, tags, engagement_id, content_hash)
        VALUES (%s::inet, %s, 'cloud_import',
                ARRAY['cloud_import','microburst']::text[], %s::uuid, %s)
        ON CONFLICT (ip, COALESCE(hostname, '')) DO UPDATE
            SET last_seen     = now(),
                engagement_id = COALESCE(assets.engagement_id, EXCLUDED.engagement_id),
                content_hash  = COALESCE(EXCLUDED.content_hash, assets.content_hash)
        RETURNING id
    """, (_CLOUD_IMPORT_IP, hostname, engagement_id, content_hash))
    row = cur.fetchone()
    if row:
        return str(row["id"]) if isinstance(row, dict) or hasattr(row, "keys") else str(row[0])
    return None

_BATCH_SIZE = 500
_PROGRESS_TICK = 1000  # rows between progress callbacks
_FILES_PER_COMMIT = 10  # group commits across N files to amortize fsync cost
# Flush the in-memory identity buffer when it crosses this threshold. Without
# this, pending_identities[] grows unbounded during a 21k-file ingest — for
# group-member-heavy MicroBurst dumps that's millions of dicts in RAM and
# the Python GC starts stalling, which surfaces as idle-in-transaction
# pauses. 10k caps the buffer at a few MB.
_IDENT_FLUSH_THRESHOLD = 10_000


def parse_microburst(path: str, profile: str = "upload", job_id: str = None,
                     engagement_id: str = None, progress_cb=None):
    """Ingest a MicroBurst output bundle.

    `path` may be a .zip, dir, or single CSV.
    `engagement_id` (optional): when provided, every CSV becomes an asset under
    this engagement (ip=127.0.1.1, hostname=<engagement_short>/<filename>) and
    every recon_finding / identity gets engagement_id stamped.
    `progress_cb` (optional) is called as progress_cb(stats) every ~1000 rows;
    use it to update a jobs.progress jsonb column for the async endpoint.
    """
    stats = dict(
        records_seen=0,
        findings_inserted=0,
        identities_upserted=0,
        assets_created=0,
        files_processed=0,
        files_resumed_skip=0,   # files already fully ingested in a prior run
        skipped=0,
        errors=0,
        by_type={},
        error_examples=[],
    )

    # Lazy import — keep the module importable in environments where
    # identity_upsert isn't yet on the path (older deployments).
    try:
        from etl.identity_upsert import bulk_upsert_identities
    except Exception:
        bulk_upsert_identities = None

    def _bulk_flush_identities(cur, items: list):
        """Flush a per-file batch of identity dicts in a single execute_values
        round-trip. Wraps the call in a SAVEPOINT so a constraint violation
        on one identity doesn't blow up the whole file's transaction."""
        if not items or bulk_upsert_identities is None:
            return
        try:
            cur.execute("SAVEPOINT ident_bulk_sp")
            n = bulk_upsert_identities(cur, items)
            cur.execute("RELEASE SAVEPOINT ident_bulk_sp")
            stats["identities_upserted"] += n
        except Exception as e:
            try:
                cur.execute("ROLLBACK TO SAVEPOINT ident_bulk_sp")
            except Exception:
                pass
            stats["errors"] += 1
            if len(stats["error_examples"]) < 5:
                stats["error_examples"].append(f"identity_bulk {type(e).__name__}: {e}")

    def _flush(cur, batch, finding_type):
        """Bulk-insert one batch; on failure fall back to per-row inserts."""
        if not batch:
            return
        try:
            cur.execute("SAVEPOINT batch_sp")
            execute_values(cur, _INSERT_SQL, batch, template=_VALUES_TEMPLATE,
                           page_size=_BATCH_SIZE)
            cur.execute("RELEASE SAVEPOINT batch_sp")
            stats["findings_inserted"] += len(batch)
            stats["by_type"][finding_type] = stats["by_type"].get(finding_type, 0) + len(batch)
        except Exception as batch_exc:
            cur.execute("ROLLBACK TO SAVEPOINT batch_sp")
            # Per-row fallback so one bad row doesn't lose the whole batch
            for tup in batch:
                try:
                    cur.execute("SAVEPOINT row_sp")
                    cur.execute(_INSERT_SQL.replace("VALUES %s", f"VALUES {_VALUES_TEMPLATE}"), tup)
                    cur.execute("RELEASE SAVEPOINT row_sp")
                    stats["findings_inserted"] += 1
                    stats["by_type"][finding_type] = stats["by_type"].get(finding_type, 0) + 1
                except Exception as e:
                    cur.execute("ROLLBACK TO SAVEPOINT row_sp")
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5:
                        stats["error_examples"].append(f"{type(e).__name__}: {e}")
            if len(stats["error_examples"]) < 5:
                stats["error_examples"].append(f"batch fallback: {type(batch_exc).__name__}: {batch_exc}")

    def _file_already_ingested(cur, engagement_id, source_file,
                                new_hash: str | None = None) -> bool:
        """Resumability check: True if this file was fully committed in a prior
        run AND its current content hash matches what we have stored.

        Hash semantics:
          new_hash matches asset.content_hash → skip (truly identical)
          new_hash differs from asset.content_hash → re-process (new data)
          asset.content_hash IS NULL (legacy) AND new_hash given → skip
            (we trust the filename match for backward compat with rows
             ingested before the content_hash column existed)
          new_hash is None (caller didn't compute one) → fall back to
            "asset has findings" check, like before
        """
        if not engagement_id or not source_file:
            return False
        eng_short = str(engagement_id).split("-")[0]
        hostname = f"{eng_short}/{source_file}"
        try:
            cur.execute("""
                SELECT a.id AS asset_id, a.content_hash,
                       (SELECT count(*) FROM recon_findings rf
                         WHERE rf.asset_id=a.id AND rf.source='microburst') AS findings
                FROM assets a
                WHERE a.ip='127.0.1.1'::inet AND a.hostname=%s
                  AND a.engagement_id=%s::uuid
                LIMIT 1
            """, (hostname, engagement_id))
            row = cur.fetchone()
            if not row or not (row["findings"] and row["findings"] > 0):
                return False
            stored = row["content_hash"]
            if new_hash and stored and stored != new_hash:
                # Same filename, different content — re-ingest
                print(f"microburst-resume content-changed [{source_file}] "
                      f"old={stored[:24]} new={new_hash[:24]}", flush=True)
                return False
            return True
        except Exception:
            return False

    last_tick = 0
    conn = psycopg2.connect(DB_DSN)

    # Override _new_cursor so it can reopen the underlying connection too
    # (the previous version only recovered closed cursors). Connection death
    # — idle-timeout, server reset, network blip — was leaving us unable to
    # recover, killing long-running ingests after thousands of files.
    def _new_cursor():
        nonlocal conn
        if getattr(conn, "closed", False):
            try:
                conn.close()
            except Exception:
                pass
            conn = psycopg2.connect(DB_DSN)
        else:
            try:
                conn.rollback()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                conn = psycopg2.connect(DB_DSN)
        return conn.cursor(cursor_factory=RealDictCursor)

    cur = _new_cursor()
    # Cross-file identity accumulator: deferred upsert at end of ingest.
    # Identities for high-traffic users (in many groups) merge in-memory in
    # bulk_upsert_identities, so the heavy ON CONFLICT DO UPDATE only runs
    # once per unique identity at the end — not once per group_member row.
    pending_identities: list[dict] = []
    files_since_commit = 0  # group commits across _FILES_PER_COMMIT files

    def _maybe_commit():
        """Commit if the per-batch threshold is met. Also flushes the
        identity buffer when it crosses _IDENT_FLUSH_THRESHOLD so it
        doesn't grow unbounded across a million-row ingest."""
        nonlocal files_since_commit
        # Flush identities first (so they're in the same commit as the
        # recon_findings if both thresholds happen to hit on the same iter).
        if len(pending_identities) >= _IDENT_FLUSH_THRESHOLD:
            print(f"microburst: mid-ingest identity flush ({len(pending_identities):,} buffered)",
                  flush=True)
            try:
                _bulk_flush_identities(cur, pending_identities)
                pending_identities.clear()
            except Exception as e:
                if len(stats["error_examples"]) < 5:
                    stats["error_examples"].append(f"mid_ident_flush: {type(e).__name__}: {e}")
                pending_identities.clear()  # don't keep retrying the same bad batch
        if files_since_commit >= _FILES_PER_COMMIT:
            try:
                conn.commit()
                files_since_commit = 0
            except Exception as e:
                if len(stats["error_examples"]) < 5:
                    stats["error_examples"].append(f"group_commit failed: {type(e).__name__}: {e}")
                try:
                    conn.rollback()
                except Exception:
                    pass
                files_since_commit = 0

    try:
        for fname, content_hash, rows_loader in _iter_csvs(path):
            stats["files_processed"] += 1
            base_type = _classify(fname)
            source_file = os.path.basename(fname)

            # Resumability: skip files already fully ingested in a prior run
            # AND whose content hash matches. Filename match alone is
            # insufficient when the operator re-runs MicroBurst and uploads
            # a fresher dump — the CRC32 / MD5 catches that.
            if _file_already_ingested(cur, engagement_id, source_file, content_hash):
                stats["files_resumed_skip"] += 1
                print(f"microburst-resume skip [{stats['files_resumed_skip']}] {source_file}",
                      flush=True)
                continue

            # Not skipped — now realize the rows. This is where we pay the
            # CSV-decode + memory cost.
            try:
                rows = rows_loader()
            except Exception as e:
                stats["errors"] += 1
                if len(stats["error_examples"]) < 5:
                    stats["error_examples"].append(f"csv_read {source_file}: {type(e).__name__}: {e}")
                continue

            # Resolve (or create) the cloud-import asset for this CSV under
            # the engagement. We pass content_hash so the asset row records
            # what bytes we actually ingested — future resume checks will
            # use it to detect content drift.
            asset_id = None
            try:
                cur.execute("SAVEPOINT asset_sp")
                asset_id = _ensure_cloud_import_asset(cur, engagement_id, source_file, content_hash)
                cur.execute("RELEASE SAVEPOINT asset_sp")
                if asset_id:
                    stats["assets_created"] += 1
            except Exception as ae:
                try:
                    cur.execute("ROLLBACK TO SAVEPOINT asset_sp")
                except Exception:
                    cur.close()
                    cur = _new_cursor()
                asset_id = None
                if len(stats["error_examples"]) < 5:
                    stats["error_examples"].append(f"asset_upsert {type(ae).__name__}: {ae}")

            # Group tuples by refined finding_type so each batch is uniform
            # and stats["by_type"] gets the correct subtype credited.
            batches: dict[str, list[tuple]] = {}
            file_failed = False
            for row in rows:
                stats["records_seen"] += 1
                if not isinstance(row, dict):
                    stats["skipped"] += 1
                    continue
                try:
                    ft = _refine_finding_type(row, base_type)
                    batches.setdefault(ft, []).append(
                        _row_to_tuple(row, ft, source_file,
                                      asset_id=asset_id,
                                      engagement_id=engagement_id))
                    # Identity fan-out is now DEFERRED: we accumulate dicts
                    # across all files in `pending_identities` and bulk-upsert
                    # ONCE at end of ingest. Eliminates the per-file ON CONFLICT
                    # DO UPDATE round-trip from the hot path. bulk_upsert_identities
                    # pre-merges in Python so the same user appearing in 1000s of
                    # groups becomes one upsert call at the end.
                    ident = _identity_from_row(row, ft)
                    if ident:
                        if engagement_id:
                            ident["engagement_id"] = engagement_id
                        if ft == "azure_group_member":
                            gname = source_file
                            for suffix in ("_Users.CSV", "_users.csv", "_Users.csv", "_USERS.CSV"):
                                if gname.endswith(suffix):
                                    gname = gname[:-len(suffix)]
                                    break
                            if gname:
                                ident.setdefault("tags", [])
                                ident["tags"].append(f"member_of:{gname[:80]}")
                        pending_identities.append(ident)
                except psycopg2.InterfaceError as ie:
                    # Cursor died — recover and abandon this file (its rows
                    # haven't committed yet so we lose nothing committed).
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5:
                        stats["error_examples"].append(f"cursor died: {ie}")
                    cur = _new_cursor()
                    file_failed = True
                    break
                except Exception as e:
                    stats["errors"] += 1
                    if len(stats["error_examples"]) < 5:
                        stats["error_examples"].append(f"{type(e).__name__}: {e}")
                    continue

                # Flush whichever sub-batch reached the threshold
                for ft, b in list(batches.items()):
                    if len(b) >= _BATCH_SIZE:
                        _flush(cur, b, ft)
                        batches[ft] = []
                        if progress_cb and stats["records_seen"] - last_tick >= _PROGRESS_TICK:
                            try:
                                progress_cb(dict(stats))
                            except Exception:
                                pass
                            last_tick = stats["records_seen"]

            # End-of-file: flush remaining sub-batches. Commit happens every
            # _FILES_PER_COMMIT files (default 10) — saves ~9 fsyncs out of 10
            # vs the old per-file commit. Crash worst-case loses the current
            # group of <=10 files; resume picks them back up on re-upload.
            if file_failed:
                try:
                    conn.rollback()
                except Exception:
                    pass
                files_since_commit = 0  # whatever was buffered just rolled back
                continue
            try:
                for ft, b in batches.items():
                    _flush(cur, b, ft)
                files_since_commit += 1
                _maybe_commit()
            except psycopg2.InterfaceError as ie:
                if len(stats["error_examples"]) < 5:
                    stats["error_examples"].append(f"cursor died at flush: {ie}")
                cur = _new_cursor()
                files_since_commit = 0
                continue
            except Exception as fe:
                try:
                    conn.rollback()
                except Exception:
                    pass
                files_since_commit = 0
                if len(stats["error_examples"]) < 5:
                    stats["error_examples"].append(f"file flush failed: {type(fe).__name__}: {fe}")
                continue

            if progress_cb:
                try:
                    progress_cb(dict(stats))
                except Exception:
                    pass
                last_tick = stats["records_seen"]

        # Final flush: any uncommitted file group + the deferred identity bulk.
        if files_since_commit > 0:
            try:
                conn.commit()
                files_since_commit = 0
            except Exception as e:
                if len(stats["error_examples"]) < 5:
                    stats["error_examples"].append(f"final group commit: {type(e).__name__}: {e}")

        # Deferred identity flush — single pass at end of ingest. Pre-merges
        # in Python (so a user in 5000 groups is one upsert, not 5000) and
        # then issues bulk INSERT ... ON CONFLICT DO UPDATE in execute_values
        # batches. This is the bulk of the speedup vs per-file identity upsert.
        if pending_identities:
            print(f"microburst: bulk-upserting {len(pending_identities):,} pending identities…",
                  flush=True)
            try:
                _bulk_flush_identities(cur, pending_identities)
                conn.commit()
            except Exception as e:
                try:
                    conn.rollback()
                except Exception:
                    pass
                if len(stats["error_examples"]) < 5:
                    stats["error_examples"].append(f"final identity flush: {type(e).__name__}: {e}")
    finally:
        try:
            cur.close()
        except Exception:
            pass
        conn.close()

    return stats
