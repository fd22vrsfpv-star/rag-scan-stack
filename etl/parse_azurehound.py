"""
ETL parser for AzureHound BloodHound-compatible JSON collection.

Parses users, groups, apps, service principals, and role assignments
from AzureHound output into recon_findings.
"""

import os
import json
import uuid

import psycopg2
from psycopg2.extras import RealDictCursor, Json

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

# Map AzureHound entity types to finding types
ENTITY_TYPE_MAP = {
    "users": "azure_user",
    "groups": "azure_group",
    "apps": "azure_app_registration",
    "applications": "azure_app_registration",
    "servicePrincipals": "azure_service_principal",
    "service_principals": "azure_service_principal",
    "roleAssignments": "azure_role_assignment",
    "role_assignments": "azure_role_assignment",
    "devices": "azure_device",
    "keyVaults": "azure_key_vault",
    "key_vaults": "azure_key_vault",
    "virtualMachines": "azure_vm",
    "managementGroups": "azure_mgmt_group",
}


def _load_records(path):
    """Load AzureHound JSON — array or JSONL or wrapped in {data: [...]}."""
    with open(path) as f:
        text = f.read().strip()

    if not text:
        return []

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try JSONL
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

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # AzureHound wraps in {data: [...]} or {value: [...]}
        return data.get("data", data.get("value", [data]))
    return []


def parse_azurehound(path: str, profile: str = "upload", job_id: str = None):
    stats = dict(records_seen=0, findings_inserted=0, identities_upserted=0,
                 skipped=0, errors=0, error_examples=[])
    records = _load_records(path)
    stats["records_seen"] = len(records)
    if not records:
        return stats

    try:
        from etl.identity_upsert import upsert_identity
    except Exception:
        upsert_identity = None

    conn = psycopg2.connect(DB_DSN)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            for rec in records:
                try:
                    cur.execute("SAVEPOINT rec_sp")
                    if not isinstance(rec, dict):
                        stats["skipped"] += 1
                        cur.execute("RELEASE SAVEPOINT rec_sp")
                        continue

                    # Determine entity kind
                    kind = rec.get("kind", rec.get("type", rec.get("entity_type", "")))
                    kind_lower = kind.lower() if kind else ""
                    finding_type = ENTITY_TYPE_MAP.get(kind, None)
                    if not finding_type:
                        for key, ftype in ENTITY_TYPE_MAP.items():
                            if key.lower() in kind_lower:
                                finding_type = ftype
                                break
                    if not finding_type:
                        finding_type = f"azure_{kind_lower}" if kind_lower else "azure_entity"

                    # Extract properties
                    props = rec.get("properties", rec)
                    display_name = props.get("displayName", props.get("name", ""))
                    object_id = props.get("id", rec.get("id", ""))
                    tenant_id = props.get("tenantId", rec.get("tenantId", ""))

                    target = display_name or object_id or kind

                    # Severity based on entity type
                    severity = "info"
                    if finding_type == "azure_role_assignment":
                        role = props.get("roleDefinitionName", props.get("role", ""))
                        if any(kw in str(role).lower() for kw in ["owner", "contributor", "admin", "global"]):
                            severity = "high"
                        else:
                            severity = "medium"
                    elif finding_type == "azure_app_registration":
                        severity = "medium"
                    elif finding_type == "azure_service_principal":
                        severity = "medium"

                    data = {
                        "kind": kind,
                        "object_id": object_id,
                        "display_name": display_name,
                        "tenant_id": tenant_id,
                        "provider": "azure",
                    }
                    # Include select properties (avoid dumping huge blobs)
                    for key in ("userPrincipalName", "mail", "roleDefinitionName",
                                "scope", "principalType", "appId", "signInAudience",
                                "accountEnabled", "operatingSystem"):
                        if key in props:
                            data[key] = props[key]

                    asset_id = None
                    cur.execute("""
                        INSERT INTO recon_findings
                            (id, asset_id, source, finding_type, target, data, severity)
                        VALUES (%s, %s, 'azurehound', %s, %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, (
                        str(uuid.uuid4()), asset_id,
                        finding_type, str(target)[:500], Json(data), severity,
                    ))
                    stats["findings_inserted"] += 1

                    # Fan out to identities table for user / SP / role-principal kinds
                    if upsert_identity is not None:
                        ident_kwargs = None
                        if finding_type == "azure_user":
                            upn = props.get("userPrincipalName") or props.get("mail") or object_id
                            if upn:
                                enabled = props.get("accountEnabled")
                                if enabled is True:
                                    status = "active"
                                elif enabled is False:
                                    status = "disabled"
                                else:
                                    status = "unknown"
                                user_type = str(props.get("userType", "")).lower()
                                ident_kwargs = dict(
                                    provider="azure", identifier=str(upn),
                                    display_name=display_name, principal_type=("guest" if user_type == "guest" else "user"),
                                    status=status, is_guest=(user_type == "guest"),
                                    tenant_id=tenant_id or None,
                                    raw={"azurehound_user": props}, source="azurehound",
                                )
                        elif finding_type == "azure_service_principal":
                            sp_id = props.get("appId") or object_id
                            if sp_id:
                                ident_kwargs = dict(
                                    provider="azure", identifier=str(sp_id),
                                    display_name=display_name, principal_type="service_principal",
                                    tenant_id=tenant_id or None,
                                    raw={"azurehound_sp": props}, source="azurehound",
                                )
                        elif finding_type == "azure_role_assignment":
                            ptype = str(props.get("principalType", "")).lower()
                            principal_type = "service_principal" if ptype == "serviceprincipal" else \
                                             "group" if ptype == "group" else "user"
                            principal_id = (props.get("principalUPN")
                                            or props.get("principalId")
                                            or props.get("principalName")
                                            or props.get("principalDisplayName"))
                            if principal_id:
                                role = str(props.get("roleDefinitionName", "")).lower()
                                is_admin = any(kw in role for kw in ("owner", "contributor", "admin", "global", "privileged"))
                                ident_kwargs = dict(
                                    provider="azure", identifier=str(principal_id),
                                    display_name=props.get("principalDisplayName"),
                                    principal_type=principal_type, is_admin=is_admin,
                                    tenant_id=tenant_id or None,
                                    raw={"azurehound_role": props}, source="azurehound",
                                )

                        if ident_kwargs:
                            try:
                                cur.execute("SAVEPOINT ident_sp")
                                upsert_identity(cur, **ident_kwargs)
                                cur.execute("RELEASE SAVEPOINT ident_sp")
                                stats["identities_upserted"] += 1
                            except Exception as ie:
                                try:
                                    cur.execute("ROLLBACK TO SAVEPOINT ident_sp")
                                except Exception:
                                    pass
                                if len(stats["error_examples"]) < 5:
                                    stats["error_examples"].append(f"identity {type(ie).__name__}: {ie}")

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
