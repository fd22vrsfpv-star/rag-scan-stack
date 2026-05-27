"""
Shared identity upsert helpers.

Parsers (microburst, azurehound, future netexec/impacket) call into here to
populate the unified `identities` table. One row per (provider, lower(identifier)).

Merge semantics on conflict:
- display_name / principal_type / tenant_id / domain / mfa_state / status :
    COALESCE(new, existing)  — first non-null wins, never overwritten with NULL
- is_admin / is_guest / is_dirsync : OR-merge (sticky once set true)
- sources, tags : array-union (deduplicated)
- raw : shallow merge (jsonb || jsonb), latest non-empty wins on key conflict
- last_seen : bumped to now() on every upsert
- last_signin : MAX(existing, new)
"""
from typing import Iterable, List, Optional

from psycopg2.extras import Json, execute_values


_UPSERT_SQL = """
    INSERT INTO identities
        (provider, identifier, display_name, principal_type, status, mfa_state,
         last_signin, tenant_id, domain, is_admin, is_guest, is_dirsync,
         tags, sources, raw, engagement_id)
    VALUES
        (%(provider)s, %(identifier)s, %(display_name)s, %(principal_type)s,
         COALESCE(%(status)s, 'unknown'), %(mfa_state)s,
         %(last_signin)s, %(tenant_id)s, %(domain)s,
         COALESCE(%(is_admin)s, false), COALESCE(%(is_guest)s, false),
         COALESCE(%(is_dirsync)s, false),
         COALESCE(%(tags)s, '{}'::text[]),
         COALESCE(%(sources)s, '{}'::text[]),
         COALESCE(%(raw)s, '{}'::jsonb),
         %(engagement_id)s)
    ON CONFLICT (provider, lower(identifier)) DO UPDATE SET
        display_name   = COALESCE(EXCLUDED.display_name, identities.display_name),
        principal_type = COALESCE(EXCLUDED.principal_type, identities.principal_type),
        status         = CASE WHEN EXCLUDED.status = 'unknown' THEN identities.status ELSE EXCLUDED.status END,
        mfa_state      = COALESCE(EXCLUDED.mfa_state, identities.mfa_state),
        last_signin    = GREATEST(identities.last_signin, EXCLUDED.last_signin),
        tenant_id      = COALESCE(EXCLUDED.tenant_id, identities.tenant_id),
        domain         = COALESCE(EXCLUDED.domain, identities.domain),
        is_admin       = identities.is_admin OR EXCLUDED.is_admin,
        is_guest       = identities.is_guest OR EXCLUDED.is_guest,
        is_dirsync     = identities.is_dirsync OR EXCLUDED.is_dirsync,
        tags           = ARRAY(SELECT DISTINCT unnest(identities.tags || EXCLUDED.tags)),
        sources        = ARRAY(SELECT DISTINCT unnest(identities.sources || EXCLUDED.sources)),
        raw            = identities.raw || EXCLUDED.raw,
        last_seen      = now(),
        engagement_id  = COALESCE(EXCLUDED.engagement_id, identities.engagement_id)
"""


def upsert_identity(cur, *, provider: str, identifier: str,
                    source: str,
                    display_name: Optional[str] = None,
                    principal_type: Optional[str] = None,
                    status: Optional[str] = None,
                    mfa_state: Optional[str] = None,
                    last_signin=None,
                    tenant_id: Optional[str] = None,
                    domain: Optional[str] = None,
                    is_admin: Optional[bool] = None,
                    is_guest: Optional[bool] = None,
                    is_dirsync: Optional[bool] = None,
                    tags: Optional[Iterable[str]] = None,
                    raw: Optional[dict] = None,
                    engagement_id: Optional[str] = None) -> None:
    """Upsert one identity row. Caller is responsible for the cursor's transaction."""
    if not provider or not identifier:
        return
    cur.execute(_UPSERT_SQL, {
        "provider":       provider,
        "identifier":     identifier,
        "display_name":   display_name,
        "principal_type": principal_type,
        "status":         status,
        "mfa_state":      mfa_state,
        "last_signin":    last_signin,
        "tenant_id":      tenant_id,
        "domain":         domain,
        "is_admin":       is_admin,
        "is_guest":       is_guest,
        "is_dirsync":     is_dirsync,
        "tags":           list(tags) if tags else [],
        "sources":        [source] if source else [],
        "raw":            Json(raw) if raw is not None else Json({}),
        "engagement_id":  engagement_id,
    })


# ── Bulk variant ──────────────────────────────────────────────────────────
# Per-row upserts are too slow for high-volume parsers (one round-trip per
# row). bulk_upsert_identities accepts a list of identity dicts (same shape
# as upsert_identity kwargs) and issues a single execute_values INSERT...
# ON CONFLICT DO UPDATE statement. Merge semantics match the per-row helper.

_BULK_UPSERT_SQL = """
    INSERT INTO identities
        (provider, identifier, display_name, principal_type, status, mfa_state,
         last_signin, tenant_id, domain, is_admin, is_guest, is_dirsync,
         tags, sources, raw, engagement_id)
    VALUES %s
    ON CONFLICT (provider, lower(identifier)) DO UPDATE SET
        display_name   = COALESCE(EXCLUDED.display_name, identities.display_name),
        principal_type = COALESCE(EXCLUDED.principal_type, identities.principal_type),
        status         = CASE WHEN EXCLUDED.status = 'unknown' THEN identities.status ELSE EXCLUDED.status END,
        mfa_state      = COALESCE(EXCLUDED.mfa_state, identities.mfa_state),
        last_signin    = GREATEST(identities.last_signin, EXCLUDED.last_signin),
        tenant_id      = COALESCE(EXCLUDED.tenant_id, identities.tenant_id),
        domain         = COALESCE(EXCLUDED.domain, identities.domain),
        is_admin       = identities.is_admin OR EXCLUDED.is_admin,
        is_guest       = identities.is_guest OR EXCLUDED.is_guest,
        is_dirsync     = identities.is_dirsync OR EXCLUDED.is_dirsync,
        tags           = ARRAY(SELECT DISTINCT unnest(identities.tags || EXCLUDED.tags)),
        sources        = ARRAY(SELECT DISTINCT unnest(identities.sources || EXCLUDED.sources)),
        raw            = identities.raw || EXCLUDED.raw,
        last_seen      = now(),
        engagement_id  = COALESCE(EXCLUDED.engagement_id, identities.engagement_id)
"""

_BULK_VALUES_TEMPLATE = (
    "(%s, %s, %s, %s, COALESCE(%s,'unknown'), %s, %s, %s, %s, "
    "COALESCE(%s,false), COALESCE(%s,false), COALESCE(%s,false), "
    "COALESCE(%s,'{}'::text[]), COALESCE(%s,'{}'::text[]), "
    "COALESCE(%s,'{}'::jsonb), %s)"
)


def bulk_upsert_identities(cur, items: List[dict], page_size: int = 200) -> int:
    """Bulk upsert identities. `items` is a list of dicts with the same kwargs
    as upsert_identity (provider, identifier, source, display_name, ...).

    Within a single call, items with the same (provider, lower(identifier))
    are pre-merged in Python so we don't issue conflicting EXCLUDED rows in
    one batch (Postgres doesn't allow that — "ON CONFLICT DO UPDATE command
    cannot affect row a second time").

    Returns the number of distinct identities actually upserted.
    """
    if not items:
        return 0

    # Pre-merge in Python to dedup keys within this batch
    merged: dict = {}
    for it in items:
        provider = it.get("provider")
        identifier = it.get("identifier")
        if not provider or not identifier:
            continue
        key = (provider, identifier.lower())
        if key in merged:
            existing = merged[key]
            # Tags + sources unioned; flags OR-merged; COALESCE for the rest
            existing.setdefault("tags", [])
            existing["tags"] = list({*existing.get("tags", []), *(it.get("tags") or [])})
            src = it.get("source")
            srcs = set(existing.get("_sources_set", []))
            if src: srcs.add(src)
            existing["_sources_set"] = list(srcs)
            for flag in ("is_admin", "is_guest", "is_dirsync"):
                if it.get(flag): existing[flag] = True
            for k in ("display_name", "principal_type", "status", "mfa_state",
                      "tenant_id", "domain", "last_signin", "engagement_id"):
                if existing.get(k) is None and it.get(k) is not None:
                    existing[k] = it.get(k)
            # raw merge: shallow Python-level merge of dicts
            er = existing.get("raw") or {}
            ir = it.get("raw") or {}
            existing["raw"] = {**er, **ir}
        else:
            entry = dict(it)
            entry["_sources_set"] = [entry["source"]] if entry.get("source") else []
            merged[key] = entry

    rows = []
    for it in merged.values():
        sources = it.get("_sources_set") or ([it["source"]] if it.get("source") else [])
        rows.append((
            it["provider"], it["identifier"],
            it.get("display_name"), it.get("principal_type"),
            it.get("status"), it.get("mfa_state"), it.get("last_signin"),
            it.get("tenant_id"), it.get("domain"),
            it.get("is_admin"), it.get("is_guest"), it.get("is_dirsync"),
            list(it.get("tags") or []),
            sources,
            Json(it.get("raw") or {}),
            it.get("engagement_id"),
        ))

    execute_values(cur, _BULK_UPSERT_SQL, rows,
                   template=_BULK_VALUES_TEMPLATE, page_size=page_size)
    return len(rows)
