"""Tag discovered credentials as Active Directory credentials.

A credential is AD when its username is domain-qualified (user@domain or
DOMAIN\\user) OR it was found against a host running Domain Controller services
(Kerberos 88 / LDAP 389/636). Tagging sets credential_findings.metadata
->> 'ad_credential' = true and records the domain, so the credentialed AD
enumeration followup (etl/ad_enum_followup) can act on it and the operator can
filter AD creds in the UI.
"""
import logging
import re
from typing import Any, Dict, List, Optional

log = logging.getLogger("ad_credentials")


def extract_domain(username: str) -> Optional[str]:
    """Domain out of a qualified username: 'user@corp.local' -> 'corp.local';
    'CORP\\user' -> 'CORP'. Returns None for a bare username."""
    if not username:
        return None
    u = username.strip()
    if "@" in u:
        dom = u.rsplit("@", 1)[1].strip()
        return dom or None
    if "\\" in u:
        dom = u.split("\\", 1)[0].strip()
        return dom or None
    return None


def _dc_ips(cur, engagement_id: Optional[str]) -> set:
    """IPs in scope running DC services (Kerberos 88 or LDAP 389/636)."""
    try:
        cur.execute(
            """SELECT DISTINCT host(a.ip) FROM ports p JOIN assets a ON a.id = p.asset_id
                WHERE p.port IN (88, 389, 636)
                  AND (%s::uuid IS NULL OR a.engagement_id = %s::uuid)""",
            (engagement_id, engagement_id))
        return {r[0] for r in cur.fetchall() if r[0]}
    except Exception:  # noqa: BLE001
        try:
            cur.connection.rollback()
        except Exception:  # noqa: BLE001
            pass
        return set()


def tag_ad_credentials(cur, target: str = "", engagement_id: Optional[str] = None) -> Dict[str, Any]:
    """Flag AD credentials in credential_findings. Returns {tagged, creds:[...]}
    where creds carries the AD creds (ip, username, domain) for the enum followup."""
    out: Dict[str, Any] = {"tagged": 0, "creds": []}
    dcs = _dc_ips(cur, engagement_id)
    try:
        where, params = ["valid_cred IS NOT FALSE"], []
        if target:
            where.append("host(ip) = %s")
            params.append(target)
        if engagement_id:
            where.append("engagement_id = %s::uuid")
            params.append(engagement_id)
        cur.execute(
            f"""SELECT id::text, host(ip), username, COALESCE(secret_value,''),
                       COALESCE(metadata,'{{}}'::jsonb)
                  FROM credential_findings
                 WHERE {' AND '.join(where)}""", params)
        rows = cur.fetchall()
    except Exception as e:  # noqa: BLE001
        log.debug("ad cred tag query failed: %s", e)
        try:
            cur.connection.rollback()
        except Exception:  # noqa: BLE001
            pass
        return out
    import json as _json
    for cid, ip, username, secret, meta in rows:
        domain = extract_domain(username)
        is_ad = bool(domain) or (ip in dcs)
        if not is_ad:
            continue
        m = meta if isinstance(meta, dict) else (_json.loads(meta or "{}") if isinstance(meta, str) else {})
        if m.get("ad_credential") is True and (not domain or m.get("domain")):
            # already tagged; still surface it for the enum followup
            out["creds"].append({"id": cid, "ip": ip, "username": username,
                                 "domain": domain or m.get("domain")})
            continue
        m["ad_credential"] = True
        if domain:
            m["domain"] = domain
        try:
            cur.execute("UPDATE credential_findings SET metadata = %s::jsonb WHERE id = %s::uuid",
                        (_json.dumps(m), cid))
            out["tagged"] += 1
            out["creds"].append({"id": cid, "ip": ip, "username": username,
                                 "domain": domain or m.get("domain")})
        except Exception as e:  # noqa: BLE001
            log.debug("ad cred tag update failed for %s: %s", cid, e)
    return out
