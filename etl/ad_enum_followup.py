"""Credentialed Active Directory enumeration followup.

When a DOMAIN credential is discovered (tagged ad_credential=true by
etl/ad_credentials), queue the SAFE authenticated AD enumeration from
knowledge/ad_attacks.yaml::credentialed_enum (BloodHound collection, Kerberoast,
AS-REP roast, LDAP dump) against the domain, filled with the credential and a DC
IP. Scope-gated, deduped, queued as pending scan_recommendations (safe lane).
Deeper/offensive AD techniques stay in ad_attacks.yaml phases[], tier-gated.
"""
import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger("ad_enum_followup")


def _cfg() -> List[Dict[str, Any]]:
    for p in ("/knowledge/ad_attacks.yaml",
              os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "knowledge", "ad_attacks.yaml")):
        if os.path.exists(p):
            try:
                import yaml
                d = (yaml.safe_load(open(p, encoding="utf-8")) or {}).get("ad_attacks") or {}
                return [t for t in (d.get("credentialed_enum") or []) if isinstance(t, dict)]
            except Exception:  # noqa: BLE001
                return []
    return []


def _secret(cur, cred_id: str) -> Optional[str]:
    try:
        cur.execute("SELECT secret_value FROM credential_findings WHERE id = %s::uuid", (cred_id,))
        r = cur.fetchone()
        return r[0] if r and r[0] else None
    except Exception:  # noqa: BLE001
        return None


def queue_ad_enum_followups(cur, context, out, *, target: str = "",
                            engagement_id: Optional[str] = None) -> None:
    """Tag AD creds, then queue safe credentialed AD enumeration for each domain
    credential. Writes a summary into out['ad_enum']."""
    try:
        from etl.ad_credentials import tag_ad_credentials, _dc_ips
    except ImportError:  # pragma: no cover
        from ad_credentials import tag_ad_credentials, _dc_ips
    res = {"tagged": 0, "queued": 0, "creds": 0}
    tag = tag_ad_credentials(cur, target=target, engagement_id=engagement_id)
    res["tagged"] = tag.get("tagged", 0)
    creds = tag.get("creds") or []
    res["creds"] = len(creds)
    templates = _cfg()
    if not creds or not templates:
        out["ad_enum"] = res
        return

    dcs = _dc_ips(cur, engagement_id)
    # scope gate
    scope_rows = aliases = None
    try:
        try:
            from etl.scope_gate import load_dispatch_scope, load_host_aliases, check_dispatch
        except ImportError:  # pragma: no cover
            from scope_gate import load_dispatch_scope, load_host_aliases, check_dispatch
        scope_rows, _ = load_dispatch_scope(cur, engagement_id)
        aliases = load_host_aliases(cur, engagement_id)
    except Exception:  # noqa: BLE001
        check_dispatch = None

    from psycopg2.extras import Json
    seen = set()
    for c in creds:
        domain = c.get("domain")
        if not domain or "\\" in str(c.get("username", "")):
            # need a routable domain (user@domain form); NETBIOS-only is skipped
            # because the impacket/bloodhound commands want the FQDN domain.
            if not domain or "." not in str(domain):
                continue
        user = str(c.get("username", "")).split("@")[0].split("\\")[-1]
        secret = _secret(cur, c["id"])
        if not (user and secret):
            continue
        # a DC to query: the cred's own host if it's a DC, else any in-scope DC
        dc_ip = c.get("ip") if c.get("ip") in dcs else (next(iter(dcs)) if dcs else c.get("ip"))
        if not dc_ip:
            continue
        for t in templates:
            if str(t.get("tier", "safe")) != "safe":
                continue
            try:
                command = str(t["command"]).format(domain=domain, user=user,
                                                   password=secret, dc_ip=dc_ip)
            except Exception:  # noqa: BLE001
                continue
            if command in seen:
                continue
            seen.add(command)
            if scope_rows is not None and check_dispatch:
                if check_dispatch(str(dc_ip), scope_rows, command=command, aliases=aliases):
                    continue  # out of scope — refusal recorded by the gate elsewhere
            try:
                cur.execute(
                    """INSERT INTO scan_recommendations
                         (ip, service, scanner, action, script, source, priority,
                          status, engagement_id, extra)
                       VALUES (%s,'ldap','ad_enum',%s,%s,'ad_enum_followup',20,
                               'pending',%s,%s)
                       ON CONFLICT (fingerprint) DO NOTHING""",
                    (dc_ip, t.get("name", "ad-enum"), command, engagement_id,
                     Json({"followup": True, "followup_type": "ad_credentialed_enum",
                           "domain": domain, "credential_id": c["id"],
                           "tool": t.get("tool"), "mitre": t.get("mitre"),
                           "queued_by": "enum:ad_enum"})))
                if cur.rowcount > 0:
                    res["queued"] += 1
            except Exception as e:  # noqa: BLE001
                log.debug("ad enum queue failed: %s", e)
    out["ad_enum"] = res
