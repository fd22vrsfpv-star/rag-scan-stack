"""Engagement scope gating for discovery ingests (G3).

subfinder/dnsx discover new hosts.  Before any discovered host is stamped
with an `engagement_id` (which is what makes the Recon Agent scan it), it
MUST be confirmed in-scope for that engagement.  This module centralizes
that check so parse_subfinder and parse_dnsx behave identically.

Hard invariant: an out-of-scope host is never stamped and never scanned --
it is still recorded (asset + recon_finding) but stays engagement-unscoped.

Matching mirrors app/rag-api/scope_classifier.py (fnmatch for domains,
ipaddress for ip/cidr) so behavior is consistent across the system.
"""
import logging
from fnmatch import fnmatch
from ipaddress import ip_address, ip_network
from urllib.parse import urlparse

logger = logging.getLogger("scope_gate")


def load_engagement_scope(cur, engagement_id):
    """Return a list of (target, target_type) for the engagement's scope.

    Returns [] when engagement_id is falsy or on any query error (fail
    closed -- no scope means nothing is in-scope).  Tolerates both tuple
    and RealDict cursors.
    """
    if not engagement_id:
        return []
    try:
        cur.execute(
            "SELECT target, target_type FROM public.scope_targets "
            "WHERE engagement_id = %s::uuid",
            (engagement_id,),
        )
        rows = cur.fetchall()
    except Exception as e:
        logger.warning("scope load failed for engagement %s: %s", engagement_id, e)
        return []
    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append((r.get("target"), r.get("target_type")))
        else:
            out.append((r[0], r[1]))
    return out


def _host_from_url(value):
    """Extract the bare host from a url/authority string."""
    try:
        netloc = urlparse(value if "://" in value else "//" + value).netloc
        return (netloc.split("@")[-1].split(":")[0]) or value
    except Exception:
        return value


def is_in_scope(host, scope_rows):
    """True if `host` (an IP or hostname) matches any scope target.

    Fail closed: empty/blank host or empty scope returns False.
      - ip      : exact IP match
      - cidr    : host IP inside the network
      - domain  : exact host or any subdomain (`*.domain`)
      - url     : same as domain, on the url's host
      - asn     : not matchable from a host alone -> ignored
    """
    if not host or not scope_rows:
        return False
    h = host.strip().lower().rstrip(".")
    if not h:
        return False
    try:
        host_ip = ip_address(h)
    except ValueError:
        host_ip = None

    for target, ttype in scope_rows:
        if not target:
            continue
        t = target.strip().lower().rstrip(".")
        tt = (ttype or "").lower()
        try:
            if tt == "ip":
                if host_ip is not None and h == t:
                    return True
            elif tt == "cidr":
                if host_ip is not None and host_ip in ip_network(t, strict=False):
                    return True
            elif tt == "domain":
                if h == t or fnmatch(h, "*." + t):
                    return True
            elif tt == "url":
                turl = _host_from_url(t)
                if turl and (h == turl or fnmatch(h, "*." + turl)):
                    return True
            # 'asn' cannot be matched from a host string alone -> skip
        except (ValueError, TypeError):
            continue
    return False
