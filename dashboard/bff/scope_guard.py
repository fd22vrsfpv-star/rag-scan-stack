"""Engagement scope enforcement, shared by every BFF dispatch path.

Extracted from routers/assets.py so the BFF has ONE implementation rather than
one per dispatcher. The stack already carries three copies of these rules —
etl/scope_gate.py, this module, and kali_listener/listener_service.py — forced
apart by container build contexts; adding a fourth inside the same container
would be self-inflicted. tests/test_dispatch_scope.py pins all three to a shared
case table.

Usage:

    from scope_guard import scope_rows_for, host_in_scope

    rows, source = scope_rows_for(current_engagement_id.get())
    if not host_in_scope(ip, rows):
        ...refuse...
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)


# ── Scope enforcement for dispatch ────────────────────────────────────────
#
# Dispatch had NO scope check at all. Recommendations are generated from
# whatever hosts appear in scan output, so a redirect or a certificate SAN can
# put a third party's IP into the queue — and 14 recommendations targeting
# Cloudflare-range addresses (104.20.44.163, 172.66.0.227) were sitting in this
# database, some already marked completed. Scanning a host nobody authorised is
# the one failure mode this tool must not have.
#
# Fails CLOSED: no scope configured means nothing is dispatchable, because the
# alternative is "unconfigured == scan anything".
#
# Semantics mirror etl/scope_gate.is_in_scope (ip / cidr / domain / url; asn is
# not matchable from a host alone). tests/test_dispatch_scope.py asserts the two
# stay in agreement rather than trusting them to.
def scope_rows_for(engagement_id):
    """(rows, source) — the engagement's own scope, else the union of all."""
    from db import get_db
    try:
        with get_db() as conn, conn.cursor() as cur:
            if engagement_id:
                cur.execute("SELECT target, target_type FROM public.scope_targets "
                            "WHERE engagement_id = %s::uuid", (engagement_id,))
                rows = [(r[0], r[1]) for r in cur.fetchall() if r[0]]
                if rows:
                    return rows, "engagement"
            cur.execute("SELECT target, target_type FROM public.scope_targets")
            return [(r[0], r[1]) for r in cur.fetchall() if r[0]], "all-engagements"
    except Exception as e:
        log.warning("scope load failed (%s) — treating everything as out of scope", e)
        return [], "unavailable"


def host_in_scope(host, rows) -> bool:
    from ipaddress import ip_address, ip_network
    from fnmatch import fnmatch
    if not host or not rows:
        return False
    h = str(host).strip().lower().rstrip(".")
    if not h:
        return False
    try:
        host_ip = ip_address(h)
    except ValueError:
        host_ip = None
    for target, ttype in rows:
        t = str(target).strip().lower().rstrip(".")
        tt = (ttype or "").lower()
        if not t:
            continue
        try:
            if tt == "ip":
                if host_ip is not None and h == t:
                    return True
            elif tt == "cidr":
                if host_ip is not None and host_ip in ip_network(t, strict=False):
                    return True
            elif tt in ("domain", "url"):
                if h == t or fnmatch(h, "*." + t):
                    return True
            elif not tt:
                # Untyped rows are common in older installs: match either way.
                if h == t or (host_ip is not None and h == t):
                    return True
        except ValueError:
            continue
    return False
