"""Engagement scope enforcement for the BFF.

The matching rules are NOT here — they live in etl/scope_gate.py, bind-mounted
at /app/bff/etl. This module is the BFF's adapter to them: the database lookup
and the request-scoped engagement id, both of which are BFF-specific.

The rules briefly existed in three copies (etl, here, kali-listener) because
container build contexts could not reach a shared file. Every dispatching
service now mounts ./etl, so they all import one implementation and the drift
problem is gone rather than merely policed.

Usage:

    from scope_guard import scope_rows_for, host_in_scope

    rows, source = scope_rows_for(current_engagement_id.get())
    if not host_in_scope(ip, rows):
        ...refuse...
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

try:
    from etl.scope_gate import (check_dispatch, is_in_scope,
                                is_in_scope_with_aliases, load_dispatch_scope,
                                load_host_aliases)
    SCOPE_GATE_AVAILABLE = True
except Exception as _err:                        # pragma: no cover
    SCOPE_GATE_AVAILABLE = False
    log.error("scope gate UNAVAILABLE (%s) — dispatch will be refused. "
              "Check the ./etl:/app/bff/etl mount on pentest-dashboard.", _err)


def scope_rows_for(engagement_id):
    """(rows, source) — the engagement's own scope, else the union of all.

    Returns ([], "unavailable") on any failure. Callers MUST treat an empty
    result as "refuse": an unconfigured or unreadable scope is a setup problem,
    not permission to scan anything.
    """
    if not SCOPE_GATE_AVAILABLE:
        return [], "unavailable"
    try:
        from db import get_db
        with get_db() as conn, conn.cursor() as cur:
            return load_dispatch_scope(cur, engagement_id)
    except Exception as e:
        log.warning("scope load failed (%s) — treating everything as out of scope", e)
        return [], "unavailable"


def aliases_for(host):
    """Observed ip<->hostname pairings for `host`. Empty set on any failure."""
    if not SCOPE_GATE_AVAILABLE or not host:
        return set()
    try:
        from db import get_db
        with get_db() as conn, conn.cursor() as cur:
            return load_host_aliases(cur, host)
    except Exception as e:
        log.warning("alias lookup failed for %r (%s) — checking the host as given", host, e)
        return set()


def host_in_scope(host, rows, use_aliases: bool = True) -> bool:
    """True if `host`, or any observed alias of it, matches the scope.

    Alias resolution is ON by default so this agrees with the scan launcher,
    which has always resolved them. Without it the same target was accepted by
    one path and refused by another.
    """
    if not SCOPE_GATE_AVAILABLE:
        return False
    h = str(host or "")
    if is_in_scope(h, rows):
        return True
    if not use_aliases:
        return False
    return bool(is_in_scope_with_aliases(h, rows, aliases_for(h)))


def refusal_for(target, rows, command: str = ""):
    """Refusal string when this dispatch must be refused, else None.

    Also validates IPv4 literals in `command`, so naming a host there while
    leaving `target` blank does not bypass the gate.
    """
    if not SCOPE_GATE_AVAILABLE:
        return "scope gate is unavailable (etl/scope_gate not importable) — refusing"
    return check_dispatch(target, rows, command, aliases=aliases_for(target))
