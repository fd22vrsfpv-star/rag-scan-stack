"""What a target told us it supports, read back out of the scan results.

WHY THIS EXISTS
---------------
netexec failed against 192.168.1.150 with

    IncompatiblePeer: Incompatible ssh peer (no acceptable host key)

and hydra failed on the same host with

    kex error : no match for method server host key algo:
    server [ssh-rsa,ssh-dss], client [ssh-ed25519,ecdsa-sha2-nistp256,...]

Both are the same statement: the client offers modern algorithms, the host is an
OpenSSH 4.7p1 that offers only legacy ones. The answer is to constrain the client
to what the host advertises.

The platform already knew what that was. `ssh-audit` had run against the host and
stored 24 findings, including `ssh-audit:host-key-ssh-rsa (2048-bit)` and
`ssh-audit:host-key-ssh-dss`. The information needed to fix the failure was
collected before the failure happened, and nothing read it back.

That is the point of this module, and it is the difference between guessing and
knowing: the retry is not an experiment, it is an application of a measurement
already taken.

WHAT IT DOES NOT DO
-------------------
It reports capabilities. It does not decide to run anything, and it does not
choose options — `etl/tool_learning.py` pairs a failure signature with a
remediation and records whether it helped. Authorisation is untouched.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

log = logging.getLogger("target_capabilities")

DB_DSN = os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL") or \
    "postgresql://app:app@rag-postgres:5432/scans"

# ssh-audit writes one finding per algorithm, with the category in the script
# name: `ssh-audit:host-key-ssh-rsa (2048-bit)`. Longest prefix first, so
# `mac-algorithm` is not shortened to `mac`.
_SSH_AUDIT_CATEGORIES = (
    "key-exchange", "mac-algorithm", "host-key", "encryption",
)

# nmap's ssh2-enum-algos prints the same information under different headings.
# Both sources are read: an install may have one, the other, or both, and a
# capability known from either is still known.
_NSE_HEADINGS = {
    "kex_algorithms": "key-exchange",
    "server_host_key_algorithms": "host-key",
    "encryption_algorithms": "encryption",
    "mac_algorithms": "mac-algorithm",
}

_PAREN = re.compile(r"\s*\([^)]*\)\s*$")


def _connect():
    import psycopg2
    return psycopg2.connect(DB_DSN, connect_timeout=5)


def _clean(value: str) -> str:
    """`ssh-rsa (2048-bit)` -> `ssh-rsa`. The size is a finding, not a name."""
    return _PAREN.sub("", (value or "").strip()).strip()


def from_ssh_audit(rows: List[str]) -> Dict[str, List[str]]:
    """Parse ssh-audit script names into `{category: [algorithm, ...]}`.

    Pure, so it can be tested without a database — the shape of this data is
    exactly the kind of thing that is easy to get subtly wrong and hard to
    notice, because a missed algorithm produces a retry that fails the same way.
    """
    out: Dict[str, List[str]] = {}
    for script in rows or []:
        s = (script or "").strip()
        if not s.lower().startswith("ssh-audit:"):
            continue
        rest = s.split(":", 1)[1]
        for cat in _SSH_AUDIT_CATEGORIES:
            if rest.startswith(cat + "-"):
                value = _clean(rest[len(cat) + 1:])
                if value and value not in out.setdefault(cat, []):
                    out[cat].append(value)
                break
    return out


def from_nse(output: str) -> Dict[str, List[str]]:
    """Parse nmap ssh2-enum-algos output into the same shape."""
    out: Dict[str, List[str]] = {}
    current: Optional[str] = None
    for raw in (output or "").splitlines():
        line = raw.strip().lstrip("|").strip()
        heading = line.rstrip(":").strip().lower().replace(" ", "_")
        if heading in _NSE_HEADINGS:
            current = _NSE_HEADINGS[heading]
            continue
        if current and line and not line.endswith(":"):
            value = _clean(line)
            # The list items are one algorithm per line, sometimes with a count
            # heading like "(6)" that _clean already removes.
            if value and not value.startswith("(") and value not in out.setdefault(current, []):
                out[current].append(value)
        elif not line:
            current = None
    return out


def capabilities(target: str, *, port: Optional[int] = None,
                 service: str = "") -> Dict[str, Any]:
    """Everything recon recorded about what this target supports.

    ``{"target", "available", "source", "categories": {cat: [values]}}``.

    `available` is False when the store could not be reached, which is NOT the
    same as a target about which nothing is known. A caller that treats an
    unreachable database as "this host supports nothing" would constrain a tool
    to an empty list and fail worse than it started.
    """
    out: Dict[str, Any] = {"target": target, "available": False,
                           "source": [], "categories": {}}
    if not target:
        return out
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT v.script, COALESCE(v.output, '')
                  FROM vulns v
                  JOIN assets a ON a.id = v.asset_id
                 WHERE host(a.ip) = %s
                   AND (v.script ILIKE 'ssh-audit:%%'
                        OR v.script ILIKE '%%ssh2-enum-algos%%')
                """,
                (target,),
            )
            rows = cur.fetchall()
            out["available"] = True
    except Exception as e:  # noqa: BLE001
        log.debug("capabilities lookup failed for %s: %s", target, e)
        return out

    audit = from_ssh_audit([r[0] for r in rows])
    if audit:
        out["source"].append("ssh-audit")
    nse: Dict[str, List[str]] = {}
    for _script, output in rows:
        for cat, values in from_nse(output).items():
            for v in values:
                if v not in nse.setdefault(cat, []):
                    nse[cat].append(v)
    if nse:
        out["source"].append("nmap:ssh2-enum-algos")

    merged: Dict[str, List[str]] = {}
    for src in (audit, nse):
        for cat, values in src.items():
            for v in values:
                if v not in merged.setdefault(cat, []):
                    merged[cat].append(v)
    out["categories"] = merged
    return out


# ── Derived tool settings ──────────────────────────────────────────────────
#
# Everything above reads a measurement. This turns it into the argument a tool
# needs, BEFORE that tool has failed for want of it.
#
# etl/tool_learning.py's remediation loop is the reactive half: something failed,
# what fixes it. This is the same knowledge applied ahead of time, which is the
# better shape — a failure that never happens costs nothing and leaves no
# confusing "exit 0 but nothing worked" row behind.

SETTINGS_SOURCE = "derived"


def derive_tool_settings(target: str, *, port: Optional[int] = None,
                         service: str = "", tools: Optional[List[str]] = None,
                         caps: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Options every known tool should use against this target, from measurement.

    ``{"target", "available", "settings": [...], "skipped": [...]}``.

    `skipped` is populated rather than dropped: "this tool has no flag for that
    category" and "the host and client have nothing in common" are both real
    answers a reader needs, and an absent row looks identical to a derivation
    that was never run.
    """
    out: Dict[str, Any] = {"target": target, "port": port, "service": service,
                           "available": False, "settings": [], "skipped": []}
    if caps is None:
        caps = capabilities(target, port=port, service=service)
    out["available"] = bool(caps.get("available"))
    categories = caps.get("categories") or {}
    if not categories:
        return out

    try:
        try:
            from etl.tool_learning import load_tool_options, client_capabilities
        except ImportError:  # pragma: no cover - bare import from within etl/
            from tool_learning import load_tool_options, client_capabilities
    except Exception as e:  # noqa: BLE001
        log.warning("tool option catalogue unavailable: %s", e)
        return out

    catalogue = load_tool_options()
    for tool, options in catalogue.items():
        if tools and tool not in tools:
            continue
        if not options:
            out["skipped"].append({
                "tool": tool, "reason": "no algorithm options — a different tool "
                                        "is the answer, not a different argument"})
            continue
        for category, template in options.items():
            offered = categories.get(category) or []
            if not offered:
                continue
            known = client_capabilities(tool, category)
            usable = [v for v in offered if v in known] if known is not None else list(offered)
            if known is not None and not usable:
                out["skipped"].append({
                    "tool": tool, "category": category,
                    "host_offers": offered, "client_supports": known[:12],
                    "reason": "no overlap — this client cannot negotiate with "
                              "this host in this category at all"})
                continue
            out["settings"].append({
                "tool": tool, "category": category,
                "option": template.replace("{values}", ",".join(usable)),
                "host_offers": offered,
                "client_supports": known or [],
                "client_verified": known is not None,
            })
    return out


def store_tool_settings(target: str, derived: Dict[str, Any], *,
                        port: Optional[int] = None, service: str = "") -> int:
    """Persist derived settings. Returns how many rows were written.

    Never raises and never overwrites a REJECTED row: an operator who ruled a
    setting out has made a decision, and re-deriving from the same measurement
    must not undo it.
    """
    rows = derived.get("settings") or []
    if not rows:
        return 0
    written = 0
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                for r in rows:
                    cur.execute(
                        """
                        INSERT INTO public.target_tool_settings
                          (target, port, service, tool, category, option_text,
                           host_offers, client_supports, source, status)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'active')
                        ON CONFLICT (target, COALESCE(port, -1), service, tool, category)
                        DO UPDATE SET
                          option_text     = EXCLUDED.option_text,
                          host_offers     = EXCLUDED.host_offers,
                          client_supports = EXCLUDED.client_supports,
                          derived_at      = now(),
                          status = CASE
                              WHEN public.target_tool_settings.status = 'rejected'
                                   THEN 'rejected'
                              ELSE 'active' END
                        """,
                        (target, port, service or "", r["tool"], r["category"],
                         r["option"], r.get("host_offers") or [],
                         r.get("client_supports") or [], SETTINGS_SOURCE),
                    )
                    written += 1
            conn.commit()
    except Exception as e:  # noqa: BLE001
        log.warning("could not store tool settings for %s: %s", target, e)
        return 0
    return written


def settings_for(tool: str, target: str, *, port: Optional[int] = None,
                 service: str = "") -> List[str]:
    """The active option strings this tool should use against this target.

    Returns a list so a caller can append them all. Empty means nothing was
    derived OR the store is unreachable — both leave the command as it was,
    which is the behaviour before any of this existed, so a failure here costs
    nothing that was not already being paid.
    """
    if not (tool and target):
        return []
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT option_text FROM public.target_tool_settings
                 WHERE tool = %s AND target = %s AND status = 'active'
                   AND (port IS NULL OR %s IS NULL OR port = %s)
                 ORDER BY category
                """,
                (tool, target, port, port),
            )
            return [r[0] for r in cur.fetchall()]
    except Exception as e:  # noqa: BLE001
        log.debug("settings_for failed: %s", e)
        return []
