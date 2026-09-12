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
