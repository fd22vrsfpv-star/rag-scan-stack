"""A working credential should queue the work it unlocks.

WHY THIS EXISTS
---------------
A full run against 192.168.1.150 recovered ten valid credentials — ssh, ftp and
telnet, including `msfadmin:msfadmin` — and produced **nothing** in the
recommendation queue. The run ended there. An operator had to notice the
credentials in the assets panel and drive every follow-on by hand, which means
in practice the ones nobody scrolled to were never used.

`knowledge/service_tools.yaml` did not help: every credential entry in it is a
brute-force tool, i.e. how to OBTAIN a credential. Nothing answered what to do
with one.

WHAT THIS DOES
--------------
Reads `knowledge/credential_followups.yaml` — data, so the operator who adds a
tool can add what it does with a password without touching Python — and queues
one PENDING `scan_recommendation` per follow-up.

IT PROPOSES; IT NEVER DISPATCHES
--------------------------------
Rows land `status='pending'`, `source='credential_followup'`. A human presses
Run, exactly like `post_review` and `auto_queue`.

Every proposal passes the **scope gate** first, and a refusal is RECORDED rather
than dropped. A proposal naming an out-of-scope host is an authorization defect
whether or not it ever executes, and an invisible refusal reads as a proposal
that was simply never made. The gate **fails closed**: no resolvable scope means
nothing is queued.

Note that "pending" is not inert in this stack — `dashboard/bff/services/
recon_agent.py` selects `WHERE sr.status = 'pending'` with no filter on `source`
and will dispatch these like any other recommendation. That is recorded in
`Docs/OPEN_ITEMS.md`; it is an operator decision, not something to paper over
here, and it is the reason the scope gate below is not optional.

THE SECRET IS NOT WRITTEN INTO THE COMMAND
------------------------------------------
`{password}` is left literal in the stored command and the recommendation
carries `credential_id` instead. A command string is shown in the UI, written
into reports and included in exports; a password substituted into it would leak
through all three. `{username}` is substituted — it is not secret, and the
command cannot be read without it.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger("credential_followups")

CATALOGUE = os.environ.get(
    "CREDENTIAL_FOLLOWUPS_YAML", "/knowledge/credential_followups.yaml")

# Fall back to the repo copy when the knowledge mount is not present (a bare
# checkout, or a container that does not mount /knowledge).
_REPO_COPY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "knowledge", "credential_followups.yaml")

SOURCE = "credential_followup"


def load_catalogue(path: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    """`{protocol: [follow-up, ...]}`, or empty if it cannot be read.

    Empty is a real answer: no catalogue means no follow-ups are proposed, which
    is the safe direction. It is logged rather than raised so a missing knowledge
    mount cannot fail a credential ingest that otherwise succeeded.
    """
    for candidate in ([path] if path else [CATALOGUE, _REPO_COPY]):
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            import yaml
            with open(candidate, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            return data.get("protocols") or {}
        except Exception as e:  # noqa: BLE001
            log.warning("credential follow-up catalogue %s unreadable: %s", candidate, e)
            return {}
    log.warning("no credential follow-up catalogue found (looked in %s, %s)",
                CATALOGUE, _REPO_COPY)
    return {}


def followups_for(protocol: str, catalogue: Optional[Dict] = None) -> List[Dict[str, Any]]:
    """Follow-ups for one protocol, highest priority first."""
    cat = load_catalogue() if catalogue is None else catalogue
    entries = cat.get((protocol or "").strip().lower()) or []
    return sorted(entries, key=lambda e: -int(e.get("priority") or 0))


def render(template: str, *, target: str, port: Any, username: str,
           credential_id: str) -> str:
    """Substitute everything EXCEPT the secret.

    `{password}` survives verbatim into the stored command on purpose — see the
    module docstring. Unknown placeholders are left alone rather than raising:
    a catalogue entry with a typo should queue a visibly-wrong command an
    operator can see and fix, not abort the whole ingest.
    """
    out = template or ""
    for key, value in (("{target}", str(target or "")),
                       ("{port}", str(port if port is not None else "")),
                       ("{username}", str(username or "")),
                       ("{credential_id}", str(credential_id or ""))):
        out = out.replace(key, value)
    return out


def queue_followups(cur, *, ip: str, port: Any, protocol: str, username: str,
                    credential_id: str, engagement_id: Optional[str] = None,
                    catalogue: Optional[Dict] = None) -> Dict[str, Any]:
    """Queue the follow-ups this credential unlocks. Returns what happened.

    ``{"proposed", "queued", "refused", "refusals", "scope_source", "entries"}``.
    `refusals` is populated, never silently dropped — a scope refusal the
    operator cannot see is indistinguishable from a proposal nobody made.

    Takes a cursor rather than opening its own connection so it runs inside the
    caller's transaction: a credential and the work it unlocks commit together
    or not at all.
    """
    out: Dict[str, Any] = {"proposed": 0, "queued": 0, "refused": 0,
                           "refusals": [], "scope_source": None, "entries": []}
    entries = followups_for(protocol, catalogue)
    if not entries:
        return out
    out["proposed"] = len(entries)

    # Fail closed. An unresolvable scope means nothing is proposed — treating an
    # unconfigured scope as permission is the defect this gate exists for.
    try:
        try:
            from etl.scope_gate import check_dispatch, load_dispatch_scope
        except ImportError:  # pragma: no cover - imported bare from within etl/
            from scope_gate import check_dispatch, load_dispatch_scope
        scope_rows, scope_source = load_dispatch_scope(cur, engagement_id)
        out["scope_source"] = scope_source
        if scope_source == "unavailable":
            out["refusals"].append(
                {"target": ip, "reason": "scope could not be loaded"})
            out["refused"] = len(entries)
            return out
    except Exception as exc:  # noqa: BLE001 - the gate must fail closed
        out["scope_source"] = "unavailable"
        out["refusals"].append({"target": ip, "reason": f"scope gate unavailable: {exc}"})
        out["refused"] = len(entries)
        return out

    from psycopg2.extras import Json
    for entry in entries:
        command = render(entry.get("command") or "", target=ip, port=port,
                         username=username, credential_id=credential_id)

        # Per entry, and WITH the command. check_dispatch returns a refusal
        # STRING when it must refuse and None when it may proceed — the polarity
        # is easy to get backwards, and backwards here means every out-of-scope
        # proposal is waved through. It also scans the command for IPv4 literals,
        # so a template that names a host the target column does not is refused
        # too; that only works if the rendered command is passed in.
        refusal = check_dispatch(str(ip), scope_rows, command=command)
        if refusal:
            out["refused"] += 1
            out["refusals"].append({"target": ip, "tool": entry.get("name"),
                                    "reason": str(refusal)})
            continue

        try:
            cur.execute(
                """
                INSERT INTO scan_recommendations
                    (ip, service, scanner, action, script, source, priority,
                     status, engagement_id, extra)
                VALUES (%s,%s,%s,%s,%s,%s,%s,'pending',%s,%s)
                ON CONFLICT (fingerprint) DO UPDATE
                   SET updated_at = now(),
                       extra = scan_recommendations.extra || EXCLUDED.extra
                RETURNING (xmax = 0) AS inserted
                """,
                (ip or None, protocol, entry.get("name"), command, command,
                 SOURCE, int(entry.get("priority") or 50), engagement_id,
                 Json({
                     "credential_id": credential_id,
                     "username": username,
                     "port": port,
                     "purpose": entry.get("purpose"),
                     "why": entry.get("why"),
                     # Says out loud that the command is not runnable as stored.
                     "secret_placeholder": "{password}" in (entry.get("command") or ""),
                     "queued_by": "credential_followups",
                 })),
            )
            row = cur.fetchone()
            if row is not None:
                was_new = row["inserted"] if isinstance(row, dict) else row[0]
                if was_new:
                    out["queued"] += 1
            out["entries"].append({"name": entry.get("name"),
                                   "purpose": entry.get("purpose"),
                                   "command": command})
        except Exception as e:  # noqa: BLE001
            # One bad catalogue entry must not lose the others, or the credential.
            log.warning("could not queue follow-up %s for %s: %s",
                        entry.get("name"), ip, e)
    return out
