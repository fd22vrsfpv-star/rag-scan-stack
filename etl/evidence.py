"""What actually reached the database, per target and per window.

WHY THIS EXISTS
---------------
Resolving "did this proposal produce anything" by reading one command's stdout
only works for commands the Kali listener ran. A proposal dispatched to a native
runner finishes in `scans`, never touches `tool_executions`, and its observation
stayed unresolved forever — so a rule proposing nmap could never be judged.

Counting EVIDENCE instead is path-independent. Whatever ran, wherever it ran,
the question is the same: did new findings appear for this target after we asked
for them? That works for the listener, the native runners, an agent, and a
manual import alike.

It is also what makes web findings first-class here. `web_findings` holds 7,641
rows — more than every other finding table combined — and nothing in the
enumeration loop could see them, because the loop was reading tool stdout rather
than results.

THE TABLES ARE A LIST, DELIBERATELY
-----------------------------------
Adding a source of evidence is one entry. A hard-coded union in a query would
have to be found and edited in several places, and the one that was missed would
be the one that mattered — this repo has shipped that shape more than once.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

log = logging.getLogger("evidence")

DB_DSN = os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL") or \
    "postgresql://app:app@rag-postgres:5432/scans"


class Source:
    """One table that holds evidence, and how to ask it about a target.

    `host_sql` is the expression that yields a plain host string for the row, so
    a caller can compare it to a target without knowing whether the table stores
    an inet, a text target, or only an asset_id. Getting this wrong is silent:
    `sr.ip` renders as `192.168.1.150/32` and never equals `192.168.1.150`.
    """

    def __init__(self, table: str, host_sql: str, joins: str = "",
                 time_col: str = "created_at", kind: str = "finding"):
        self.table = table
        self.host_sql = host_sql
        self.joins = joins
        self.time_col = time_col
        self.kind = kind


# Every table a finished action can deposit evidence into. `ports` and
# `detected_software` are included because "we learned the host runs X" is a
# result even though it is not a finding, and a proposal that only ever adds
# ports is still producing something.
SOURCES: List[Source] = [
    Source("vulns", "host(a.ip)", "JOIN assets a ON a.id = vulns.asset_id"),
    Source("web_findings", "host(a.ip)", "JOIN assets a ON a.id = web_findings.asset_id"),
    Source("recon_findings", "COALESCE(recon_findings.target, host(a.ip))",
           "LEFT JOIN assets a ON a.id = recon_findings.asset_id"),
    Source("credential_findings", "host(credential_findings.ip)"),
    Source("ports", "host(a.ip)", "JOIN assets a ON a.id = ports.asset_id",
           kind="service"),
    Source("follow_up_items", "follow_up_items.target", kind="followup"),
]


def _connect():
    import psycopg2
    return psycopg2.connect(DB_DSN, connect_timeout=5)


def evidence_since(target: str, since, *, cur=None,
                   engagement_id: Optional[str] = None) -> Dict[str, Any]:
    """New evidence for this target since `since`, counted per source.

    ``{"target", "since", "total", "by_source", "available"}``.

    `available` False means the question could not be asked — which is NOT the
    same as "nothing was produced", and a caller that records the first as the
    second will suppress a rule that works.
    """
    out: Dict[str, Any] = {"target": target, "since": since, "total": 0,
                           "by_source": {}, "available": False}
    if not target or since is None:
        return out

    own = cur is None
    conn = None
    try:
        if own:
            conn = _connect()
            cur = conn.cursor()
        for src in SOURCES:
            try:
                cur.execute(
                    f"""SELECT count(*) FROM {src.table} {src.joins}
                         WHERE {src.host_sql} = %s
                           AND {src.table}.{src.time_col} >= %s""",
                    (target, since))
                n = int(cur.fetchone()[0] or 0)
            except Exception as e:  # noqa: BLE001
                # One unusable source must not lose the others. A table that
                # cannot be queried is reported as absent from the breakdown
                # rather than as a zero.
                log.debug("evidence source %s unusable: %s", src.table, e)
                if own:
                    conn.rollback()
                continue
            if n:
                out["by_source"][src.table] = n
                out["total"] += n
        out["available"] = True
    except Exception as e:  # noqa: BLE001
        log.debug("evidence_since failed for %s: %s", target, e)
    finally:
        if own and conn is not None:
            conn.close()
    return out


def unanalysed(cur, *, engagement_id: Optional[str] = None,
               limit: int = 500) -> Dict[str, Any]:
    """How much evidence has never been through post-enumeration.

    This is what "until everything has been analysed" means, and it has to be
    measurable or the loop has no stopping condition — it would either run
    forever or stop after a fixed number of passes and call that done.
    """
    out = {"tool_executions": 0, "web_findings": 0, "total": 0}
    try:
        cur.execute(
            """SELECT count(*) FROM tool_executions te
                WHERE COALESCE(te.output,'') <> ''
                  AND NOT EXISTS (SELECT 1 FROM enumeration_observations eo
                                   WHERE eo.source_execution = te.id)
                  AND te.started_at > now() - interval '30 days'""")
        out["tool_executions"] = int(cur.fetchone()[0] or 0)
    except Exception as e:  # noqa: BLE001
        log.debug("unanalysed tool_executions failed: %s", e)
    try:
        cur.execute(
            """SELECT count(*) FROM web_findings wf
                WHERE wf.created_at > now() - interval '30 days'
                  AND NOT EXISTS (SELECT 1 FROM enumeration_observations eo
                                   WHERE eo.fact->>'web_finding_id' = wf.id::text)""")
        out["web_findings"] = int(cur.fetchone()[0] or 0)
    except Exception as e:  # noqa: BLE001
        log.debug("unanalysed web_findings failed: %s", e)
    out["total"] = out["tool_executions"] + out["web_findings"]
    return out
