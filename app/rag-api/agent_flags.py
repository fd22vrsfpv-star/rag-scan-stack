"""Agent-to-agent feedback channel.

One agent flags something worth another run — an interesting finding, a coverage
gap, a host that needs re-scanning. Flags are durable and queryable (the operator
sees the agent-to-agent chatter). When a flag is approved, a coordinator turns it
into a `scan_recommendation`, which the recon agent dispatches THROUGH the scope
gate + concurrency limit — a flag never bypasses authorization.
"""
import json
import logging
from typing import Any, Optional

log = logging.getLogger("agent_flags")


def _one(cur):
    r = cur.fetchone()
    return r


def _val(row, key, idx):
    if row is None:
        return None
    return row[key] if isinstance(row, dict) else row[idx]


def flag_for_agent(cur, flagging_agent: str, flag_type: str, data: dict,
                   engagement_id: Optional[str] = None,
                   target_agent: Optional[str] = None) -> Optional[str]:
    """Record a flag + emit an `agent_flag` webhook. Returns the flag id."""
    cur.execute("""
        INSERT INTO agent_flags (flagging_agent, target_agent, engagement_id, flag_type, data)
        VALUES (%s, %s, %s::uuid, %s, %s::jsonb)
        RETURNING id::text
    """, (flagging_agent, target_agent, engagement_id, flag_type, json.dumps(data or {})))
    fid = _val(_one(cur), "id", 0)
    try:
        from webhooks import emit_webhook
        emit_webhook("agent_flag", flagging_agent, {
            "flag_id": fid, "flag_type": flag_type, "target_agent": target_agent,
            "engagement_id": engagement_id, **(data or {})})
    except Exception:
        pass
    return fid


def _resolve_ip(cur, data: dict) -> Optional[str]:
    ip = str(data.get("ip") or "").strip()
    if ip:
        return ip
    host = str(data.get("target") or "").strip()
    if not host:
        return None
    try:
        cur.execute("SELECT host(ip) AS ip FROM assets "
                    "WHERE lower(hostname) = lower(%s) AND ip IS NOT NULL LIMIT 1", (host,))
        return _val(_one(cur), "ip", 0)
    except Exception:
        return None


def _in_scope(cur, engagement_id, host_or_ip) -> bool:
    """Best-effort scope check. If the shared gate can't be imported, defer to the
    recon agent's own gate at dispatch (fail-safe: return True so the rec is queued
    and the agent decides) — the agent NEVER dispatches out-of-scope."""
    if not engagement_id or not host_or_ip:
        return True
    try:
        from scope_gate import load_engagement_scope, is_in_scope
        rows = load_engagement_scope(cur, engagement_id)
        if not rows:
            return True
        return is_in_scope(host_or_ip, rows)
    except Exception:
        return True


def enqueue_from_flag(cur, flag) -> dict:
    """Turn one flag into a pending scan_recommendation (scope-gated). Returns the
    outcome to record on the flag: 'acted' (queued) or 'acknowledged' (+reason)."""
    data = flag["data"] if isinstance(flag["data"], dict) else {}
    scanner = str(data.get("scanner") or "").strip()
    if not scanner:
        return {"status": "acknowledged", "reason": "no scanner specified"}
    ip = _resolve_ip(cur, data)
    if not ip:
        return {"status": "acknowledged", "reason": "no resolvable IP for target"}
    if not _in_scope(cur, flag.get("engagement_id"), data.get("target") or ip):
        return {"status": "acknowledged", "reason": "target out of engagement scope"}
    try:
        cur.execute("""
            INSERT INTO scan_recommendations
                (ip, service, scanner, template, script, source, priority, status,
                 extra, target_kind)
            VALUES (%s::inet, %s, %s, %s, %s, 'agent_flag', %s, 'pending', %s::jsonb, 'service')
        """, (ip, data.get("service"), scanner, data.get("template"), data.get("script"),
              int(data.get("priority", 50) or 50),
              json.dumps({"flag_id": str(flag["id"]), "reason": data.get("reason")})))
    except Exception as e:
        return {"status": "acknowledged", "reason": f"enqueue failed: {type(e).__name__}: {e}"}
    return {"status": "acted"}
