"""Every finished command, analysed — and what follows from it, proposed.

WHY THIS EXISTS
---------------
The platform could parse a tool's output and could queue a recommendation. What
it could not do was get from one to the other. netexec reported

    SMB  192.168.1.150  445  METASPLOITABLE  tmp  READ,WRITE  oh noes!

and nothing followed. A pentester reading that share table knows immediately
what it means; the platform stored it and stopped. The same was true of a null
session, an SMBv1-only dialect, a private key in a home directory, and a
known_hosts entry naming a host nobody had scanned.

THE LOOP
--------
    command finishes
      -> parse         (etl/tool_output_parsers.py)
      -> FACTS         normalised observations, tool-independent
      -> RULES         knowledge/enumeration_rules.yaml, matched against facts
      -> PROPOSALS     scope-gated, queued status='pending'
      -> observation   recorded, so what came of it can be written back
      -> LEARN         a rule that keeps firing and never yields stops firing

Every command goes through it, not only the ones at the end of a pipeline: the
hook is `kali_listener.db_update_tool_execution`, the single point every tool the
platform runs passes through. The pipeline phase calls the same function over
anything the per-command hook missed.

WHAT IS TYPED AND WHAT IS LEARNED
---------------------------------
The IMPLICATION is typed, as data: "a writable share is worth listing" is domain
knowledge an operator can write down. Whether acting on it produces anything
HERE is learned — every firing is recorded, the outcome written back when the
proposal runs, and a rule below the threshold stops firing.

IT PROPOSES; IT NEVER DISPATCHES
--------------------------------
Rows land `status='pending'` for a human to run. Every proposal passes the scope
gate first and a refusal is RECORDED — a `known_hosts` entry is a lead, not a
licence, and an invisible refusal reads as a proposal nobody made.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

log = logging.getLogger("post_enumeration")

RULES_YAML = os.environ.get("ENUMERATION_RULES_YAML",
                            "/knowledge/enumeration_rules.yaml")
_REPO_RULES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "knowledge", "enumeration_rules.yaml")

SOURCE = "post_enumeration"

# A rule that has been acted on this many times with nothing to show for it
# stops firing. Below the threshold it keeps its chance: a rule that is right
# but rare should not be killed by its first two misses.
SUPPRESS_AFTER = int(os.environ.get("ENUMERATION_SUPPRESS_AFTER", "5"))

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")
_KEY_PATH = re.compile(r"(/[^\s:]*\.ssh/id_[a-z0-9_]+)")


def _connect():
    import psycopg2
    return psycopg2.connect(
        os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL")
        or "postgresql://app:app@rag-postgres:5432/scans", connect_timeout=5)


def load_rules() -> List[Dict[str, Any]]:
    """The rule catalogue, or empty if unreadable.

    Empty is the safe direction and it is logged: no rules means nothing is
    proposed, never that everything is.
    """
    for candidate in (RULES_YAML, _REPO_RULES):
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            import yaml
            with open(candidate, encoding="utf-8") as fh:
                return (yaml.safe_load(fh) or {}).get("rules") or []
        except Exception as e:  # noqa: BLE001
            log.warning("enumeration rules %s unreadable: %s", candidate, e)
            return []
    log.warning("no enumeration rules found (looked in %s, %s)", RULES_YAML, _REPO_RULES)
    return []


# ── Facts ──────────────────────────────────────────────────────────────────

def facts_from(parsed: Optional[Dict[str, Any]], *, output: str = "",
               target: str = "", service: str = "") -> List[Dict[str, Any]]:
    """Normalise a parse into tool-independent observations.

    A rule is written against a FACT, not against one tool's text format, so the
    same rule fires whether the share table came from netexec, smbmap or
    crackmapexec. That is the difference between a rule catalogue and a pile of
    per-tool string matching.
    """
    facts: List[Dict[str, Any]] = []
    parsed = parsed or {}

    for c in parsed.get("credentials") or []:
        facts.append({"fact": "credential", "target": c.get("ip") or target,
                      "port": c.get("port"), "service": c.get("protocol") or service,
                      "username": c.get("username"), "password": c.get("secret"),
                      "pwned": bool(c.get("pwned"))})
    for sh in parsed.get("shares") or []:
        facts.append({"fact": "share", "target": sh.get("ip") or target,
                      "service": sh.get("protocol") or service,
                      "share": sh.get("share"),
                      "permissions": sh.get("permissions"),
                      "writable": bool(sh.get("writable")),
                      "readable": bool(sh.get("readable"))})
    for h in parsed.get("hosts") or []:
        for key, value in (h.get("facts") or {}).items():
            facts.append({"fact": "host_fact", "target": h.get("ip") or target,
                          "port": h.get("port"), "service": h.get("protocol") or service,
                          "key": key, "value": str(value)})

    # Command output is where post-access steps put everything they found, and
    # it is the least structured thing here — so it gets the widest reading.
    lines = list(parsed.get("command_output") or [])
    if output and not lines:
        lines = output.splitlines()
    for line in lines:
        if _PRIVATE_KEY.search(line) or _KEY_PATH.search(line):
            m = _KEY_PATH.search(line)
            facts.append({"fact": "file", "kind": "private_key",
                          "target": target, "service": service,
                          "path": m.group(1) if m else None, "line": line[:200]})
        for ip in _IPV4.findall(line):
            # A host named in known_hosts is somewhere this account already
            # reaches. Recording it as a LEAD; the scope gate decides whether it
            # may be touched, and it usually will not.
            if ip != target and not ip.startswith(("0.", "127.", "255.")):
                facts.append({"fact": "host", "target": ip, "source": "known_hosts",
                              "seen_on": target, "line": line[:200]})
    return facts


def _matches(rule: Dict[str, Any], fact: Dict[str, Any]) -> bool:
    when = rule.get("when") or {}
    if (when.get("fact") or "") != fact.get("fact"):
        return False
    for key, expected in (when.get("where") or {}).items():
        got = fact.get(key)
        if isinstance(expected, bool):
            if bool(got) is not expected:
                return False
        elif str(got).lower() != str(expected).lower():
            return False
    return True


def render(template: str, fact: Dict[str, Any], *, target: str = "",
           port: Any = None) -> str:
    """Fill a proposal's command from the fact that triggered it.

    `{password}` and `{username}` survive verbatim: the proposal carries
    credential_id and the secret is resolved at dispatch, never stored. Same
    contract as knowledge/credential_followups.yaml, for the same reason — a
    stored command is shown in the UI, written into reports and exported.
    """
    out = template or ""
    values = dict(fact)
    values.setdefault("target", fact.get("target") or target)
    values.setdefault("port", fact.get("port") or port or "")
    for key, value in values.items():
        if key in ("password", "username") or value is None:
            continue
        out = out.replace("{" + key + "}", str(value))
    return out


# ── Learning ───────────────────────────────────────────────────────────────

def rule_status(cur, rule_id: str, service: str = "") -> Dict[str, Any]:
    """What has come of this rule so far, and whether it should still fire."""
    cur.execute(
        """SELECT fired, executed, produced, confidence, status
             FROM public.enumeration_rule_learned
            WHERE rule_id = %s AND service = %s""",
        (rule_id, service or ""))
    row = cur.fetchone()
    if not row:
        return {"fired": 0, "executed": 0, "produced": 0, "confidence": None,
                "status": "active", "suppressed": False}
    fired, executed, produced, confidence, status = row
    # Suppressed only once it has actually been ACTED on enough times, AND the
    # outcome was measurable. A rule whose proposals nobody ran has not been
    # disproved — it has been ignored — and a rule whose proposals ran through a
    # tool with no parser has not been disproved either: nobody read the result.
    # `executed` only counts observations that were RESOLVED, so both cases stay
    # out of the denominator.
    suppressed = (status == "rejected"
                  or (executed >= SUPPRESS_AFTER and (produced or 0) == 0))
    return {"fired": fired, "executed": executed, "produced": produced,
            "confidence": float(confidence) if confidence is not None else None,
            "status": status, "suppressed": suppressed}


def _record_firing(cur, rule_id: str, service: str) -> None:
    cur.execute(
        """
        INSERT INTO public.enumeration_rule_learned (rule_id, service, fired,
                                                     last_fired_at)
        VALUES (%s, %s, 1, now())
        ON CONFLICT (rule_id, service) DO UPDATE
           SET fired = public.enumeration_rule_learned.fired + 1,
               last_fired_at = now()
        """, (rule_id, service or ""))


def record_outcome(recommendation_id: str, *, produced: bool,
                   result_count: Optional[int] = None) -> bool:
    """Write back what came of a proposal. This is the carry-forward.

    Called when a recommendation queued here is executed. Without it every rule
    stays at "fired N times, outcome unknown" forever and nothing is ever
    learned — the loop would propose and never find out.
    """
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE public.enumeration_observations
                          SET produced = %s, result_count = %s, resolved_at = now()
                        WHERE recommendation_id = %s::uuid AND produced IS NULL
                    RETURNING rule_id, service""",
                    (produced, result_count, recommendation_id))
                rows = cur.fetchall()
                for rule_id, service in rows:
                    cur.execute(
                        """
                        UPDATE public.enumeration_rule_learned
                           SET executed = executed + 1,
                               produced = produced + %s,
                               confidence = (produced + %s)::numeric
                                            / GREATEST(executed + 1, 1)
                         WHERE rule_id = %s AND service = %s
                        """,
                        (1 if produced else 0, 1 if produced else 0,
                         rule_id, service or ""))
            conn.commit()
            return bool(rows)
    except Exception as e:  # noqa: BLE001
        log.debug("record_outcome failed for %s: %s", recommendation_id, e)
        return False


def record_outcome_for_command(command: str, *, produced: bool,
                              result_count: Optional[int] = None) -> int:
    """Close the loop by matching an execution back to the proposal that caused it.

    Keyed on the command text rather than on a foreign key, because
    `tool_executions` has no link to `scan_recommendations` and every dispatch
    path would otherwise have to be taught to carry one. The command is stored
    on both sides and is what actually ran.

    Returns how many observations were resolved. Zero is ordinary — most
    commands were not proposed by a rule.
    """
    if not (command or "").strip():
        return 0
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """UPDATE public.enumeration_observations
                          SET produced = %s, result_count = %s, resolved_at = now()
                        WHERE produced IS NULL
                          AND proposed_command = %s
                    RETURNING rule_id, service""",
                    (produced, result_count, command))
                rows = cur.fetchall()
                for rule_id, service in rows:
                    cur.execute(
                        """
                        UPDATE public.enumeration_rule_learned
                           SET executed = executed + 1,
                               produced = produced + %s,
                               confidence = (produced + %s)::numeric
                                            / GREATEST(executed + 1, 1)
                         WHERE rule_id = %s AND service = %s
                        """,
                        (1 if produced else 0, 1 if produced else 0,
                         rule_id, service or ""))
            conn.commit()
        return len(rows)
    except Exception as e:  # noqa: BLE001
        log.debug("record_outcome_for_command failed: %s", e)
        return 0


def resolve_pending_observations(*, limit: int = 200,
                                 engagement_id: Optional[str] = None) -> Dict[str, Any]:
    """Close out proposals whose dispatch has finished, whatever ran them.

    Reading one command's stdout only resolves what the Kali listener ran. A
    proposal dispatched to a native runner finishes in `scans`, never touches
    `tool_executions`, and its observation stayed unresolved forever — so a rule
    proposing nmap could never be judged.

    This asks a path-independent question instead: after we asked for this, did
    new evidence appear for that target? That counts `web_findings` too, which
    hold more rows than every other finding table combined and which nothing in
    this loop could previously see.

    A recommendation still queued is left alone. "Not finished yet" is a third
    state and recording it as "produced nothing" would suppress rules for being
    slow.
    """
    out = {"examined": 0, "resolved": 0, "produced": 0, "still_running": 0,
           "available": False}
    try:
        try:
            from etl.evidence import evidence_since
        except ImportError:  # pragma: no cover
            from evidence import evidence_since
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)
        return out
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT eo.id::text, eo.rule_id, eo.service, eo.target,
                           sr.status, sr.executed_at
                      FROM public.enumeration_observations eo
                      JOIN scan_recommendations sr ON sr.id = eo.recommendation_id
                     WHERE eo.produced IS NULL
                       AND sr.executed_at IS NOT NULL
                     ORDER BY sr.executed_at
                     LIMIT %s
                    """, (limit,))
                rows = cur.fetchall()
                out["available"] = True
                for obs_id, rule_id, service, target, status, executed_at in rows:
                    out["examined"] += 1
                    if status in ("queued", "running", "pending"):
                        out["still_running"] += 1
                        continue
                    ev = evidence_since(target, executed_at, cur=cur)
                    if not ev.get("available"):
                        # Could not ask. Leaving it unresolved is the honest
                        # answer; recording a zero here would be the same
                        # mistake as recording an unparsed run as fruitless.
                        continue
                    produced = ev["total"] > 0
                    cur.execute(
                        """UPDATE public.enumeration_observations
                              SET produced = %s, result_count = %s,
                                  resolved_at = now()
                            WHERE id = %s::uuid""",
                        (produced, ev["total"], obs_id))
                    cur.execute(
                        """
                        UPDATE public.enumeration_rule_learned
                           SET executed = executed + 1,
                               produced = produced + %s,
                               confidence = (produced + %s)::numeric
                                            / GREATEST(executed + 1, 1)
                         WHERE rule_id = %s AND service = %s
                        """,
                        (1 if produced else 0, 1 if produced else 0,
                         rule_id, service or ""))
                    out["resolved"] += 1
                    out["produced"] += 1 if produced else 0
            conn.commit()
    except Exception as e:  # noqa: BLE001
        log.warning("resolve_pending_observations failed: %s", e)
    return out


def facts_from_exploits(cur, *, target: str = "", hours: int = 24,
                        limit: int = 50) -> List[Dict[str, Any]]:
    """A successful exploit is ACCESS, and access is a fact.

    The vsftpd 2.3.4 backdoor was executed against 192.168.1.150, opened a root
    shell on port 6200, and nothing enumerated through it: the exploit was
    marked `executed` and that was the end of it. `exploit_callbacks` had zero
    rows, so there was no session to find — but the listener was right there on
    a port that had not been there before.

    Two facts come out of this, and the second is the useful one:
      * `exploit_executed` — we ran something and it reported success
      * `open_port` — a port that appeared AFTER the exploit, which is the
        listener it opened

    The second needs no knowledge of which module opens which port. A port that
    was not there before the exploit and is there afterwards is the thing worth
    looking at, whatever module produced it.
    """
    facts: List[Dict[str, Any]] = []
    where, params = ["pe.status = 'executed'",
                     "pe.updated_at > now() - (%s || ' hours')::interval"], [hours]
    if target:
        where.append("host(pe.target_ip) = %s")
        params.append(target)
    params.append(limit)
    try:
        cur.execute(
            f"""SELECT pe.id::text, host(pe.target_ip), pe.exploit_id,
                       pe.target_port, COALESCE(pe.target_service,''), pe.updated_at
                  FROM pending_exploits pe
                 WHERE {' AND '.join(where)}
                 ORDER BY pe.updated_at DESC
                 LIMIT %s""", params)
        rows = cur.fetchall()
    except Exception as e:  # noqa: BLE001
        log.debug("exploit facts unavailable: %s", e)
        return facts

    for pid, host, exploit_id, port, service, executed_at in rows:
        facts.append({"fact": "exploit_executed", "target": host,
                      "service": service, "port": port,
                      "exploit_id": exploit_id, "pending_exploit_id": pid,
                      "executed_at": str(executed_at)})
    return facts


# What "nothing has identified this" looks like in the service column. `lm-x`
# is what nmap calls 6200 on Metasploitable, which is the vsftpd backdoor's root
# shell; `tcpwrapped` means the handshake completed and nothing else was learned.
_UNIDENTIFIED = {"", "?", "unknown", "lm-x", "tcpwrapped", "status"}


def facts_from_open_ports(cur, *, target: str = "", limit: int = 60) -> List[Dict[str, Any]]:
    """Open ports nothing has identified.

    This started as "ports that appeared after the exploit", which does not
    work: `ports` is upserted, so `created_at` is the FIRST time a port was ever
    seen, not the last. Port 6200 had been seen on an earlier scan and matched
    nothing, while port 21 — the exploit's own target — matched the window.

    So the honest signal is the one that does not depend on timing at all: an
    open port with no identified service is worth a banner grab whether an
    exploit opened it or not. The full re-scan proposed by
    `exploit-find-the-listener` is what actually finds something NEW.
    """
    facts: List[Dict[str, Any]] = []
    where, params = ["COALESCE(p.is_open, true)"], []
    if target:
        where.append("host(a.ip) = %s")
        params.append(target)
    params.append(limit)
    try:
        cur.execute(
            f"""SELECT host(a.ip), p.port, COALESCE(p.service,''),
                       COALESCE(p.banner,'')
                  FROM ports p JOIN assets a ON a.id = p.asset_id
                 WHERE {' AND '.join(where)}
                 ORDER BY p.port LIMIT %s""", params)
        for host, port, service, banner in cur.fetchall():
            if service.strip().lower() not in _UNIDENTIFIED:
                continue
            facts.append({"fact": "open_port", "target": host, "port": port,
                          "service": service, "banner": banner[:120],
                          "unidentified": True})
    except Exception as e:  # noqa: BLE001
        log.debug("open port facts unavailable: %s", e)
    return facts


def facts_from_web_findings(cur, *, target: str = "", limit: int = 200,
                            engagement_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Evidence that never came from a command's stdout.

    `web_findings` holds more rows than every other finding table combined and
    the loop could not see any of it, because it was reading tool output rather
    than results. A finding is a fact whatever produced it.
    """
    facts: List[Dict[str, Any]] = []
    where, params = ["wf.created_at > now() - interval '30 days'"], []
    if target:
        where.append("host(a.ip) = %s")
        params.append(target)
    params.append(limit)
    try:
        cur.execute(
            f"""SELECT wf.id::text, host(a.ip), wf.url, wf.severity,
                       COALESCE(wf.name,'')
                  FROM web_findings wf
                  JOIN assets a ON a.id = wf.asset_id
                 WHERE {' AND '.join(where)}
                   AND NOT EXISTS (SELECT 1 FROM public.enumeration_observations eo
                                    WHERE eo.fact->>'web_finding_id' = wf.id::text)
                 ORDER BY wf.created_at DESC
                 LIMIT %s""", params)
        for wid, host, url, severity, name in cur.fetchall():
            facts.append({"fact": "web_finding", "target": host, "service": "http",
                          "web_finding_id": wid, "url": url,
                          "severity": (severity or "").lower(),
                          "name": name})
    except Exception as e:  # noqa: BLE001
        log.debug("web finding facts unavailable: %s", e)
    return facts


# ── The analysis every command goes through ────────────────────────────────

def analyse(execution: Dict[str, Any], *, queue: bool = True) -> Dict[str, Any]:
    """One finished command: what it found, and what should follow.

    ``{"facts", "proposals", "queued", "refused", "refusals", "suppressed",
    "available"}``. Never raises — an analysis failure must not fail a command
    that already completed.
    """
    out: Dict[str, Any] = {"facts": 0, "proposals": [], "queued": 0,
                           "refused": 0, "refusals": [], "suppressed": [],
                           "available": False}
    tool = (execution.get("tool") or "").strip()
    target = (execution.get("target") or "").strip()
    service = (execution.get("service") or "").strip()

    parsed = execution.get("parsed_results")
    if parsed is None:
        try:
            try:
                from etl.tool_output_parsers import parse_for
            except ImportError:  # pragma: no cover
                from tool_output_parsers import parse_for
            parsed = parse_for(tool, execution.get("output") or "",
                               execution.get("error") or "")
        except Exception as e:  # noqa: BLE001
            log.debug("parse for %s failed: %s", tool, e)

    facts = facts_from(parsed, output=execution.get("output") or "",
                       target=target, service=service)
    out["facts"] = len(facts)
    rules = load_rules()
    if not facts or not rules:
        return out

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                out["available"] = True
                try:
                    from etl.scope_gate import check_dispatch, load_dispatch_scope
                except ImportError:  # pragma: no cover
                    from scope_gate import check_dispatch, load_dispatch_scope
                scope_rows, scope_source = load_dispatch_scope(
                    cur, execution.get("engagement_id"))
                # Fail closed. No resolvable scope proposes nothing, because the
                # alternative is treating an unconfigured scope as permission.
                if scope_source == "unavailable":
                    out["refusals"].append({"reason": "scope could not be loaded"})
                    out["refused"] = len(facts)
                    return out

                _propose_from_facts(cur, facts, execution, rules, out,
                                    scope_rows=scope_rows)
            conn.commit()
    except Exception as e:  # noqa: BLE001
        log.warning("post-enumeration analysis failed for %s: %s", tool, e)
    return out


def _propose_from_facts(cur, facts, context, rules, out, scope_rows=None):
    """Match facts against rules, gate them, queue them, and record the firing.

    One implementation for every source of facts. A second copy for findings
    would drift from the one for command output, and the drifted one would be
    the one nobody was watching.
    """
    from psycopg2.extras import Json
    try:
        from etl.scope_gate import check_dispatch, load_dispatch_scope
    except ImportError:  # pragma: no cover
        from scope_gate import check_dispatch, load_dispatch_scope
    if scope_rows is None:
        scope_rows, scope_source = load_dispatch_scope(
            cur, context.get("engagement_id"))
        if scope_source == "unavailable":
            out["refusals"].append({"reason": "scope could not be loaded"})
            out["refused"] = len(facts)
            return

    service = context.get("service") or ""
    seen = set()
    for fact in facts:
        for rule in rules:
            if not _matches(rule, fact):
                continue
            rule_id = rule.get("id") or "unnamed"
            st = rule_status(cur, rule_id, service)
            if st["suppressed"]:
                if rule_id not in out["suppressed"]:
                    out["suppressed"].append(rule_id)
                continue

            proposal = rule.get("propose") or {}
            command = render(proposal.get("command") or "", fact,
                             target=context.get("target") or "",
                             port=context.get("port"))
            fact_target = fact.get("target") or context.get("target") or ""
            key = (command, fact_target)
            if key in seen:
                continue
            seen.add(key)

            refusal = check_dispatch(str(fact_target), scope_rows, command=command)
            if refusal:
                out["refused"] += 1
                out["refusals"].append({"target": fact_target, "rule": rule_id,
                                        "reason": str(refusal)})
                _observe(cur, rule_id, context, fact, command, None,
                         refused=str(refusal))
                continue

            out["proposals"].append({"rule": rule_id, "tool": proposal.get("tool"),
                                     "target": fact_target, "command": command,
                                     "why": rule.get("why")})
            cur.execute(
                """
                INSERT INTO scan_recommendations
                    (ip, service, scanner, action, script, source, priority,
                     status, engagement_id, extra)
                VALUES (%s,%s,%s,%s,%s,%s,%s,'pending',%s,%s)
                ON CONFLICT (fingerprint) DO NOTHING
                RETURNING id::text
                """,
                (fact_target, fact.get("service") or service,
                 proposal.get("tool"), command, command, SOURCE,
                 int(proposal.get("priority") or 40),
                 context.get("engagement_id"),
                 Json({"enumeration_rule": rule_id, "why": rule.get("why"),
                       "fact": {k: v for k, v in fact.items() if k != "password"},
                       "source_execution": context.get("id"),
                       "credential_id": context.get("credential_id"),
                       "queued_by": SOURCE})))
            row = cur.fetchone()
            rec_id = row[0] if row else None
            if rec_id:
                out["queued"] += 1
            _record_firing(cur, rule_id, service)
            _observe(cur, rule_id, context, fact, command, rec_id)


def analyse_findings(*, target: str = "", engagement_id: Optional[str] = None,
                     limit: int = 200) -> Dict[str, Any]:
    """Analyse evidence that never came from a command's stdout.

    `web_findings` alone holds more rows than every other finding table
    combined, and the loop could not see any of it because it read tool output
    rather than results. A finding is a fact whatever produced it, and it goes
    through exactly the same rules and the same scope gate as one extracted from
    a command.
    """
    context = {"id": None, "tool": "findings", "target": target,
               "service": "http", "engagement_id": engagement_id}
    out: Dict[str, Any] = {"facts": 0, "proposals": [], "queued": 0,
                           "refused": 0, "refusals": [], "suppressed": [],
                           "available": False}
    rules = load_rules()
    if not rules:
        return out
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                facts = facts_from_web_findings(cur, target=target, limit=limit,
                                                engagement_id=engagement_id)
                # A successful exploit is access, and nothing was enumerating
                # through it.
                facts += facts_from_exploits(cur, target=target)
                # An open port nothing has identified is worth a look whatever
                # opened it — 6200 on this host reads as `lm-x` and is a root
                # shell.
                facts += facts_from_open_ports(cur, target=target)
                out["facts"] = len(facts)
                if facts:
                    _propose_from_facts(cur, facts, context, rules, out)
                out["available"] = True
            conn.commit()
    except Exception as e:  # noqa: BLE001
        log.warning("finding analysis failed: %s", e)
    return out


def _observe(cur, rule_id, execution, fact, command, rec_id, refused=None):
    """Record that a rule fired, with what it proposed and on what evidence."""
    from psycopg2.extras import Json
    cur.execute(
        """
        INSERT INTO public.enumeration_observations
          (rule_id, source_execution, tool, target, service, fact,
           proposed_command, recommendation_id, refused_reason, engagement_id)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (rule_id, execution.get("id"), execution.get("tool") or "",
         fact.get("target") or execution.get("target") or "",
         execution.get("service") or "",
         Json({k: v for k, v in fact.items() if k != "password"}),
         command, rec_id, refused, execution.get("engagement_id")))
