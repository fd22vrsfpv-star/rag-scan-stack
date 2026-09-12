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

                from psycopg2.extras import Json
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
                                         target=target,
                                         port=execution.get("port"))
                        fact_target = fact.get("target") or target
                        key = (command, fact_target)
                        if key in seen:
                            continue
                        seen.add(key)

                        refusal = check_dispatch(str(fact_target), scope_rows,
                                                 command=command)
                        if refusal:
                            out["refused"] += 1
                            out["refusals"].append(
                                {"target": fact_target, "rule": rule_id,
                                 "reason": str(refusal)})
                            _observe(cur, rule_id, execution, fact, command,
                                     None, refused=str(refusal))
                            continue

                        out["proposals"].append(
                            {"rule": rule_id, "tool": proposal.get("tool"),
                             "target": fact_target, "command": command,
                             "why": rule.get("why")})
                        if not queue:
                            continue

                        cur.execute(
                            """
                            INSERT INTO scan_recommendations
                                (ip, service, scanner, action, script, source,
                                 priority, status, engagement_id, extra)
                            VALUES (%s,%s,%s,%s,%s,%s,%s,'pending',%s,%s)
                            ON CONFLICT (fingerprint) DO NOTHING
                            RETURNING id::text
                            """,
                            (fact_target, fact.get("service") or service,
                             proposal.get("tool"), command, command, SOURCE,
                             int(proposal.get("priority") or 40),
                             execution.get("engagement_id"),
                             Json({"enumeration_rule": rule_id,
                                   "why": rule.get("why"),
                                   "fact": {k: v for k, v in fact.items()
                                            if k != "password"},
                                   "source_execution": execution.get("id"),
                                   "credential_id": execution.get("credential_id"),
                                   "queued_by": SOURCE})))
                        row = cur.fetchone()
                        rec_id = row[0] if row else None
                        if rec_id:
                            out["queued"] += 1
                        _record_firing(cur, rule_id, service)
                        _observe(cur, rule_id, execution, fact, command, rec_id)
            conn.commit()
    except Exception as e:  # noqa: BLE001
        log.warning("post-enumeration analysis failed for %s: %s", tool, e)
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
