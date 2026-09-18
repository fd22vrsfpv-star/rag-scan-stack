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

EXTRACTORS_YAML = os.environ.get("ENUMERATION_EXTRACTORS_YAML",
                                 "/knowledge/enumeration_extractors.yaml")
_REPO_EXTRACTORS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "knowledge", "enumeration_extractors.yaml")

SOURCE = "post_enumeration"

# A rule that has been acted on this many times with nothing to show for it
# stops firing. Below the threshold it keeps its chance: a rule that is right
# but rare should not be killed by its first two misses.
SUPPRESS_AFTER = int(os.environ.get("ENUMERATION_SUPPRESS_AFTER", "5"))

# ── LLM fallback ─────────────────────────────────────────────────────────────
# When substantive output produces NO facts from any known extractor, hand it to
# the LLM to classify into STRUCTURED facts that re-enter the SAME rules -> scope
# gate -> pending path. The LLM PROPOSES facts; the deterministic scope gate
# still DISPOSES (CLAUDE.md: retrieve/ask to decide, gate to act). Off if the LLM
# is unreachable — the safe direction is "no extra facts", never "act blind".
LLM_FALLBACK_ENABLED = os.environ.get("ENUMERATION_LLM_FALLBACK", "1") not in (
    "0", "false", "False", "")
LLM_URL = os.environ.get("LLM_URL", "https://llm_query:8002/ollama/chat")
# Omit the model by default so llm_query TASK-ROUTES it. A hardcoded model here
# masquerades as a caller choice and 404s on backends that route by task
# (see memory: llm-query-model-default-defeats-routing). Set POSTEX_LLM_MODEL to
# pin one deliberately.
LLM_MODEL = os.environ.get("POSTEX_LLM_MODEL") or None
LLM_FALLBACK_MIN_CHARS = int(os.environ.get("ENUMERATION_LLM_MIN_CHARS", "40"))
LLM_FALLBACK_MAX_CHARS = int(os.environ.get("ENUMERATION_LLM_MAX_CHARS", "6000"))

# Fact kinds the LLM fallback is allowed to emit — the same vocabulary the
# extractors and rules already speak. An LLM-invented fact kind nothing consumes
# is dropped, so a hallucinated shape cannot leak into the queue.
_LLM_ALLOWED_FACTS = {"secret", "host", "file", "credential", "share", "host_fact"}

API_BASE = os.environ.get("RAG_API_URL", "https://rag-api:8000")
API_KEY = os.environ.get("API_KEY", "changeme")
WEBHOOK_ENABLED = os.environ.get("WEBHOOK_ENABLED", "1") not in (
    "0", "false", "False", "")


def _emit_webhook(event_type: str, data: Dict[str, Any],
                  severity: Optional[str] = None) -> None:
    """Best-effort webhook emit (CLAUDE.md: features that perform actions emit
    events). Never raises into the analysis."""
    if not WEBHOOK_ENABLED:
        return
    try:
        import requests
        payload: Dict[str, Any] = {"event_type": event_type,
                                   "source": SOURCE, "data": data}
        if severity:
            payload["severity"] = severity
        requests.post(f"{API_BASE}/webhooks/emit",
                      headers={"x-api-key": API_KEY,
                               "Content-Type": "application/json"},
                      json=payload, timeout=5, verify=False)
    except Exception as e:  # noqa: BLE001
        log.debug("webhook emit %s failed: %s", event_type, e)

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")
_KEY_PATH = re.compile(r"(/[^\s:]*\.ssh/id_[a-z0-9_]+)")

# The hardcoded regexes above are the FALLBACK for _extract_from_lines when the
# extractor YAML is unreadable — the safe direction is "still read private keys
# and host leads", never "read nothing".
_FALLBACK_EXTRACTORS: List[Dict[str, Any]] = [
    {"id": "private-key-block", "_rx": _PRIVATE_KEY,
     "emit": {"fact": "file", "kind": "private_key"}},
    {"id": "ssh-key-path", "_rx": _KEY_PATH, "fields": {"path": 1},
     "emit": {"fact": "file", "kind": "private_key"}},
    {"id": "known-host-ip", "_rx": _IPV4, "fields": {"target": 0}, "lead": True,
     "emit": {"fact": "host", "source": "known_hosts"}},
]

_EXTRACTORS_CACHE: Optional[List[Dict[str, Any]]] = None

# Promoted (operator-approved) enumeration extractors live in the SHARED
# extractor_learned table — the same store the /extractors learning loop uses —
# under this synthetic tool, so there is ONE learned-pattern store and ONE review
# surface (/extractors/learned), not a parallel one. See propose_learned_extractor.
_ENUM_TOOL = "_enumeration"
_PROMOTED_CACHE: Optional[List[Dict[str, Any]]] = None
_PROMOTED_CACHE_AT: float = 0.0
_PROMOTED_TTL = int(os.environ.get("ENUM_PROMOTED_TTL", "300"))


def _load_yaml_extractors() -> List[Dict[str, Any]]:
    """The YAML extractor catalogue (regex compiled and cached forever), or the
    hardcoded fallback if the file is unreadable. The safe direction on any error
    is that private keys and host leads are still read, never that a config typo
    silently turns off all free-text fact extraction."""
    global _EXTRACTORS_CACHE
    if _EXTRACTORS_CACHE is not None:
        return _EXTRACTORS_CACHE
    compiled: List[Dict[str, Any]] = []
    for candidate in (EXTRACTORS_YAML, _REPO_EXTRACTORS):
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            import yaml
            with open(candidate, encoding="utf-8") as fh:
                raw = (yaml.safe_load(fh) or {}).get("extractors") or []
            for ex in raw:
                pat = ex.get("match")
                if not pat:
                    continue
                try:
                    ex = dict(ex)
                    ex["_rx"] = re.compile(pat)
                    compiled.append(ex)
                except re.error as re_err:
                    log.warning("extractor %s has a bad regex, skipped: %s",
                                ex.get("id"), re_err)
            break
        except Exception as e:  # noqa: BLE001
            log.warning("enumeration extractors %s unreadable: %s", candidate, e)
            compiled = []
            break
    if not compiled:
        log.warning("no enumeration extractors loaded (looked in %s, %s) — "
                    "using hardcoded fallback", EXTRACTORS_YAML, _REPO_EXTRACTORS)
        compiled = _FALLBACK_EXTRACTORS
    _EXTRACTORS_CACHE = compiled
    return compiled


def _load_promoted_extractors() -> List[Dict[str, Any]]:
    """APPROVED learned enumeration extractors from the shared extractor_learned
    table (tool=_enumeration, status=active). These are the patterns the LLM
    discovered that an operator promoted — permanent and deterministic from then
    on, no more LLM cost. TTL-cached; best-effort ([] if the DB is unreachable)."""
    global _PROMOTED_CACHE, _PROMOTED_CACHE_AT
    import time as _t
    now = _t.time()
    if _PROMOTED_CACHE is not None and (now - _PROMOTED_CACHE_AT) < _PROMOTED_TTL:
        return _PROMOTED_CACHE
    compiled: List[Dict[str, Any]] = []
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT rule FROM public.extractor_learned "
                "WHERE tool = %s AND status = 'active'", (_ENUM_TOOL,))
            for (rule,) in cur.fetchall():
                if not isinstance(rule, dict):
                    continue
                pat = rule.get("match")
                if not pat:
                    continue
                try:
                    ex = dict(rule)
                    ex["_rx"] = re.compile(pat)
                    ex["_promoted"] = True
                    compiled.append(ex)
                except re.error as re_err:
                    log.warning("promoted extractor %s bad regex, skipped: %s",
                                rule.get("id"), re_err)
    except Exception as e:  # noqa: BLE001
        log.debug("promoted extractors unavailable: %s", e)
        # keep any previous cache rather than dropping to none on a transient error
        if _PROMOTED_CACHE is not None:
            return _PROMOTED_CACHE
        compiled = []
    _PROMOTED_CACHE = compiled
    _PROMOTED_CACHE_AT = now
    return compiled


def load_extractors() -> List[Dict[str, Any]]:
    """The full extractor set: the YAML catalogue PLUS operator-approved promoted
    extractors from extractor_learned. A shape the LLM kept finding, once
    approved, is caught here for free — the same as a hand-written YAML rule."""
    return _load_yaml_extractors() + _load_promoted_extractors()


def _extract_from_lines(lines: List[str], *, target: str = "",
                        service: str = "") -> List[Dict[str, Any]]:
    """Scan raw output lines against every extractor, emitting normalised facts.

    A rule is written against a FACT, so an extractor added here (a new token
    shape, say) is picked up by any rule that matches its fact — no code change
    on either side."""
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for line in lines:
        for ex in load_extractors():
            rx = ex.get("_rx")
            if rx is None:
                continue
            for m in rx.finditer(line):
                emit = ex.get("emit") or {}
                if not emit.get("fact"):
                    continue
                fact: Dict[str, Any] = dict(emit)
                fact["service"] = fact.get("service") or service
                fact["line"] = line[:200]
                for field, grp in (ex.get("fields") or {}).items():
                    try:
                        gi = int(grp)
                        val = m.group(gi) if gi else m.group(0)
                    except (IndexError, ValueError):
                        val = None
                    if val is not None:
                        fact[field] = val
                if ex.get("lead"):
                    lead = fact.get("target")
                    if (not lead or lead == target
                            or lead.startswith(("0.", "127.", "255."))):
                        continue
                    fact["seen_on"] = target
                else:
                    fact.setdefault("target", target)
                key = (ex.get("id"),
                       fact.get("value") or fact.get("path") or fact.get("target"),
                       fact.get("fact"))
                if key in seen:
                    continue
                seen.add(key)
                out.append(fact)
    return out


def _connect():
    import psycopg2
    return psycopg2.connect(
        os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL")
        or "postgresql://app:app@rag-postgres:5432/scans", connect_timeout=5)


def load_rules(engagement_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """The rule catalogue (YAML) plus the operator-authored DB overlay, or empty
    if the YAML is unreadable.

    Empty is the safe direction and it is logged: no rules means nothing is
    proposed, never that everything is.
    """
    yaml_rules: List[Dict[str, Any]] = []
    for candidate in (RULES_YAML, _REPO_RULES):
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            import yaml
            with open(candidate, encoding="utf-8") as fh:
                yaml_rules = (yaml.safe_load(fh) or {}).get("rules") or []
            break
        except Exception as e:  # noqa: BLE001
            log.warning("enumeration rules %s unreadable: %s", candidate, e)
            yaml_rules = []
            break
    else:
        log.warning("no enumeration rules found (looked in %s, %s)", RULES_YAML, _REPO_RULES)
    return yaml_rules + load_custom_rules(engagement_id)


def test_rules(*, rules: Optional[List[Dict[str, Any]]] = None, target: str = "",
               engagement_id: Optional[str] = None, limit: int = 60) -> Dict[str, Any]:
    """DRY-RUN a rule set against a host's REAL facts: what fires, and what would
    it propose? Never queues and never dispatches — for authoring and testing a
    flow against engagement data before committing it.

    rules: the rules to test (a candidate list). None => the live catalogue
    (YAML + DB overlay). Scope is checked and reported, not enforced."""
    if rules is None:
        rules = load_rules(engagement_id)
    out: Dict[str, Any] = {"target": target, "engagement_id": engagement_id,
                           "rules_tested": len(rules), "facts": 0, "matched": 0,
                           "proposals": [], "refusals": [], "scope": "ok"}
    try:
        from etl.scope_gate import check_dispatch, load_dispatch_scope
    except ImportError:  # pragma: no cover
        from scope_gate import check_dispatch, load_dispatch_scope
    try:
        with _connect() as conn, conn.cursor() as cur:
            facts = facts_from_web_findings(cur, target=target, limit=200,
                                            engagement_id=engagement_id)
            facts += facts_from_exploits(cur, target=target)
            facts += facts_from_open_ports(cur, target=target, limit=limit)
            facts += facts_from_login_services(cur, target=target, limit=limit)
            out["facts"] = len(facts)
            scope_rows, scope_src = load_dispatch_scope(cur, engagement_id)
            if scope_src == "unavailable":
                out["scope"] = "unavailable"
            seen = set()
            for fact in facts:
                for rule in rules:
                    if not _matches(rule, fact):
                        continue
                    proposal = rule.get("propose") or {}
                    command = render(proposal.get("command") or "", fact, target=target)
                    ftgt = fact.get("target") or target or ""
                    key = (rule.get("id"), command, ftgt)
                    if key in seen:
                        continue
                    seen.add(key)
                    out["matched"] += 1
                    refusal = (check_dispatch(str(ftgt), scope_rows, command=command)
                               if out["scope"] != "unavailable" else "scope unavailable")
                    entry = {"rule": rule.get("id") or "unnamed",
                             "tool": proposal.get("tool"), "target": ftgt,
                             "command": command,
                             "matched_fact": {k: fact.get(k) for k in ("fact", "service", "port")},
                             "would_dispatch": not refusal}
                    if refusal:
                        entry["refused"] = str(refusal)
                        out["refusals"].append(entry)
                    out["proposals"].append(entry)
    except Exception as e:  # noqa: BLE001
        out["error"] = str(e)[:200]
    return out


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
    # The reading itself is DATA (knowledge/enumeration_extractors.yaml): a new
    # token/secret shape is added there, not here. A host named in known_hosts
    # is a LEAD, not a licence — the scope gate decides whether it may be
    # touched, and it usually will not.
    lines = list(parsed.get("command_output") or [])
    if output and not lines:
        lines = output.splitlines()
    if lines:
        facts.extend(_extract_from_lines(lines, target=target, service=service))
    return facts


_CUSTOM_RULES_DDL = """
CREATE TABLE IF NOT EXISTS public.custom_enumeration_rules (
    id            text PRIMARY KEY,
    rule          jsonb NOT NULL,
    enabled       boolean NOT NULL DEFAULT true,
    engagement_id uuid,
    created_by    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
)
"""


def load_custom_rules(engagement_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Operator-authored rules from the DB — the writable overlay on the
    read-only YAML. Global rules (engagement_id NULL) always apply; an
    engagement's own rules apply for that engagement."""
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(_CUSTOM_RULES_DDL)
            conn.commit()
            if engagement_id:
                cur.execute(
                    "SELECT rule FROM public.custom_enumeration_rules "
                    " WHERE enabled AND (engagement_id IS NULL OR engagement_id = %s::uuid)",
                    (engagement_id,))
            else:
                cur.execute("SELECT rule FROM public.custom_enumeration_rules "
                            " WHERE enabled AND engagement_id IS NULL")
            return [r[0] for r in cur.fetchall() if isinstance(r[0], dict)]
    except Exception as e:  # noqa: BLE001
        log.debug("custom rules unavailable: %s", e)
        return []


def _matches(rule: Dict[str, Any], fact: Dict[str, Any]) -> bool:
    when = rule.get("when") or {}
    if (when.get("fact") or "") != fact.get("fact"):
        return False
    for key, expected in (when.get("where") or {}).items():
        got = fact.get(key)
        if isinstance(expected, bool):
            if bool(got) is not expected:
                return False
        elif isinstance(expected, list):
            # any-of: fact value must equal one of the listed values (ci).
            if str(got).lower() not in [str(e).lower() for e in expected]:
                return False
        elif isinstance(expected, dict) and "contains" in expected:
            # substring match (ci) — for varied free-text fields like a web
            # finding's issue_type/name where exact match is too brittle.
            if str(expected["contains"]).lower() not in str(got or "").lower():
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

# A port can carry an IDENTIFIED service name that is itself a shell/backdoor —
# Metasploitable's root shell on 1524 is labelled `bindshell` with a
# `root@metasploitable:/#` banner. Filtering to only unidentified services drops
# exactly the ports that ARE shells while offering tcpwrapped/lm-x/status ports
# that are not. So a port is ALSO a bind-shell candidate when its service name or
# banner looks like a shell — the probe (`id`) then decides for real.
_SHELL_SERVICES = {"bindshell", "shell", "rootshell", "backdoor", "ingreslock"}
_SHELL_BANNER_RE = re.compile(
    r"(root@|\buid=\d+|/bin/(?:ba)?sh|[\w.-]+@[\w.-]+:[~/][^\n]*[#$]|\$\s*$|#\s*$)",
    re.I)


def _looks_like_shell(service: str, banner: str) -> bool:
    """A port whose service name or banner betrays a shell/backdoor."""
    if (service or "").strip().lower() in _SHELL_SERVICES:
        return True
    return bool(_SHELL_BANNER_RE.search(banner or ""))


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
    # TCP only. A bind shell is a TCP socket the probe reaches with `nc <host>
    # <port>`; a UDP-only port (68/138/162/4500 on Metasploitable — DHCP,
    # NetBIOS-dgm, SNMP-trap, IPsec-NAT) has nothing on TCP, so the probe gets
    # "Connection refused". Offering those as bind-shell candidates produced
    # four dead-on-arrival "shells" per host. proto NULL defaults to tcp.
    where, params = ["COALESCE(p.is_open, true)",
                     "LOWER(COALESCE(p.proto, 'tcp')) = 'tcp'"], []
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
            svc = service.strip().lower()
            shell_like = _looks_like_shell(service, banner)
            # Offer a candidate when the service is unidentified OR it looks like
            # a shell/backdoor. Miss the second and the actual root shell (service
            # 'bindshell', banner 'root@…:/#') is invisible while dead
            # tcpwrapped/lm-x ports are offered.
            if svc not in _UNIDENTIFIED and not shell_like:
                continue
            facts.append({"fact": "open_port", "target": host, "port": port,
                          "service": service, "banner": banner[:120],
                          "unidentified": svc in _UNIDENTIFIED,
                          "shell_like": shell_like})
    except Exception as e:  # noqa: BLE001
        log.debug("open port facts unavailable: %s", e)
    return facts


# Services that take a login and are worth a default-credential check.
_LOGIN_SERVICES = {
    "ssh": 22, "ftp": 21, "telnet": 23, "mysql": 3306, "mariadb": 3306,
    "postgresql": 5432, "postgres": 5432, "mssql": 1433, "ms-sql-s": 1433,
    "vnc": 5900, "rdp": 3389, "ms-wbt-server": 3389, "smb": 445,
    "microsoft-ds": 445, "netbios-ssn": 139, "redis": 6379, "mongodb": 27017,
    "mongod": 27017, "rlogin": 513, "rexec": 512, "vnc-http": 5800,
    "imap": 143, "pop3": 110, "smtp": 25, "ldap": 389, "snmp": 161,
}


def facts_from_login_services(cur, *, target: str = "", limit: int = 60) -> List[Dict[str, Any]]:
    """Open ports running a service that takes a login — each a candidate for a
    default-credential check. Emitted as `login_service` facts so a rule can
    propose the guess. The gap this closes: recon identifies ssh/ftp/db and the
    platform never tries the defaults, so no valid password is ever found."""
    facts: List[Dict[str, Any]] = []
    where = ["COALESCE(p.is_open, true)", "LOWER(COALESCE(p.proto,'tcp')) = 'tcp'"]
    params: List[Any] = []
    if target:
        where.append("host(a.ip) = %s")
        params.append(target)
    params.append(limit)
    try:
        cur.execute(
            f"""SELECT host(a.ip), p.port, LOWER(COALESCE(p.service,''))
                  FROM ports p JOIN assets a ON a.id = p.asset_id
                 WHERE {' AND '.join(where)}
                 ORDER BY p.port LIMIT %s""", params)
        for host, port, service in cur.fetchall():
            svc = (service or "").strip()
            if svc in _LOGIN_SERVICES:
                facts.append({"fact": "login_service", "target": host,
                              "port": port, "service": svc, "login_service": True})
    except Exception as e:  # noqa: BLE001
        log.debug("login-service facts unavailable: %s", e)
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
                       COALESCE(wf.name,''), COALESCE(wf.issue_type,'')
                  FROM web_findings wf
                  JOIN assets a ON a.id = wf.asset_id
                 WHERE {' AND '.join(where)}
                   AND NOT EXISTS (SELECT 1 FROM public.enumeration_observations eo
                                    WHERE eo.fact->>'web_finding_id' = wf.id::text)
                 ORDER BY wf.created_at DESC
                 LIMIT %s""", params)
        for wid, host, url, severity, name, issue_type in cur.fetchall():
            # issue_type/name carried so rules can key off WHAT the finding is
            # (e.g. information disclosure, directory listing), not only severity —
            # the deterministic tier of "deepen informational findings".
            facts.append({"fact": "web_finding", "target": host, "service": "http",
                          "web_finding_id": wid, "url": url,
                          "severity": (severity or "").lower(),
                          "name": name, "issue_type": issue_type})
    except Exception as e:  # noqa: BLE001
        log.debug("web finding facts unavailable: %s", e)
    return facts


# ── The analysis every command goes through ────────────────────────────────

def _enum_router():
    """The shared enumeration LLM router (model routing + triage + review),
    wired to this module's DB connection for reading operator config."""
    try:
        from etl.enumeration_llm_router import get_router
    except ImportError:  # pragma: no cover
        from enumeration_llm_router import get_router
    return get_router(connect=_connect)


def _llm_classify_output(output: str, *, tool: str = "", target: str = "",
                         service: str = "") -> List[Dict[str, Any]]:
    """LLM EXTRACTION of facts from output that matched NO known extractor.

    Thin wrapper over the router's extract role (kept for backward compat and the
    global LLM_FALLBACK_ENABLED kill switch). The router selects the model/params
    for the extraction role and does the bounded, validated call; the facts it
    returns are still scope-gated downstream — this proposes WHAT was found, never
    authorises acting on it."""
    if not LLM_FALLBACK_ENABLED:
        return []
    return _enum_router().extract(output, tool=tool, target=target,
                                  service=service)


def _record_secret_facts(cur, facts: List[Dict[str, Any]],
                         execution: Dict[str, Any]) -> int:
    """Record `secret` facts as observations even when NO rule proposes a
    follow-up command. A JWT or an AWS key is valuable on its own — the tool's
    purpose is to collect data for a tester's manual workflow — so it must not
    vanish just because the rules engine had nothing to dispatch for it."""
    recorded = 0
    for fact in facts:
        if fact.get("fact") != "secret":
            continue
        kind = fact.get("kind") or "unknown"
        try:
            _observe(cur, f"secret:{kind}", execution, fact, None, None)
            recorded += 1
        except Exception as e:  # noqa: BLE001
            log.debug("recording secret fact failed: %s", e)
    return recorded


# Kinds too vague to generalize into a reusable pattern — never promote these.
_UNPROMOTABLE_KINDS = {"generic", "llm", "unknown", ""}


def _synthesize_regex(value: str) -> Optional[str]:
    """Conservative regex generalized from ONE sample value: runs of the same
    character class become that class with the run's exact length; other
    characters are matched literally (escaped). Precise by design — an operator
    broadens it if needed, and false positives are worse than a narrow pattern.

    "AKIAIOSFODNN7EXAMPLE" -> r"[A-Z]{12}[0-9]{1}[A-Z]{7}"
    """
    s = str(value or "")
    if len(s) < 6 or len(s) > 200:
        return None

    def _cls(ch: str) -> Optional[str]:
        if ch.isascii() and ch.isupper():
            return "[A-Z]"
        if ch.isascii() and ch.islower():
            return "[a-z]"
        if ch.isdigit():
            return "[0-9]"
        return None

    out, i, n = [], 0, len(s)
    while i < n:
        cls = _cls(s[i])
        if cls is None:
            out.append(re.escape(s[i]))
            i += 1
            continue
        j = i
        while j < n and _cls(s[j]) == cls:
            j += 1
        out.append(f"{cls}{{{j - i}}}")
        i = j
    pattern = "".join(out)
    try:
        rx = re.compile(pattern)
    except re.error:
        return None
    # Must still match its own sample, and not be trivially broad.
    if not rx.search(s) or pattern.count("{") < 1:
        return None
    return pattern


def _count_kind_sightings(cur, kind: str) -> int:
    """How many times a secret of this kind has already been recorded (prior
    confirmed sightings), from enumeration_observations. The recurrence signal
    for auto-approval — a shape seen many times is worth making permanent."""
    try:
        cur.execute("SELECT count(*) FROM public.enumeration_observations "
                    "WHERE rule_id = %s", (f"secret:{kind}",))
        r = cur.fetchone()
        return int(r[0]) if r else 0
    except Exception:  # noqa: BLE001
        return 0


def _embed_learned_to_rag() -> None:
    """Best-effort: ask rag-api to (re)embed active learned extractors into RAG.
    Called after an AUTO-approval so the pattern reaches RAG without an operator
    click. The per-request approve endpoint embeds directly; this covers the
    auto path from inside etl (which cannot import the rag-api embed helper)."""
    try:
        import requests
        requests.post(f"{API_BASE}/extractors/learned/sync-rag",
                      headers={"x-api-key": API_KEY}, timeout=10, verify=False)
    except Exception as e:  # noqa: BLE001
        log.debug("auto-promote RAG embed failed: %s", e)


def propose_learned_extractor(kind: str, value: str, *, fact: str = "secret",
                              why: str = "", engagement_id: Optional[str] = None,
                              source: str = "enum_promotion",
                              auto_approve_after: int = 0) -> Optional[str]:
    """Propose a promoted enumeration extractor into the SHARED extractor_learned
    table (tool=_enumeration, kind=deterministic) for review. Approving it
    (status='active' via /extractors/learned) makes the shape a permanent, free,
    deterministic extractor that load_extractors() picks up.

    ``auto_approve_after`` (operator setting enum_router.promotion.auto_approve_after):
    0 (default) => always land 'proposed' for manual review — a one-off LLM guess
    never becomes a rule on its own. N>0 => land 'active' immediately when this
    kind already has >= N prior confirmed sightings (a shape seen that many times
    is trusted), and upgrade an existing 'proposed' row for it to 'active' too. A
    'rejected' row is never revived.

    De-duped by the unique (tool, kind, md5(rule)) index. Returns the row id, or
    None (unpromotable kind, no regex, DB down). Best-effort — never raises."""
    k = (kind or "").strip().lower()
    if k in _UNPROMOTABLE_KINDS:
        return None
    pattern = _synthesize_regex(value)
    if not pattern:
        return None
    try:
        from psycopg2.extras import Json
    except ImportError:  # pragma: no cover - psycopg2 always present in prod
        def Json(x):  # type: ignore
            return x
    rule = {
        "id": f"learned-{k}",
        "match": pattern,
        "emit": {"fact": fact, "kind": k},
        "fields": {"value": 0},
        "why": (why or f"Promoted from a shape the LLM repeatedly classified as "
                       f"{k}.")[:300],
        "sample": str(value)[:80],
    }
    activated = False
    try:
        with _connect() as conn, conn.cursor() as cur:
            # extractor_learned holds cross-engagement technique knowledge (a
            # reusable pattern), so it has no engagement_id by design — like
            # port_access_advice. The engagement is recorded in the rule only for
            # provenance.
            if engagement_id:
                rule["proposed_for_engagement"] = str(engagement_id)
            threshold = int(auto_approve_after or 0)
            auto = bool(threshold > 0
                        and _count_kind_sightings(cur, k) >= threshold)
            new_status = "active" if auto else "proposed"
            # On conflict: upgrade an existing 'proposed' row to 'active' when the
            # threshold is now met, but NEVER revive a 'rejected' one.
            cur.execute(
                """INSERT INTO public.extractor_learned
                     (tool, kind, rule, status, source, confidence, approved_at,
                      reviewed_by)
                   VALUES (%s, 'deterministic', %s::jsonb, %s, %s, 0.6,
                      CASE WHEN %s = 'active' THEN now() ELSE NULL END,
                      CASE WHEN %s = 'active' THEN 'auto:promotion' ELSE NULL END)
                   ON CONFLICT (tool, kind, md5(rule::text)) DO UPDATE
                     SET status = CASE
                            WHEN %s = 'active' AND extractor_learned.status = 'proposed'
                              THEN 'active' ELSE extractor_learned.status END,
                         approved_at = CASE
                            WHEN %s = 'active' AND extractor_learned.status = 'proposed'
                              THEN now() ELSE extractor_learned.approved_at END,
                         reviewed_by = CASE
                            WHEN %s = 'active' AND extractor_learned.status = 'proposed'
                              THEN 'auto:promotion' ELSE extractor_learned.reviewed_by END,
                         updated_at = now()
                   RETURNING id::text, status""",
                (_ENUM_TOOL, Json(rule), new_status, source,
                 new_status, new_status, new_status, new_status, new_status))
            row = cur.fetchone()
            conn.commit()
            if not row:
                return None
            rid, final_status = row[0], row[1]
            activated = (final_status == "active")
            _emit_webhook(
                "enum_extractor_auto_approved" if activated and auto
                else "enum_extractor_proposed",
                {"kind": k, "pattern": pattern, "status": final_status,
                 "auto": auto, "engagement_id": engagement_id})
    except Exception as e:  # noqa: BLE001
        log.debug("propose_learned_extractor failed: %s", e)
        return None
    if activated:
        # picked up by this process immediately, and embedded into RAG.
        global _PROMOTED_CACHE
        _PROMOTED_CACHE = None
        _embed_learned_to_rag()
    return rid


def analyse(execution: Dict[str, Any], *, queue: bool = True,
            allow_llm: bool = True) -> Dict[str, Any]:
    """One finished command: what it found, and what should follow.

    ``allow_llm`` gates the LLM roles (extraction + review). It MUST be False for
    BATCH callers — the post-enumeration sweep re-analyses up to 100 historical
    executions in a loop, and an LLM call per row turned a fast sweep into a
    30-minute one. The LLM fallback is for FRESH single-command output (the
    per-command hook), where it is also bounded by the router's rolling budget.

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
    output_text = execution.get("output") or ""
    router = _enum_router()

    # LLM EXTRACTION (routed + triaged): substantive output that matched NO known
    # extractor is handed to the router's extraction role to classify into
    # structured facts, which re-enter the SAME rules -> scope gate -> pending
    # path below. The router decides IF the LLM runs (deterministic first) and
    # WHICH model. The LLM proposes WHAT was found; the gate still disposes.
    # Skipped entirely for batch callers (allow_llm=False) so a 100-row sweep
    # never fires 100 serial LLM calls.
    if allow_llm and router.should_extract(output_text, facts):
        llm_facts = router.extract(output_text, tool=tool, target=target,
                                   service=service)
        if llm_facts:
            facts = llm_facts
            out["llm_fallback"] = {"facts": len(llm_facts),
                                   "kinds": sorted({f.get("kind") for f in llm_facts})}
            _emit_webhook("post_enum_llm_classified",
                          {"target": target, "tool": tool, "service": service,
                           "facts": len(llm_facts),
                           "engagement_id": execution.get("engagement_id")})

    # REVIEW (routed): validate candidate facts (from BOTH deterministic
    # extractors and the LLM fallback) before they are queued, dropping false
    # positives. Fails OPEN — a reviewer outage keeps the facts, never silently
    # drops findings. Skipped for batch callers (allow_llm=False).
    if facts and allow_llm:
        rev = router.review(facts, output=output_text, target=target,
                            service=service)
        if rev.get("reviewed"):
            out["review"] = {"reviewed": rev["reviewed"], "dropped": rev["dropped"]}
            _emit_webhook("post_enum_facts_reviewed",
                          {"target": target, "tool": tool,
                           "reviewed": rev["reviewed"], "dropped": rev["dropped"],
                           "kept": len(rev["facts"]),
                           "engagement_id": execution.get("engagement_id")})
        facts = rev["facts"]

        # PROMOTION: a secret the LLM discovered (not a known extractor) and the
        # review CONFIRMED is worth turning into a permanent, free, deterministic
        # extractor. Land it 'proposed' for operator review, or auto-approve once
        # the kind has enough prior sightings (operator setting
        # enum_router.promotion.auto_approve_after; 0 = manual only). Only specific
        # kinds, only review-confirmed — a one-off / vague "generic" is never
        # promoted.
        promo = router.route("promotion")
        if promo.get("enabled"):
            auto_after = int(promo.get("auto_approve_after") or 0)
            proposed = []
            for f in facts:
                if (f.get("fact") == "secret" and f.get("source") == "llm_fallback"
                        and (f.get("review") or {}).get("confidence") in ("high", "medium")):
                    rid = propose_learned_extractor(
                        f.get("kind"), f.get("value") or f.get("line") or "",
                        why=f.get("why") or "",
                        engagement_id=execution.get("engagement_id"),
                        auto_approve_after=auto_after)
                    if rid:
                        proposed.append(f.get("kind"))
            if proposed:
                out["promotions_proposed"] = sorted(set(proposed))

    out["facts"] = len(facts)
    if not facts:
        return out
    rules = load_rules(execution.get("engagement_id"))

    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                out["available"] = True
                # Secrets are recorded even with no rule to dispatch — a token is
                # worth keeping for the tester's manual workflow on its own.
                secrets = _record_secret_facts(cur, facts, execution)
                if secrets:
                    out["secrets_recorded"] = secrets
                    _emit_webhook("post_enum_secret_found",
                                  {"target": target, "count": secrets,
                                   "kinds": sorted({f.get("kind") for f in facts
                                                    if f.get("fact") == "secret"}),
                                   "engagement_id": execution.get("engagement_id")},
                                  severity="high")
                if not rules:
                    conn.commit()
                    return out
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
                    conn.commit()
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
    rules = load_rules(engagement_id)
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
                # An open LOGIN service (ssh/ftp/db/vnc/…) is worth a default-
                # credential check. Without this the agent found ssh on a host and
                # never guessed msfadmin:msfadmin.
                facts += facts_from_login_services(cur, target=target)
                out["facts"] = len(facts)
                if facts:
                    _propose_from_facts(cur, facts, context, rules, out)
                    # B2: deepen INFORMATIONAL web findings the deterministic
                    # rules did not name (the long tail) — budget-bounded LLM.
                    _deepen_info_findings(cur, facts, context, rules, out)
                out["available"] = True
            conn.commit()
    except Exception as e:  # noqa: BLE001
        log.warning("finding analysis failed: %s", e)
    return out


def _deepen_info_findings(cur, facts, context, rules, out) -> None:
    """For info/low web findings that matched NO deterministic rule, ask the
    router (budget-bounded, fail-closed) for ONE read-only probe that turns the
    note into evidence, scope-gate it, and queue it pending — the AI tier of
    "deepen informational findings". Symmetric with the command-output LLM
    fallback; the router budget caps how many findings we spend the LLM on."""
    from psycopg2.extras import Json
    try:
        from etl.scope_gate import check_dispatch, load_dispatch_scope
    except ImportError:  # pragma: no cover
        from scope_gate import check_dispatch, load_dispatch_scope
    candidates = [f for f in facts
                  if f.get("fact") == "web_finding"
                  and f.get("severity") in ("info", "low")
                  and not any(_matches(r, f) for r in rules)]
    if not candidates:
        return
    router = _enum_router()
    scope_rows, scope_source = load_dispatch_scope(cur, context.get("engagement_id"))
    if scope_source == "unavailable":
        return
    deepened = 0
    for fact in candidates:
        proposal = router.deepen_finding(fact)   # None once the budget is spent
        if not proposal:
            continue
        command = proposal["command"]
        fact_target = fact.get("target") or context.get("target") or ""
        refusal = check_dispatch(str(fact_target), scope_rows, command=command)
        if refusal:
            _observe(cur, "deepen:info", context, fact, command, None, refused=str(refusal))
            out["refused"] += 1
            continue
        cur.execute(
            """INSERT INTO scan_recommendations
                 (ip, service, scanner, action, script, source, priority,
                  status, engagement_id, extra)
               VALUES (%s,%s,%s,%s,%s,%s,%s,'pending',%s,%s)
               ON CONFLICT (fingerprint) DO NOTHING RETURNING id::text""",
            (fact_target, "http", "deepen", command, command, SOURCE, 30,
             context.get("engagement_id"),
             Json({"deepened_finding": fact.get("web_finding_id"),
                   "why": proposal.get("why"), "assertion": proposal.get("assertion"),
                   "finding_name": fact.get("name"), "queued_by": "deepen:info"})))
        row = cur.fetchone()
        rec_id = row[0] if row else None
        if rec_id:
            out["queued"] += 1
            deepened += 1
        _observe(cur, "deepen:info", context, fact, command, rec_id)
    if deepened:
        out["info_deepened"] = deepened
        _emit_webhook("post_enum_info_deepened",
                      {"target": context.get("target"), "count": deepened,
                       "engagement_id": context.get("engagement_id")})


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
