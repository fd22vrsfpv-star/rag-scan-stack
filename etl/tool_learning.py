"""Learned tool selection — pick the next tool from the error text, not a rule
somebody typed.

WHY THIS EXISTS
---------------
`cred_checker` used to decide its fallback like this::

    if "kex error" in hydra_output or "no match for method" in hydra_output:
        fall back to nmap

That rule is correct, and it is also the whole problem. It exists because a
human read one error message from one tool on one protocol and wrote the
conclusion down. Nothing else in the platform got the same treatment, so every
other tool/error pair kept re-running a tool that could not work, produced
nothing, and reported "nothing found" — which reads identically to "there was
nothing to find".

This module replaces the typed rule with an observation loop:

1. **Signature.** `error_signature()` turns a tool's raw output into a stable
   hash. It knows *no* protocol vocabulary — no "kex", no "ssh", no service
   names. It keeps the lines that look like diagnostics by generic English
   ("error", "failed", "refused", "unsupported", "no match", …), strips the
   volatile parts (addresses, ports, digits, hex, timestamps), redacts anything
   sitting after a credential label, and hashes what is left. The same failure
   from the same tool hashes the same way against any target.

2. **Record.** Every attempt lands in `tool_attempts`: tool, service, whether it
   produced anything, and the signature of what it printed.

3. **Learn.** `observe_sequence()` reads one run's ordered attempts. Where tool
   A failed with signature S and tool B then succeeded on the same
   (target, port, service), that pair is upserted into `tool_selection_learned`
   with support/attempts/successes counters. The rule becomes `active` the first
   time B is actually observed to succeed where A failed.

4. **Apply.** `next_tool()` consults those rules, so the second time a signature
   is seen the platform goes straight to the tool that worked. `preferred_order()`
   goes further: once a rule has enough support, the winner is tried FIRST and
   the dead round-trip stops happening at all.

The first encounter with an unknown failure is an **exploration** — try another
authorised candidate and record what happened. That exploration is the learning
mechanism; there is nothing to configure and nothing to type.

NOT JUST CREDENTIALS
--------------------
Nothing above is specific to credential checking; `phase` keeps the rules for
different kinds of work apart. `observe_execution()` is the general entry point
— one call after ANY command finishes — and `kali_listener.db_update_tool_execution`
calls it for every tool the platform runs, so a command that errors anywhere
post-analysis feeds the same loop. `learn_from_tool_executions()` backfills from
the history already captured in `tool_executions`, and `suggest_alternatives()`
answers "this just failed like this, what has worked after it before?" for any
tool at all.

WHAT THIS IS NOT
----------------
This is **not** an authorisation mechanism and must never become one. A rule can
only reorder candidates the caller already had — tools the operator authorised
for that engagement, against a target that already passed the scope gate. It can
never add a tool, a target or a port. `next_tool()` takes the remaining
candidates as an argument and can only return one of them.

DEGRADED MODE
-------------
No database, or a database that refuses the query, means **no learning** — not
"no rule found". Those are different answers and the caller is told which:
`available()` is False and every lookup returns a reason of ``"unavailable"``,
so the audit says "could not consult" rather than implying a clean miss.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger("tool_learning")

DEFAULT_PHASE = "credential_check"

DB_DSN = os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL") or \
    "postgresql://app:app@rag-postgres:5432/scans"

# A learned rule is applied from the first observed success (confidence is then
# 1.0 over a single attempt). Re-ORDERING the candidate list — trying the winner
# before the loser on the next run — is the stronger claim, so it waits for
# corroboration.
PROMOTE_AFTER_SUPPORT = int(os.environ.get("TOOL_LEARNING_PROMOTE_SUPPORT", "2"))
PROMOTE_MIN_CONFIDENCE = float(os.environ.get("TOOL_LEARNING_PROMOTE_CONFIDENCE", "0.6"))
# After this many tries with nothing to show for it, a fallback is a dead end
# for that failure and stops being offered. Learning only which tool WORKS would
# leave every useless fallback running forever.
SUPPRESS_AFTER = int(os.environ.get("TOOL_LEARNING_SUPPRESS_AFTER", "3"))

# ── Signature ──────────────────────────────────────────────────────────────
#
# Deliberately generic. Every token below is ordinary English for "this did not
# work"; none of it names a tool, a protocol or a service. Adding protocol
# vocabulary here would re-create the hardcoded rule this module exists to
# remove.
_DIAGNOSTIC_MARKERS = (
    "error", "failed", "failure", "fatal", "cannot", "can't", "could not",
    "couldn't", "unable", "refused", "denied", "rejected", "timeout",
    "timed out", "unsupported", "not supported", "no match", "mismatch",
    "invalid", "unreachable", "no route", "exception", "aborted", "broken",
    "missing", "permission", "unknown", "not found", "closed by",
)

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_MAC = re.compile(r"\b(?:[0-9a-f]{2}:){3,}[0-9a-f]{2}\b")
_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX = re.compile(r"\b[0-9a-f]{8,}\b")
_NUM = re.compile(r"\d+")
_WS = re.compile(r"\s+")
# Anything following a credential label is redacted before it can reach the
# database: a failure phrase is shown to operators and exported, and tools like
# hydra echo the pair they just tried on the same line as the error.
_SECRET = re.compile(
    r"\b(pass(?:word)?|passwd|login|user(?:name)?|secret|token|key)\b"
    r"\s*[:=]\s*\S+", re.I)


def normalise_line(line: str) -> str:
    """Strip everything that varies between two runs of the same failure."""
    s = _ANSI.sub("", line or "").strip().lower()
    s = _SECRET.sub(lambda m: f"{m.group(1)}:<redacted>", s)
    s = _MAC.sub("<mac>", s)
    s = _IPV4.sub("<ip>", s)
    s = _HEX.sub("<hex>", s)
    s = _NUM.sub("<n>", s)
    return _WS.sub(" ", s).strip()


def salient_lines(text: str, limit: int = 3) -> List[str]:
    """The lines that read like diagnostics, normalised and de-duplicated.

    Falls back to the last non-empty lines when nothing matches, because a tool
    that fails without saying "error" anywhere still fails the same way twice —
    and an empty signature would collapse every such failure into one bucket.
    """
    lines = [ln for ln in (text or "").splitlines() if ln.strip()]
    hits, seen = [], set()
    for ln in lines:
        low = ln.lower()
        if any(m in low for m in _DIAGNOSTIC_MARKERS):
            n = normalise_line(ln)
            if n and n not in seen:
                seen.add(n)
                hits.append(n)
    if not hits:
        for ln in reversed(lines[-limit:]):
            n = normalise_line(ln)
            if n and n not in seen:
                seen.add(n)
                hits.append(n)
    return hits[:limit]


def error_signature(text: str, limit: int = 3) -> Tuple[Optional[str], Optional[str]]:
    """``(signature, phrase)`` for a tool's output.

    `signature` is a stable 16-hex-char hash of the salient normalised lines;
    `phrase` is the first of those lines, kept so an operator reviewing a
    learned rule can see which message taught it. Both are None when the output
    is empty — a tool that printed nothing has not told us anything to learn
    from, and pretending otherwise would merge unrelated silences.
    """
    lines = salient_lines(text, limit)
    if not lines:
        return None, None
    blob = "\n".join(sorted(lines))
    return hashlib.md5(blob.encode("utf-8", "replace")).hexdigest()[:16], lines[0][:300]


# ── Storage ────────────────────────────────────────────────────────────────

def _connect():
    import psycopg2  # imported lazily: callers must work without a database
    return psycopg2.connect(DB_DSN, connect_timeout=5)


def available() -> bool:
    """True when the learning store can actually be reached.

    Separate from "no rule matched" on purpose. A probe that could not run is
    not a negative result, and an audit that conflates them tells the operator
    the platform looked and found nothing when it never looked.
    """
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1 FROM public.tool_selection_learned LIMIT 1")
            cur.fetchone()
        return True
    except Exception as e:  # noqa: BLE001 - any failure means "cannot consult"
        log.debug("tool_learning unavailable: %s", e)
        return False


def record_attempt(
    tool: str,
    *,
    service: str = "",
    target: Optional[str] = None,
    port: Optional[int] = None,
    success: bool = False,
    result_count: int = 0,
    output: str = "",
    signature: Optional[str] = None,
    phrase: Optional[str] = None,
    chosen_because: Optional[str] = None,
    rule_id: Optional[str] = None,
    engagement_id: Optional[str] = None,
    phase: str = DEFAULT_PHASE,
) -> Optional[str]:
    """Persist one attempt. Returns the row id, or None if it could not be stored.

    Never raises: an unwritable audit row must not abort a scan that ran.
    """
    if signature is None and not success:
        signature, phrase = error_signature(output)
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public.tool_attempts
                  (phase, tool, service, target, port, success, result_count,
                   failure_signature, failure_phrase, chosen_because, rule_id,
                   engagement_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING id
                """,
                (phase, tool, service or "", target, port, bool(success),
                 int(result_count or 0), signature, phrase, chosen_because,
                 rule_id, engagement_id),
            )
            return str(cur.fetchone()[0])
    except Exception as e:  # noqa: BLE001
        log.debug("record_attempt failed: %s", e)
        return None


# ── Lookup ─────────────────────────────────────────────────────────────────

def rules_for_signature(
    failed_tool: str,
    signature: Optional[str],
    candidates: Sequence[str],
    *,
    service: str = "",
    phase: str = DEFAULT_PHASE,
) -> List[Dict[str, Any]]:
    """Every rule — any status — for this exact failure, restricted to `candidates`.

    Restricting to the caller's candidate list is the guarantee that a learned
    rule can only reorder what was already authorised: it can never introduce a
    tool the caller did not offer.

    Rejected and zero-success rules are returned too, because "we tried that
    after this failure N times and it never helped" is as much a thing to have
    learned as a positive rule, and the caller uses it to stop reaching for a
    dead fallback.
    """
    if not signature or not candidates:
        return []
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, preferred_tool, support, attempts, successes,
                       confidence, failure_phrase, status
                  FROM public.tool_selection_learned
                 WHERE phase = %s AND service = %s AND failed_tool = %s
                   AND failure_signature = %s
                   AND preferred_tool = ANY(%s)
                 ORDER BY successes DESC, confidence DESC NULLS LAST, support DESC
                """,
                (phase, service or "", failed_tool, signature, list(candidates)),
            )
            rows = cur.fetchall()
    except Exception as e:  # noqa: BLE001
        log.debug("rules_for_signature failed: %s", e)
        return []
    return [{
        "id": str(r[0]), "preferred_tool": r[1], "support": r[2],
        "attempts": r[3], "successes": r[4],
        "confidence": float(r[5]) if r[5] is not None else None,
        "failure_phrase": r[6], "status": r[7],
    } for r in rows]


def service_success_rates(
    candidates: Sequence[str], *, service: str = "", phase: str = DEFAULT_PHASE,
) -> Dict[str, float]:
    """Observed success rate per tool for this service, from `tool_attempts`.

    Used to order an exploration when no rule matches: prefer the candidate that
    has actually worked here before over one that never has. Tools with no
    history are absent from the mapping rather than scored 0 — never having run
    is not the same as having run and failed.
    """
    if not candidates:
        return {}
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT tool,
                       SUM(CASE WHEN success THEN 1 ELSE 0 END)::float
                         / NULLIF(COUNT(*), 0)
                  FROM public.tool_attempts
                 WHERE phase = %s AND service = %s AND tool = ANY(%s)
                 GROUP BY tool
                """,
                (phase, service or "", list(candidates)),
            )
            return {r[0]: float(r[1]) for r in cur.fetchall() if r[1] is not None}
    except Exception as e:  # noqa: BLE001
        log.debug("service_success_rates failed: %s", e)
        return {}


def preferred_order(
    candidates: Sequence[str], *, service: str = "", phase: str = DEFAULT_PHASE,
) -> Tuple[List[str], List[str]]:
    """``(ordered candidates, notes)`` — the winner first once it has earned it.

    A rule with enough support says "on this service, that tool fails this way
    and this other one works". Acting on it before the first tool runs is what
    turns the fallback from a recovery into a saved round-trip. Below the
    support threshold the declared order stands, so a single lucky observation
    does not reshape the pipeline.
    """
    order = list(candidates)
    notes: List[str] = []
    if len(order) < 2:
        return order, notes
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT failed_tool, preferred_tool, support, confidence,
                       failure_phrase
                  FROM public.tool_selection_learned
                 WHERE phase = %s AND service = %s AND status = 'active'
                   AND support >= %s
                   AND COALESCE(confidence, 0) >= %s
                   AND failed_tool = ANY(%s) AND preferred_tool = ANY(%s)
                 ORDER BY support DESC
                """,
                (phase, service or "", PROMOTE_AFTER_SUPPORT,
                 PROMOTE_MIN_CONFIDENCE, order, order),
            )
            rows = cur.fetchall()
    except Exception as e:  # noqa: BLE001
        log.debug("preferred_order unavailable: %s", e)
        return order, ["learning store unavailable; declared order used"]

    for failed_tool, preferred_tool, support, confidence, phrase in rows:
        if failed_tool not in order or preferred_tool not in order:
            continue
        if order.index(preferred_tool) < order.index(failed_tool):
            continue  # already ahead
        order.remove(preferred_tool)
        order.insert(order.index(failed_tool), preferred_tool)
        notes.append(
            f"{preferred_tool} promoted ahead of {failed_tool} for {service or 'service'} "
            f"(learned from {support} observations of: {phrase or 'a repeated failure'})"
        )
    return order, notes


def next_tool(
    failed_tool: str,
    signature: Optional[str],
    remaining: Sequence[str],
    *,
    service: str = "",
    phase: str = DEFAULT_PHASE,
    store_available: Optional[bool] = None,
) -> Tuple[Optional[str], str, Optional[str]]:
    """``(tool, reason, rule_id)`` — what to try after `failed_tool` failed.

    `remaining` bounds the answer: only a tool the caller already offered can
    come back. `reason` is one of ``learned`` / ``exploration`` /
    ``only_candidate`` / ``exhausted`` / ``learned_dead_end`` / ``unavailable``
    and goes into the audit verbatim, so an operator can always tell a rule from
    a guess.

    Two directions are learned here, not one. A rule with observed successes
    selects the winner outright. A rule with `SUPPRESS_AFTER` attempts and zero
    successes does the opposite: that candidate is dropped, because the platform
    has watched it fail after this exact message enough times to stop paying for
    it. Learning only the positive half would leave every useless fallback
    running forever.
    """
    remaining = [t for t in remaining if t != failed_tool]
    if not remaining:
        return None, "exhausted", None
    if store_available is False:
        return remaining[0], "unavailable", None

    known = rules_for_signature(failed_tool, signature, remaining,
                                service=service, phase=phase)
    for r in known:
        if r["status"] == "active" and (r["successes"] or 0) > 0:
            return r["preferred_tool"], "learned", r["id"]

    dead = {r["preferred_tool"] for r in known
            if (r["successes"] or 0) == 0
            and ((r["attempts"] or 0) >= SUPPRESS_AFTER or r["status"] == "rejected")}
    viable = [t for t in remaining if t not in dead]
    if not viable:
        return None, "learned_dead_end", None
    if len(viable) == 1:
        return viable[0], "only_candidate", None

    rates = service_success_rates(viable, service=service, phase=phase)
    ranked = sorted(viable, key=lambda t: (-rates.get(t, 0.0), viable.index(t)))
    return ranked[0], "exploration", None


# ── Learn ──────────────────────────────────────────────────────────────────
#
# One upsert, used by every learner. Counters only ever move forward, and a rule
# an operator rejected stays rejected — new evidence never silently reinstates a
# tool a human ruled out.
_UPSERT_RULE = """
                            INSERT INTO public.tool_selection_learned
                              (phase, service, failed_tool, failure_signature,
                               preferred_tool, failure_phrase, support, attempts,
                               successes, confidence, status)
                            VALUES (%s,%s,%s,%s,%s,%s,1,1,%s,%s,%s)
                            ON CONFLICT (phase, service, failed_tool,
                                         failure_signature, preferred_tool)
                            DO UPDATE SET
                              support   = public.tool_selection_learned.support + 1,
                              attempts  = public.tool_selection_learned.attempts + 1,
                              successes = public.tool_selection_learned.successes
                                          + EXCLUDED.successes,
                              confidence = (public.tool_selection_learned.successes
                                            + EXCLUDED.successes)::numeric
                                           / (public.tool_selection_learned.attempts + 1),
                              failure_phrase = COALESCE(
                                  public.tool_selection_learned.failure_phrase,
                                  EXCLUDED.failure_phrase),
                              last_seen_at = now(),
                              -- A rule an operator rejected stays rejected; new
                              -- evidence does not silently reinstate it.
                              status = CASE
                                  WHEN public.tool_selection_learned.status = 'rejected'
                                       THEN 'rejected'
                                  WHEN public.tool_selection_learned.successes
                                       + EXCLUDED.successes > 0 THEN 'active'
                                  ELSE public.tool_selection_learned.status END
                            RETURNING id, support, attempts, successes, confidence,
                                      status, (xmax = 0) AS inserted
                            """


def _upsert_rule(cur, phase, service, failed_tool, signature, preferred_tool,
                 phrase, succeeded):
    cur.execute(_UPSERT_RULE, (phase, service or "", failed_tool, signature,
                               preferred_tool, phrase, 1 if succeeded else 0,
                               1.0 if succeeded else 0.0,
                               "active" if succeeded else "proposed"))
    r = cur.fetchone()
    return {
        "id": str(r[0]), "failed_tool": failed_tool,
        "preferred_tool": preferred_tool, "signature": signature,
        "phrase": phrase, "support": r[1], "attempts": r[2], "successes": r[3],
        "confidence": float(r[4]) if r[4] is not None else None,
        "status": r[5], "new": bool(r[6]), "service": service,
    }


def observe_sequence(
    attempts: Sequence[Dict[str, Any]],
    *,
    service: str = "",
    phase: str = DEFAULT_PHASE,
    emit: bool = True,
) -> List[Dict[str, Any]]:
    """Derive rules from one run's ordered attempts. Returns the rules touched.

    For every failed attempt, each LATER attempt in the same run is evidence
    about what to do next time that signature appears: a later success makes the
    rule active, a later failure is counted against its confidence. Both matter
    — a fallback that never works is worth learning too, so the platform stops
    reaching for it.
    """
    rows = [a for a in attempts if a.get("tool")]
    if len(rows) < 2:
        return []
    touched: List[Dict[str, Any]] = []
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                for i, failed in enumerate(rows):
                    if failed.get("success") or not failed.get("signature"):
                        continue
                    for later in rows[i + 1:]:
                        if later["tool"] == failed["tool"]:
                            continue
                        ok = bool(later.get("success"))
                        touched.append(_upsert_rule(
                            cur, phase, service, failed["tool"],
                            failed["signature"], later["tool"],
                            failed.get("phrase"), ok))
            conn.commit()
    except Exception as e:  # noqa: BLE001
        log.debug("observe_sequence failed: %s", e)
        return []

    if emit:
        for t in touched:
            if t["new"] and t["status"] == "active":
                _emit_webhook(t, phase)
    return touched


# ── Any command, not just credential checks ────────────────────────────────
#
# Everything above is phase-parameterised for this reason. `observe_execution()`
# is the general entry point: one call after ANY command finishes, from any
# runner, and the same loop applies — signature the error text, record it, and
# pair it against what ran before on the same target so the platform learns
# which tool to reach for when that message appears again.
#
# It is deliberately a single call with no candidate list, because a general
# runner does not have one. What comes back is advice: `suggest_alternatives()`
# names tools that have worked after this exact failure. Acting on that advice
# is the caller's decision and still goes through the scope gate and whatever
# approval that phase requires — a learned rule has never been, and must never
# become, a reason to run something.
TOOL_EXECUTION_PHASE = "tool_execution"

# How far back a failure counts as "the thing this run followed". Two commands
# against the same target an hour apart are plausibly the same attempt at the
# same problem; two a week apart are not, and pairing them would manufacture
# rules out of coincidence.
CORRELATION_WINDOW_MINUTES = int(
    os.environ.get("TOOL_LEARNING_WINDOW_MINUTES", "360"))


def execution_failed(status: Optional[str] = None, exit_code: Optional[int] = None,
                     error: str = "", output: str = "") -> bool:
    """Did this command fail? Three independent signals, any one is enough.

    A tool that exits 0 while printing a fatal error to stderr is common enough
    that trusting the exit code alone would miss most of what there is to learn.
    """
    if status in ("failed", "timeout"):
        return True
    if exit_code not in (None, 0):
        return True
    if (error or "").strip():
        return True
    return False


def observe_execution(
    tool: str,
    *,
    service: str = "",
    target: Optional[str] = None,
    port: Optional[int] = None,
    status: Optional[str] = None,
    exit_code: Optional[int] = None,
    output: str = "",
    error: str = "",
    result_count: int = 0,
    engagement_id: Optional[str] = None,
    phase: str = TOOL_EXECUTION_PHASE,
    emit: bool = True,
) -> Dict[str, Any]:
    """Record one finished command and learn from it. Never raises.

    Returns ``{"recorded": bool, "failed": bool, "signature": str|None,
    "phrase": str|None, "learned": [rules]}``. A caller that gets
    ``recorded: False`` knows the platform did not observe this run — which is
    not the same as the run having taught it nothing.
    """
    failed = execution_failed(status, exit_code, error, output)
    sig = phrase = None
    if failed:
        # The tool's complaint first; its normal output only if it said nothing
        # on stderr. Mixing the two would let a noisy success drown the error.
        sig, phrase = error_signature(error or output)
    out: Dict[str, Any] = {"recorded": False, "failed": failed,
                           "signature": sig, "phrase": phrase, "learned": []}
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.tool_attempts
                      (phase, tool, service, target, port, success, result_count,
                       failure_signature, failure_phrase, chosen_because,
                       engagement_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'observed',%s)
                    RETURNING id
                    """,
                    (phase, tool, service or "", target, port, not failed,
                     int(result_count or 0), sig, phrase, engagement_id),
                )
                out["recorded"] = True
                out["attempt_id"] = str(cur.fetchone()[0])
                out["learned"] = _learn_against_recent(
                    cur, phase=phase, service=service or "", target=target,
                    port=port, tool=tool, succeeded=not failed)
            conn.commit()
    except Exception as e:  # noqa: BLE001
        log.debug("observe_execution failed: %s", e)
        return out

    if emit:
        for r in out["learned"]:
            if r["new"] and r["status"] == "active":
                _emit_webhook(r, phase)
    return out


def _learn_against_recent(cur, *, phase, service, target, port, tool, succeeded):
    """Pair this run against the recent failures it followed on the same target.

    This is the incremental form of `observe_sequence`: a general runner reports
    one command at a time, so the sequence has to be reconstructed from what is
    already recorded rather than handed over whole.
    """
    if not target:
        return []
    cur.execute(
        """
        SELECT DISTINCT ON (tool, failure_signature)
               tool, failure_signature, failure_phrase
          FROM public.tool_attempts
         WHERE phase = %s AND service = %s AND target = %s
           AND COALESCE(port, -1) = COALESCE(%s, -1)
           AND tool <> %s
           AND success = false
           AND failure_signature IS NOT NULL
           AND created_at > now() - (%s || ' minutes')::interval
         ORDER BY tool, failure_signature, created_at DESC
         LIMIT 10
        """,
        (phase, service or "", target, port, tool, CORRELATION_WINDOW_MINUTES),
    )
    return [_upsert_rule(cur, phase, service, r[0], r[1], tool, r[2], succeeded)
            for r in cur.fetchall()]


def suggest_alternatives(
    tool: str,
    output: str = "",
    *,
    error: str = "",
    service: str = "",
    phase: str = TOOL_EXECUTION_PHASE,
    signature: Optional[str] = None,
    limit: int = 5,
) -> Dict[str, Any]:
    """What has worked before after this exact failure.

    Advice, not permission. The caller decides whether to act, and anything it
    dispatches goes through the scope gate and its phase's approval like any
    other dispatch.

    ``{"signature", "phrase", "available", "suggestions": [...]}``.
    `available` distinguishes "nothing has been learned about this failure yet"
    from "the platform could not look" — reporting an unreachable store as an
    empty result is exactly the mistake this codebase keeps making.
    """
    if signature is None:
        signature, phrase = error_signature(error or output)
    else:
        _, phrase = error_signature(error or output)
    res: Dict[str, Any] = {"signature": signature, "phrase": phrase,
                           "available": False, "suggestions": []}
    if not signature:
        res["available"] = available()
        return res
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT preferred_tool, support, attempts, successes, confidence,
                       status, failure_phrase
                  FROM public.tool_selection_learned
                 WHERE phase = %s AND service = %s AND failed_tool = %s
                   AND failure_signature = %s AND status = 'active'
                   AND successes > 0
                 ORDER BY confidence DESC NULLS LAST, successes DESC
                 LIMIT %s
                """,
                (phase, service or "", tool, signature, limit),
            )
            rows = cur.fetchall()
    except Exception as e:  # noqa: BLE001
        log.debug("suggest_alternatives failed: %s", e)
        return res
    res["available"] = True
    res["suggestions"] = [{
        "tool": r[0], "support": r[1], "attempts": r[2], "successes": r[3],
        "confidence": float(r[4]) if r[4] is not None else None,
        "status": r[5], "learned_from": r[6],
    } for r in rows]
    return res


def learn_from_tool_executions(
    *, since_hours: Optional[int] = None, limit: int = 5000,
    phase: str = TOOL_EXECUTION_PHASE, emit: bool = False,
) -> Dict[str, Any]:
    """Backfill rules from `tool_executions`, which already has the raw signal.

    Every command the platform has ever run is in that table with its command
    line, stderr, exit code and status. Learning starts from that history rather
    than from zero, so the first run after this ships already knows what the
    last few hundred runs demonstrated.

    Idempotent in effect, not in counters: re-running it re-counts the same
    pairs, so it is a backfill to run once per window, not a cron job.
    """
    out = {"examined": 0, "failures": 0, "rules": 0, "available": False}
    where = "WHERE started_at > now() - (%s || ' hours')::interval" if since_hours else ""
    params: List[Any] = [since_hours] if since_hours else []
    params.append(limit)
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT tool, COALESCE(service, ''), target, port, status,
                           exit_code, output, error, started_at
                      FROM public.tool_executions
                      {where}
                     ORDER BY target, port NULLS FIRST, started_at
                     LIMIT %s
                    """,
                    params,
                )
                rows = cur.fetchall()
                out["available"] = True
                out["examined"] = len(rows)

                # Group by what a fallback would actually be a fallback FOR: the
                # same service on the same target and port.
                groups: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = {}
                for tool, service, target, port, status, code, output, error, ts in rows:
                    if not target:
                        continue
                    failed = execution_failed(status, code, error or "", output or "")
                    sig = ph = None
                    if failed:
                        sig, ph = error_signature((error or "") or (output or ""))
                        out["failures"] += 1
                    groups.setdefault((service, target, port), []).append({
                        "tool": tool, "success": not failed,
                        "signature": sig, "phrase": ph, "ts": ts,
                    })

                for (service, _target, _port), seq in groups.items():
                    for i, failed_row in enumerate(seq):
                        if failed_row["success"] or not failed_row["signature"]:
                            continue
                        for later in seq[i + 1:]:
                            if later["tool"] == failed_row["tool"]:
                                continue
                            gap = (later["ts"] - failed_row["ts"]).total_seconds() / 60
                            if gap > CORRELATION_WINDOW_MINUTES:
                                break
                            _upsert_rule(cur, phase, service, failed_row["tool"],
                                         failed_row["signature"], later["tool"],
                                         failed_row["phrase"], later["success"])
                            out["rules"] += 1
            conn.commit()
    except Exception as e:  # noqa: BLE001
        log.debug("learn_from_tool_executions failed: %s", e)
    return out


def _emit_webhook(rule: Dict[str, Any], phase: str) -> None:
    """Announce a newly learned rule. Fire-and-forget; never fatal."""
    base = os.environ.get("API_BASE") or os.environ.get("RAG_API_URL") or ""
    if not base:
        return
    try:
        import requests
        requests.post(
            f"{base.rstrip('/')}/webhooks/emit",
            json={
                "source": "tool_learning",
                "event_type": "tool_selection_rule_learned",
                "data": {
                    "phase": phase,
                    "service": rule.get("service"),
                    "failed_tool": rule["failed_tool"],
                    "preferred_tool": rule["preferred_tool"],
                    "failure_phrase": rule.get("phrase"),
                    "signature": rule["signature"],
                    "confidence": rule.get("confidence"),
                    "support": rule.get("support"),
                },
            },
            headers={"X-API-Key": os.environ.get("API_KEY", "")},
            timeout=4,
            verify=os.environ.get("REQUESTS_CA_BUNDLE", False),
        )
    except Exception as e:  # noqa: BLE001
        log.debug("tool_learning webhook emit failed: %s", e)


def rules(
    *, phase: Optional[str] = DEFAULT_PHASE, service: Optional[str] = None,
    status: Optional[str] = None, limit: int = 200,
) -> List[Dict[str, Any]]:
    """Learned rules, newest first — for the operator review surface and tests."""
    where, params = ["1=1"], []
    if phase:
        where.append("phase = %s"); params.append(phase)
    if service is not None:
        where.append("service = %s"); params.append(service)
    if status:
        where.append("status = %s"); params.append(status)
    params.append(limit)
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, phase, service, failed_tool, failure_signature,
                       preferred_tool, failure_phrase, support, attempts,
                       successes, confidence, status, source, reviewed_by,
                       created_at, last_seen_at
                  FROM public.tool_selection_learned
                 WHERE {' AND '.join(where)}
                 ORDER BY last_seen_at DESC
                 LIMIT %s
                """,
                params,
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception as e:  # noqa: BLE001
        log.debug("rules() failed: %s", e)
        return []
