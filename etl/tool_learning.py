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


# A tool that ran cleanly and produced nothing a parser could use is its own
# outcome — not an error, and emphatically not a success. It is the single most
# useful signal for "reach for a different tool", and treating it as a success
# was actively harmful: it would teach the platform that a tool which finds
# nothing here is fine, and suppress the fallback that would have found
# something. Measured on this stack: 34 of 76 completed runs (45%) parsed to
# nothing.
#
# All such runs for one (tool, service) share this signature deliberately. It is
# one condition, not many, and the phrase says so in words an operator reading
# the learned rule will understand — they must not think the tool errored.
UNPRODUCTIVE_PHRASE = "ran to completion and produced no parseable result"


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
    # Stderr alone is NOT a failure. Plenty of tools log their banner, their
    # version and their progress there and exit 0 having done the job — nuclei
    # prints "nuclei-templates are not installed, installing..." on stderr and
    # then writes 165KB of findings to stdout. Reading that as an error made
    # every nuclei run look failed and taught rules from its startup log.
    #
    # It only counts when the tool ALSO produced nothing: exited 0, wrote
    # nothing, complained. That is the "died quietly" case the signal is for.
    if (error or "").strip() and not (output or "").strip():
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
    # None means "the caller does not know how many results this produced".
    # That is NOT the same as zero, and conflating them would record every
    # uninstrumented runner's output as fruitless. Pass a number only when the
    # parser actually ran.
    result_count: Optional[int] = None,
    engagement_id: Optional[str] = None,
    phase: str = TOOL_EXECUTION_PHASE,
    emit: bool = True,
) -> Dict[str, Any]:
    """Record one finished command and learn from it. Never raises.

    Three outcomes, not two:

      * **errored**   — status/exit code/stderr says so; signature from the
        tool's own words.
      * **fruitless** — ran clean, and the parser got nothing out of it. Learned
        from, under `UNPRODUCTIVE_PHRASE`, because that is precisely when
        another tool is worth trying.
      * **productive** — ran clean and produced something.

    A `result_count` of None means the caller does not know, and the run is
    recorded as a plain success rather than being guessed at either way.

    Returns ``{"recorded", "failed", "fruitless", "signature", "phrase",
    "learned"}``. ``recorded: False`` means the platform did not observe this
    run — which is not the same as the run having taught it nothing.
    """
    failed = execution_failed(status, exit_code, error, output)
    fruitless = (not failed) and result_count is not None and result_count <= 0
    # Nobody measured this run. That is NOT a success, and it must not be able
    # to act as one: a live netexec run against a legacy SSH host exited 0 with
    # a Python traceback in its output and no parser to read it, and was
    # recorded `success: true` — where it could then have ACTIVATED a rule as
    # proof that netexec works after some other tool failed.
    unmeasured = (not failed) and result_count is None
    sig = phrase = None
    if failed:
        # The tool's complaint first; its normal output only if it said nothing
        # on stderr. Mixing the two would let a noisy success drown the error.
        sig, phrase = error_signature(error or output)
    elif fruitless:
        sig, phrase = error_signature(UNPRODUCTIVE_PHRASE)
    out: Dict[str, Any] = {"recorded": False, "failed": failed,
                           "fruitless": fruitless, "unmeasured": unmeasured,
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
                    (phase, tool, service or "", target, port,
                     # An unmeasured run is recorded as NOT a success. It has no
                     # signature either, so it teaches nothing in either
                     # direction — which is the honest position when no parser
                     # looked at the output.
                     not (failed or fruitless or unmeasured),
                     int(result_count or 0), sig, phrase, engagement_id),
                )
                out["recorded"] = True
                out["attempt_id"] = str(cur.fetchone()[0])
                # An unmeasured run pairs with nothing. Letting it act as the
                # "later success" would manufacture a rule out of a run nobody
                # read.
                out["learned"] = [] if unmeasured else _learn_against_recent(
                    cur, phase=phase, service=service or "", target=target,
                    port=port, tool=tool, succeeded=not (failed or fruitless))
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


def _parsed_anything(parsed: Any) -> bool:
    """Did the parser get anything out of this run?

    Deliberately permissive about shape — `parsed_results` is written by a dozen
    runners and is a dict, a list, or NULL depending on which. Anything
    non-empty counts; only NULL, {} and [] are "nothing".
    """
    if parsed is None:
        return False
    if isinstance(parsed, str):
        parsed = parsed.strip()
        if parsed in ("", "null", "{}", "[]"):
            return False
        try:
            import json
            parsed = json.loads(parsed)
        except Exception:  # noqa: BLE001
            return True
    if isinstance(parsed, dict):
        return any(v not in (None, "", [], {}) for v in parsed.values())
    if isinstance(parsed, (list, tuple)):
        return len(parsed) > 0
    return bool(parsed)


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
    out = {"examined": 0, "failures": 0, "fruitless": 0, "rules": 0,
           "available": False}
    where = "WHERE started_at > now() - (%s || ' hours')::interval" if since_hours else ""
    params: List[Any] = [since_hours] if since_hours else []
    params.append(limit)
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT tool, COALESCE(service, ''), target, port, status,
                           exit_code, output, error, parsed_results, started_at
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
                for (tool, service, target, port, status, code, output, error,
                     parsed, ts) in rows:
                    if not target:
                        continue
                    failed = execution_failed(status, code, error or "", output or "")
                    fruitless = (not failed) and not _parsed_anything(parsed)
                    sig = ph = None
                    if failed:
                        sig, ph = error_signature((error or "") or (output or ""))
                        out["failures"] += 1
                    elif fruitless:
                        sig, ph = error_signature(UNPRODUCTIVE_PHRASE)
                        out["fruitless"] += 1
                    groups.setdefault((service, target, port), []).append({
                        "tool": tool, "success": not (failed or fruitless),
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


# ── Fixing the tool instead of replacing it ────────────────────────────────
#
# Everything above answers "which OTHER tool should I reach for". This answers
# the question that comes first: can this tool be made to work by telling it
# something the target already told us?
#
# The case that produced it: netexec and hydra both fail against an OpenSSH
# 4.7p1 that offers only ssh-rsa and ssh-dss host keys. ssh-audit had already
# recorded exactly that — 24 findings — BEFORE either failure. The information
# needed to fix the failure was collected before the failure happened and
# nothing read it back, so the platform kept discovering by trial what it had
# already measured.
#
# Two halves, and only one of them is typed:
#   * WHAT a tool's option looks like is a fact (knowledge/tool_options.yaml),
#     checkable against its man page.
#   * WHETHER adding it fixes a given failure is a judgement, and it is observed
#     here, never written down.
#
# Candidates are ranked by how much the error text actually talks about the
# category — "no acceptable host key" against `host-key` — which needs no
# protocol vocabulary and works for a category nobody anticipated.

TOOL_OPTIONS = os.environ.get("TOOL_OPTIONS_YAML", "/knowledge/tool_options.yaml")
_TOOL_OPTIONS_REPO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "knowledge", "tool_options.yaml")


def load_tool_options() -> Dict[str, Dict[str, str]]:
    """`{tool: {category: option_template}}`, or empty if unreadable."""
    for candidate in (TOOL_OPTIONS, _TOOL_OPTIONS_REPO):
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            import yaml
            with open(candidate, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            return {t: {k: v for k, v in (opts or {}).items()
                        if k not in ("note", "probe")}
                    for t, opts in (data.get("tools") or {}).items()}
        except Exception as e:  # noqa: BLE001
            log.warning("tool options catalogue %s unreadable: %s", candidate, e)
            return {}
    return {}


_probe_cache: Dict[str, Optional[List[str]]] = {}


def _load_probes() -> Dict[str, Dict[str, str]]:
    for candidate in (TOOL_OPTIONS, _TOOL_OPTIONS_REPO):
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            import yaml
            with open(candidate, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
            return {t: (opts or {}).get("probe") or {}
                    for t, opts in (data.get("tools") or {}).items()}
        except Exception:  # noqa: BLE001
            return {}
    return {}


def client_capabilities(tool: str, category: str) -> Optional[List[str]]:
    """What the TOOL says it supports, by asking it. None when it cannot be asked.

    None and `[]` are different answers and the caller acts differently on each:
    None means the tool is not installed here so the intersection cannot be
    computed, `[]` means it was asked and supports nothing in this category.
    Collapsing them would either constrain a tool to nothing or silently skip a
    check that could have run.
    """
    probe = (_load_probes().get((tool or "").lower()) or {}).get(category)
    if not probe:
        return None
    key = f"{tool}:{category}"
    if key in _probe_cache:
        return _probe_cache[key]
    try:
        import shlex
        import subprocess
        argv = shlex.split(probe)
        r = subprocess.run(argv, capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            _probe_cache[key] = None
            return None
        values = [ln.strip() for ln in (r.stdout or "").splitlines() if ln.strip()]
        _probe_cache[key] = values or None
        return _probe_cache[key]
    except Exception as e:  # noqa: BLE001
        log.debug("client capability probe %r failed: %s", probe, e)
        _probe_cache[key] = None
        return None


def _category_relevance(error_text: str, category: str, values: List[str]) -> float:
    """How much this error is talking about this capability category.

    Deliberately lexical and vocabulary-free: it scores the category NAME and the
    advertised VALUES against the error text. "no acceptable host key" scores on
    `host-key`; "no match for method server host key algo: server
    [ssh-rsa,ssh-dss]" scores on both the name and the values. A category nobody
    anticipated is ranked the same way, which a typed
    `if "kex" in error: use KexAlgorithms` rule could never do.
    """
    low = (error_text or "").lower()
    if not low:
        return 0.0
    score = 0.0
    words = [w for w in re.split(r"[^a-z0-9]+", category.lower()) if len(w) > 2]
    if words and all(w in low for w in words):
        score += 2.0
    else:
        score += sum(0.5 for w in words if w in low)
    # The host's own advertised values appearing in the error is the strongest
    # signal there is: the tool is quoting them back at us.
    score += sum(1.0 for v in values if v and v.lower() in low)
    return score


def propose_remediations(
    tool: str,
    error_text: str,
    *,
    target: str = "",
    service: str = "",
    capabilities: Optional[Dict[str, List[str]]] = None,
    limit: int = 3,
) -> Dict[str, Any]:
    """Options worth adding to THIS tool for THIS failure, best first.

    ``{"signature", "phrase", "tool_has_options", "capabilities_available",
    "candidates": [{"category", "option", "values", "score", "learned"}]}``.

    `tool_has_options` False means the catalogue says this tool takes no
    algorithm flags — `hydra` and `netexec` genuinely do not — and the answer is
    a different tool, which `next_tool()` already provides. That is a real
    answer and distinct from "we have not looked".
    """
    sig, phrase = error_signature(error_text)
    options = load_tool_options().get((tool or "").strip().lower(), {})
    out: Dict[str, Any] = {
        "signature": sig, "phrase": phrase,
        "tool_has_options": bool(options),
        "capabilities_available": capabilities is not None,
        "candidates": [],
    }
    if not options:
        return out

    if capabilities is None and target:
        try:
            try:
                from etl.target_capabilities import capabilities as _caps
            except ImportError:  # pragma: no cover - bare import from within etl/
                from target_capabilities import capabilities as _caps
            found = _caps(target, service=service)
            out["capabilities_available"] = bool(found.get("available"))
            capabilities = found.get("categories") or {}
        except Exception as e:  # noqa: BLE001
            log.debug("capability lookup failed for %s: %s", target, e)
            capabilities = {}
    capabilities = capabilities or {}

    learned = {r["option_template"]: r
               for r in remediations_for(tool, sig, service=service)}
    scored = []
    for category, template in options.items():
        values = capabilities.get(category) or []
        if not values:
            # No measurement for this category means no value to fill in. A
            # template with an empty list would constrain the tool to nothing.
            continue
        # Intersect with what the CLIENT knows, when it can be asked. The host
        # offering ssh-dss does not help if this ssh has removed it: the whole
        # option is then rejected as `Bad key types '+ssh-rsa,ssh-dss'` and the
        # connection that +ssh-rsa alone would have made never happens.
        known = client_capabilities(tool, category)
        usable = [v for v in values if v in known] if known is not None else list(values)
        if known is not None and not usable:
            # Asked, and there is no overlap. That is a finding in its own
            # right — this client cannot negotiate with this host at all — and
            # proposing an empty option would just fail differently.
            scored.append({
                "category": category, "option": None, "values": values,
                "client_supports": known[:12],
                "score": _category_relevance(error_text, category, values),
                "learned": None,
                "note": ("no overlap between what the host offers and what this "
                         "client supports — a different tool is needed, not a "
                         "different argument"),
            })
            continue
        option = template.replace("{values}", ",".join(usable))
        scored.append({
            "category": category,
            "option": option,
            "values": usable,
            "host_offers": list(values),
            "client_verified": known is not None,
            "score": _category_relevance(error_text, category, values),
            "learned": learned.get(option),
        })
    # A rule that has already worked outranks any lexical score.
    scored.sort(key=lambda c: (
        -(c["learned"]["successes"] if c["learned"] else 0), -c["score"], c["category"]))
    out["candidates"] = scored[:limit]
    return out


def remediations_for(tool: str, signature: Optional[str], *,
                     service: str = "") -> List[Dict[str, Any]]:
    """Every recorded remediation for this exact failure, any status."""
    if not signature:
        return []
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, category, option_template, support, attempts,
                       successes, confidence, status, failure_phrase
                  FROM public.tool_remediation_learned
                 WHERE tool = %s AND service = %s AND failure_signature = %s
                 ORDER BY successes DESC, confidence DESC NULLS LAST
                """,
                (tool, service or "", signature),
            )
            rows = cur.fetchall()
    except Exception as e:  # noqa: BLE001
        log.debug("remediations_for failed: %s", e)
        return []
    return [{"id": str(r[0]), "category": r[1], "option_template": r[2],
             "support": r[3], "attempts": r[4], "successes": r[5],
             "confidence": float(r[6]) if r[6] is not None else None,
             "status": r[7], "failure_phrase": r[8]} for r in rows]


def best_remediation(tool: str, signature: Optional[str], *,
                     service: str = "") -> Optional[Dict[str, Any]]:
    """The option already observed to fix this failure, if there is one."""
    for r in remediations_for(tool, signature, service=service):
        if r["status"] == "active" and (r["successes"] or 0) > 0:
            return r
    return None


def record_remediation(tool: str, signature: str, option: str, *,
                       category: str = "", service: str = "",
                       phrase: Optional[str] = None, worked: bool = False,
                       emit: bool = True) -> Optional[Dict[str, Any]]:
    """Remember whether adding `option` fixed this failure.

    Both outcomes are recorded. An option tried three times that never helps
    should stop being offered, and learning only the successes would leave the
    platform re-adding a useless flag forever.
    """
    if not (tool and signature and option):
        return None
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO public.tool_remediation_learned
                      (tool, service, failure_signature, category,
                       option_template, failure_phrase, support, attempts,
                       successes, confidence, status)
                    VALUES (%s,%s,%s,%s,%s,%s,1,1,%s,%s,%s)
                    ON CONFLICT (tool, service, failure_signature, option_template)
                    DO UPDATE SET
                      support   = public.tool_remediation_learned.support + 1,
                      attempts  = public.tool_remediation_learned.attempts + 1,
                      successes = public.tool_remediation_learned.successes
                                  + EXCLUDED.successes,
                      confidence = (public.tool_remediation_learned.successes
                                    + EXCLUDED.successes)::numeric
                                   / (public.tool_remediation_learned.attempts + 1),
                      failure_phrase = COALESCE(
                          public.tool_remediation_learned.failure_phrase,
                          EXCLUDED.failure_phrase),
                      last_seen_at = now(),
                      status = CASE
                          WHEN public.tool_remediation_learned.status = 'rejected'
                               THEN 'rejected'
                          WHEN public.tool_remediation_learned.successes
                               + EXCLUDED.successes > 0 THEN 'active'
                          ELSE public.tool_remediation_learned.status END
                    RETURNING id, support, attempts, successes, confidence,
                              status, (xmax = 0) AS inserted
                    """,
                    (tool, service or "", signature, category, option, phrase,
                     1 if worked else 0, 1.0 if worked else 0.0,
                     "active" if worked else "proposed"),
                )
                r = cur.fetchone()
            conn.commit()
    except Exception as e:  # noqa: BLE001
        log.debug("record_remediation failed: %s", e)
        return None
    rule = {"id": str(r[0]), "tool": tool, "option": option, "category": category,
            "support": r[1], "attempts": r[2], "successes": r[3],
            "confidence": float(r[4]) if r[4] is not None else None,
            "status": r[5], "new": bool(r[6]), "service": service,
            "signature": signature, "phrase": phrase}
    if emit and rule["new"] and rule["status"] == "active":
        _emit_webhook({**rule, "failed_tool": tool, "preferred_tool": tool},
                      "remediation")
    return rule


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
