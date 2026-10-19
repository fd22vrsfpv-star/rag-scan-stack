"""Reuse a previous recon result instead of re-running the tool.

Every recon node in the build-PoC graph calls its tool unconditionally. Prior
results ARE read — `_scan_evidence_for_target` pulls earlier ports, banners,
web findings and `prior_live_recon`, and `node_discovered_knowledge_recon`
pulls app facts from past builds — but all of it is EXTRA CONTEXT, never a
substitute. So rebuilding the same CVE against the same host pays for a full
ZAP spider, a full Playwright crawl and a full arjun fan-out again, every time,
for answers already in the database.

This is the cache that lets a node skip. What makes it safe is the fact
challenger built alongside it: a reused result carries its AGE, and
`knowledge/fact_contradictions.yaml`'s `fact_is_stale` rule downgrades a fact
past its TTL. Reuse cannot quietly turn yesterday's route into today's
evidence — the worst it can do is hand synthesis a fact marked old.

THREE OUTCOMES, never two. The decision is `reuse` / `refresh` / `miss`, plus
`unavailable` when the cache itself could not be consulted. A cache we could
not read is NOT a cache miss: both lead to running the tool, but one of them
means the cache is broken and an operator needs to know which. This repo's
most expensive recurring bug is a probe that could not run reported as a
negative result; a cache is the same shape.

Modes:
    auto   — DEFAULT. Reuse while fresh, re-run once past the tool's TTL.
    always — reuse whatever the age. For re-deriving a PoC against a target
             you know has not changed, without paying for recon again.
    never  — always run the tool. The pre-cache behaviour, kept so a result
             can be reproduced from scratch.

Pure except for the two functions that take a cursor, so the decision logic is
testable with no database:

    pytest tests/test_recon_cache.py
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any, Dict, Optional, Tuple

log = logging.getLogger("recon_cache")

AUTO, ALWAYS, NEVER = "auto", "always", "never"
MODES = (AUTO, ALWAYS, NEVER)

REUSE, REFRESH, MISS, UNAVAILABLE = "reuse", "refresh", "miss", "unavailable"

# Per-tool freshness. Chosen by how fast the answer actually changes, not by
# how expensive the tool is — an expensive tool with a volatile answer is
# exactly the one that must not be reused.
#
#   port_sweep / basic_recon  a service list changes when someone deploys
#   zap / playwright / arjun  a crawl of the same build returns the same paths
#   waf_detect                an edge config changes rarely and visibly
#
# Override one with RECON_CACHE_TTL_<TOOL> (seconds); 0 disables caching for
# that tool entirely, which is a legitimate way to pin one noisy step.
DEFAULT_TTL_SECONDS: Dict[str, int] = {
    "port_sweep": 6 * 3600,
    "basic_recon": 6 * 3600,
    "waf_detect": 24 * 3600,
    "waf_characterize": 24 * 3600,
    "product_identification": 12 * 3600,
    "response_mine": 12 * 3600,
    "framework_deep_enum": 12 * 3600,
    "zap": 12 * 3600,
    "zap_active": 6 * 3600,
    "playwright": 12 * 3600,
    "arjun": 12 * 3600,
    "openapi": 24 * 3600,
}
# Anything not named above. Deliberately short: an unknown tool is one nobody
# has reasoned about, so it gets the least benefit of the doubt.
FALLBACK_TTL_SECONDS = 3600


def valid_mode(mode) -> str:
    """Normalise a mode. An unrecognised value falls back to `auto` rather
    than silently disabling reuse — or, worse, enabling `always`."""
    m = str(mode or "").strip().lower()
    return m if m in MODES else AUTO


def ttl_for(tool: str) -> int:
    """Freshness window for a tool, in seconds. 0 means 'never cache'."""
    key = "RECON_CACHE_TTL_" + str(tool or "").strip().upper().replace("-", "_")
    raw = os.environ.get(key)
    if raw is not None:
        try:
            return max(0, int(raw))
        except (TypeError, ValueError):
            log.warning("recon_cache: %s=%r is not an integer; using the default", key, raw)
    return DEFAULT_TTL_SECONDS.get(str(tool or "").strip().lower(), FALLBACK_TTL_SECONDS)


def cache_key(tool: str, ip, port, variant: Any = None) -> str:
    """Stable identity for one recon result.

    `variant` captures the INPUTS that change a tool's answer — the zap path
    list arjun fans across, active-vs-passive for ZAP, the credential set a
    crawl ran under. Leave it out and an authenticated crawl would be served
    from an unauthenticated one's cache, which is a wrong answer rather than a
    slow one.
    """
    payload = json.dumps(
        {"tool": str(tool or "").strip().lower(), "ip": str(ip or ""),
         "port": int(port or 0), "variant": variant},
        sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def decide(mode, age_seconds, ttl_seconds) -> Tuple[str, str]:
    """(action, human reason) for a cache lookup that FOUND a row.

    Separated from the lookup so the policy can be tested without a database,
    and so the reason is written once rather than at each call site.
    """
    m = valid_mode(mode)
    if m == NEVER:
        return REFRESH, "reuse disabled for this run (reuse_recon=never)"
    try:
        ttl = int(ttl_seconds)
    except (TypeError, ValueError):
        ttl = FALLBACK_TTL_SECONDS
    try:
        age = int(age_seconds)
    except (TypeError, ValueError):
        # An unmeasurable age is not evidence of freshness. Re-run.
        return REFRESH, "cached result has no readable age"
    if ttl <= 0:
        return REFRESH, "caching is disabled for this tool (ttl=0)"
    if age < 0:
        return REFRESH, "cached result is dated in the future (clock skew)"
    if m == ALWAYS:
        return REUSE, "reused at any age by request (reuse_recon=always), age %ds" % age
    if age <= ttl:
        return REUSE, "reused, age %ds within the %ds window" % (age, ttl)
    return REFRESH, "re-run, age %ds past the %ds window" % (age, ttl)


def note(action: str, tool: str, reason: str) -> str:
    """One line for the trace and the recon metrics.

    `reused` and `ran fresh` must be visibly different in the run's own record,
    or an operator reading a fast build cannot tell whether the tool ran.
    """
    verb = {REUSE: "REUSED", REFRESH: "ran fresh", MISS: "ran fresh",
            UNAVAILABLE: "ran fresh"}.get(action, "ran")
    return "[recon-cache] %s %s — %s" % (tool, verb, reason)


# ── database side ────────────────────────────────────────────────────────────
#
# Both take a cursor so the caller owns the connection and the transaction.
# Neither raises: a broken cache must never fail a build. They report
# UNAVAILABLE instead, which the caller treats as "run the tool" while still
# recording that the cache itself is the problem.


def lookup(cur, key: str, tool: str, mode=AUTO) -> Tuple[str, str, Optional[dict], Optional[int]]:
    """(action, reason, payload, age_seconds) for one cache key.

    Returns MISS with a None payload when nothing is stored, UNAVAILABLE when
    the cache could not be read, and REUSE/REFRESH from `decide` otherwise.
    """
    if valid_mode(mode) == NEVER:
        return REFRESH, "reuse disabled for this run (reuse_recon=never)", None, None
    try:
        cur.execute("""SELECT payload,
                              EXTRACT(EPOCH FROM (now() - created_at))::bigint AS age
                         FROM public.recon_cache
                        WHERE cache_key = %s
                        ORDER BY created_at DESC
                        LIMIT 1""", [key])
        row = cur.fetchone()
    except Exception as e:  # noqa: BLE001
        # NOT a miss. Both run the tool, but only one of them means the cache
        # is broken, and collapsing them hides a cache that never works.
        log.warning("recon_cache lookup failed for %s: %s", tool, e)
        return UNAVAILABLE, "cache unreadable (%s)" % type(e).__name__, None, None
    if not row:
        return MISS, "nothing cached for this target yet", None, None
    payload, age = (row[0], row[1]) if not isinstance(row, dict) else (row.get("payload"), row.get("age"))
    action, reason = decide(mode, age, ttl_for(tool))
    return action, reason, (payload if action == REUSE else None), (int(age) if age is not None else None)


def store(cur, key: str, tool: str, ip, port, payload: dict, *,
          engagement_id=None, variant=None, run_id=None) -> bool:
    """Upsert one recon result. True when stored.

    `engagement_id` is required by CLAUDE.md's attribution rule — this is
    collected data about a target during an engagement, so a purge has to be
    able to claim it. It is written NULL-able only because a legacy caller may
    not resolve one; the writer should always pass it.
    """
    if ttl_for(tool) <= 0:
        return False
    try:
        cur.execute("""INSERT INTO public.recon_cache
                           (cache_key, tool, ip, port, engagement_id, variant,
                            payload, run_id, created_at)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())
                       ON CONFLICT (cache_key) DO UPDATE
                          SET payload = EXCLUDED.payload,
                              run_id = EXCLUDED.run_id,
                              engagement_id = COALESCE(EXCLUDED.engagement_id,
                                                       public.recon_cache.engagement_id),
                              created_at = now()""",
                    [key, str(tool), str(ip or ""), int(port or 0),
                     str(engagement_id) if engagement_id else None,
                     json.dumps(variant, sort_keys=True, default=str) if variant is not None else None,
                     json.dumps(payload, default=str), str(run_id) if run_id else None])
        return True
    except Exception as e:  # noqa: BLE001
        log.warning("recon_cache store failed for %s: %s", tool, e)
        return False
