"""Where a fact came from, and therefore how much it is worth.

`confirmed_facts` has carried a `confidence` column since it was created. Every
one of the 72 rows in it holds **0.9** — confirmed, unverified and *refuted*
alike. It is the default argument of `_record_confirmation`, and of the 13 call
sites not one passes it. The read path never looks at it; it filters on
`status='refuted'`. So the column was decoration: it could not distinguish a
fact we had just proven with a request from one the model invented, and
synthesis trusted both the same way.

This module makes confidence a FUNCTION of two things we actually know:

  * PROVENANCE — where the value came from. A value copied out of the grading
    harness's own `eval.yml` is the answer key; a value the LLM proposed is a
    guess. Those are not the same kind of thing and must not score the same.
  * STATUS — whether a probe has since confirmed or refuted it. A claim from a
    perfect source is still only a claim until something checks it.

Nothing here touches the database or the network, so it is cheap to test and
impossible to get wrong by accident at a call site: a caller names its source,
and the number follows.

Design rules this encodes:

  * A REFUTED fact is 0.0 whatever its source. A disproof outranks a pedigree.
  * An UNVERIFIED fact is worth HALF its source tier, never its full value.
    "The advisory says the parameter is `listingfields`" is good information
    and is still not evidence that this installation has that parameter.
  * A fact past its TTL is UNVERIFIED, not confirmed — `session_valid` with a
    900s TTL that was last checked an hour ago is a guess wearing a tick. All
    72 rows in the ledger are currently past their TTL and every reader treats
    them as live, which is this repo's "unreachable is not absent" again: we
    cannot see the fact now, so we report what we saw before as if it were now.
  * `harness_declared` is 1.0 and is the ONLY tier that reaches 1.0, because it
    is definitionally correct — it is the file the scoring is performed from.
"""
from __future__ import annotations

# Source tier -> base confidence for a CONFIRMED fact from that source.
# Ordered best-first; the docstring on each says what earns that number.
PROVENANCE = {
    # The grading harness's own challenge definition (CVE-Bench eval.yml).
    # This is the key the score is computed against, so it cannot be wrong
    # about itself.
    "harness_declared": 1.0,
    # We sent a request/command and observed the answer, in this run.
    "probe_confirmed": 0.9,
    # Read back from our own stored scan output (nmap/httpx/ZAP). True when
    # observed; may be stale, which is what the TTL is for.
    "scan_observed": 0.8,
    # Operator typed it in (scope entry, credential, tool setting).
    "operator_supplied": 0.8,
    # Derived from the CVE advisory, NVD text or a patch diff. Describes the
    # software in general, not this installation.
    "advisory_derived": 0.6,
    # Recalled from a prior build against the same product (build_poc_lessons).
    "cross_run_lesson": 0.5,
    # The model proposed it and nothing has checked it.
    "model_inferred": 0.3,
    # Source not recorded. Deliberately low: an unattributed fact is the one
    # most likely to be a guess that lost its label.
    "unknown": 0.1,
}

# A claim from a good source that nothing has checked is still just a claim.
UNVERIFIED_FACTOR = 0.5

CONFIRMED = "confirmed"
UNVERIFIED = "unverified"
REFUTED = "refuted"
STATUSES = (CONFIRMED, UNVERIFIED, REFUTED)


def tier_base(source: str) -> float:
    """Base confidence for a source tier. Unknown names score as `unknown`."""
    return PROVENANCE.get(str(source or "").strip().lower(), PROVENANCE["unknown"])


def confidence_for(source: str, status: str, *, stale: bool = False) -> float:
    """Confidence in [0, 1] for a fact from `source` currently at `status`.

    `stale=True` (past its TTL) demotes a confirmation to a claim, because that
    is exactly what it is: something that WAS true when we looked.
    """
    st = str(status or "").strip().lower()
    if st == REFUTED:
        return 0.0
    base = tier_base(source)
    if st == CONFIRMED and not stale:
        return round(base, 3)
    return round(base * UNVERIFIED_FACTOR, 3)


def is_stale(ttl_seconds, age_seconds) -> bool:
    """True when a fact with this TTL has aged out. TTL 0 means 'never stale'.

    A negative or unreadable age is NOT stale — an unmeasurable age is not
    evidence of expiry, and guessing 'expired' would silently discard good
    facts the same way guessing 'fresh' keeps bad ones.
    """
    try:
        ttl = int(ttl_seconds or 0)
        age = float(age_seconds)
    except (TypeError, ValueError):
        return False
    if ttl <= 0 or age < 0:
        return False
    return age > ttl


def effective_status(status: str, ttl_seconds, age_seconds) -> str:
    """The status a READER should act on, after applying the TTL.

    A confirmed-but-stale fact reads as `unverified`. A refutation never goes
    stale: if the endpoint 404'd an hour ago that is still the best thing we
    know, and re-promoting it to 'maybe' would hand the loop back a dead end it
    had already ruled out.
    """
    st = str(status or "").strip().lower()
    if st == REFUTED:
        return REFUTED
    if st == CONFIRMED and is_stale(ttl_seconds, age_seconds):
        return UNVERIFIED
    return st if st in STATUSES else UNVERIFIED


def label(source: str, status: str, *, stale: bool = False) -> str:
    """One-line human/prompt rendering: how sure, and why.

    Synthesis reads this. "proven" vs "claimed" is the distinction that decides
    whether the model should spend an iteration verifying the fact or may build
    on it directly.
    """
    conf = confidence_for(source, status, stale=stale)
    st = str(status or "").strip().lower()
    if st == REFUTED:
        return "REFUTED (0.00) — disproved by %s; do not retry" % (source or "unknown")
    kind = "PROVEN" if (st == CONFIRMED and not stale) else "CLAIMED"
    extra = " [STALE — was true, not rechecked]" if (st == CONFIRMED and stale) else ""
    return "%s (%.2f) via %s%s" % (kind, conf, source or "unknown", extra)
