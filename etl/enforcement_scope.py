"""A value used to REFUSE something must carry the context it was proven in.

THE RULE
--------
Refusing is the strongest thing the platform does to its own work: a refused
command is never dispatched, so whatever the target would have said is never
heard. A refusal is therefore only as good as the evidence behind it, and
evidence is never context-free — it was established against some endpoint, some
CVE, some run. Applied anywhere else it is a guess wearing the authority of a
fact.

Five instances of exactly this were found in one chain during 2026-10-22/23:

  * the strategist grounded its endpoint against ZAP paths from a stage that
    had not run, so the set was empty and everything was "ungrounded";
  * the fact challenge read the literal string "unknown" as a product NAME and
    called every WordPress route foreign;
  * plan-verify probed `?param=canary` when the plan said POST-with-a-body, so
    a dispatcher endpoint could not pass by any parameter;
  * the proven-fact gate enforced `input_field='roles'`, proven against
    /wp-json/wp/v2/users, on a command targeting /wp-admin/admin-ajax.php —
    refusing the one command that carried the advisory's real parameters;
  * `known_dead` pools error signatures across every CVE and host, and counts
    the harness's own pre-dispatch refusals among them.

Each was found and fixed separately. This module exists so the next one is a
test failure rather than a six-run investigation.

THE TWO PRIMITIVES
------------------
`tag` / `scope_of`  — write the context into a fact's provenance string and
                      read it back. A fact with no recorded scope is UNSCOPED,
                      which is a real and common state (legacy rows), not an
                      error.
`may_enforce`       — may this fact refuse this action? Only when the scopes
                      are known to differ is the answer no.
`prefer_current`    — when a stored value and the current run's value disagree,
                      the current run wins. It is evidence about the thing being
                      attacked right now; the stored value is evidence about the
                      host from some earlier build.

FAIL-OPEN, DELIBERATELY. These gates are quality checks, not authorization.
`etl/scope_gate.py` is the one that fails CLOSED, and nothing here may be used
to decide whether traffic is permitted — only whether our own command is worth
sending. An unknown scope therefore permits enforcement rather than blocking it.

    pytest tests/test_enforcement_scope.py
"""
from __future__ import annotations

from typing import Dict, Optional

# How a scope is appended to a provenance string. Chosen to be readable in the
# ledger and in a trace: "gather_manifest:input_field (via plan_verify) @ /x".
SCOPE_SEP = " @ "

# A value that names nothing. A filled field is not a context — the CVE-Bench
# runner sends `product=unknown` whenever a challenge .env omits
# APPLICATION_NAME, and `_norm("unknown")` is truthy, which is how a WordPress
# route on a WordPress target came to be "another product's route".
UNNAMED = frozenset({"", "unknown", "unidentified", "none", "null", "n/a", "na",
                     "-", "?", "undefined", "generic", "other"})


def is_named(value) -> bool:
    """Does this value actually identify something?"""
    return str(value or "").strip().lower() not in UNNAMED


def tag(source_ref: str, scope: Optional[str]) -> str:
    """Record the context a fact was established in, alongside its provenance.

    No scope (or an unnamed one) leaves the ref untouched: inventing a scope
    would be worse than admitting there isn't one.
    """
    ref = str(source_ref or "")
    if not is_named(scope):
        return ref
    return f"{ref}{SCOPE_SEP}{str(scope).strip()}"


def scope_of(source_ref) -> Optional[str]:
    """The context a stored fact was established in, or None when unrecorded.

    None means UNSCOPED — a legacy row, or a fact whose writer predates this
    module. It does NOT mean "global": see may_enforce.
    """
    txt = str(source_ref or "")
    if SCOPE_SEP not in txt:
        return None
    scope = txt.rsplit(SCOPE_SEP, 1)[-1].strip()
    return scope if is_named(scope) else None


def may_enforce(fact_scope, current_scope) -> bool:
    """May a fact established in `fact_scope` refuse an action in `current_scope`?

    Only a KNOWN mismatch refuses enforcement. If either side is unrecorded we
    cannot show the fact is foreign, and silently dropping every unscoped fact
    would empty an existing gate without anyone noticing — the failure mode this
    module is supposed to prevent, inverted.
    """
    if not is_named(fact_scope) or not is_named(current_scope):
        return True
    return str(fact_scope).strip() == str(current_scope).strip()


def prefer_current(stored: Dict[str, str], current: Dict[str, str]) -> Dict[str, str]:
    """Merge stored evidence with this run's, the current run winning.

    `stored` is what some earlier build proved about this host. `current` is
    what THIS run established about the thing it is attacking — it has already
    been through the live probes and the fact challenge. When they disagree the
    run that is happening now is the better evidence.
    """
    out = dict(stored or {})
    for key, val in (current or {}).items():
        if val not in (None, ""):
            out[key] = str(val)
    return out
