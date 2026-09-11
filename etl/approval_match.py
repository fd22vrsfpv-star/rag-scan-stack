"""Wildcard matching for operator approval rules.

Why this exists
---------------
Approval used to be strictly one row per concrete thing: one `pending_exploits`
id for an exploit, one `(username, service)` pair for a credential spray. That
is correct but unusable at volume — an engagement that turns up 200 pending
exploits across four types cannot be approved one id at a time, and a spray
approval had to be repeated for every service an account appears on.

So an approval's selector may now be a pattern. `all` approves everything of
that dimension, `web*` approves a family, `rce,sqli` approves a list.

What a pattern does NOT do
--------------------------
A pattern widens the operator's *approval*. It never widens *scope*. Every
dispatch that a matched approval unblocks still passes the scope gate
independently, exactly as a hand-approved one does — see
`tests/test_approval_rules.py::test_rule_never_bypasses_scope_gate`. This is the
CLAUDE.md invariant that override flags overrule the platform's suppression
judgement and never the operator's authorization; a wildcard is an operator
authorization for a *class*, not permission to leave scope.

Grammar
-------
A pattern is a comma-separated list of alternatives; the value matches if ANY
alternative matches.

    all | any | * | % | ""     catch-all: matches every value, INCLUDING NULL
    rce                        exact, case-insensitive
    web*                       glob: * and % are multi-char, ? is single-char
    rce,sqli,xss               list of alternatives

`%` is accepted alongside `*` because the repo already tells operators to "Use *
or % as wildcards" in the AssetBrowser bulk-delete box; two wildcard dialects in
one product is a papercut nobody needs.

NULL is deliberate, not incidental
----------------------------------
`pending_exploits.exploit_type` is nullable and roughly a fifth of live rows
have no type at all. A catch-all matches those; a glob or a literal does not.
The alternative — letting `web*` silently sweep up untyped rows — would mean an
operator approving "web exploits" also approved everything the classifier could
not label, which is the opposite of what they asked for.

Specificity, and why deny wins a tie
------------------------------------
Rules overlap. `best_match()` resolves that by scoring each dimension (exact 2,
glob 1, catch-all 0) and summing, so a rule naming an exact service beats a rule
that said `all`. When two rules tie, the one that DENIES wins: an operator who
writes "approve all, except this one account" gets the exception honoured. A
revocation that can be outvoted by a broader allow is not a revocation.

Kept dependency-free (stdlib only) so it is importable from every service that
bind-mounts ./etl — rag-api, the dashboard BFF, exploit-runner and autogen.
"""
from fnmatch import fnmatchcase
from typing import Any, Iterable, List, Mapping, Optional, Sequence

__all__ = [
    "CATCH_ALL_TOKENS",
    "alternatives",
    "is_catch_all",
    "matches",
    "specificity",
    "best_match",
]

#: Tokens an operator may type to mean "every value of this dimension".
#: The empty string is included because an omitted form field and an explicit
#: "all" mean the same thing to the person filling it in.
CATCH_ALL_TOKENS = frozenset({"", "*", "%", "all", "any"})

#: Exact literal beats glob beats catch-all when two rules both match.
_SPEC_EXACT = 2
_SPEC_GLOB = 1
_SPEC_CATCH_ALL = 0


def alternatives(pattern: Any) -> List[str]:
    """Split a pattern into its lowercased, stripped alternatives.

        alternatives("rce")          -> ["rce"]
        alternatives("rce, sqli")    -> ["rce", "sqli"]
        alternatives(None)           -> [""]        (absence is a catch-all)
        alternatives(["rce","xss"])  -> ["rce", "xss"]

    A list/tuple is accepted because callers that already hold a parsed list
    should not have to re-join it into a string just to be understood.
    """
    if pattern is None:
        return [""]
    if isinstance(pattern, (list, tuple, set, frozenset)):
        parts = [str(p).strip().lower() for p in pattern]
    else:
        parts = [p.strip().lower() for p in str(pattern).split(",")]
    parts = [p for p in parts if p != ""] or [""]
    return parts


def is_catch_all(pattern: Any) -> bool:
    """True if `pattern` matches every value of its dimension, NULL included.

    A list is a catch-all if ANY alternative is — "rce,all" is just "all" with
    extra typing, and treating it as the narrower thing would surprise.
    """
    return any(a in CATCH_ALL_TOKENS for a in alternatives(pattern))


def _glob(alt: str) -> str:
    """Translate our wildcard dialect into one fnmatch understands."""
    return alt.replace("%", "*")


def _alt_specificity(alt: str, value: str) -> Optional[int]:
    """Score one alternative against an already-lowercased value.

    Returns None when it does not match, so callers can distinguish "no match"
    from "matched at score 0" — a catch-all legitimately scores 0.
    """
    if alt in CATCH_ALL_TOKENS:
        return _SPEC_CATCH_ALL
    if "*" in alt or "%" in alt or "?" in alt:
        return _SPEC_GLOB if fnmatchcase(value, _glob(alt)) else None
    return _SPEC_EXACT if alt == value else None


def specificity(pattern: Any, value: Any) -> Optional[int]:
    """How specifically `pattern` matches `value`, or None if it does not.

        specificity("rce",  "rce")   -> 2   (exact)
        specificity("web*", "webapp")-> 1   (glob)
        specificity("all",  "rce")   -> 0   (catch-all)
        specificity("rce",  "sqli")  -> None
        specificity("web*", None)    -> None  (only a catch-all matches NULL)
        specificity("all",  None)    -> 0

    When several alternatives match, the most specific one scores — `rce,*`
    against "rce" is an exact match that also happens to have a catch-all
    alternative, and reporting 0 there would let a broader rule outrank it.
    """
    if value is None:
        return _SPEC_CATCH_ALL if is_catch_all(pattern) else None
    val = str(value).strip().lower()
    scores = [s for s in (_alt_specificity(a, val) for a in alternatives(pattern))
              if s is not None]
    return max(scores) if scores else None


def matches(pattern: Any, value: Any) -> bool:
    """True if `pattern` selects `value`. See `specificity()` for the grammar."""
    return specificity(pattern, value) is not None


def match_score(patterns: Sequence[Any], values: Sequence[Any]) -> Optional[int]:
    """Summed specificity across several dimensions, or None if any fails.

    Every dimension must match — the dimensions of a rule are ANDed, so a rule
    naming username `svc_*` and service `ssh` does not apply to `svc_backup` on
    smb.
    """
    if len(patterns) != len(values):
        raise ValueError(
            f"patterns ({len(patterns)}) and values ({len(values)}) must align")
    total = 0
    for pattern, value in zip(patterns, values):
        score = specificity(pattern, value)
        if score is None:
            return None
        total += score
    return total


def best_match(rows: Iterable[Mapping[str, Any]],
               values: Sequence[Any],
               *,
               pattern_fields: Sequence[str],
               deny_field: Optional[str] = "approved") -> Optional[Mapping[str, Any]]:
    """The rule that governs `values`, or None if no rule matches.

    `pattern_fields` names the columns of each row holding patterns, aligned
    with `values`. The winner is the highest summed specificity; ties go to a
    row whose `deny_field` is falsy, so an explicit revocation is never
    outvoted by a broader allow. Pass deny_field=None when rows carry no
    allow/deny sense and the most specific match should simply win.

        rows = [{"username": "all",  "service": "all", "approved": True},
                {"username": "root", "service": "ssh", "approved": False}]
        best_match(rows, ["root", "ssh"], pattern_fields=["username","service"])
        -> the approved=False row (score 4 beats score 0)
    """
    best: Optional[Mapping[str, Any]] = None
    best_score = -1
    for row in rows:
        score = match_score([row.get(f) for f in pattern_fields], values)
        if score is None:
            continue
        if score > best_score:
            best, best_score = row, score
        elif score == best_score and deny_field is not None and best is not None:
            # Same specificity, conflicting verdicts: the denial stands.
            if not row.get(deny_field) and best.get(deny_field):
                best = row
    return best
