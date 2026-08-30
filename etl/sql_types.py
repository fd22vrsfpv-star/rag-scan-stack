"""Adapters for Postgres column types psycopg2 will not coerce for you.

Why this exists
---------------
`web_findings.cwe` is `text[]`, and the Playwright ZAP path passed the alert's
bare string. Verified against the live column:

    scalar "CWE-79": REJECTED -> InvalidTextRepresentation:
                                 malformed array literal: "CWE-79"
    list  ["CWE-79"]: ACCEPTED

Every array column has the same trap, and the shape of the incoming value is
usually whatever a tool's JSON happened to contain — a string for one scanner, a
list for another, absent for a third. Normalising at each of ~19 call sites
invites 19 slightly different versions, so it lives here once.

`tests/test_sql_columns.py` lists these helpers in LIST_SAFE_FUNCS, so a call
site that routes through one becomes statically provable and drops out of
ARRAY_UNVERIFIED. That is the point: the guard can only reward normalisation it
can recognise.

Kept dependency-free (stdlib only) so it is importable from every service that
bind-mounts ./etl.
"""
from typing import Any, List, Optional

__all__ = ["as_text_array", "as_int_array"]


def as_text_array(value: Any, *, dedupe: bool = False) -> Optional[List[str]]:
    """Coerce `value` into a list of strings for a Postgres `text[]` column.

    Returns None for an absent value, because NULL and '{}' are different things
    in Postgres and callers overwhelmingly mean "unknown", not "known empty".

        as_text_array(None)              -> None
        as_text_array("")                -> None      (blank is absence)
        as_text_array("CWE-79")          -> ["CWE-79"]
        as_text_array(["CWE-79", ""])    -> ["CWE-79"]   (blanks dropped)
        as_text_array("CVE-1, CVE-2")    -> ["CVE-1", "CVE-2"]
        as_text_array([])                -> None
        as_text_array(7)                 -> ["7"]

    A comma-separated string is split, because several tools emit CVE and CWE
    lists that way and passing the whole string as one element silently produces
    a one-item array that no lookup will ever match.

    Set dedupe=True to drop repeats while preserving first-seen order.
    """
    if value is None:
        return None

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        # Drop empty fragments: "CVE-1,,CVE-2," would otherwise yield two blank
        # elements, and a blank string in a text[] is not the same as absence.
        items = [p.strip() for p in text.split(",") if p.strip()] if "," in text else [text]
    elif isinstance(value, (list, tuple, set, frozenset)):
        # set/frozenset are sorted first so the result is deterministic; an
        # arbitrary iteration order would make fingerprints and exports unstable.
        source = sorted(value, key=str) if isinstance(value, (set, frozenset)) else value
        items = []
        for element in source:
            if element is None:
                continue
            if isinstance(element, str):
                text = element.strip()
                if text:
                    items.append(text)
            else:
                items.append(str(element))
    elif isinstance(value, dict):
        # A dict is never a meaningful text[]; treating its keys as the array
        # would be a guess. Callers wanting that must be explicit.
        raise TypeError(
            "as_text_array() received a dict; a mapping is not a text[]. "
            "Pass a list, or Json(value) if the column is jsonb."
        )
    else:
        items = [str(value).strip()]
        items = [i for i in items if i]

    if not items:
        return None
    if dedupe:
        seen, unique = set(), []
        for item in items:
            if item not in seen:
                seen.add(item)
                unique.append(item)
        items = unique
    return items


def as_int_array(value: Any) -> Optional[List[int]]:
    """Coerce `value` into a list of ints for an `integer[]` column.

    Non-numeric entries are dropped rather than raising: these feeds come from
    tool output, and one malformed port should not fail an entire ingest.
    """
    texts = as_text_array(value)
    if texts is None:
        return None
    out = []
    for text in texts:
        try:
            out.append(int(text))
        except (TypeError, ValueError):
            continue
    return out or None
