"""etl/sql_types.py — coercion into Postgres array columns.

Run on demand:

    pytest tests/test_sql_types.py -v

WHY THIS EXISTS
---------------
`web_findings.cwe` is `text[]` and the Playwright ZAP path passed the alert's
bare string. Verified against the live column at the time:

    scalar "CWE-79": REJECTED -> InvalidTextRepresentation:
                                 malformed array literal: "CWE-79"
    list  ["CWE-79"]: ACCEPTED

`as_text_array()` is the single normaliser those feeds route through, and
`tests/test_sql_columns.py` lists it in LIST_SAFE_FUNCS so its call sites become
statically provable. If its contract drifts, that guard keeps passing while the
inserts start failing — so the contract needs its own tests.

The None-vs-empty-list distinction is the subtle part: in Postgres NULL and
'{}' are different values, and callers overwhelmingly mean "unknown" rather
than "known to be empty".
"""
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

sql_types = pytest.importorskip(
    "etl.sql_types", reason="etl.sql_types not importable from this checkout")

as_text_array = sql_types.as_text_array
as_int_array = sql_types.as_int_array


# ── absence maps to NULL, not to an empty array ──────────────────────────────

@pytest.mark.unit
@pytest.mark.parametrize("value", [None, "", "   ", [], (), set()])
def test_absent_values_become_none(value):
    """NULL and '{}' are different in Postgres; absence means NULL."""
    assert as_text_array(value) is None


@pytest.mark.unit
def test_list_of_only_blanks_is_absence():
    assert as_text_array(["", "  ", None]) is None


# ── the bug this exists for ──────────────────────────────────────────────────

@pytest.mark.unit
def test_bare_string_becomes_a_single_element_list():
    """The exact shape that raised 'malformed array literal: "CWE-79"'."""
    assert as_text_array("CWE-79") == ["CWE-79"]


@pytest.mark.unit
def test_existing_list_passes_through():
    assert as_text_array(["CWE-79", "CWE-89"]) == ["CWE-79", "CWE-89"]


@pytest.mark.unit
def test_blanks_and_nones_are_dropped_from_a_list():
    assert as_text_array(["CWE-79", "", None, "  ", "CWE-89"]) == ["CWE-79", "CWE-89"]


@pytest.mark.unit
def test_elements_are_stripped():
    assert as_text_array(["  CWE-79  "]) == ["CWE-79"]


# ── comma-separated strings ──────────────────────────────────────────────────

@pytest.mark.unit
def test_comma_separated_string_is_split():
    """Several tools emit CVE lists this way.

    Passing the whole string as one element yields a one-item array that no
    lookup will ever match — a silent data defect rather than an error.
    """
    assert as_text_array("CVE-2021-1, CVE-2021-2") == ["CVE-2021-1", "CVE-2021-2"]


@pytest.mark.unit
def test_comma_split_drops_empty_fragments():
    assert as_text_array("CVE-1,,CVE-2,") == ["CVE-1", "CVE-2"]


@pytest.mark.unit
def test_a_string_without_commas_is_not_split():
    assert as_text_array("Some finding name") == ["Some finding name"]


# ── other input shapes ───────────────────────────────────────────────────────

@pytest.mark.unit
def test_non_string_scalars_are_stringified():
    assert as_text_array(7) == ["7"]
    assert as_text_array(7.5) == ["7.5"]


@pytest.mark.unit
def test_mixed_element_types_are_stringified():
    assert as_text_array([1, "two", 3]) == ["1", "two", "3"]


@pytest.mark.unit
def test_tuple_is_accepted():
    assert as_text_array(("a", "b")) == ["a", "b"]


@pytest.mark.unit
def test_set_input_is_ordered_deterministically():
    """An arbitrary set order would make exports and fingerprints unstable."""
    assert as_text_array({"b", "a", "c"}) == as_text_array({"c", "a", "b"})
    assert as_text_array({"b", "a", "c"}) == ["a", "b", "c"]


@pytest.mark.unit
def test_zero_is_kept_not_treated_as_absence():
    """0 is falsy but is a real value; a truthiness test would drop it."""
    assert as_text_array(0) == ["0"]
    assert as_text_array([0]) == ["0"]


@pytest.mark.unit
def test_dict_is_rejected_rather_than_guessed():
    """Silently using the keys would be a guess, and dicts belong in jsonb."""
    with pytest.raises(TypeError, match="not a text"):
        as_text_array({"a": 1})


# ── dedupe ───────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_dedupe_is_off_by_default():
    assert as_text_array(["a", "a", "b"]) == ["a", "a", "b"]


@pytest.mark.unit
def test_dedupe_preserves_first_seen_order():
    assert as_text_array(["b", "a", "b", "c", "a"], dedupe=True) == ["b", "a", "c"]


# ── idempotence, since values may pass through twice ─────────────────────────

@pytest.mark.unit
@pytest.mark.parametrize("value", ["CWE-79", ["CWE-79"], None, "", ["a", "b"], 7])
def test_applying_twice_changes_nothing(value):
    once = as_text_array(value)
    assert as_text_array(once) == once


# ── as_int_array ─────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_as_int_array_converts():
    assert as_int_array(["1", "2"]) == [1, 2]
    assert as_int_array("80,443") == [80, 443]
    assert as_int_array(443) == [443]


@pytest.mark.unit
def test_as_int_array_drops_non_numeric_rather_than_raising():
    """Tool output is untrusted; one bad port must not fail a whole ingest."""
    assert as_int_array(["80", "not-a-port", "443"]) == [80, 443]


@pytest.mark.unit
def test_as_int_array_absence_and_all_invalid_are_none():
    assert as_int_array(None) is None
    assert as_int_array([]) is None
    assert as_int_array(["x", "y"]) is None


# ── the guard's promise about this module ────────────────────────────────────

@pytest.mark.unit
def test_helper_names_match_the_guards_list_safe_funcs():
    """A rename here silently un-proves every call site.

    tests/test_sql_columns.py trusts these names to mean "returns a list", so
    the two must not drift apart.
    """
    guard = pytest.importorskip("test_sql_columns")
    for name in ("as_text_array", "as_int_array"):
        assert name in guard.LIST_SAFE_FUNCS, (
            f"{name} is not in LIST_SAFE_FUNCS; its call sites would stop being "
            "provable and silently need ARRAY_UNVERIFIED entries"
        )
        assert hasattr(sql_types, name), f"{name} missing from etl/sql_types.py"
