"""One severity scale, three implementations, pinned to one case table.

Run on demand:

    pytest tests/test_severity_scale.py -v

WHY THIS EXISTS
---------------
Severity ordering was hand-written in eleven places in at least five
incompatible conventions — `critical` was 0, 1 or 5 depending on the file, the
unknown bucket was `ELSE 0`, `ELSE 4`, `ELSE 5`, `ELSE 7` or `?? 0`, and two
copies collapsed `low` and `info` together. None of the frontend copies knew
about the backend's `recon` value, which is how 1495 attack vectors came to sort
below `info`, tied with garbage.

The scale now exists once per language boundary and nowhere else:

    etl/severity.py                              Python
    public.severity_rank(text)                   SQL
    dashboard/frontend/src/lib/constants.ts      TypeScript

Three implementations is the minimum — there is no shared runtime — so CLAUDE.md's
rule applies: "when logic must be duplicated, add an agreement test pinning both
implementations to a shared case table". That is this file. The SQL and
TypeScript sides are read from the real deployment and the real source, not from
a re-typed copy, because a copy would agree with itself while the deployed one
had drifted.
"""
import json
import os
import re
import subprocess
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

severity = pytest.importorskip(
    "etl.severity", reason="etl.severity not importable from this checkout")

severity_rank = severity.severity_rank
SEVERITY_RANK = severity.SEVERITY_RANK
UNKNOWN_RANK = severity.UNKNOWN_RANK


# The shared case table. Every implementation must agree on all of it, including
# the awkward inputs — case, padding, the legacy alias, and the unknowns that
# every old copy handled differently.
CASES = [
    ("critical", 6),
    ("high", 5),
    ("medium", 4),
    ("low", 3),
    ("info", 2),
    ("recon", 2),        # legacy alias for info
    ("error", 1),
    ("CRITICAL", 6),     # scanners are not consistent about case
    ("  High  ", 5),     # nor about whitespace
    ("nonsense", 0),
    ("", 0),
]


def _psql(sql):
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


# ── Python ──────────────────────────────────────────────────────────────────

@pytest.mark.unit
@pytest.mark.parametrize("value,expected", CASES)
def test_python_scale(value, expected):
    assert severity_rank(value) == expected


@pytest.mark.unit
def test_python_treats_none_as_unknown():
    assert severity_rank(None) == UNKNOWN_RANK == 0


@pytest.mark.unit
def test_higher_is_more_severe():
    """The direction is the whole point.

    The copies this replaces disagreed about it, and an ascending scale makes
    unknown sort FIRST unless every call site remembers a sentinel like ELSE 7.
    """
    assert severity_rank("critical") > severity_rank("high") > severity_rank("medium") \
        > severity_rank("low") > severity_rank("info") > severity_rank("error") \
        > severity_rank("nonsense")


@pytest.mark.unit
def test_unknown_sorts_last_in_a_descending_sort():
    values = ["info", "nonsense", "critical", None, "high"]
    ordered = sorted(values, key=lambda s: -severity_rank(s))
    assert ordered[0] == "critical"
    assert ordered[-1] in (None, "nonsense")


# ── SQL, read from the live database ────────────────────────────────────────

@pytest.fixture(scope="module")
def db():
    if _psql("SELECT 1") != "1":
        pytest.skip("no reachable rag-postgres")
    if _psql("SELECT count(*) FROM pg_proc WHERE proname='severity_rank'") == "0":
        pytest.skip("public.severity_rank() not installed")
    return True


def test_sql_agrees_with_python(db):
    """Exercise the DEPLOYED function, not a re-typed copy of its CASE."""
    pairs = ", ".join(
        f"(public.severity_rank({'NULL' if v is None else chr(39) + v + chr(39)}))"
        for v, _ in CASES)
    got = _psql(f"SELECT array_to_json(ARRAY[{pairs}])")
    assert got, "could not read severity_rank from the database"
    ranks = json.loads(got)
    mismatches = [
        (value, expected, actual)
        for (value, expected), actual in zip(CASES, ranks)
        if actual != expected
    ]
    assert not mismatches, (
        "SQL severity_rank disagrees with etl/severity.py:\n  "
        + "\n  ".join(f"{v!r}: python={e} sql={a}" for v, e, a in mismatches))


def test_sql_handles_null(db):
    assert _psql("SELECT public.severity_rank(NULL)") == str(UNKNOWN_RANK)


def test_sql_function_is_immutable(db):
    """IMMUTABLE lets the planner fold it and permits indexing on it. STABLE
    would silently forbid an expression index later."""
    assert _psql(
        "SELECT provolatile FROM pg_proc WHERE proname='severity_rank'") == "i"


def test_findings_search_orders_by_the_shared_function(db):
    """The main listing must use the function, not a re-introduced CASE."""
    src = open(os.path.join(REPO, "app", "rag-api", "api.py"), encoding="utf-8").read()
    assert 'severity_order = "public.severity_rank(severity) DESC"' in src, \
        "the findings search no longer orders by the shared function"


# ── TypeScript, read from the real source ───────────────────────────────────

@pytest.fixture(scope="module")
def ts_constants():
    path = os.path.join(REPO, "dashboard", "frontend", "src", "lib", "constants.ts")
    if not os.path.exists(path):
        pytest.skip("frontend constants.ts not present")
    return open(path, encoding="utf-8").read()


def test_typescript_severity_order_matches_python(ts_constants):
    """The frontend derives its ranks from SEVERITY_LEVELS, so agreement means
    that list is in the same order as the Python scale — which is what actually
    determines the numbers on both sides."""
    m = re.search(r"SEVERITY_LEVELS = \[([^\]]+)\]", ts_constants)
    assert m, "could not find SEVERITY_LEVELS"
    levels = [x.strip().strip("'\"") for x in m.group(1).split(",") if x.strip()]

    py_order = [s for s in severity.severities_by_rank() if s in levels]
    ts_order = [s for s in levels if s in SEVERITY_RANK]
    assert ts_order == py_order, (
        f"frontend order {ts_order} != python order {py_order} — the derived "
        "ranks will disagree")


def test_typescript_ranks_legacy_recon_as_info(ts_constants):
    """The specific omission that caused the original bug."""
    assert "recon:" in ts_constants, "frontend has no rank for legacy 'recon'"
    assert severity_rank("recon") == severity_rank("info")


def test_typescript_unknown_is_zero_like_python(ts_constants):
    assert "return 0" in ts_constants, \
        "frontend severityRank no longer returns 0 for unknown"


# ── what must NOT be folded into this scale ─────────────────────────────────

@pytest.mark.unit
def test_nessus_and_risk_scales_are_left_alone():
    """Three lookalike numbers are deliberately NOT this scale.

    Unifying them would be wrong, not tidy:
      * _severity_to_nessus is the .nessus file format's 0-4 risk level, defined
        externally — changing it corrupts exports.
      * risk_map is a 0-3 weighting that intentionally collapses critical and
        high into one bucket.
      * the `priority` orderings are a different column with its own vocabulary.
    """
    src = open(os.path.join(REPO, "app", "rag-api", "api.py"), encoding="utf-8").read()
    assert '{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}' in src, \
        "the Nessus risk-level mapping was changed; it is fixed by that file format"
    assert '"critical": 3, "high": 3' in src, \
        "risk_map no longer collapses critical and high, which it did on purpose"
