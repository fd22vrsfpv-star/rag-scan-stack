"""ENFORCED: every WRITER that INSERTs COLLECTED TARGET DATA must POPULATE the
engagement link — its INSERT column list must name `engagement_id` or `asset_id`
(from which `assets.engagement_id` resolves) — or be a declared exception.

`tests/test_engagement_attribution.py` proves each collected-data TABLE HAS an
`engagement_id`/`asset_id` column. That is not enough: `identities` had the column
AND a writer that left it NULL, and the schema test stayed green the whole time. A
column that exists but is never filled reads as "attributed" to the schema check
while every row it writes leaks across engagements and survives an engagement purge.

This guard closes that gap for the collected-data tables named in the invariant
(CLAUDE.md "Engagement attribution is mandatory"). It is a SOURCE guard (no DB
needed): it finds each `INSERT INTO <collected-data table>` in the writer modules,
extracts the SQL column list, and asserts the writer either names `engagement_id`
(or `asset_id`) OR is declared in WRITER_POP_DEBT / WRITER_POP_EXEMPT with a reason.

It RATCHETS, exactly like ENG_ATTR_DEBT in test_engagement_attribution.py:
- A NEW writer (or a new column-shape in an existing file) that sets neither column
  and is not declared FAILS BY NAME.
- Removing `engagement_id`/`asset_id` from a currently-covered writer creates a new
  undeclared gap key -> fails.
- Adding `engagement_id`/`asset_id` to a DEBT writer makes its key stop being a gap
  -> `test_writer_debt_does_not_rot` flags the stale entry so it must be removed.

Skips cleanly when the writer modules are absent (wrong tree / partial checkout).

    pytest tests/test_engagement_writer_population.py
"""
import re
import pathlib

import pytest

# Repo root = parent of tests/. Works in the worktree and the main checkout.
ROOT = pathlib.Path(__file__).resolve().parent.parent

# Collected-data tables that MUST be engagement-attributable (CLAUDE.md invariant).
# These are the tables the OPEN_ITEM named plus the ones the writers touch.
TABLES = (
    "credential_findings",
    "web_findings",
    "vulns",
    "recon_findings",
    "enumeration_observations",
    "identities",
)

# Directories that hold collected-data WRITERS (exclude tests/ — those are fixtures).
WRITER_DIRS = (
    "etl",
    "app/rag-api",
    "exploit_runner",
    "node_manager",
    "nuclei",
    "osint_runner",
    "playwright_scanner",
    "web_scanner",
)

# Case-sensitive: real SQL in this repo is upper-case `INSERT INTO`. Lower/mixed-case
# occurrences ("insert into vulns ... tables") are prose in docstrings/comments and
# must NOT be treated as writers.
_INSERT_RE = re.compile(r"INSERT INTO\s+(%s)\b" % "|".join(TABLES))
_KW_RE = re.compile(r"\bVALUES\b|\bSELECT\b|\bON CONFLICT\b")
_COLGROUP_RE = re.compile(r"\(([^()]*)\)", re.S)

# EXEMPT — a collected-data writer that legitimately does NOT resolve an engagement
# at its INSERT (e.g. a cross-engagement/shared sink). Each needs a reason. Empty
# today: every gap below is real debt, not a design exemption.
WRITER_POP_EXEMPT = {}

# DEBT — collected-data writers that SHOULD populate engagement_id/asset_id but do
# not yet. Keyed by `<path>::<table>::(<sorted columns>)` so the entry is stable
# across line moves and each distinct INSERT shape is named. Shrink by resolving the
# engagement at the writer (see exploit_runner/cred_cracker.py::_resolve_engagement);
# do NOT grow without a reason.
WRITER_POP_DEBT = {
    "etl/parse_subdomain_takeover.py::recon_findings::(data,finding_type,severity,source,tags,target)":
        "takeover recon_findings keyed by target only; resolve engagement from the target's asset/scope",
    "etl/parse_tool_output.py::web_findings::(evidence,fingerprint,id,issue_type,name,severity,source,url)":
        "generic tool-output web_findings keyed by URL only; resolve engagement from asset/scope",
    "app/rag-api/api.py::web_findings::(evidence,issue_type,name,severity,source,url)":
        "BFF web_findings writer keyed by URL only; resolve engagement from asset/scope",
    "app/rag-api/api.py::web_findings::(confidence,description,evidence,issue_type,method,name,payload,severity,source,status_code,url)":
        "BFF import web_findings writer keyed by URL only; resolve engagement from asset/scope",
    "app/rag-api/post_review_agent.py::recon_findings::(data,finding_type,severity,source,target)":
        "post-review recon_findings keyed by target only; resolve engagement from asset/scope",
    "node_manager/node_manager.py::recon_findings::(data,finding_type,severity,source,target)":
        "node-relayed recon_findings keyed by target only; resolve engagement from asset/scope",
    "nuclei/nuclei_runner.py::web_findings::(evidence,first_seen,id,issue_type,last_seen,name,severity,source,url)":
        "nuclei web_findings keyed by URL only; resolve engagement from asset/scope",
    "osint_runner/osint_runner.py::recon_findings::(data,finding_type,severity,source,target)":
        "osint recon_findings keyed by target only; resolve engagement from asset/scope",
    "osint_runner/osint_runner.py::web_findings::(evidence,first_seen,id,issue_type,last_seen,name,severity,source,url)":
        "osint web_findings keyed by URL only; resolve engagement from asset/scope",
    "osint_runner/osint_runner.py::recon_findings::(created_at,data,finding_type,id,severity,source,target)":
        "osint email-enum (SPF/DMARC/...) recon_findings keyed by domain/target only; resolve engagement from asset/scope",
    "playwright_scanner/playwright_scanner.py::web_findings::(evidence,first_seen,id,issue_type,last_seen,name,severity,source,url)":
        "playwright web_findings keyed by URL only; resolve engagement from asset/scope",
    "web_scanner/web_scan.py::web_findings::(evidence,first_seen,id,issue_type,last_seen,name,severity,source,url)":
        "web_scanner info/scan-note web_findings keyed by URL only; resolve engagement from asset/scope",
}


def _writer_files():
    files = []
    for d in WRITER_DIRS:
        base = ROOT / d
        if base.is_dir():
            files.extend(sorted(base.glob("*.py")))
    return files


def _insert_columns(text, start):
    """From an `INSERT INTO` match at `start`, return (columns, dynamic).

    Columns come from the first `(...)` group before the first VALUES/SELECT/ON
    CONFLICT keyword. `dynamic` is True when no static column list is present (the
    column list is built at runtime), so attribution cannot be proven from source.
    """
    after = text[start:]
    mkw = _KW_RE.search(after)
    head = after[: mkw.start()] if mkw else after[:400]
    mcol = _COLGROUP_RE.search(head)
    if not mcol:
        return [], True
    cols = [re.sub(r"\s+", "", c).strip('"') for c in mcol.group(1).split(",") if c.strip()]
    return cols, False


def _writer_key(path, table, cols, dynamic):
    if dynamic:
        return f"{path}::{table}::dynamic-columns"
    return f"{path}::{table}::({','.join(sorted(c.lower() for c in cols))})"


def _scan():
    """Return (all_sites, covered_keys, gap_keys).

    all_sites: total number of INSERT sites found.
    gap_keys: distinct keys for writers whose INSERT names NEITHER engagement_id
              NOR asset_id (nor, if dynamic, cannot prove it).
    """
    all_sites = 0
    covered = set()
    gaps = set()
    for p in _writer_files():
        rel = p.relative_to(ROOT).as_posix()
        src = p.read_text(errors="replace")
        for m in _INSERT_RE.finditer(src):
            all_sites += 1
            table = m.group(1)
            cols, dynamic = _insert_columns(src, m.start())
            joined = " ".join(cols).lower()
            key = _writer_key(rel, table, cols, dynamic)
            if (not dynamic) and ("engagement_id" in joined or "asset_id" in joined):
                covered.add(key)
            else:
                gaps.add(key)
    return all_sites, covered, gaps


def test_every_collected_data_writer_populates_engagement_or_is_declared():
    files = _writer_files()
    if not files:
        pytest.skip("writer modules absent (partial checkout / wrong tree)")
    all_sites, covered, gaps = _scan()
    if all_sites == 0:
        pytest.skip("no INSERT sites into collected-data tables found")
    # Guard the scanner itself: if it can no longer see the many covered writers,
    # something broke the extraction rather than the code being suddenly clean.
    assert covered, ("scanner found INSERT sites but none carry engagement_id/asset_id "
                     "— the extraction is broken, not the codebase")
    known = set(WRITER_POP_DEBT) | set(WRITER_POP_EXEMPT)
    undeclared = sorted(gaps - known)
    assert not undeclared, (
        "collected-data WRITERS that populate NEITHER engagement_id NOR asset_id in "
        "their INSERT and are not declared:\n  " + "\n  ".join(undeclared) +
        "\nResolve the engagement at the writer (see "
        "exploit_runner/cred_cracker.py::_resolve_engagement) and add engagement_id "
        "(or asset_id) to the INSERT, OR declare it in WRITER_POP_DEBT with a reason "
        "(if it should be attributed but is not yet) or WRITER_POP_EXEMPT (if it is "
        "genuinely cross-engagement/shared).")


def test_writer_debt_does_not_rot():
    """A DEBT writer that has GAINED attribution must be removed from the list."""
    files = _writer_files()
    if not files:
        pytest.skip("writer modules absent (partial checkout / wrong tree)")
    all_sites, covered, gaps = _scan()
    if all_sites == 0:
        pytest.skip("no INSERT sites into collected-data tables found")
    resolved = sorted(k for k in WRITER_POP_DEBT if k not in gaps)
    assert not resolved, (
        "these are in WRITER_POP_DEBT but no longer read as gaps (the writer gained "
        "engagement_id/asset_id, or its column shape changed) — remove or re-key "
        "them:\n  " + "\n  ".join(resolved))


def test_writer_exempt_and_debt_are_disjoint():
    both = sorted(set(WRITER_POP_EXEMPT) & set(WRITER_POP_DEBT))
    assert not both, f"a writer is both exempt and debt — pick one: {both}"
