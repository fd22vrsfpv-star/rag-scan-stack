"""Valid credentials must be reachable as findings.

`credential_findings` held 7 working credentials for a live engagement — the
highest-value result the engagement had produced — while the unified
`/findings/search` endpoint UNIONed only vulns, web_findings,
playwright_findings and ports. Credentials were therefore invisible to every
severity filter, export and report built on that endpoint.

Two properties are load-bearing and easy to break silently:

  * the credential branch exists and is gated on `valid_cred = true` (failed
    attempts are audit trail; surfacing them buries the working credentials
    among the passwords that did not work);
  * the aggregation subquery mirrors the main query. They are separate SQL
    blocks, so if one gains the credential branch and the other does not, the
    severity facet counts silently disagree with the rows returned.

These are asserted against the source text: `search_findings` builds one large
SQL string inline and cannot be exercised without a database.
"""
import re
from pathlib import Path

import pytest

API = Path(__file__).parent.parent / "app" / "rag-api" / "api.py"


@pytest.fixture(scope="module")
def search_sql():
    """The body of search_findings(), where both SQL blocks live."""
    src = API.read_text()
    start = src.index('@app.get("/findings/search"')
    end = src.index("@app.get", start + 10)
    return src[start:end]


@pytest.mark.unit
def test_credential_findings_is_a_finding_source(search_sql):
    assert "FROM credential_findings cf" in search_sql, (
        "credential_findings dropped out of the unified findings UNION — valid "
        "credentials would stop appearing in the findings list"
    )


@pytest.mark.unit
def test_only_valid_credentials_are_surfaced(search_sql):
    """Failed brute-force attempts must not be reported as findings."""
    branch = search_sql[search_sql.index("FROM credential_findings cf"):]
    assert re.search(r"WHERE\s+cf\.valid_cred\s*=\s*true", branch), (
        "the valid_cred gate is missing — every failed password attempt would "
        "be listed as a finding"
    )


@pytest.mark.unit
def test_aggregation_mirrors_the_main_query(search_sql):
    """Both SQL blocks must include credentials, with the same gate.

    Otherwise the severity facet and the result list disagree — the kind of
    mismatch that reads as a UI bug rather than a query bug.
    """
    occurrences = search_sql.count("credential_findings cf")
    assert occurrences >= 2, (
        f"credential_findings appears {occurrences}x; expected it in BOTH the "
        "main UNION and the aggregation subquery"
    )
    # The gate must appear as many times as the table does.
    gates = len(re.findall(r"cf\.valid_cred\s*=\s*true", search_sql))
    assert gates == occurrences, (
        f"{occurrences} credential_findings references but {gates} valid_cred "
        "gates — the aggregation and the main query have drifted"
    )


@pytest.mark.unit
def test_the_secret_itself_is_not_selected(search_sql):
    """Evidence names the account and proves access; it does not print secrets.

    credential_findings stores only a masked form by design and cleartext
    belongs in credential_vault behind its own access control. A findings list
    is rendered, exported and screenshotted, so a secret selected here would
    propagate far beyond the vault's controls.
    """
    branch = search_sql[search_sql.index("FROM credential_findings cf"):]
    for leaked in ("password_masked", "credential_value", "cracked_value",
                   "cf.secret ", "password'"):
        assert leaked not in branch, f"credential branch selects {leaked!r}"


# ------------------------------------------------------- engagement scoping

@pytest.mark.unit
def test_engagement_scope_resolves_by_id_not_only_by_name(search_sql):
    """Scope lookup must not depend solely on a name string matching.

    The filter previously resolved scope via
    `scope_targets.name = engagements.scope_name`. On a live engagement
    `scope_name` was EMPTY while its scope_targets rows were named 'msf', so the
    subquery returned nothing, the filter collapsed to `engagement_id = %s`, and
    every finding with a NULL engagement_id disappeared from the engagement view
    — 49 nmap and 28,232 zap findings, with no error. scope_targets.engagement_id
    is reliably populated and is the authoritative link.
    """
    assert "SELECT target FROM scope_targets" in search_sql
    scope_clause = search_sql[search_sql.index("SELECT target FROM scope_targets"):]
    scope_clause = scope_clause[:400]
    assert "engagement_id = %s::uuid" in scope_clause, (
        "scope resolution no longer matches scope_targets by engagement_id"
    )


@pytest.mark.unit
def test_empty_scope_name_cannot_match_scope_targets(search_sql):
    """An empty scope_name must not be used as a join key.

    Without NULLIF, `name = ''` would match any scope_targets row whose name is
    also empty — silently widening an engagement's scope, which for an
    authorization-adjacent filter is the dangerous direction to fail in.
    """
    assert "NULLIF((SELECT scope_name FROM engagements" in search_sql, (
        "empty scope_name is not guarded with NULLIF"
    )
