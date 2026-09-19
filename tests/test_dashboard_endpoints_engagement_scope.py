"""Every collected-data LIST endpoint must scope to the active engagement.

Run on demand:

    pytest tests/test_dashboard_endpoints_engagement_scope.py -v

WHY THIS EXISTS
---------------
A sweep of the dashboard found many list/summary endpoints that queried
collected-data tables (credentials, vulns, ports, software, content, findings,
identities) but never applied the active engagement — they returned every
engagement's rows regardless of the X-Engagement-Id header. Each must resolve the
engagement (_resolve_engagement_id, so the header works, not only an explicit
param) and add an engagement predicate — either the table's own engagement_id or,
for tables that lack it, the linked asset's / identity's engagement.

SABOTAGE PROOF
--------------
Delete the `_resolve_engagement_id` line or the engagement predicate from any
listed handler and its case fails.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")

# handler name -> substrings its source must contain
REQUIRED = {
    "list_credentials_vault":     ["_resolve_engagement_id", "engagement_id = %s::uuid"],
    "list_all_credentials":       ["_resolve_engagement_id", "engagement_id = %s::uuid"],
    "credentials_expiring":       ["_resolve_engagement_id", "engagement_id = %s::uuid"],
    "credential_cloud_summary":   ["_resolve_engagement_id", "engagement_id = %s::uuid"],
    "get_vulnerabilities":        ["_resolve_engagement_id", "v.engagement_id = %s::uuid"],
    "get_vulnx_findings":         ["_resolve_engagement_id", "v.engagement_id = %s::uuid"],
    "get_open_ports":             ["_resolve_engagement_id", "a.engagement_id = %s::uuid"],
    "get_detected_software":      ["_resolve_engagement_id",
                                   "asset_id IN (SELECT id FROM assets WHERE engagement_id = %s::uuid)"],
    "list_content_extractions":   ["_resolve_engagement_id",
                                   "ce.asset_id IN (SELECT id FROM assets WHERE engagement_id = %s::uuid)"],
    # search_findings filters over a UNION that selects engagement_id::text, so
    # it compares as text (a `= %s::uuid` here raises text = uuid).
    "search_findings":            ["_resolve_engagement_id", 'engagement_id = %s")'],
    "assets_pending_exploit_counts": ["_resolve_engagement_id", "pe.engagement_id = %s::uuid"],
    "identities_credential_state": ["_resolve_engagement_id",
                                    "identity_id IN (SELECT id FROM identities WHERE engagement_id = %s::uuid)"],
}


def _funcs():
    if not os.path.exists(API):
        pytest.skip("api.py not present")
    src = open(API, encoding="utf-8").read()
    tree = ast.parse(src)
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in REQUIRED:
            out[node.name] = ast.get_source_segment(src, node)
    return out


@pytest.mark.parametrize("fname", sorted(REQUIRED))
def test_endpoint_scopes_to_engagement(fname):
    funcs = _funcs()
    assert fname in funcs, f"{fname} not found in api.py (renamed?)"
    body = funcs[fname]
    for needle in REQUIRED[fname]:
        assert needle in body, (
            f"{fname} is missing '{needle}' — it must resolve the active "
            f"engagement and filter by it, or it returns every engagement's data.")
