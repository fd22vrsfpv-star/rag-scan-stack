"""Export endpoints must scope to the active engagement.

Run on demand:

    pytest tests/test_export_engagement_scope.py -v

WHY THIS EXISTS
---------------
An export bundles findings into a file the operator hands to Burp/ZAP or a
report. Exporting every engagement's data — one client's findings inside
another client's export — is a data-leak, not a cosmetic bug. Each export
resolves the active engagement (X-Engagement-Id header) and filters by it: the
finding table's own engagement_id, or (for /export/data's generic table dump)
the linked asset when the table lacks the column.

SABOTAGE PROOF
--------------
Remove the `_resolve_engagement_id` line or the engagement predicate from any
listed handler/helper and its case fails.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")

REQUIRED = {
    "export_burp_sitemap":   ["_resolve_engagement_id",
                              "asset_id IN (SELECT id::text FROM assets WHERE engagement_id = %s::uuid)"],
    "export_har":            ["_resolve_engagement_id", "wf.engagement_id = %s::uuid",
                              "v.engagement_id = %s::uuid"],
    "export_zap_report":     ["_resolve_engagement_id", "wf.engagement_id = %s::uuid"],
    "export_sarif":          ["_resolve_engagement_id", "v.engagement_id = %s::uuid",
                              "AND engagement_id = %s::uuid"],
    "export_findings_exchange": ["_resolve_engagement_id", "wf.engagement_id = %s::uuid",
                                 "v.engagement_id = %s::uuid"],
    "export_data":           ["_resolve_engagement_id", "engagement_id=_eid"],
    # /export/data's generic dump filters inside these helpers.
    "_export_web_findings":  ["engagement_id = %s::uuid"],
    "_export_table_rows":    ["engagement_id = %s::uuid",
                              "asset_id IN (SELECT id FROM assets WHERE engagement_id = %s::uuid)"],
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
def test_export_scopes_to_engagement(fname):
    funcs = _funcs()
    assert fname in funcs, f"{fname} not found in api.py (renamed?)"
    body = funcs[fname]
    for needle in REQUIRED[fname]:
        assert needle in body, (
            f"{fname} is missing '{needle}' — an export must scope to the active "
            f"engagement or it leaks other engagements' findings into the file.")
