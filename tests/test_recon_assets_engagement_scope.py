"""The asset & recon LIST endpoints must scope to the active engagement.

Run on demand:

    pytest tests/test_recon_assets_engagement_scope.py -v

WHY THIS EXISTS
---------------
/assets and the /recon/* list endpoints proxied the X-Engagement-Id header from
the BFF but never applied it: the SQL had no engagement predicate. With 1830
assets across engagements (1827 in one, 2 in another) ordered by IP, the small
engagement's assets fell on a later page, so "assets under this scope" looked
empty though the data was there. Same for the recon page (21,675 recon rows, 91
for the viewed engagement). Each handler must resolve the engagement
(_resolve_engagement_id, so the header works, not only an explicit param) and add
an engagement predicate to its WHERE.

Recon rows scope by the LINKED ASSET's engagement, because
recon_findings.engagement_id is badly under-populated (mostly NULL) while the
asset it points at is reliably attributed.

SABOTAGE PROOF
--------------
Delete the `_resolve_engagement_id` line (or the engagement WHERE predicate) from
any of the four handlers and this fails by name.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")

# handler function name -> substrings its source must contain
REQUIRED = {
    "get_assets": ["_resolve_engagement_id", "a.engagement_id = %s"],
    "search_recon": ["_resolve_engagement_id", "a.engagement_id = %s::uuid"],
    "get_recon_subdomains": ["_resolve_engagement_id", "a.engagement_id = %s::uuid"],
    "list_recon_domains": ["_resolve_engagement_id", "engagement_id = %s::uuid"],
    # OSINT Explorer Parameters tab — scope via the linked asset's engagement.
    "search_params": ["_resolve_engagement_id", "dp.asset_id IN (SELECT id FROM assets WHERE engagement_id = %s::uuid)"],
    "params_summary": ["_resolve_engagement_id", "dp.asset_id IN (SELECT id FROM assets WHERE engagement_id = %s::uuid)"],
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
            f"{fname} is missing '{needle}' — it must resolve the active engagement "
            f"(header or param) and apply an engagement predicate, or it returns "
            f"every engagement's rows and buries the viewed scope.")
