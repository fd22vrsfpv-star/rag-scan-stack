"""Identity & Content-Intel endpoints must scope to the active engagement.

Run on demand:

    pytest tests/test_identities_content_engagement_scope.py -v

WHY THIS EXISTS
---------------
The Users/Identities page and the Content Intelligence summary showed GLOBAL
counts/rows regardless of the selected engagement:
  * the identity endpoints had no engagement predicate (and the frontend used a
    raw fetch that never sent X-Engagement-Id);
  * /content-extractions/summary counted every engagement's rows, so the summary
    cards did not match the scope-filtered list.
Each handler must resolve the active engagement (_resolve_engagement_id, so the
X-Engagement-Id header works) and apply an engagement predicate. Identities carry
engagement_id directly; content_extractions has none, so it is scoped via the
linked asset's engagement (and an optional scope URL match).

SABOTAGE PROOF
--------------
Delete the `_resolve_engagement_id` line or the engagement predicate from any of
the named handlers and its case fails.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")

REQUIRED = {
    "list_identities": ["_resolve_engagement_id", "i.engagement_id = %s::uuid"],
    "identities_summary": ["_resolve_engagement_id", "engagement_id = %s::uuid"],
    "identities_groups": ["_resolve_engagement_id", "engagement_id = %s::uuid"],
    "content_extraction_summary": ["_resolve_engagement_id",
                                    "engagement_id = %s::uuid"],
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
