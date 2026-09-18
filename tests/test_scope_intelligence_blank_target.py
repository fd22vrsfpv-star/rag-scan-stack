"""A blank scope target must NOT become an ILIKE '%%' wildcard.

Run on demand:

    pytest tests/test_scope_intelligence_blank_target.py -v

WHY THIS EXISTS
---------------
scope_intelligence / scope_analysis build `f"%{target}%"` LIKE patterns from a
scope's `scope_targets` rows. A blank target ("") yields '%%', which ILIKE-matches
EVERY recon_findings row — so the 'testfire' scope (which has an empty domain row
alongside http://demo.testfire.net) pulled in all 21,675 recon rows across every
engagement (blackbaud/convio included) instead of its 12. The blank row must be
skipped, and if no concrete target remains the handler returns the empty view (an
empty LIKE list would also make the WHERE clause invalid).

SABOTAGE PROOF
--------------
Remove the `if not target:` skip from either handler and this fails by name.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")

HANDLERS = ["scope_intelligence", "scope_analysis"]


def _sources():
    if not os.path.exists(API):
        pytest.skip("api.py not present")
    src = open(API, encoding="utf-8").read()
    tree = ast.parse(src)
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in HANDLERS:
            out[node.name] = ast.get_source_segment(src, node)
    return out


@pytest.mark.parametrize("fname", HANDLERS)
def test_handler_skips_blank_scope_targets(fname):
    srcs = _sources()
    assert fname in srcs, f"{fname} not found in api.py (renamed?)"
    body = srcs[fname]
    # The loop must strip the target and skip empties BEFORE building a pattern.
    assert 'r["target"] or ""' in body and ".strip()" in body, (
        f"{fname} must normalise the scope target with (r['target'] or '').strip() "
        "so a blank/whitespace row is detectable.")
    assert "if not target:" in body and "continue" in body, (
        f"{fname} must `continue` on a blank target — otherwise \"%\"+\"\"+\"%\" "
        "is '%%' and ILIKE matches every recon finding across all engagements.")


def test_handlers_guard_empty_like_list():
    srcs = _sources()
    for fname in HANDLERS:
        assert "if not like_patterns:" in srcs[fname], (
            f"{fname} must return empty when no concrete target remains "
            "(an empty OR-list makes the WHERE clause invalid).")
