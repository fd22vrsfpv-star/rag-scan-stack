"""A build is attributed to the TARGET's engagement, not the operator's tab.

Why this exists
---------------
`build_poc_endpoint` set `eid = _validate_engagement_uuid(_resolve_engagement_id())`
— the engagement the UI happened to be on — and stamped every artifact the
build produced with it. So a build launched against engagement A's host while
the operator was looking at engagement B filed the result under B.

Observed 2026-10-19: one `exploit_store` row and one `build_poc_attempts` row
for a host that belongs to another engagement's scope carried the engagement
that was merely active at 14:19 UTC. Two consequences, and the second is the
one that matters: the rows surfaced under the wrong engagement in the PoC
listings, AND the owning engagement's data purge could not reach them, because
the purge keys on `engagement_id`.

CLAUDE.md: "A writer that creates collected target data MUST set
engagement_id, resolving it from the target's asset or scope — do NOT leave it
NULL and rely on a later backfill trigger."

Read with `ast` rather than importing api.py (fastapi/psycopg2 absent on a
bare checkout).
"""
from __future__ import annotations

import ast
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _ast_assert import call_order, calls  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"

pytestmark = pytest.mark.skipif(not API.exists(), reason="rag-api source not present")


def _tree():
    return ast.parse(API.read_text(encoding="utf-8"))


def _func(name: str) -> ast.FunctionDef:
    for node in ast.walk(_tree()):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not found in api.py")


def test_resolver_exists_and_prefers_asset_then_scope():
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func("_engagement_for_build_target")) or ""
    assert "FROM assets" in src, "the asset is the first authority"
    assert "FROM scope_targets" in src, "scope is the second authority"
    assert src.index("FROM assets") < src.index("FROM scope_targets"), \
        "asset must be consulted before scope"


def test_resolver_scope_leg_is_not_ip_only():
    """An external engagement's scope is mostly HOSTNAMES. The shared helper
    `identity_upsert.resolve_engagement_for_host` filters its scope lookup to
    `target_type = 'ip'`, which resolves a hostname target to nothing — which
    is exactly the case that misattributed the build."""
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func("_engagement_for_build_target")) or ""
    scope_leg = src[src.index("FROM scope_targets"):]
    assert "target_type" not in scope_leg, (
        "the scope leg must match hostname targets too — restricting it to "
        "target_type='ip' reintroduces the bug")


def test_resolver_never_claims_the_global_deny_list():
    """`not_in_scope` rows carry `engagement_id IS NULL` by design. A resolver
    that returned them would attribute a build to 'no engagement' and put the
    artifacts right back out of a purge's reach."""
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func("_engagement_for_build_target")) or ""
    assert src.count("engagement_id IS NOT NULL") >= 2, \
        "both legs must exclude NULL-engagement rows"


def test_endpoint_overrides_the_header_with_the_target_engagement():
    """Structural, not substring: a comment mentioning the resolver would
    satisfy a text search, and the ORDER is the real contract — resolving the
    target after `eid` is already final is dead code."""
    api_src = API.read_text(encoding="utf-8")
    assert calls(api_src, "_engagement_for_build_target"), \
        "the endpoint must resolve the target's engagement"
    assert call_order(api_src, "_resolve_engagement_id",
                      "_engagement_for_build_target", within="build_poc_endpoint"), \
        "the header must be read before the target is resolved"

    # ...and the resolved value must actually be assigned back to `eid`,
    # otherwise the resolve is an expensive no-op.
    fn = _func("build_poc_endpoint")
    assigned = any(
        isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "eid" for t in n.targets)
        and isinstance(n.value, ast.Name) and n.value.id == "_target_eid"
        for n in ast.walk(fn))
    assert assigned, "the target's engagement must be assigned back to eid"


def test_mismatch_is_surfaced_not_silent():
    """Re-attribution changes which engagement owns a result. An operator who
    launched a build and sees it land elsewhere must be able to find out why."""
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _func("build_poc_endpoint")) or ""
    seg = src[src.index("_engagement_for_build_target(ip)"):]
    assert "logging.warning" in seg, "a silent re-attribution is a surprise"
    assert "build_poc_engagement_reattributed" in seg, \
        "CLAUDE.md requires an action like this to emit a webhook event"


def test_attribution_does_not_touch_the_scope_gate():
    """Attribution answers 'whose data is this'. Authorization answers 'may a
    packet be sent'. This change must not have become a second gate.

    Checked against the executable body only — the docstring is allowed to
    EXPLAIN the deny-list it must not consult, and a substring search over the
    whole segment would fail on the explanation rather than on the code."""
    fn = _func("_engagement_for_build_target")
    body = [n for n in fn.body if not (isinstance(n, ast.Expr)
                                       and isinstance(n.value, ast.Constant)
                                       and isinstance(n.value.value, str))]
    code = "\n".join(ast.dump(n) for n in body)
    for forbidden in ("scope_gate", "not_in_scope"):
        assert forbidden not in code, (
            f"{forbidden!r} in the resolver body — attribution must not gate traffic")
    assert not any(isinstance(n, ast.Raise) for n in ast.walk(fn)), \
        "the resolver must never raise — it returns None and the caller falls back"
