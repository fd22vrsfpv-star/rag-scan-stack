"""A scope filter must test every identity an asset carries.

Run on demand:

    pytest tests/test_scope_filter_identities.py -v

WHY THIS EXISTS
---------------
Three pages filtered with `matchesScope(a.hostname || a.ip)` — the FIRST
non-empty value, not all of them. The 'msf' scope names the IP 192.168.1.150,
and the asset is named `metasploitable`, so the host was filtered OUT of its own
scope.

It went unnoticed because the same host also existed as a second, hostname-less
asset row that DID match by IP. Merging those duplicates removed the accidental
cover, and the operator's report was "in assets when we select the scope msf it
doesn't show it correctly / it filters out 192.168.1.150".

This is a source guard: the `||` idiom is the defect, and it is easy to
reintroduce because it reads as a sensible fallback.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
HOOK = "dashboard/frontend/src/hooks/useScopeFilter.ts"
CALLERS = (
    "dashboard/frontend/src/pages/AssetBrowser.tsx",
    "dashboard/frontend/src/pages/FindingsExplorer.tsx",
    "dashboard/frontend/src/pages/ReconExplorer.tsx",
)


@pytest.mark.unit
def test_the_hook_exposes_a_multi_identity_matcher():
    src = open(os.path.join(REPO, HOOK), encoding="utf-8").read()
    assert "matchesAnyScope" in src, "the multi-identity matcher is gone"
    assert "return { matchesScope, matchesAnyScope" in src, \
        "matchesAnyScope is defined but not returned"
    assert "present.some(v => matchesScope(v))" in src, \
        "matchesAnyScope no longer tests EVERY identity"


@pytest.mark.unit
@pytest.mark.parametrize("rel", CALLERS)
def test_no_caller_uses_the_first_non_empty_identity(rel):
    """`matchesScope(a.hostname || a.ip)` silently drops in-scope hosts."""
    src = open(os.path.join(REPO, rel), encoding="utf-8").read()
    # strip comments, or the explanation of the bug reads as the bug
    code = "\n".join(l.split("//", 1)[0] for l in src.splitlines())
    # `matchesScope(x || '')` is a null-guard on ONE identity and is fine —
    # a subdomain row genuinely has only its name. What is wrong is choosing
    # between two real identities, so strip the empty-string literals first.
    stripped = re.sub(r"\|\|\s*(''|\"\")", "", code)
    bad = re.findall(r"matchesScope\([^)]*\|\|[^)]*\)", stripped)
    assert not bad, (
        f"{rel} tests only the first non-empty identity: {bad} — use "
        "matchesAnyScope(hostname, ip, ...) so a host in scope by EITHER "
        "identity is kept")


@pytest.mark.unit
@pytest.mark.parametrize("rel", CALLERS)
def test_every_caller_actually_uses_it(rel):
    src = open(os.path.join(REPO, rel), encoding="utf-8").read()
    assert "matchesAnyScope(" in src, f"{rel} does not use matchesAnyScope"
    assert "matchesAnyScope, isFiltering" in src or "matchesAnyScope," in src, \
        f"{rel} does not destructure matchesAnyScope from the hook"


@pytest.mark.unit
def test_a_placeholder_scope_row_cannot_match_everything():
    """scope_targets carries `__placeholder__` rows whose target is ''.

    An empty target must be dropped, not treated as a wildcard — the 'msf' scope
    has one alongside its real IP.
    """
    src = open(os.path.join(REPO, HOOK), encoding="utf-8").read()
    assert ".filter(Boolean)" in src, \
        "empty scope targets are no longer filtered out; '' would be a wildcard"


@pytest.mark.unit
def test_scope_targets_fall_back_to_the_global_lookup():
    """The scope DROPDOWN is global; the target lookup was engagement-only.

    useScopeNames returns the global scope list when no engagement is selected,
    so the dropdown can offer a scope the selected engagement does not own. The
    engagement-scoped target lookup then returned zero targets, and
    useScopeFilter reads "no targets" as "nothing matches" — so selecting the
    `msf` scope emptied the Assets table rather than showing 192.168.1.150.
    """
    api = open(os.path.join(REPO, "dashboard/frontend/src/api/scope.ts"),
               encoding="utf-8").read()
    fn = api.split("export function useScope(", 1)[1].split("export function", 1)[0]
    assert "scoped?.targets?.length" in fn, (
        "useScope no longer falls back when the engagement-scoped lookup is "
        "empty — a scope from another engagement hides every row")
    assert "/scope?name=" in fn, "the global scope endpoint is gone"

    hook = open(os.path.join(REPO, HOOK), encoding="utf-8").read()
    assert "useScope(scopeName)" in hook, \
        "useScopeFilter no longer uses the falling-back lookup"
    # Comments stripped: the hook explains the bug by NAMING the old hook, and a
    # naive substring check reads that prose as the defect it documents. Fourth
    # time this trap has fired in this repo.
    hook_code = "\n".join(l.split("//", 1)[0] for l in hook.splitlines())
    assert "useEngagementScopeTargets" not in hook_code, (
        "useScopeFilter is back on the engagement-only lookup, which returns "
        "nothing for a scope the selected engagement does not own")
