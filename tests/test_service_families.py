"""One training doc must serve every name nmap gives the same service.

Run on demand:

    pytest tests/test_service_families.py -v

WHY THIS EXISTS
---------------
Retrieval scoped on `lower(service) = lower(%s)`, so a document filed under
`http` was invisible to an `https` query — despite being, for testing purposes,
the same service over a different transport. The workaround was ingesting the
same document once per name, which duplicates chunks, doubles embedding cost and
leaves copies to keep in step.

Two mechanisms replaced that, and both are pinned here:

  * `_service_scope()` widens the SQL scope to the whole family, so one doc
    answers every alias.
  * `service_canonical()` is added to the retrieval QUERY, because UNSCOPED
    prose documents are matched on wording alone. Measured: the SMB playbook
    scored 0.648 for a query saying "smb" and 0.506 for one saying
    "microsoft-ds" — the latter under the 0.55 floor, so the same service got
    guidance or not depending only on how nmap fingerprinted it.

Families must stay TIGHT: a scoped hit bypasses the similarity floor, so a wide
family would paste one service's guidance into an unrelated service's prompt.

Pure functions read out of the source with `ast` — no DB, no embedder — so this
runs on a bare checkout.

Sabotage proofs performed:
  * dropped "https" from the http family  -> test_web_family_covers_tls RED
  * made _service_scope return [service]  -> test_aliases_resolve_to_the_family RED
  * merged the http and smb families      -> test_families_do_not_overlap RED
"""
import ast
import os
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SRC = REPO / "scan_recommender" / "exploits_rag.py"


@pytest.fixture(scope="module")
def mod():
    if not SRC.exists():
        pytest.skip("scan_recommender/exploits_rag.py not present")
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    ns: dict = {}
    want_fn = {"_service_scope", "service_canonical"}
    want_const = {"_SERVICE_FAMILIES"}
    got = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in want_fn:
            exec(compile(ast.Module([node], []), "<f>", "exec"), ns)
            got.add(node.name)
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in want_const):
            exec(compile(ast.Module([node], []), "<c>", "exec"), ns)
            got.add(node.targets[0].id)
    missing = (want_fn | want_const) - got
    assert not missing, (
        f"could not extract {sorted(missing)} — service-family scoping was "
        "renamed or removed and this guard would pass vacuously")
    return ns


def test_aliases_resolve_to_the_family(mod):
    """Every alias must return the whole family, not just itself."""
    scope = mod["_service_scope"]
    for alias in ("https", "http-proxy", "ssl/http"):
        fam = scope(alias)
        assert "http" in fam and "https" in fam, (
            f"{alias!r} resolved to {fam} — a doc filed under another name in "
            "its family will not be found")


def test_web_family_covers_tls(mod):
    """http and https must be the same family. This is the motivating case:
    this deployment has 887 https ports against 527 http ones, so a doc that
    only answered `http` would miss the majority of its web surface."""
    scope = mod["_service_scope"]
    assert set(scope("http")) == set(scope("https"))


def test_smb_aliases_reach_the_same_docs(mod):
    scope = mod["_service_scope"]
    assert set(scope("microsoft-ds")) == set(scope("smb")) == set(scope("netbios-ssn"))


def test_unknown_service_is_unchanged(mod):
    """A service in no family must behave exactly as before — this widening
    must not change retrieval for anything it does not explicitly cover."""
    assert mod["_service_scope"]("finger") == ["finger"]
    assert mod["_service_scope"]("") == []


def test_canonical_name_is_stable_across_aliases(mod):
    canon = mod["service_canonical"]
    assert canon("https") == canon("http") == "http"
    assert canon("microsoft-ds") == canon("smb") == "smb"
    assert canon("mariadb") == "mysql"
    assert canon("finger") == "finger"


def test_families_do_not_overlap(mod):
    """A service in two families would make scope() order-dependent, so the
    same query could return different documents run to run."""
    fams = mod["_SERVICE_FAMILIES"]
    seen: dict = {}
    for canon, members in fams.items():
        for m in members:
            assert m not in seen, (
                f"{m!r} is in both {seen[m]!r} and {canon!r} families")
            seen[m] = canon


def test_every_family_contains_its_canonical_name(mod):
    for canon, members in mod["_SERVICE_FAMILIES"].items():
        assert canon in members, (
            f"canonical {canon!r} is not a member of its own family {sorted(members)} — "
            "service_canonical would name something the scope never matches")


def test_families_stay_tight(mod):
    """A scoped hit BYPASSES the similarity floor, so an over-broad family
    pastes one service's guidance into an unrelated service's prompt."""
    for canon, members in mod["_SERVICE_FAMILIES"].items():
        assert len(members) <= 10, (
            f"the {canon!r} family has {len(members)} members; that is wide "
            "enough to leak guidance between unrelated services")


def test_the_query_includes_the_canonical_name():
    """Widening the SQL scope is only half of it — unscoped prose docs are
    matched on wording, so the canonical name must reach the query text too."""
    rec = REPO / "scan_recommender" / "scan_recommender.py"
    if not rec.exists():
        pytest.skip("scan_recommender.py not present")
    src = rec.read_text(encoding="utf-8")
    i = src.index("def _get_training_context(")
    body = src[i:src.index("\ndef ", i + 10)]
    assert "service_canonical" in body, (
        "_get_training_context no longer adds the canonical service name to the "
        "query — 'microsoft-ds' will score below the floor where 'smb' passes")
