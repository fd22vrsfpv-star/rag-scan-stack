"""One class vocabulary — and proof the eleven old sets are fully covered.

The defect this closes, measured before the change:

    PRODUCERS: the classifier emits 10 canonical names; the LLM fallback emits
    free text. Its own docstring claimed `path-traversal`, which the checks
    table never returns (it maps traversal to `lfi`).

    CONSUMERS, and how many entries the classifier can never emit — i.e. alias
    handling, inlined, at a different depth each time:
        _CRAFT_CLASS_ALIASES               10 entries, 10 non-canonical
        _FILE_READ_CLASSES                  8 entries,  6 non-canonical
        _GATHER_PATH_IS_THE_FIELD_CLASSES   7 entries,  6 non-canonical
        _WEB_VULN_CLASSES                  15 entries,  5 non-canonical
        _GATHER_FIELD_REQUIRED_CLASSES      9 entries,  2 non-canonical
        _GATHER_OOB_CLASSES                 3 entries,  0 non-canonical

    So in ONE run `path-traversal` passed one gate and failed another.

And the semantic bug the merge caused: `lfi` sat in the path-is-the-field set,
so the gather gate recorded `input_field` as satisfied by the endpoint and
never demanded the parameter for ANY file read — while a classic LFI injects
through `?page=../../etc/passwd`.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest pyyaml && \
      PYTHONPATH=. python -m pytest tests/test_vuln_classes.py -v'
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from etl import vuln_classes as vc  # noqa: E402

YAML_PATH = REPO / "knowledge" / "vuln_classes.yaml"
API = REPO / "app" / "rag-api" / "api.py"
ATTACK_MAP = REPO / "knowledge" / "mitre" / "attack_map.yaml"

RAW = yaml.safe_load(YAML_PATH.read_text(encoding="utf-8"))
CLASSES = RAW["classes"]

OWASP_2021 = {
    "A01:2021 – Broken Access Control",
    "A02:2021 – Cryptographic Failures",
    "A03:2021 – Injection",
    "A04:2021 – Insecure Design",
    "A05:2021 – Security Misconfiguration",
    "A06:2021 – Vulnerable and Outdated Components",
    "A07:2021 – Identification and Authentication Failures",
    "A08:2021 – Software and Data Integrity Failures",
    "A09:2021 – Security Logging and Monitoring Failures",
    "A10:2021 – Server-Side Request Forgery (SSRF)",
}


def _api_const(name):
    tree = ast.parse(API.read_text(encoding="utf-8"))
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == name for t in n.targets):
            try:
                return ast.literal_eval(n.value)
            except Exception:  # noqa: BLE001
                return None
    return None


# ── the table ──────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestTable:
    def test_it_loads(self):
        assert vc.loaded() is True
        assert len(vc.names()) == len(CLASSES)

    def test_names_are_unique(self):
        names = [c["name"] for c in CLASSES]
        assert len(names) == len(set(names))

    def test_no_alias_is_claimed_by_two_classes(self):
        """A colliding alias makes `canonical()` depend on file order."""
        seen = {}
        for c in CLASSES:
            for a in (c.get("aliases") or []):
                key = vc._squash(a)
                assert seen.get(key, c["name"]) == c["name"], (
                    "alias %r claimed by both %s and %s" % (a, seen.get(key), c["name"]))
                seen[key] = c["name"]

    def test_no_alias_is_a_mere_separator_variant(self):
        """`canonical()` squashes case and separators already, so listing
        `sql_injection` beside `sql-injection` adds nothing and reads as a
        collision. Nine such entries were removed when this test was written."""
        for c in CLASSES:
            seen = {vc._squash(c["name"])}
            for a in (c.get("aliases") or []):
                k = vc._squash(a)
                assert k not in seen, (
                    "%s: %r is only a separator/case variant of something it "
                    "already lists" % (c["name"], a))
                seen.add(k)

    def test_no_alias_collides_with_another_classs_name(self):
        names = {vc._squash(c["name"]) for c in CLASSES}
        for c in CLASSES:
            for a in (c.get("aliases") or []):
                k = vc._squash(a)
                assert k not in (names - {vc._squash(c["name"])}), (
                    "%r is an alias of %s AND the name of another class" % (a, c["name"]))

    def test_the_property_vocabularies_are_closed(self):
        pts, pks = set(RAW["injection_points"]), set(RAW["proof_kinds"])
        for c in CLASSES:
            assert set(c.get("injects_via") or []) <= pts, c["name"]
            assert set(c.get("proof") or []) <= pks, c["name"]

    def test_every_class_declares_every_property(self):
        for c in CLASSES:
            for f in ("name", "title", "aliases", "injects_via", "file_read",
                      "needs_oob_sink", "blind_capable", "proof", "wstg",
                      "mitre", "cwes"):
                assert f in c, "%s is missing %s" % (c["name"], f)

    def test_unknown_is_a_real_class_with_conservative_properties(self):
        u = vc.get("unknown")
        assert u is not None, "`unknown` must be a class, not an absence"
        assert u["injects_via"] == [] and u["needs_oob_sink"] is False
        assert vc.path_is_the_field("unknown") is False
        assert vc.needs_input_field("unknown") is False


# ── normalisation ──────────────────────────────────────────────────────────

@pytest.mark.unit
class TestCanonical:
    @pytest.mark.parametrize("spelling,expect", [
        ("path-traversal", "path-traversal"), ("path_traversal", "path-traversal"),
        ("Path Traversal", "path-traversal"), ("DIRECTORY-TRAVERSAL", "path-traversal"),
        ("directory_traversal", "path-traversal"),
        ("lfi", "lfi"), ("local-file-inclusion", "lfi"), ("file-read", "lfi"),
        ("arbitrary-file-read", "lfi"),
        ("sql-injection", "sqli"), ("SQL Injection", "sqli"),
        ("os-command-injection", "cmdi"), ("command_injection", "cmdi"),
        ("deser", "deserialization"),
        ("rfi", "rfi"), ("remote-file-inclusion", "rfi"),
    ])
    def test_every_known_spelling_resolves(self, spelling, expect):
        assert vc.canonical(spelling) == expect

    def test_an_unknown_name_resolves_to_unknown_not_a_crash(self):
        for bad in ("nonsense", "", None, "   ", "sql injectionnn", 42):
            assert vc.canonical(bad) == "unknown", bad

    def test_normalisation_is_not_fuzzy(self):
        """A gate that guesses is not a gate. Only case and separators are
        normalised away — never a letter."""
        assert vc.canonical("sqlj") == "unknown"
        assert vc.canonical("xxxe") == "unknown"

    def test_canonical_is_idempotent(self):
        for n in vc.names():
            assert vc.canonical(vc.canonical(n)) == n


# ── the eleven old sets are fully covered ──────────────────────────────────

@pytest.mark.unit
class TestMigrationCoverage:
    OLD_SETS = ("_FILE_READ_CLASSES", "_WEB_VULN_CLASSES",
                "_GATHER_FIELD_REQUIRED_CLASSES", "_GATHER_PATH_IS_THE_FIELD_CLASSES",
                "_GATHER_OOB_CLASSES")

    def test_every_spelling_the_old_sets_contained_resolves(self):
        """The migration-completeness check: if a spelling some gate used to
        accept now resolves to `unknown`, that gate silently got narrower."""
        unresolved = {}
        for setname in self.OLD_SETS:
            vals = _api_const(setname)
            if vals is None:
                continue        # already removed — fine
            for v in vals:
                if not isinstance(v, str):
                    continue
                if vc.canonical(v) == "unknown":
                    unresolved.setdefault(setname, []).append(v)
        assert not unresolved, (
            "spellings the old sets accepted that the table does not know: %s"
            % unresolved)

    def test_every_alias_target_of_the_old_alias_table_resolves(self):
        aliases = _api_const("_CRAFT_CLASS_ALIASES")
        if aliases is None:
            pytest.skip("_CRAFT_CLASS_ALIASES already removed")
        for spelling, target in aliases.items():
            assert vc.canonical(spelling) != "unknown", spelling
            # The old table collapsed path-traversal into lfi; the new one
            # keeps them apart ON PURPOSE, so the TARGET need not match — but
            # it must still be a class we know.
            assert vc.canonical(target) != "unknown", target

    def test_the_cwe_map_agrees(self):
        """Two tables mapping CWE -> class must not disagree, or the same CVE
        classifies differently depending on which one a path consults."""
        old = _api_const("_CWE_TO_VULN_CLASS")
        if old is None:
            pytest.skip("_CWE_TO_VULN_CLASS already removed")
        # Divergences we MEAN, each with the reason. Anything else is drift.
        intended = {
            # The merge that broke the gather gate: a traversal injects
            # through the path, an LFI through a parameter.
            "CWE-22": ("lfi", "path-traversal"),
            "CWE-23": ("lfi", "path-traversal"),
            "CWE-36": ("lfi", "path-traversal"),
            # "Authorization Bypass Through User-Controlled Key" IS the
            # definition of an IDOR; the old map called it auth-bypass.
            "CWE-639": ("auth-bypass", "idor"),
        }
        disagree = {}
        for cwe, cls in old.items():
            mine = vc.class_for_cwe(cwe)
            was = vc.canonical(cls)
            if mine == "unknown":
                disagree[cwe] = ("absent", cls)
            elif mine != was and intended.get(cwe) != (was, mine):
                disagree[cwe] = (mine, cls)
        assert not disagree, "CWE map disagreement: %s" % disagree

    def test_an_ambiguous_cwe_has_a_declared_primary(self):
        """A CWE under several classes must not be resolved by file order."""
        import collections
        owners = collections.defaultdict(list)
        for c in CLASSES:
            for cw in (c.get("cwes") or []):
                owners[str(cw["id"])].append(c["name"])
        declared = {str(k).upper() for k in (RAW.get("cwe_primary_class") or {})}
        ambiguous = {k for k, v in owners.items() if len(v) > 1}
        assert ambiguous <= declared, (
            "CWEs claimed by several classes with no declared primary: %s"
            % sorted(ambiguous - declared))
        for cid, cls in (RAW.get("cwe_primary_class") or {}).items():
            assert vc.class_for_cwe(cid) == cls, cid


# ── the semantic bug ───────────────────────────────────────────────────────

@pytest.mark.unit
class TestInjectionSemantics:
    def test_lfi_injects_through_a_parameter_not_the_path(self):
        """`?page=../../etc/passwd`. Listing lfi as path-injection is what
        stopped the gather gate demanding a parameter for every file read."""
        assert vc.path_is_the_field("lfi") is False
        assert vc.needs_input_field("lfi") is True
        assert "parameter" in vc.injection_points("lfi")

    def test_a_path_traversal_has_no_parameter_to_find(self):
        assert vc.path_is_the_field("path-traversal") is True
        assert vc.needs_input_field("path-traversal") is False

    def test_rfi_injects_through_a_parameter_and_needs_a_sink(self):
        """It makes the server FETCH, so it is SSRF-shaped. Aliasing it to lfi
        lost that and the gate never required an out-of-band sink."""
        assert vc.needs_input_field("rfi") is True
        assert vc.needs_oob_sink("rfi") is True

    def test_path_is_the_field_means_path_is_the_ONLY_point(self):
        """auth-bypass and idor CAN inject via the path; that does not mean
        they have no parameter. `in` would wrongly exempt both."""
        for cls in ("auth-bypass", "idor"):
            assert "path" in vc.injection_points(cls), cls
            assert vc.path_is_the_field(cls) is False, cls
            assert vc.needs_input_field(cls) is True, cls

    def test_file_read_is_orthogonal_to_where_it_injects(self):
        """XXE reads files through a request BODY. One flat set could never
        answer both questions, which is why the old ones drifted."""
        assert vc.is_file_read("xxe") is True
        assert vc.injection_points("xxe") == ["body"]
        assert vc.path_is_the_field("xxe") is False

    def test_the_file_read_projection_matches_the_old_set_after_normalising(self):
        old = _api_const("_FILE_READ_CLASSES")
        if old is None:
            pytest.skip("_FILE_READ_CLASSES already removed")
        assert {vc.canonical(x) for x in old} == vc.classes_where(file_read=True)

    def test_the_oob_projection_covers_the_old_set(self):
        old = _api_const("_GATHER_OOB_CLASSES")
        if old is None:
            pytest.skip("_GATHER_OOB_CLASSES already removed")
        assert {vc.canonical(x) for x in old} <= vc.classes_where(needs_oob_sink=True)


# ── reference vocabularies ─────────────────────────────────────────────────

@pytest.mark.unit
class TestReferences:
    def test_every_owasp_value_is_a_real_2021_category(self):
        for c in CLASSES:
            o = c.get("owasp")
            if o is None:
                continue
            assert o in OWASP_2021, "%s: %r is not an OWASP 2021 category" % (c["name"], o)

    def test_every_cwe_carries_an_id_and_a_name(self):
        import re
        for c in CLASSES:
            for cw in (c.get("cwes") or []):
                assert re.fullmatch(r"CWE-\d+", str(cw.get("id"))), (c["name"], cw)
                assert len(str(cw.get("name") or "")) > 10, (
                    "%s: CWE %s has no official name" % (c["name"], cw.get("id")))

    def test_every_wstg_id_is_well_formed(self):
        import re
        for c in CLASSES:
            for w in (c.get("wstg") or []):
                assert re.fullmatch(r"WSTG-[A-Z]{4}-\d{2}", str(w)), (c["name"], w)

    def test_every_mitre_technique_exists_in_the_attack_map(self):
        """Referencing a technique the ATT&CK map does not define gives a
        report an id nothing can resolve."""
        amap = yaml.safe_load(ATTACK_MAP.read_text(encoding="utf-8"))
        known = set((amap.get("techniques") or {}).keys())
        assert known, "attack_map.yaml has no techniques"
        for c in CLASSES:
            for t in (c.get("mitre") or []):
                assert t in known, (
                    "%s references %s, absent from knowledge/mitre/attack_map.yaml"
                    % (c["name"], t))

    def test_references_returns_every_vocabulary_at_once(self):
        r = vc.references("path_traversal")
        assert r["class"] == "path-traversal"
        assert r["owasp"] and r["cwes"] and r["wstg"] and r["mitre"]
        assert any(x["id"] == "CWE-22" for x in r["cwes"])

    def test_a_cwe_resolves_to_exactly_one_class(self):
        """CWE-98 appears under both lfi and rfi by design; the lookup must be
        deterministic rather than order-dependent noise."""
        assert vc.class_for_cwe("CWE-98") in ("lfi", "rfi")
        assert vc.class_for_cwe("CWE-98") == vc.class_for_cwe("cwe-98")
        assert vc.class_for_cwe("CWE-9999") == "unknown"


# ── fail-soft ──────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestFailSoft:
    def test_an_unreadable_table_is_distinguishable_from_an_empty_one(self):
        """`loaded() is False` must not read as 'this vocabulary has no
        classes' — the repo's most expensive recurring bug."""
        t = vc.load(path="/nonexistent/vuln_classes.yaml")
        assert t["loaded"] is False
        assert t["by_name"] == {}

    def test_the_table_is_cached_but_reloadable(self):
        a = vc.load()
        assert vc.load() is a
        assert vc.load(force=True)["loaded"] is True


# ── RAG ────────────────────────────────────────────────────────────────────

@pytest.mark.unit
def test_the_renderer_is_registered_and_emits_a_document_per_class():
    """CLAUDE.md: a knowledge file ships its loader in the same change."""
    src = (REPO / "etl" / "load_knowledge_documents.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef)
               and n.name == "_render_vuln_classes"), None)
    assert fn is not None, "no renderer for vuln_classes.yaml"
    registry = next(n.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
                    and any(getattr(t, "id", "") == "RENDERERS" for t in n.targets))
    keys = {k.value for k in registry.keys if isinstance(k, ast.Constant)}
    assert "vuln_classes" in keys
    ns = {"Dict": dict, "Any": object, "List": list, "Doc": tuple}
    helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_s")
    exec(compile(ast.Module([helper, fn], []), "<r>", "exec"), ns)
    docs = ns["_render_vuln_classes"](RAW)
    assert len(docs) == len(CLASSES)
    joined = " ".join(b for _, b in docs)
    assert "CWE-22" in joined and "OWASP" in joined
