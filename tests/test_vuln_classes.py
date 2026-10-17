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
        """The old map was single-valued; the new one is one-to-many. Agreement
        now means the old answer is still AMONG the candidates — anything else
        is a class a path used to reach and no longer can."""
        old = _api_const("_CWE_TO_VULN_CLASS")
        if old is None:
            pytest.skip("_CWE_TO_VULN_CLASS already removed")
        # Divergences we MEAN, each with the reason. Anything else is drift.
        intended = {
            # The merge that broke the gather gate: a traversal injects through
            # the path, an LFI through a parameter.
            "CWE-22": "lfi", "CWE-23": "lfi", "CWE-36": "lfi",
            # "Authorization Bypass Through User-Controlled Key" IS an IDOR;
            # the old map called it auth-bypass.
            "CWE-639": "auth-bypass",
        }
        lost = {}
        for cwe, cls in old.items():
            cands = vc.classes_for_cwe(cwe)
            if not cands:
                lost[cwe] = ("absent", cls)
            elif vc.canonical(cls) not in cands and intended.get(cwe) != vc.canonical(cls):
                lost[cwe] = (cands, cls)
        assert not lost, "CWE mappings the table lost: %s" % lost


    def test_a_cwe_may_point_at_several_classes(self):
        """A CWE is a narrowing SIGNAL, not an answer. CWE-78 is OS command
        injection AND remote code execution — the second is the consequence of
        the first. An earlier draft forced one "primary" per CWE, which made
        the lookup lie about the other."""
        assert vc.classes_for_cwe("CWE-78") == ["cmdi", "rce"]
        assert vc.classes_for_cwe("CWE-98") == ["lfi", "rfi"]
        assert vc.classes_for_cwe("CWE-9999") == []

    def test_the_candidate_list_is_sorted_not_file_ordered(self):
        """A lookup whose answer changes when someone reorders the YAML is not
        a lookup."""
        for cwe in ("CWE-78", "CWE-98", "CWE-502"):
            got = vc.classes_for_cwe(cwe)
            assert got == sorted(got), cwe

    def test_a_cwe_alone_answers_only_when_it_is_unambiguous(self):
        """`unknown` for an ambiguous CWE is the truthful answer; returning the
        alphabetically-first class would be fabricated certainty."""
        assert vc.class_for_cwe("CWE-22") == "path-traversal"
        assert vc.class_for_cwe("CWE-918") == "ssrf"
        assert vc.class_for_cwe("CWE-78") == "unknown"
        assert vc.class_for_cwe("CWE-98") == "unknown"


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
        """The payload is the path. The item stays REQUIRED and the ENDPOINT
        satisfies it — two different mechanisms. Dropping the requirement
        would let a traversal with no endpoint through the gate with nothing
        to attack."""
        assert vc.path_is_the_field("path-traversal") is True
        assert vc.needs_input_field("path-traversal") is True

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

    def test_requiring_a_parameter_is_declared_not_inferred(self):
        """"Can inject through a parameter" and "requires one" are different
        questions. auth-bypass can use a parameter and needs none — requesting
        a protected path directly is the whole exploit. Inferring it from
        injects_via made the gate demand a parameter for auth-bypass, which
        the set this replaced deliberately excluded."""
        assert "parameter" in vc.injection_points("auth-bypass")
        assert vc.needs_input_field("auth-bypass") is False
        assert vc.needs_input_field("idor") is True

    def test_the_required_set_matches_the_set_it_replaced(self):
        """Widening it blocks runs that used to proceed, so it is a separate
        deliberate decision — not a side effect of modelling. Preserved
        verbatim, plus rfi, which was split out of lfi."""
        # Preserved verbatim from the removed _GATHER_FIELD_REQUIRED_CLASSES.
        preserved = {"sqli", "ssrf", "ssti", "lfi", "cmdi", "xss", "idor",
                     "path-traversal", "xxe"}
        # Added deliberately, each an injection class the table gained after
        # the migration. `rfi` was split out of `lfi`, which was in the set;
        # the rest are the injection types the WSTG lane already tested and
        # the class table did not know. Every one injects through a parameter,
        # so demanding one is correct rather than a widening by accident.
        added = {"rfi", "el-injection", "jndi-injection", "crlf-injection",
                 "ssi-injection", "xpath-injection", "smtp-injection",
                 "format-string", "hpp"}
        expected = preserved | added
        got = {n for n in vc.names() if vc.needs_input_field(n)}
        assert got == expected, "required-parameter set drifted: %s" % (
            sorted(got ^ expected))

    def test_no_misconfiguration_demands_a_parameter(self):
        """A finding has no payload, so it must never reach a gate that asks
        for one."""
        for n in vc.names():
            if vc.is_exploitable(n):
                continue
            assert vc.needs_input_field(n) is False, n
            assert vc.path_is_the_field(n) is False, n
            assert vc.needs_oob_sink(n) is False, n

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

    def test_a_shared_cwe_keeps_both_owners(self):
        """CWE-98 enables local AND remote inclusion. Both must stay reachable
        from it, and the lookup must be case-insensitive."""
        assert set(vc.classes_for_cwe("CWE-98")) == {"lfi", "rfi"}
        assert vc.classes_for_cwe("cwe-98") == vc.classes_for_cwe("CWE-98")


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


# ── kind: a misconfiguration is not an exploit mechanism ───────────────────

@pytest.mark.unit
class TestKind:
    def test_every_class_declares_a_known_kind(self):
        for c in CLASSES:
            assert c.get("kind") in vc.KINDS, (c["name"], c.get("kind"))

    def test_only_vulnerabilities_are_exploitable(self):
        """A misconfiguration has no injection point, no payload and nothing
        to assert. It must never enter the build-PoC gates."""
        for c in CLASSES:
            assert vc.is_exploitable(c["name"]) is (c["kind"] == vc.VULNERABILITY)

    def test_a_non_vulnerability_declares_no_mechanism(self):
        """If it had an injection point and a proof it would be a
        vulnerability — the fields would be lying about the kind."""
        for c in CLASSES:
            if c["kind"] == vc.VULNERABILITY:
                continue
            assert not c["injects_via"], c["name"]
            assert not c["proof"], c["name"]
            assert c["input_field_required"] is False, c["name"]
            assert c["needs_oob_sink"] is False, c["name"]

    def test_an_unknown_name_is_not_an_exploitable_class(self):
        assert vc.is_exploitable("not-a-real-class") is False
        assert vc.is_exploitable("unknown") is False

    def test_leads_to_names_a_real_exploitable_class(self):
        """The chain is the point: a finding earns its place by saying which
        MECHANISM it enables, not by pretending to be one."""
        known = set(vc.names())
        for c in CLASSES:
            for t in (c.get("leads_to") or []):
                assert t in known, (c["name"], t)
                assert vc.is_exploitable(t), (
                    "%s leads_to %s, which is not an exploit mechanism"
                    % (c["name"], t))

    def test_the_chains_that_matter_are_recorded(self):
        """WebDAV PUT is not exploitable AS a misconfiguration — it is
        exploitable because it hands you an upload. Both are IMPACTFUL tests
        in knowledge/wstg_map.yaml, so the chain is already real elsewhere."""
        assert vc.leads_to("webdav-put") == ["upload"]
        assert vc.leads_to("default-credentials") == ["auth-bypass"]

    def test_a_vulnerability_does_not_need_leads_to(self):
        for c in CLASSES:
            if c["kind"] == vc.VULNERABILITY:
                assert not c.get("leads_to"), (
                    "%s is a mechanism; it does not need a chain" % c["name"])

    def test_both_lanes_share_one_vocabulary(self):
        """The scanner's spellings resolve too — that is what stops the two
        lanes having separate names for the same finding."""
        for spelling, expect in (("webdav enabled", "webdav-put"),
                                 ("put method enabled", "webdav-put"),
                                 ("default password", "default-credentials"),
                                 ("directory browsing", "directory-listing"),
                                 ("stack trace", "verbose-errors"),
                                 ("git exposure", "exposed-files")):
            assert vc.canonical(spelling) == expect, spelling

    def test_exploitable_classes_is_the_gate_filter(self):
        got = vc.exploitable_classes()
        assert got == {c["name"] for c in CLASSES if c["kind"] == vc.VULNERABILITY}
        assert "webdav-put" not in got and "sqli" in got


# ── the injection types the scanning lane already knew ─────────────────────

@pytest.mark.unit
class TestInjectionCoverage:
    def test_the_wstg_injection_types_resolve(self):
        """These were tested by knowledge/wstg_map.yaml and unknown to the
        class table, so the same finding had two names across two lanes."""
        for spelling, expect in (("xpath injection", "xpath-injection"),
                                 ("crlf injection", "crlf-injection"),
                                 ("http response splitting", "crlf-injection"),
                                 ("host header injection", "host-header-injection"),
                                 ("ssi injection", "ssi-injection"),
                                 ("smtp injection", "smtp-injection"),
                                 ("format string", "format-string"),
                                 ("http parameter pollution", "hpp"),
                                 ("log4shell", "jndi-injection"),
                                 ("ognl injection", "el-injection")):
            assert vc.canonical(spelling) == expect, spelling

    def test_jndi_is_proven_only_out_of_band(self):
        """Log4Shell returns a plain 200; the response proves nothing."""
        assert vc.proof_kinds("jndi-injection") == ["oob"]
        assert vc.needs_oob_sink("jndi-injection") is True

    def test_crlf_injects_through_a_parameter_but_proves_in_a_header(self):
        assert "parameter" in vc.injection_points("crlf-injection")
        assert vc.needs_oob_sink("crlf-injection") is False

    def test_host_header_injection_injects_through_a_header(self):
        assert vc.injection_points("host-header-injection") == ["header"]
        assert vc.needs_input_field("host-header-injection") is False

    def test_el_injection_is_not_an_alias_of_ssti(self):
        """Same gate profile, different payload syntax: `%{...}` and `${...}`
        rather than `{{...}}`. Folding it into ssti would hand the crafter the
        wrong delimiters."""
        assert vc.canonical("ognl") == "el-injection"
        assert vc.canonical("ssti") == "ssti"


# ── the combination: name is primary, CWE narrows ──────────────────────────

@pytest.mark.unit
class TestResolve:
    def test_a_named_class_beats_the_cwe(self):
        """An advisory that says "local file inclusion" has told us the class.
        CWE-22 points at path-traversal; the name still wins."""
        r = vc.resolve("local file inclusion via the page parameter",
                       ["CWE-98", "CWE-22"])
        assert r["class"] == "lfi"
        assert r["basis"] == "name"
        assert r["ambiguous"] is False

    def test_a_cwe_answers_when_the_text_names_nothing(self):
        r = vc.resolve("the endpoint is vulnerable", ["CWE-918"])
        assert r["class"] == "ssrf" and r["basis"] == "cwe"

    def test_an_ambiguous_cwe_with_no_name_reports_the_ambiguity(self):
        """Not a guess. The caller can ask for more evidence instead of acting
        on the alphabetically-first candidate."""
        r = vc.resolve("the endpoint is vulnerable", ["CWE-78"])
        assert r["class"] == "unknown"
        assert r["ambiguous"] is True
        assert r["candidates"] == ["cmdi", "rce"]

    def test_the_text_breaks_a_cwe_tie(self):
        r = vc.resolve("OS command injection in the ping handler", ["CWE-78"])
        assert r["class"] == "cmdi"
        assert r["ambiguous"] is False

    def test_the_same_cwe_resolves_differently_by_name(self):
        """CWE-98 enables both; only the text says which."""
        assert vc.resolve("arbitrary file read", ["CWE-98"])["class"] == "lfi"
        assert vc.resolve("remote file inclusion lets the server fetch",
                          ["CWE-98"])["class"] == "rfi"

    def test_nothing_to_go_on_is_unknown_and_says_so(self):
        r = vc.resolve("", [])
        assert r["class"] == "unknown" and r["basis"] == "none"
        assert r["ambiguous"] is False
        r2 = vc.resolve("nothing useful here", [])
        assert r2["class"] == "unknown" and r2["basis"] == "none"

    def test_a_short_class_name_does_not_match_mid_word(self):
        """`rce` is a substring of "resou(rce)key". A substring scan over the
        separator-squashed text classified a real path traversal as remote
        code execution; matching is boundary-anchored now."""
        r = vc.resolve("the resource key is validated", [])
        assert r["class"] == "unknown", r
        r2 = vc.resolve("script.execute allows path traversal via the resource key",
                        ["CWE-22"])
        assert r2["class"] == "path-traversal"
        assert r2["candidates"] == ["path-traversal"], (
            "`rce` leaked in from the word 'resource': %s" % r2["candidates"])

    def test_separators_in_the_text_do_not_matter(self):
        for spelling in ("arbitrary file read", "arbitrary-file-read",
                         "arbitrary_file_read", "Arbitrary File Read"):
            assert vc.resolve(spelling, [])["class"] == "lfi", spelling

    def test_the_longest_alias_wins(self):
        """`remote file inclusion` contains `file` tokens a shorter alias could
        claim; the longer, more specific spelling must win."""
        assert vc.resolve("remote file inclusion", [])["class"] == "rfi"

    def test_resolve_never_raises_on_odd_input(self):
        for t, c in ((None, None), (42, ["CWE-78"]), ("x", ["not-a-cwe"]),
                     ("x", [None])):
            r = vc.resolve(t, c)
            assert r["class"] in vc.names() or r["class"] == "unknown"
