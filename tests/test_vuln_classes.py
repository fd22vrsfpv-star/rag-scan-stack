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
    # A doc is (title, body) or (title, body, metadata) — the third slot
    # carries the structured retrieval keys (vuln_class, cwes, owasp) that
    # make a knowledge row filterable instead of reachable only by similarity.
    joined = " ".join(d[1] for d in docs)
    assert "CWE-22" in joined and "OWASP" in joined
    metas = [d[2] for d in docs if len(d) > 2]
    assert len(metas) == len(docs), (
        "every class document must carry its structured keys; a doc without "
        "them is reachable only by similarity")
    assert all(m.get("vuln_class") for m in metas), (
        "vuln_class is the key a classified CVE already holds")
    assert any(m.get("cwes") for m in metas), (
        "at least some classes must carry their CWE ids — that is what lets "
        "a CWE-89 CVE find the sqli document deterministically")


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
        # `cwe+name`, not `name`: the CWEs WERE consulted — they bound the
        # candidate set and the advisory's own words picked `lfi` from it.
        # The old label claimed the taxonomy was ignored, which made a
        # name-only match indistinguishable from a name that the CWEs
        # actually supported.
        assert r["basis"] == "cwe+name"
        assert r["ambiguous"] is False

    def test_the_cwe_bounds_what_the_prose_may_name(self):
        """A word in prose may not outrank a curated identifier.

        A CWE-918 (SSRF) advisory whose text merely mentions an SQL error was
        classified `sqli`, so the crafter got the wrong payload family for
        every iteration. The name may now only pick from classes the CWEs
        support — and the rejected name is reported, because a silent
        disagreement cannot be reviewed.
        """
        r = vc.resolve("a sql injection error was observed in the response",
                       ["CWE-918"])
        assert r["class"] == "ssrf", r
        assert r["basis"] == "cwe"
        assert r.get("name_disagreed") == "sqli", r

    def test_a_behaviourally_identical_name_still_wins(self):
        """NVD files an LFI under CWE-22 routinely.

        `lfi` and `path-traversal` are the same shape — both file_read, both
        input_field_required, neither needs an OOB sink — so the advisory's
        own word is better information for crafting and changes no gate.
        Compared on the properties the gates branch on, not a hand-kept list
        of related pairs, which would drift as classes are added.
        """
        r = vc.resolve("local file inclusion via the page parameter",
                       ["CWE-22"])          # CWE-22 -> path-traversal only
        assert r["class"] == "lfi", r
        assert "name_disagreed" not in r

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


# ---------------------------------------------------------------------------
# Regression guard: no NEW private taxonomy set
# ---------------------------------------------------------------------------
# The eight sets this module replaced are gone, but nothing stopped a ninth
# appearing — and one had: `_VULN_CLASSES` in the LLM-fallback validator, which
# rejected "Path Traversal" two lines above the `_vc_canonical` call that
# exists to resolve exactly that. A migration with no guard is a migration that
# gets re-done.
#
# Declared exceptions are keyed by (file, variable) and carry a reason. The
# list RATCHETS: a stale entry fails, so it cannot outlive what it excuses.
TAXONOMY_SET_DEBT = {
    # empty: _CRAFT_CLASS_GUIDANCE and the WAF `shapes` moved to knowledge/
    # on 2026-10-17. A new entry needs a reason and is a regression.
}

_SCAN_ROOTS = ("app/rag-api/api.py", "etl", "autogen_agents")


def _candidate_sources():
    out = []
    for rel in _SCAN_ROOTS:
        p = REPO / rel
        if p.is_file():
            out.append(p)
        elif p.is_dir():
            out.extend(sorted(p.glob("*.py")))
    # the table's own reader legitimately names every class
    return [p for p in out if p.name != "vuln_classes.py"]


def _literal_sides(node):
    """Describe a literal collection as (side, strings, total, all_strings).

    `total` is the element count, so a collection only PARTLY made of string
    literals is never judged. A dict yields both sides: which one carries the
    class names is what separates an alias table from a translation table.
    """
    v = node
    if isinstance(v, (ast.Set, ast.List, ast.Tuple)):
        strs = [e.value for e in v.elts
                if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        return [("members", strs, len(v.elts), len(strs) == len(v.elts))]
    if isinstance(v, ast.Dict):
        keys = [k.value for k in v.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        vals = [x.value for x in v.values
                if isinstance(x, ast.Constant) and isinstance(x.value, str)]
        n = len(v.keys)
        return [("keys", keys, n, len(keys) == n),
                ("values", vals, n, len(vals) == n)]
    if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) \
            and v.func.id in ("set", "frozenset"):
        got, total = [], 0
        for a in v.args:
            if isinstance(a, (ast.Set, ast.List, ast.Tuple)):
                got += [e.value for e in a.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                total += len(a.elts)
        return [("members", got, total, total > 0 and len(got) == total)]
    return []


def _all_classes(strings, total, all_strings, minimum=3):
    """True when this side is a vocabulary: every element a class name.

    `is_known(s)` is the membership test, applied ONCE to the RAW string.
    It accepts the literal `unknown` sentinel — which is a real class, and
    appears as a key in the per-class guidance table — while rejecting
    arbitrary strings.

    Do NOT compose it as `is_known(canonical(s))`: that passes EVERYTHING,
    because an unrecognised string canonicalises to `unknown`, which is then
    reported as known. That composition made the first draft of this guard
    return 60KB of false positives including '/etc/passwd' and 'nmap'.
    """
    if not all_strings or total < minimum or len(strings) != total:
        return False
    return all(vc.is_known(s) for s in strings)


def _private_class_sets():
    """Every literal collection that hard-codes the class vocabulary.

    Three shapes are vocabularies, and one shape is not:

      * a sequence of class names              -> a private class set
      * a mapping that is a vocabulary on either side, UNLESS its keys are
        all classes, every key is ALREADY CANONICAL, and its values are
        TOKENS of another vocabulary rather than prose.

    The key side is what separates the two, and the values side cannot: the
    `exploit_type` enum spells the same concepts differently
    (`command_injection`, `file_upload`, `auth_bypass`), so those values
    canonicalise to real classes just as an alias table's do.

    An alias table exists PRECISELY to hold non-canonical spellings
    (`{"sql-injection": "sqli"}`), and a CWE map is keyed by something that
    is not a class at all — both are drift, and `canonical()` /
    `classes_for_cwe()` already answer them. A table keyed by canonical names
    is a translation OUT to another vocabulary, which is legitimate, and
    keeping its keys canonical is exactly what lets `canonical()` do the
    folding in front of it.
    """
    found = []
    for path in _candidate_sources():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        rel = str(path.relative_to(REPO))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [t.id for t in targets if isinstance(t, ast.Name)]
            if not names:
                continue
            sides = {lbl: (strs, tot, allstr)
                     for lbl, strs, tot, allstr in _literal_sides(node.value)}
            if not sides:
                continue
            hit = None
            if "members" in sides:
                if _all_classes(*sides["members"]):
                    hit = sides["members"][0]
            else:
                keys_vocab = _all_classes(*sides["keys"])
                vals, _vtot, vals_all_str = sides["values"]
                # A translation table maps to another vocabulary, so its
                # values are TOKENS. Prose values mean this is class-keyed
                # DATA (guidance, payload shapes) and belongs in a YAML the
                # operator can edit without a deploy.
                token_values = vals_all_str and all(
                    v and len(v) <= 40 and not any(c.isspace() for c in v)
                    for v in vals)
                if keys_vocab and token_values and all(
                        vc.canonical(k) == k for k in sides["keys"][0]):
                    continue                      # translation table: legal
                if _all_classes(*sides["values"]):
                    hit = sides["values"][0]      # alias folding
                elif keys_vocab:
                    hit = sides["keys"][0]        # non-canonical class keys
            if hit is not None:
                found.append((rel, names[0], node.lineno, hit))
    return found


class TestNoPrivateTaxonomySet:
    def test_no_module_hardcodes_a_class_vocabulary(self):
        offenders = [f for f in _private_class_sets()
                     if (f[0], f[1]) not in TAXONOMY_SET_DEBT]
        assert not offenders, (
            "hard-coded vuln-class vocabulary — read knowledge/vuln_classes.yaml "
            "through etl/vuln_classes.py instead:\n" + "\n".join(
                f"  {rel}:{line} {name} = {members}"
                for rel, name, line, members in offenders))

    def test_every_declared_exception_still_exists(self):
        """A debt entry that no longer matches anything must be deleted."""
        live = {(rel, name) for rel, name, _, _ in _private_class_sets()}
        stale = sorted(k for k in TAXONOMY_SET_DEBT if k not in live)
        assert not stale, (
            f"TAXONOMY_SET_DEBT entries no longer present — delete them: {stale}")

    def test_the_guard_can_actually_fail(self):
        """Sabotage-proof: the detector must flag each shape it claims to.

        Without this, a change to `canonical` that made everything `unknown`
        would turn the guard into a no-op that still reports green.
        """
        def sides_of(src):
            return {lbl: (strs, tot, allstr) for lbl, strs, tot, allstr
                    in _literal_sides(ast.parse(src).body[0].value)}

        # a private class sequence
        seq = sides_of('X = ("sqli", "xss", "path traversal")')
        assert _all_classes(*seq["members"])

        # the sentinel class is a real member, not an accident
        assert vc.is_known("unknown")
        # ...and the composition trap must stay rejected
        assert not vc.is_known("/etc/passwd")
        assert vc.is_known(vc.canonical("/etc/passwd")), (
            "is_known(canonical(x)) passes everything — never compose them")

        # private alias folding: values are class names
        alias = sides_of('X = {"CWE-78": "cmdi", "CWE-89": "sqli", "CWE-79": "xss"}')
        assert _all_classes(*alias["values"])

        # non-canonical class keys: a vocabulary spelled by hand
        data = sides_of('X = {"SQLi": [1], "Path Traversal": [2], "RCE": [3]}')
        assert _all_classes(*data["keys"])
        assert not all(vc.canonical(k) == k for k in data["keys"][0])

    def test_a_translation_table_is_not_flagged(self):
        """class -> another vocabulary must stay legal, or the guard would
        push callers back towards private alias lists to appease it."""
        sides = {lbl: (strs, tot, allstr) for lbl, strs, tot, allstr
                 in _literal_sides(ast.parse(
                     'X = {"cmdi": "command_injection", "upload": "file_upload",'
                     ' "auth-bypass": "auth_bypass"}').body[0].value)}
        assert _all_classes(*sides["keys"])               # keys ARE classes
        assert all(vc.canonical(k) == k for k in sides["keys"][0])
        # values are single tokens, not prose — that is what makes it a
        # translation rather than class-keyed data
        assert all(" " not in v for v in sides["values"][0])
        # and the values canonicalise too — which is why the VALUE side can
        # never be the discriminator between this and an alias table
        assert _all_classes(*sides["values"])


class TestIssueTypeMapIsCanonical:
    """The Burp/ZAP issue_type -> exploit_type map is two vocabularies.

    Its keys must be canonical class names (so `canonical()` does the alias
    folding) and its values must be members of the pending_exploits CHECK
    enum (so every mapping is actually writable).
    """

    @staticmethod
    def _type_map():
        tree = ast.parse((REPO / "app/rag-api/api.py").read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and any(
                    getattr(t, "id", "") == "type_map" for t in n.targets):
                return {k.value: v.value for k, v in zip(n.value.keys, n.value.values)}
        return None

    @staticmethod
    def _enum():
        import re
        sql = (REPO / "db_init/ensure_all_tables.sql").read_text(encoding="utf-8")
        m = re.search(
            r"pending_exploits_exploit_type_check\s*\n?\s*CHECK \(exploit_type IN \((.*?)\)\)",
            sql, re.S)
        return set(re.findall(r"'([a-z_]+)'", m.group(1))) if m else set()

    def test_the_map_is_present(self):
        assert self._type_map(), "type_map not found — did the handler move?"

    def test_every_key_is_already_canonical(self):
        tm = self._type_map()
        bad = {k: vc.canonical(k) for k in tm if vc.canonical(k) != k}
        assert not bad, (
            "keys must be canonical class names so canonical() folds the "
            f"aliases: {bad}")

    def test_every_value_is_a_writable_exploit_type(self):
        enum = self._enum()
        assert enum, "could not read the exploit_type CHECK constraint"
        bad = sorted(set(self._type_map().values()) - enum)
        assert not bad, (
            f"exploit_type values the CHECK constraint rejects: {bad}")


class TestDeletedSynonymTableIsCovered:
    """`_VC_SYN` — 42 hand-written synonyms in the LLM-fallback parser — is
    gone. These pin what replaced it, because "canonical() surely knows that
    spelling" is the assumption that let the table drift in the first place.
    """

    # every key of the deleted table, with the class IT returned
    OLD = {
        "sql injection": "sqli", "sqli": "sqli", "sql": "sqli",
        "blind sqli": "sqli", "cross-site scripting": "xss", "xss": "xss",
        "command injection": "cmdi", "os command injection": "cmdi",
        "cmdi": "cmdi", "server-side template injection": "ssti",
        "template injection": "ssti", "ssti": "ssti",
        "server-side request forgery": "ssrf", "ssrf": "ssrf",
        "xml external entity": "xxe", "xxe": "xxe",
        "local file inclusion": "lfi", "lfi": "lfi", "file inclusion": "lfi",
        "remote file inclusion": "rfi", "rfi": "rfi",
        "path traversal": "path-traversal", "directory traversal": "path-traversal",
        "path-traversal": "path-traversal", "file access": "path-traversal",
        "arbitrary file read": "path-traversal", "remote code execution": "rce",
        "rce": "rce", "code execution": "rce",
        "insecure direct object reference": "idor", "idor": "idor",
        "file upload": "upload", "arbitrary file upload": "upload",
        "upload": "upload", "authentication bypass": "auth-bypass",
        "auth bypass": "auth-bypass", "auth-bypass": "auth-bypass",
        "deserialization": "deser", "insecure deserialization": "deser",
        "deser": "deser", "open redirect": "open-redirect",
        "open-redirect": "open-redirect",
    }

    # Spellings the private table mapped but the TABLE deliberately does not,
    # because they name no single class. The fallback now rejects these with a
    # reason instead of guessing — an ambiguous answer is not an answer.
    AMBIGUOUS = {
        "file inclusion": "local vs remote is the whole distinction (lfi/rfi)",
        "file access": "names an outcome, not a mechanism",
    }

    # Where the old table and the table DISAGREE, and why the table is right.
    CORRECTED = {
        "deser": "deserialization",
        "deserialization": "deserialization",
        "insecure deserialization": "deserialization",
        "arbitrary file read": "lfi",
    }

    def test_every_unambiguous_spelling_still_resolves(self):
        missed = sorted(k for k in self.OLD
                        if k not in self.AMBIGUOUS and vc.canonical(k) == "unknown")
        assert not missed, (
            "spellings the deleted table accepted that canonical() now "
            f"rejects — add them as aliases in knowledge/vuln_classes.yaml: {missed}")

    def test_the_ambiguous_spellings_are_rejected_not_guessed(self):
        for spelling, why in self.AMBIGUOUS.items():
            assert vc.canonical(spelling) == "unknown", (
                f"{spelling!r} should stay unresolved ({why}); guessing a "
                "class here is what the old table did")

    def test_the_corrections_hold(self):
        """The disagreements are deliberate, and each is the table's answer."""
        for spelling, expect in self.CORRECTED.items():
            assert vc.canonical(spelling) == expect, spelling

    def test_deser_was_the_drift_that_motivated_the_deletion(self):
        """The old table emitted `deser`, which is NOT a class name — so a
        correctly-normalised answer became one no consumer recognised."""
        assert self.OLD["deser"] == "deser"
        assert "deser" not in vc.names()
        assert vc.canonical("deser") == "deserialization"
        assert "deserialization" in vc.names()

    def test_everything_else_agrees(self):
        """Outside the declared corrections, old and new must match — so a
        future table edit that silently re-points a spelling fails here."""
        for spelling, old_class in self.OLD.items():
            if spelling in self.AMBIGUOUS or spelling in self.CORRECTED:
                continue
            assert vc.canonical(spelling) == old_class, spelling


class TestFactContradictionsReadTheClassTable:
    """`path_class_with_a_query_parameter` (action: clear) carried a private
    copy of the path-is-the-field classes that listed `lfi`. LFI injects
    through a PARAMETER, so the rule deleted the real injection point on every
    LFI build. It now asks the class table; these pin the behaviour, not the
    wiring.
    """

    @staticmethod
    def _check(vc, field):
        from etl import fact_contradictions as F
        return F._check_field_kind_mismatch(
            {"check": "field_kind_mismatch"},
            {"vuln_class": vc, "facts": {"input_field": field}})

    def test_an_lfi_parameter_is_kept(self):
        assert self._check("lfi", "page") == [], (
            "LFI injects through a parameter; clearing `page` deletes the one "
            "real injection point")

    def test_a_parameter_on_a_path_traversal_is_still_flagged(self):
        assert self._check("path-traversal", "file"), (
            "a traversal has no parameter — a recorded one is a leftover")

    def test_a_route_on_a_path_traversal_is_kept(self):
        assert self._check("path-traversal", "/download/x") == []

    def test_the_yaml_no_longer_restates_the_list(self):
        y = yaml.safe_load((REPO / "knowledge" / "fact_contradictions.yaml")
                           .read_text(encoding="utf-8"))
        rules = y.get("rules") or y.get("contradictions") or []
        for r in (rules if isinstance(rules, list) else []):
            assert "path_is_the_field_classes" not in (r or {}), (
                "a private class list in fact_contradictions.yaml can drift "
                "from the table again — it did, and it listed lfi")
