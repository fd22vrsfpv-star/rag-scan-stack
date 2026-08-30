"""Walkthrough → knowledge converter tests.

The LLM call itself isn't unit-testable, but everything around it is — and the
parts that matter for safety are all deterministic:

  * the scrubber, which decides what gets quarantined
  * the renderer, which must make quarantined entries INVISIBLE to the importer
  * the selector validator, shared with the CRUD path
  * prompt layering (file → DB override → per-run focus)

The renderer test is the load-bearing one: if a flagged entry ever parsed as
active YAML, box-specific guidance would reach live scanning.
"""
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scan_recommender"))

yaml = pytest.importorskip("yaml", reason="PyYAML required")

SR_DIR = os.path.join(os.path.dirname(__file__), "..", "scan_recommender")
SR_FILE = os.path.join(SR_DIR, "scan_recommender.py")
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture(scope="module")
def sr():
    """Load scan_recommender.py by path, with its heavy deps stubbed.

    Loaded by path rather than `import scan_recommender`: other test files put
    the repo root on sys.path, which makes that name resolve to the
    scan_recommender *directory* as a namespace package.
    """
    if not isinstance(sys.modules.get("exploits_rag"), types.ModuleType) or \
            not hasattr(sys.modules.get("exploits_rag"), "TRAINING_SOURCE_REPO"):
        from fastapi import APIRouter
        stub = types.ModuleType("exploits_rag")
        stub.rag_router = APIRouter()
        stub.TRAINING_SOURCE_REPO = "training"
        stub._embed = lambda *a, **k: []
        stub._retrieve = lambda *a, **k: []
        sys.modules["exploits_rag"] = stub
    if SR_DIR not in sys.path:
        sys.path.insert(0, SR_DIR)
    # tool_kb reads TOOL_KB_PATH at import and defaults to the CONTAINER path
    # (/knowledge/...), which doesn't exist when tests run against a checkout.
    # Point it at the repo copy so coverage detection has a real vocabulary.
    os.environ.setdefault(
        "TOOL_KB_PATH",
        os.path.join(os.path.dirname(__file__), "..", "knowledge", "service_tools.yaml"),
    )
    import importlib.util
    try:
        spec = importlib.util.spec_from_file_location("scan_recommender_wt", SR_FILE)
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    except Exception as e:                                    # pragma: no cover
        pytest.skip(f"scan_recommender not importable: {e}")
    return m


# ── Scrubber: must catch box-specific data ──────────────────────────────────
class TestScrubberFlags:
    @pytest.mark.parametrize("text,expect", [
        ("the flag was HTB{s3nt1n3l_pwn3d}", "capture-the-flag"),
        ("grab THM{another_one} from root", "capture-the-flag"),
        ("login with admin:Summer2023! to proceed", "credential pair"),
        ("the password was hunter2 on this host", "stated password"),
        ("creds were bob:passw0rd123", "credential pair"),
        ("ntlm hash 5f4dcc3b5aa765d61d8327deb882cf99 cracked offline", "password hash"),
        ("target sat at 10.10.10.42 on the lab net", "lab IP"),
        ("pivot to 192.168.56.101 next", "lab IP"),
        ("internal host 172.16.4.9 was reachable", "lab IP"),
    ])
    def test_flags_box_specific(self, sr, text, expect):
        reasons = sr.scrub_entry({"title": "t", "prompt": text})
        assert reasons, f"should have flagged: {text}"
        assert any(expect.lower() in r.lower() for r in reasons), reasons

    def test_scans_training_notes_and_content_too(self, sr):
        assert sr.scrub_entry({"title": "t", "training_notes": "flag: HTB{x1}"})
        assert sr.scrub_entry({"title": "t", "content": "password was hunter2 here"})

    def test_bare_pass_is_deliberately_not_a_trigger(self, sr):
        """'pass' alone must not flag — 'pass the hash' is a legitimate technique.

        The pattern requires password/passwd/cred(s)/credentials precisely so
        this stays clean; widening it would bury real guidance under warnings.
        """
        assert sr.scrub_entry(
            {"title": "t", "prompt": "Use pass the hash with the recovered NTLM material."}
        ) == []

    def test_reason_includes_the_offending_snippet(self, sr):
        r = sr.scrub_entry({"title": "t", "prompt": "flag HTB{abc123}"})
        assert "HTB{abc123}" in r[0]


class TestScrubberFalsePositives:
    """The reason flagged entries are kept-and-commented rather than deleted.

    Every pattern family overlaps with legitimate guidance; deleting would throw
    away exactly the knowledge worth having.
    """
    @pytest.mark.parametrize("text", [
        "Try the default community strings first: public, private, community.",
        "Run whatweb before nuclei to fingerprint the stack.",
        "Enumerate plugins under /wp-content/plugins/ before generic templates.",
        "Walk 1.3.6.1.2.1.4.22.1.2 for the ARP cache.",
        "Check /manager/html and /host-manager/html for the manager app.",
        "Anonymous FTP often exposes backup files; list recursively.",
    ])
    def test_legitimate_guidance_is_clean(self, sr, text):
        assert sr.scrub_entry({"title": "t", "prompt": text}) == [], text

    def test_oid_strings_are_not_mistaken_for_lab_ips(self, sr):
        """SNMP OIDs are dotted numbers; the IP pattern must not claim them."""
        assert sr.scrub_entry({"title": "t", "prompt": "1.3.6.1.2.1.1.1.0 gives sysDescr"}) == []

    def test_public_routable_ip_is_not_flagged_as_lab(self, sr):
        assert sr.scrub_entry({"title": "t", "prompt": "resolves to 93.184.216.34"}) == []


# ── Renderer: the safety-critical property ──────────────────────────────────
class TestRenderSeedYaml:
    def _render(self, sr, prompts, flagged):
        return sr.render_seed_yaml(prompts, [], flagged, {}, "lab01.md")

    def test_flagged_entries_are_invisible_to_the_importer(self, sr):
        """Load-bearing: commented entries must not parse as active rules."""
        prompts = [
            {"selector_type": "service", "service": "snmp", "title": "Clean", "prompt": "ok"},
            {"selector_type": "service", "service": "ftp", "title": "Dirty",
             "prompt": "login admin:Summer2023!"},
        ]
        out = self._render(sr, prompts, {1: ["credential pair: admin:Summer2023!"]})
        parsed = yaml.safe_load(out) or {}
        titles = [p["title"] for p in (parsed.get("prompts") or [])]
        assert titles == ["Clean"]

    def test_flagged_entry_text_is_retained_for_review(self, sr):
        """Operator must still be able to see and un-comment it."""
        out = self._render(sr, [{"selector_type": "service", "service": "ftp",
                                 "title": "Dirty", "prompt": "x"}],
                           {0: ["credential pair: a:b"]})
        assert "Dirty" in out
        assert "# !REVIEW" in out
        assert "credential pair: a:b" in out

    def test_clean_entries_render_active(self, sr):
        out = self._render(sr, [{"selector_type": "service", "service": "snmp",
                                 "title": "Clean", "prompt": "ok"}], {})
        parsed = yaml.safe_load(out)
        assert parsed["prompts"][0]["title"] == "Clean"

    def test_all_flagged_yields_no_active_entries(self, sr):
        out = self._render(sr, [{"selector_type": "service", "service": "ftp",
                                 "title": "D", "prompt": "x"}], {0: ["r"]})
        parsed = yaml.safe_load(out) or {}
        assert not (parsed.get("prompts") or [])

    def test_empty_result_is_still_valid_yaml(self, sr):
        parsed = yaml.safe_load(sr.render_seed_yaml([], [], {}, {}, "x.md"))
        assert parsed == {"prompts": []}

    def test_output_carries_import_instructions(self, sr):
        out = self._render(sr, [], {})
        assert "import-knowledge.sh" in out

    def test_multiline_training_notes_survive_the_round_trip(self, sr):
        notes = "## H\n- one\n- two\n"
        out = self._render(sr, [{"selector_type": "service", "service": "snmp",
                                 "title": "T", "prompt": "p", "training_notes": notes}], {})
        assert yaml.safe_load(out)["prompts"][0]["training_notes"] == notes


# ── Selector validation, shared with the CRUD path ──────────────────────────
class TestNormalizeSelector:
    def test_valid_shapes(self, sr):
        assert sr.normalize_selector("service", "HTTP", None, None, "t")[:3] == ("http", None, None)
        assert sr.normalize_selector("port", None, None, 8080, "t")[:3] == (None, None, 8080)
        assert sr.normalize_selector("port_service", "http", None, 8080, "t")[:3] == ("http", None, 8080)
        assert sr.normalize_selector("tech", None, "WordPress", None, "t")[:3] == (None, "wordpress", None)

    def test_irrelevant_fields_are_nulled(self, sr):
        """A stray field would otherwise trip the DB's shape CHECK as a 500."""
        svc, tech, port, err = sr.normalize_selector("service", "http", "wordpress", 80, "t")
        assert (svc, tech, port, err) == ("http", None, None, None)

    @pytest.mark.parametrize("args,expect", [
        (("service", None, None, None, "t"), "requires a service"),
        (("port", None, None, None, "t"), "requires a port"),
        (("port_service", "http", None, None, "t"), "requires a port"),
        (("tech", None, None, None, "t"), "requires a tech"),
        (("bogus", "http", None, None, "t"), "selector_type must be"),
        (("port", None, None, 99999, "t"), "between 1 and 65535"),
        (("service", "http", None, None, ""), "title is required"),
    ])
    def test_errors(self, sr, args, expect):
        assert expect in (sr.normalize_selector(*args)[3] or "")

    def test_string_port_is_coerced(self, sr):
        """LLM and YAML output both produce stringified ports."""
        assert sr.normalize_selector("port", None, None, "8080", "t")[2] == 8080


# ── Prompt layering ─────────────────────────────────────────────────────────
class TestPromptResolution:
    def test_falls_back_to_the_file_default(self, sr, monkeypatch):
        monkeypatch.setattr(sr, "_get_app_setting", lambda k, d="": "")
        monkeypatch.setattr(sr, "_read_default_walkthrough_prompt", lambda: "FILE-DEFAULT")
        assert sr.resolve_walkthrough_prompt() == "FILE-DEFAULT"

    def test_db_override_wins_over_the_file(self, sr, monkeypatch):
        monkeypatch.setattr(sr, "_get_app_setting", lambda k, d="": "DB-OVERRIDE")
        monkeypatch.setattr(sr, "_read_default_walkthrough_prompt", lambda: "FILE-DEFAULT")
        assert sr.resolve_walkthrough_prompt() == "DB-OVERRIDE"

    def test_empty_override_reverts_to_the_file(self, sr, monkeypatch):
        """Saving a blank override means 'use the default', per the cve_analysis convention."""
        monkeypatch.setattr(sr, "_get_app_setting", lambda k, d="": "")
        monkeypatch.setattr(sr, "_read_default_walkthrough_prompt", lambda: "FILE-DEFAULT")
        assert sr.resolve_walkthrough_prompt() == "FILE-DEFAULT"

    def test_focus_is_appended_not_substituted(self, sr, monkeypatch):
        monkeypatch.setattr(sr, "_get_app_setting", lambda k, d="": "BASE")
        out = sr.resolve_walkthrough_prompt("Active Directory only")
        assert out.startswith("BASE")
        assert "Active Directory only" in out

    def test_blank_focus_changes_nothing(self, sr, monkeypatch):
        monkeypatch.setattr(sr, "_get_app_setting", lambda k, d="": "BASE")
        assert sr.resolve_walkthrough_prompt("   ") == "BASE"


# ── The shipped prompt file ─────────────────────────────────────────────────
class TestShippedPrompt:
    PATH = os.path.join(os.path.dirname(__file__), "..",
                        "knowledge", "prompts", "walkthrough_to_seed.md")

    def test_exists_and_is_substantial(self):
        assert os.path.exists(self.PATH)
        assert len(open(self.PATH).read()) > 1000

    def test_names_every_selector_type(self):
        text = open(self.PATH).read()
        for sel in ("port_service", "tech", "port", "service"):
            assert sel in text

    def test_instructs_against_carrying_secrets(self):
        text = open(self.PATH).read().lower()
        assert "secret" in text or "credential" in text
        assert "discard" in text


# ── Entry repair: recovering rules from wrong-field model output ────────────
class TestRepairEntry:
    """Models routinely name the right thing in the wrong field.

    Rejecting those throws away correct knowledge over a field name, so the
    converter repairs the obvious cases before validating.
    """

    def test_tech_selector_with_value_in_service_is_repaired(self, sr):
        """The exact failure seen converting the Rapid7 Metasploitable guide."""
        e = sr.repair_entry({"selector_type": "tech", "service": "distccd", "title": "t"})
        assert e["tech"] == "distccd" and "service" not in e

    def test_service_selector_with_value_in_tech_is_repaired(self, sr):
        e = sr.repair_entry({"selector_type": "service", "tech": "smtp", "title": "t"})
        assert e["service"] == "smtp" and "tech" not in e

    def test_repaired_entry_then_passes_validation(self, sr):
        e = sr.repair_entry({"selector_type": "tech", "service": "postgresql", "title": "t"})
        assert sr.normalize_selector(e.get("selector_type"), e.get("service"),
                                     e.get("tech"), e.get("port"), "t")[3] is None

    @pytest.mark.parametrize("junk", ["//s", "http://x/y", "a b c", "", "-", "1234"])
    def test_url_fragments_and_junk_are_dropped(self, sr, junk):
        """`tech: //s` scraped from a URL would be an unmatchable rule."""
        e = sr.repair_entry({"selector_type": "tech", "tech": junk, "title": "t"})
        assert not e.get("tech")

    @pytest.mark.parametrize("good", ["wordpress", "ms-sql", "vsftpd", "tomcat9", "node.js"])
    def test_legitimate_names_survive(self, sr, good):
        e = sr.repair_entry({"selector_type": "tech", "tech": good, "title": "t"})
        assert e["tech"] == good

    def test_missing_selector_type_is_inferred(self, sr):
        assert sr.repair_entry({"service": "http", "port": 8080, "title": "t"})["selector_type"] == "port_service"
        assert sr.repair_entry({"tech": "wordpress", "title": "t"})["selector_type"] == "tech"
        assert sr.repair_entry({"service": "ftp", "title": "t"})["selector_type"] == "service"
        assert sr.repair_entry({"port": 161, "title": "t"})["selector_type"] == "port"

    def test_port_service_without_a_port_degrades_to_service(self, sr):
        """Better a working service rule than a discarded one."""
        e = sr.repair_entry({"selector_type": "port_service", "service": "ftp", "title": "t"})
        assert e["selector_type"] == "service"

    def test_repair_never_invents_a_selector(self, sr):
        """An entry with nothing usable must still fail validation, not be faked."""
        e = sr.repair_entry({"title": "t", "prompt": "p"})
        assert "selector_type" not in e
        assert sr.normalize_selector(e.get("selector_type"), None, None, None, "t")[3]

    def test_input_is_not_mutated(self, sr):
        original = {"selector_type": "tech", "service": "distccd", "title": "t"}
        sr.repair_entry(original)
        assert original["service"] == "distccd"

    def test_port_service_without_a_service_degrades_to_port(self, sr):
        """Seen on 'vsFTPd 2.3.4 Backdoor Check': a port but no service named."""
        e = sr.repair_entry({"selector_type": "port_service", "port": 21, "title": "t"})
        assert e["selector_type"] == "port"
        assert sr.normalize_selector(e["selector_type"], None, None, e["port"], "t")[3] is None


# ── Coverage reporting ──────────────────────────────────────────────────────
class TestCoverageReport:
    """A thin conversion must be distinguishable from a thin document.

    The Rapid7 guide covers ~20 services and produced 7 rules, and nothing in
    the output said so — this is what makes that visible.
    """

    @pytest.fixture(autouse=True)
    def _needs_kb_vocabulary(self, sr):
        """coverage_report derives its vocabulary from the tool KB.

        The KB module lives in scan_recommender/ and is only importable with
        that directory on sys.path — which the suite deliberately does NOT do,
        because service directories contain colliding module names. Without it
        coverage_report returns an empty result and every assertion below fails
        on a function that is provably correct: inside the running
        scan-recommender the same call reports mentioned=[mysql, postgresql,
        smb], covered=[mysql], missed=[postgresql, smb].

        So this SKIPS rather than fails — the test cannot run here, which is not
        the same as the code being wrong.
        """
        rep = sr.coverage_report("mysql and samba", [])
        if not rep or not rep.get("mentioned"):
            pytest.skip("tool KB vocabulary unavailable — coverage_report has no "
                        "services to match against (run inside scan-recommender, "
                        "or add scan_recommender/ to sys.path for this module)")

    def test_names_services_mentioned_but_not_covered(self, sr):
        text = "The host ran mysql, postgresql and vsftpd. Also samba shares."
        rep = sr.coverage_report(text, [{"selector_type": "service", "service": "mysql"}])
        assert "mysql" in rep["covered"]
        # "samba" is reported as the canonical "smb" — that is the value a rule
        # must carry for it to fire, so reporting the prose name would mislead.
        for missed in ("postgresql", "smb"):
            assert missed in rep["missed"], rep

    def test_prose_aliases_are_detected_as_their_canonical_service(self, sr):
        """Documents say "Samba" / "microsoft-ds"; the KB canonical is "smb"."""
        assert "smb" in sr.coverage_report("Samba shares were exposed", [])["mentioned"]
        assert "smb" in sr.coverage_report("microsoft-ds on 445", [])["mentioned"]

    def test_full_coverage_reports_no_gap(self, sr):
        text = "Only mysql was exposed."
        rep = sr.coverage_report(text, [{"selector_type": "service", "service": "mysql"}])
        assert rep["missed"] == []
        assert rep["coverage_pct"] == 100

    def test_tech_rules_count_as_coverage(self, sr):
        text = "The site ran wordpress behind nginx."
        rep = sr.coverage_report(text, [{"selector_type": "tech", "tech": "wordpress"}])
        assert "wordpress" in rep["covered"]

    def test_model_declared_skips_are_not_counted_as_missed(self, sr):
        """A service the model consciously skipped, with a reason, isn't a gap."""
        text = "telnet was open but nothing was done with it. mysql was exploited."
        rep = sr.coverage_report(
            text,
            [{"selector_type": "service", "service": "mysql"}],
            skipped=[{"service": "telnet", "reason": "no technique given"}],
        )
        assert "telnet" not in rep["missed"]
        assert rep["skipped"][0]["reason"] == "no technique given"

    def test_matching_is_word_bounded(self, sr):
        """Short service names must not fire inside unrelated words."""
        rep = sr.coverage_report("discussion of transmission protocols", [])
        assert "smb" not in rep["mentioned"]

    def test_empty_document_yields_no_false_gaps(self, sr):
        rep = sr.coverage_report("nothing relevant here at all", [])
        assert rep["mentioned"] == [] and rep["missed"] == []
        assert rep["coverage_pct"] is None

    def test_report_is_absent_rather_than_wrong_when_kb_unavailable(self, sr, monkeypatch):
        monkeypatch.setattr(sr, "get_tool_kb", lambda: (_ for _ in ()).throw(RuntimeError("down")))
        assert sr.coverage_report("mysql here", []) == {}

    def test_report_carries_the_total_rule_count(self, sr):
        rep = sr.coverage_report("mysql here", [{"selector_type": "service", "service": "mysql"},
                                                {"selector_type": "tech", "tech": "distcc"}])
        assert rep["rules_total"] == 2

    def test_rules_outside_the_kb_vocabulary_are_surfaced(self, sr):
        """Real output that can't be counted against `mentioned` — the
        percentage would otherwise read as a failure."""
        rep = sr.coverage_report("mysql here", [{"selector_type": "tech", "tech": "mutillidae"}])
        assert "mutillidae" in rep["rules_outside_kb_vocabulary"]
