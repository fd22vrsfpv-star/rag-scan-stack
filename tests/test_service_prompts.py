"""Per-service / per-port prompt resolution tests.

Covers the precedence rules in scan_recommender._get_service_prompts and the
guidance block assembly in _build_guidance_block.

The properties these lock down:
  1. Specificity beats priority — a port_service rule always precedes a port
     rule, which always precedes a service rule, regardless of priority values.
  2. Engagement-scoped rules never leak across engagements.
  3. With no matching rules the guidance block is EMPTY, so the LLM prompt is
     byte-identical to its pre-feature form.
"""
import os
import sys
import types
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scan_recommender"))


SR_DIR = os.path.join(os.path.dirname(__file__), "..", "scan_recommender")
SR_FILE = os.path.join(SR_DIR, "scan_recommender.py")


@pytest.fixture(scope="module")
def sr():
    """Load scan_recommender.py with its heavy/IO-bound deps stubbed.

    Loaded from an explicit file path rather than `import scan_recommender`.
    Other test files put the repo root on sys.path, which makes that name
    resolve to the scan_recommender *directory* as a namespace package — the
    module's functions then simply aren't there, and every test here fails, but
    only when the suite runs in a particular order.
    """
    # exploits_rag pulls in psycopg2/pgvector and opens connections at import;
    # scan_recommender only needs the names, so a stub keeps this hermetic.
    if not isinstance(sys.modules.get("exploits_rag"), types.ModuleType) or \
            not hasattr(sys.modules.get("exploits_rag"), "TRAINING_SOURCE_REPO"):
        from fastapi import APIRouter
        stub = types.ModuleType("exploits_rag")
        # Must be a real router — scan_recommender calls app.include_router on it.
        stub.rag_router = APIRouter()
        stub.TRAINING_SOURCE_REPO = "training"
        stub._embed = lambda *a, **k: []
        stub._retrieve = lambda *a, **k: []
        sys.modules["exploits_rag"] = stub

    # scan_recommender.py does bare imports of its siblings (tool_kb, ...), so
    # its own directory must be importable.
    if SR_DIR not in sys.path:
        sys.path.insert(0, SR_DIR)

    import importlib.util
    try:
        spec = importlib.util.spec_from_file_location("scan_recommender_under_test", SR_FILE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as e:                                    # pragma: no cover
        pytest.skip(f"scan_recommender not importable in this env: {e}")
    return module


def _row(selector_type, *, service=None, port=None, title="t",
         prompt="p", priority=100, engagement_id=None):
    return {
        "id": f"{selector_type}-{service}-{port}-{title}",
        "selector_type": selector_type, "service": service, "port": port,
        "title": title, "prompt": prompt, "priority": priority,
        "engagement_id": engagement_id,
    }


@pytest.fixture
def rules(sr):
    """Patch the cached row loader so tests never touch the database."""
    def _install(rows):
        return patch.object(sr, "_get_all_service_prompts", lambda: rows)
    return _install


class TestPrecedence:
    def test_specificity_beats_priority(self, sr, rules):
        """A port_service rule leads even when a port rule has better priority."""
        rows = [
            _row("service", service="http", title="svc", priority=1),
            _row("port", port=8080, title="port", priority=1),
            _row("port_service", service="http", port=8080, title="both", priority=999),
        ]
        with rules(rows):
            got = [r["title"] for r in sr._get_service_prompts("http", 8080)]
        assert got == ["both", "port", "svc"]

    def test_all_matches_returned_not_just_best(self, sr, rules):
        """Broad and narrow rules compose rather than shadowing each other."""
        rows = [
            _row("service", service="http", title="svc"),
            _row("port_service", service="http", port=8080, title="both"),
        ]
        with rules(rows):
            assert len(sr._get_service_prompts("http", 8080)) == 2

    def test_priority_breaks_ties_within_a_tier(self, sr, rules):
        rows = [
            _row("service", service="http", title="late", priority=200),
            _row("service", service="http", title="early", priority=1),
        ]
        with rules(rows):
            got = [r["title"] for r in sr._get_service_prompts("http", None)]
        assert got == ["early", "late"]

    def test_service_match_is_case_insensitive(self, sr, rules):
        with rules([_row("service", service="http", title="svc")]):
            assert len(sr._get_service_prompts("HTTP", None)) == 1


class TestScoping:
    def test_non_matching_service_returns_nothing(self, sr, rules):
        with rules([_row("service", service="http", title="svc")]):
            assert sr._get_service_prompts("ssh", 22) == []

    def test_port_rule_does_not_match_other_ports(self, sr, rules):
        with rules([_row("port", port=8080, title="p")]):
            assert sr._get_service_prompts("http", 443) == []

    def test_port_service_needs_both_to_match(self, sr, rules):
        rows = [_row("port_service", service="http", port=8080, title="both")]
        with rules(rows):
            assert sr._get_service_prompts("http", 443) == []   # right svc, wrong port
            assert sr._get_service_prompts("ssh", 8080) == []   # right port, wrong svc
            assert len(sr._get_service_prompts("http", 8080)) == 1

    def test_engagement_rules_do_not_leak(self, sr, rules):
        rows = [_row("service", service="http", title="scoped", engagement_id="eng-A")]
        with rules(rows):
            assert sr._get_service_prompts("http", None, "eng-B") == []
            assert sr._get_service_prompts("http", None, None) == []
            assert len(sr._get_service_prompts("http", None, "eng-A")) == 1

    def test_global_rules_apply_within_any_engagement(self, sr, rules):
        with rules([_row("service", service="http", title="global")]):
            assert len(sr._get_service_prompts("http", None, "eng-A")) == 1

    def test_engagement_rule_precedes_global_in_same_tier(self, sr, rules):
        rows = [
            _row("service", service="http", title="global", priority=1),
            _row("service", service="http", title="scoped", priority=500,
                 engagement_id="eng-A"),
        ]
        with rules(rows):
            got = [r["title"] for r in sr._get_service_prompts("http", None, "eng-A")]
        assert got == ["scoped", "global"]


class TestGuidanceBlock:
    def test_no_rules_yields_empty_string(self, sr, rules):
        """The critical no-op property: unchanged prompt when unused."""
        with rules([]):
            assert sr._build_guidance_block("http", 8080) == ""

    def test_block_labels_each_rule_with_its_scope(self, sr, rules):
        rows = [
            _row("port_service", service="http", port=8080, title="T1", prompt="Do X"),
            _row("service", service="http", title="T2", prompt="Do Y"),
        ]
        with rules(rows):
            block = sr._build_guidance_block("http", 8080)
        assert "SERVICE-SPECIFIC GUIDANCE" in block
        assert "[http on port 8080] T1: Do X" in block
        assert "[service http] T2: Do Y" in block
        # Most specific must appear first in the injected text.
        assert block.index("T1") < block.index("T2")

    def test_training_context_empty_without_service_or_port(self, sr):
        assert sr._get_training_context(None, None) == ""


class TestExportRow:
    """Seed export must be re-importable and must not leak this install's identity.

    The round-trip property that matters: exporting the live KB and re-importing
    it produces UPDATEs, never CREATEs. That holds only if every field the
    importer keys on survives, and every field local to this database is dropped.
    """

    def test_drops_db_only_columns(self, sr):
        row = _row("service", service="mysql", title="T", prompt="P")
        row.update({
            "id": "3f2b1c00-0000-0000-0000-000000000001",
            "created_at": "2026-08-14T00:00:00Z",
            "updated_at": "2026-08-14T00:00:00Z",
            "rag_ingested_at": "2026-08-14T00:00:00Z",
        })
        out = sr._export_row(row)
        for gone in ("id", "created_at", "updated_at", "rag_ingested_at"):
            assert gone not in out
        assert out["service"] == "mysql"
        assert out["title"] == "T"

    def test_drops_engagement_id(self, sr):
        """A UUID from this install would fail the FK on any other one."""
        row = _row("service", service="vnc", title="T", prompt="P")
        row["engagement_id"] = "3f2b1c00-0000-0000-0000-0000000000ff"
        assert "engagement_id" not in sr._export_row(row)

    def test_keeps_enabled_false(self, sr):
        """Regression: dropping falsey values would silently re-enable a rule.

        `enabled: false` is the intended way to ship a noisy lab rule, so losing
        it on export turns a disabled rule back on at the next install.
        """
        row = _row("service", service="dvwa", title="T", prompt="P")
        row["enabled"] = False
        out = sr._export_row(row)
        assert out["enabled"] is False

    def test_keeps_zero_priority(self, sr):
        row = _row("service", service="ftp", title="T", prompt="P")
        row["priority"] = 0
        assert sr._export_row(row)["priority"] == 0

    def test_drops_nulls_and_empty_tags(self, sr):
        row = _row("service", service="smb", title="T", prompt="P")
        row.update({"tech": None, "port": None, "training_notes": None, "tags": []})
        out = sr._export_row(row)
        for gone in ("tech", "port", "training_notes", "tags"):
            assert gone not in out

    def test_keeps_populated_tags(self, sr):
        row = _row("service", service="smb", title="T", prompt="P")
        row["tags"] = ["lab", "smb"]
        assert sr._export_row(row)["tags"] == ["lab", "smb"]


class TestMergeKbRecs:
    """The hybrid pass must add what the rules missed and nothing they covered.

    Before this merge existed, service_prompts had no effect on automated recon
    at all: /next_scan answers from tool_kb rules whenever port rows exist, and
    only the LLM branch injects operator guidance.
    """

    def test_bare_duplicate_of_a_rule_scanner_is_dropped(self, sr):
        """Observed on the first real run — bare snmpwalk beside the rules' full form."""
        rules = [{"scanner": "snmpwalk", "action": None,
                  "script": "snmpwalk -v2c -c public {target}", "template": None}]
        llm = [{"scanner": "snmpwalk", "action": None, "script": None, "template": None}]
        assert sr._merge_kb_recs(rules, llm, set()) == []

    def test_bare_rec_for_a_new_scanner_is_kept(self, sr):
        """The LLM contributing a tool the static KB lacks is the whole point."""
        rules = [{"scanner": "nmap", "action": None, "script": "snmp-info", "template": None}]
        llm = [{"scanner": "onesixtyone", "action": None, "script": None, "template": None}]
        assert len(sr._merge_kb_recs(rules, llm, set())) == 1

    def test_specific_rec_kept_even_when_scanner_overlaps(self, sr):
        """Same scanner, different script, is a real addition — not a duplicate."""
        rules = [{"scanner": "nmap", "action": None, "script": "snmp-info", "template": None}]
        llm = [{"scanner": "nmap", "action": None, "script": "snmp-brute", "template": None}]
        assert len(sr._merge_kb_recs(rules, llm, set())) == 1

    def test_exact_duplicate_dropped_via_seen_keys(self, sr):
        seen = {("nuclei", None, None, "snmp-default-creds", "", "")}
        llm = [{"scanner": "nuclei", "action": None, "script": None,
                "template": "snmp-default-creds"}]
        assert sr._merge_kb_recs([], llm, seen) == []

    def test_seen_keys_is_updated_for_the_caller(self, sr):
        """The caller keeps deduping against this set after we return."""
        seen = set()
        llm = [{"scanner": "hydra", "action": "brute", "script": None, "template": None}]
        sr._merge_kb_recs([], llm, seen)
        assert ("hydra", "brute", None, None, "", "") in seen

    def test_repeated_llm_recs_collapse(self, sr):
        llm = [{"scanner": "snmp-check", "action": None, "script": "x", "template": None}] * 3
        assert len(sr._merge_kb_recs([], llm, set())) == 1

    def test_no_llm_recs_is_empty(self, sr):
        assert sr._merge_kb_recs([{"scanner": "nmap"}], [], set()) == []
