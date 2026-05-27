"""Unit tests for the cloud scan suggestor engine."""

import os
import sys
import hashlib
import pytest
from unittest.mock import MagicMock, patch

# Ensure app/rag-api is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app", "rag-api"))

import cloud_suggestor


RULES_PATH = os.path.join(os.path.dirname(__file__), "..", "knowledge", "cloud_scan_rules.yaml")


class TestLoadRules:
    def test_load_rules_from_disk(self):
        rules = cloud_suggestor.load_rules(RULES_PATH)
        assert "bootstrap_rules" in rules
        assert "finding_rules" in rules
        assert "credential_rules" in rules
        assert len(rules["bootstrap_rules"]) >= 4
        assert len(rules["finding_rules"]) >= 8
        assert len(rules["credential_rules"]) >= 2

    def test_load_rules_missing_file(self):
        rules = cloud_suggestor.load_rules("/nonexistent/path.yaml")
        assert rules["bootstrap_rules"] == []
        assert rules["finding_rules"] == []
        assert rules["credential_rules"] == []

    def test_rules_have_required_fields(self):
        rules = cloud_suggestor.load_rules(RULES_PATH)
        for rule in rules["bootstrap_rules"]:
            assert "id" in rule
            assert "name" in rule
            assert "priority" in rule
            assert "recommendations" in rule
            for rec in rule["recommendations"]:
                assert "tool" in rec
                assert "action" in rec

        for rule in rules["finding_rules"]:
            assert "id" in rule
            assert "source" in rule
            assert "finding_type_pattern" in rule


class TestFingerprint:
    def test_fingerprint_deterministic(self):
        fp1 = cloud_suggestor._fingerprint("rule1", "prowler", "abc-123", "do something")
        fp2 = cloud_suggestor._fingerprint("rule1", "prowler", "abc-123", "do something")
        assert fp1 == fp2

    def test_fingerprint_differs(self):
        fp1 = cloud_suggestor._fingerprint("rule1", "prowler", "abc-123", "do something")
        fp2 = cloud_suggestor._fingerprint("rule1", "prowler", "abc-456", "do something")
        assert fp1 != fp2

    def test_fingerprint_none_trigger(self):
        fp = cloud_suggestor._fingerprint("no_cloud_data", "prowler", None, "run prowler")
        assert isinstance(fp, str)
        assert len(fp) == 32


class TestEvaluateBootstrap:
    def _make_cursor(self, cloud_cred_count=0):
        """Create a mock cursor that returns specified values."""
        cur = MagicMock()
        # For _cloud_cred_count
        cur.fetchone.return_value = {"cnt": cloud_cred_count}
        return cur

    def test_no_cloud_data_triggers(self):
        rules = cloud_suggestor.load_rules(RULES_PATH)
        source_counts = {}  # No cloud data
        cur = self._make_cursor()
        # _detect_providers returns empty set
        cur.fetchall.return_value = []

        recs = cloud_suggestor.evaluate_bootstrap(cur, rules, source_counts)
        rule_ids = {r["rule_id"] for r in recs}
        assert "no_cloud_data" in rule_ids

    def test_no_cloud_data_suppressed_when_data_exists(self):
        rules = cloud_suggestor.load_rules(RULES_PATH)
        source_counts = {"prowler": 50}
        cur = self._make_cursor()
        cur.fetchall.return_value = [{"provider": "aws"}]

        recs = cloud_suggestor.evaluate_bootstrap(cur, rules, source_counts)
        rule_ids = {r["rule_id"] for r in recs}
        assert "no_cloud_data" not in rule_ids

    def test_aws_no_privesc_check(self):
        rules = cloud_suggestor.load_rules(RULES_PATH)
        source_counts = {"prowler": 100}  # Has prowler, no cloudfox
        cur = self._make_cursor()
        cur.fetchall.return_value = [{"provider": "aws"}]

        recs = cloud_suggestor.evaluate_bootstrap(cur, rules, source_counts)
        rule_ids = {r["rule_id"] for r in recs}
        assert "aws_no_privesc_check" in rule_ids

    def test_have_creds_no_access_map(self):
        rules = cloud_suggestor.load_rules(RULES_PATH)
        source_counts = {"prowler": 50}  # No cloudfox
        cur = self._make_cursor(cloud_cred_count=3)
        cur.fetchall.return_value = [{"provider": "aws"}]

        recs = cloud_suggestor.evaluate_bootstrap(cur, rules, source_counts)
        rule_ids = {r["rule_id"] for r in recs}
        assert "have_creds_no_access_map" in rule_ids

    def test_all_suppressed_when_complete(self):
        """When all cloud sources are present, bootstrap rules should be mostly suppressed."""
        rules = cloud_suggestor.load_rules(RULES_PATH)
        source_counts = {"prowler": 100, "scoutsuite": 50, "pacu": 30, "cloudfox": 20, "azurehound": 10}
        cur = self._make_cursor()
        cur.fetchall.return_value = [{"provider": "aws"}]

        recs = cloud_suggestor.evaluate_bootstrap(cur, rules, source_counts)
        rule_ids = {r["rule_id"] for r in recs}
        assert "no_cloud_data" not in rule_ids
        assert "aws_no_privesc_check" not in rule_ids


class TestEvaluateFindings:
    def test_finding_rule_matches(self):
        rules = cloud_suggestor.load_rules(RULES_PATH)
        cur = MagicMock()

        # Simulate prowler finding with s3/public pattern
        cur.fetchall.return_value = [
            {
                "id": "00000000-0000-0000-0000-000000000001",
                "target": "arn:aws:s3:::public-bucket",
                "finding_type": "s3_bucket_public_access",
                "severity": "critical",
                "source": "prowler",
                "provider": "aws",
                "account_id": "123456789",
                "summary": "s3_bucket_public_access arn:aws:s3:::public-bucket",
            }
        ]

        recs = cloud_suggestor.evaluate_findings(cur, rules)
        rule_ids = {r["rule_id"] for r in recs}
        assert "public_s3_suggest_cloudfox" in rule_ids

    def test_finding_rule_no_match(self):
        rules = cloud_suggestor.load_rules(RULES_PATH)
        cur = MagicMock()

        # Finding that doesn't match any pattern
        cur.fetchall.return_value = [
            {
                "id": "00000000-0000-0000-0000-000000000002",
                "target": "something-unrelated",
                "finding_type": "logging_enabled",
                "severity": "info",
                "source": "prowler",
                "provider": "aws",
                "account_id": "123456789",
                "summary": "logging_enabled something-unrelated",
            }
        ]

        recs = cloud_suggestor.evaluate_findings(cur, rules)
        # Only prowler rules should match, and none should match "logging_enabled"
        prowler_recs = [r for r in recs if r["trigger_source"] == "prowler"]
        rule_ids = {r["rule_id"] for r in prowler_recs}
        assert "public_s3_suggest_cloudfox" not in rule_ids


class TestEvaluateCredentials:
    def test_expiring_credential_detected(self):
        from datetime import datetime, timezone, timedelta

        rules = cloud_suggestor.load_rules(RULES_PATH)
        cur = MagicMock()

        # First call is for credential_expiring_soon, second for stale_key
        cur.fetchall.side_effect = [
            [
                {
                    "id": "00000000-0000-0000-0000-000000000003",
                    "username": "test-user",
                    "credential_type": "aws_sts",
                    "domain": "123456789",
                    "expires_at": datetime.now(timezone.utc) + timedelta(minutes=15),
                    "source": "manual",
                }
            ],
            [],  # No stale keys
        ]

        recs = cloud_suggestor.evaluate_credentials(cur, rules)
        rule_ids = {r["rule_id"] for r in recs}
        assert "credential_expiring_soon" in rule_ids

    def test_stale_key_detected(self):
        from datetime import datetime, timezone, timedelta

        rules = cloud_suggestor.load_rules(RULES_PATH)
        cur = MagicMock()

        cur.fetchall.side_effect = [
            [],  # No expiring creds
            [
                {
                    "id": "00000000-0000-0000-0000-000000000004",
                    "username": "old-key-user",
                    "credential_type": "aws_access_key",
                    "domain": "123456789",
                    "created_at": datetime.now(timezone.utc) - timedelta(days=120),
                    "source": "manual",
                }
            ],
        ]

        recs = cloud_suggestor.evaluate_credentials(cur, rules)
        rule_ids = {r["rule_id"] for r in recs}
        assert "stale_key_suggest_rotation" in rule_ids


class TestRecommendationFields:
    def test_recommendation_has_all_fields(self):
        rules = cloud_suggestor.load_rules(RULES_PATH)
        source_counts = {}
        cur = MagicMock()
        cur.fetchone.return_value = {"cnt": 0}
        cur.fetchall.return_value = []

        recs = cloud_suggestor.evaluate_bootstrap(cur, rules, source_counts)
        assert len(recs) > 0
        for rec in recs:
            assert "rule_id" in rec
            assert "rule_name" in rec
            assert "priority" in rec
            assert "tool" in rec
            assert "action" in rec
            assert rec["priority"] in ("critical", "high", "medium", "low")
