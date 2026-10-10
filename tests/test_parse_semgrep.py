"""Tests for etl/parse_semgrep.py — Semgrep SAST parser.

Fixture: tests/fixtures/semgrep_sample.json (real Semgrep output shape,
redacted keys/secrets). Runs standalone with no infra dependency.
"""
import json
import os
import sys

import pytest

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "semgrep_sample.json")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "etl"))


from etl.parse_semgrep import (
    parse_semgrep_json,
    sast_fingerprint,
    findings_to_attack_surface,
    _classify_vuln,
    _extract_endpoint_hint,
    _extract_param_hint,
)


@pytest.fixture
def sample_data():
    with open(FIXTURE) as f:
        return json.load(f)


@pytest.fixture
def parsed(sample_data):
    return parse_semgrep_json(sample_data)


class TestParser:
    def test_parse_count(self, parsed):
        assert len(parsed) == 6

    def test_severity_normalization(self, parsed):
        sev_map = {f["rule_id"].split(".")[-1]: f["severity"] for f in parsed}
        assert parsed[0]["severity"] == "high"  # ERROR -> high
        assert parsed[2]["severity"] == "medium"  # WARNING -> medium

    def test_vuln_class_from_cwe(self, parsed):
        by_rule = {f["rule_id"]: f["vuln_class"] for f in parsed}
        assert by_rule["python.lang.security.audit.dangerous-system-call.dangerous-system-call"] == "cmdi"
        assert by_rule["python.django.security.injection.sql.sql-injection-using-raw.sql-injection-using-raw"] == "sqli"
        assert by_rule["javascript.express.security.audit.xss.mustache-escape.template-unescaped-with-var"] == "xss"
        assert by_rule["python.flask.security.injection.ssrf-requests.ssrf-requests"] == "ssrf"
        assert by_rule["python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load"] == "deserialization"

    def test_hardcoded_secret_class(self, parsed):
        secret_findings = [f for f in parsed if f["vuln_class"] == "hardcoded-secret"]
        assert len(secret_findings) == 1
        assert "API_KEY" in secret_findings[0]["matched_code"]

    def test_cwe_extracted(self, parsed):
        sqli = [f for f in parsed if f["vuln_class"] == "sqli"][0]
        assert any("89" in c for c in sqli["cwe"])

    def test_file_path_preserved(self, parsed):
        paths = [f["file_path"] for f in parsed]
        assert "app/views/admin.py" in paths
        assert "app/views/search.py" in paths

    def test_line_numbers(self, parsed):
        cmdi = [f for f in parsed if f["vuln_class"] == "cmdi"][0]
        assert cmdi["line_start"] == 42
        assert cmdi["line_end"] == 42

    def test_version_captured(self, parsed):
        for f in parsed:
            assert f["semgrep_version"] == "1.96.0"

    def test_matched_code_present(self, parsed):
        for f in parsed:
            assert f["matched_code"], f"Empty matched_code for {f['rule_id']}"


class TestFingerprint:
    def test_stable(self):
        fp1 = sast_fingerprint("rule.a", "file.py", 10, "code()")
        fp2 = sast_fingerprint("rule.a", "file.py", 10, "code()")
        assert fp1 == fp2

    def test_differs_on_rule(self):
        fp1 = sast_fingerprint("rule.a", "file.py", 10, "code()")
        fp2 = sast_fingerprint("rule.b", "file.py", 10, "code()")
        assert fp1 != fp2

    def test_differs_on_line(self):
        fp1 = sast_fingerprint("rule.a", "file.py", 10, "code()")
        fp2 = sast_fingerprint("rule.a", "file.py", 11, "code()")
        assert fp1 != fp2

    def test_length(self):
        fp = sast_fingerprint("rule", "file", 1, "x")
        assert len(fp) == 40


class TestClassifyVuln:
    def test_cwe_priority(self):
        assert _classify_vuln("random.rule", ["CWE-89"], "") == "sqli"
        assert _classify_vuln("random.rule", ["CWE-79"], "") == "xss"

    def test_rule_id_fallback(self):
        assert _classify_vuln("security.sql-injection.check", [], "") == "sqli"
        assert _classify_vuln("audit.command-injection.os", [], "") == "cmdi"

    def test_message_fallback(self):
        assert _classify_vuln("generic.rule", [], "possible ssrf via user input") == "ssrf"

    def test_other_default(self):
        assert _classify_vuln("unknown.thing", [], "some random warning") == "other"


class TestAttackSurface:
    def test_structure(self, parsed):
        surface = findings_to_attack_surface(parsed)
        assert "vuln_classes" in surface
        assert "injection_points" in surface
        assert "hardcoded_secrets" in surface
        assert "attack_vectors" in surface
        assert surface["total_findings"] == 6

    def test_vuln_classes_present(self, parsed):
        surface = findings_to_attack_surface(parsed)
        assert "sqli" in surface["vuln_classes"]
        assert "cmdi" in surface["vuln_classes"]
        assert "xss" in surface["vuln_classes"]

    def test_injection_points_sorted_by_severity(self, parsed):
        surface = findings_to_attack_surface(parsed)
        points = surface["injection_points"]
        severities = [p["severity"] for p in points]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for i in range(len(severities) - 1):
            assert order.get(severities[i], 5) <= order.get(severities[i + 1], 5)

    def test_hardcoded_secrets_extracted(self, parsed):
        surface = findings_to_attack_surface(parsed)
        assert len(surface["hardcoded_secrets"]) == 1
        assert "config/settings.py" in surface["hardcoded_secrets"][0]["file"]

    def test_attack_vectors_grouped(self, parsed):
        surface = findings_to_attack_surface(parsed)
        classes = [v["vuln_class"] for v in surface["attack_vectors"]]
        assert "sqli" in classes


class TestEndpointHint:
    def test_route_decorator(self):
        f = {"file_path": "app.py", "matched_code": "@app.get('/api/users')"}
        assert _extract_endpoint_hint(f) == "/api/users"

    def test_express_route(self):
        f = {"file_path": "routes.js", "matched_code": "router.post('/login', handler)"}
        assert _extract_endpoint_hint(f) == "/login"

    def test_views_path(self):
        f = {"file_path": "app/views/admin.py", "matched_code": "x = 1"}
        hint = _extract_endpoint_hint(f)
        assert hint is not None
        assert "admin" in hint

    def test_no_hint(self):
        f = {"file_path": "utils/helper.py", "matched_code": "x = 1"}
        assert _extract_endpoint_hint(f) is None


class TestParamHint:
    def test_flask_request(self):
        f = {"matched_code": "request.args.get('host')"}
        assert _extract_param_hint(f) == "host"

    def test_flask_request_dquote(self):
        f = {"matched_code": 'request.args.get("url")'}
        assert _extract_param_hint(f) == "url"

    def test_express_body(self):
        f = {"matched_code": "req.body.username"}
        assert _extract_param_hint(f) == "username"

    def test_php_get(self):
        f = {"matched_code": "$_GET['page']"}
        assert _extract_param_hint(f) == "page"

    def test_no_param(self):
        f = {"matched_code": "print('hello')"}
        assert _extract_param_hint(f) is None


class TestInputFormats:
    def test_bare_list(self, sample_data):
        results = parse_semgrep_json(sample_data["results"])
        assert len(results) == 6

    def test_json_string(self, sample_data):
        results = parse_semgrep_json(json.dumps(sample_data))
        assert len(results) == 6

    def test_empty_input(self):
        assert parse_semgrep_json({}) == []
        assert parse_semgrep_json([]) == []
        assert parse_semgrep_json('{"results": []}') == []
