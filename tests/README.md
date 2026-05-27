# RAG Scan Stack - Security Tests

This directory contains unit tests for security fixes implemented in the RAG Scan Stack.

## Test Coverage

### test_validation.py

Tests for **SECURITY-1: Path Traversal Vulnerability** fixes.

**Coverage:**
- Scan ID validation (prevents `../../etc/passwd` attacks)
- Filename sanitization (removes path components)
- Output path validation (prevents directory escape)
- Target validation (prevents SSRF attacks)
- Port sanitization (prevents invalid ports)
- Command argument validation (prevents command injection)

**Attack Scenarios Tested:**
- Path traversal in nmap scanner scan_ids
- Path traversal in masscan output files
- SSRF attacks against AWS metadata endpoint (169.254.169.254)
- SSRF attacks against internal/private IPs
- Command injection via port parameters
- Shell metacharacter injection

## Running Tests

### Prerequisites

Install pytest:
```bash
pip install pytest
```

### Run All Tests

```bash
# From project root
python -m pytest tests/test_validation.py -v

# Or from tests directory
cd tests
pytest test_validation.py -v
```

### Run Specific Test Class

```bash
pytest tests/test_validation.py::TestScanIDSanitization -v
pytest tests/test_validation.py::TestTargetValidation -v
```

### Run Specific Test

```bash
pytest tests/test_validation.py::TestScanIDSanitization::test_path_traversal_blocked -v
```

### Generate Coverage Report

```bash
pip install pytest-cov
pytest tests/test_validation.py --cov=common.validation --cov-report=html
```

## Test Results Expected

All tests should PASS, indicating that:
- ✅ Path traversal attacks are blocked
- ✅ Command injection attempts are blocked
- ✅ SSRF attacks are prevented
- ✅ Invalid inputs are rejected
- ✅ Valid inputs pass through correctly

## Adding New Tests

When adding new security fixes:

1. Create test class for the vulnerability type
2. Add positive tests (valid inputs should work)
3. Add negative tests (attacks should be blocked)
4. Add integration tests (real-world attack scenarios)

Example:
```python
class TestNewFeatureSecurity:
    """Test security for new feature"""

    def test_valid_input(self):
        """Valid input should work"""
        result = new_function("valid_input")
        assert result == expected_output

    def test_attack_blocked(self):
        """Malicious input should be blocked"""
        with pytest.raises(ValidationError):
            new_function("malicious_input")
```

## CI/CD Integration

These tests should be run:
- Before every commit (pre-commit hook)
- In CI/CD pipeline (GitHub Actions, etc.)
- Before deployment to production

Example GitHub Actions workflow:
```yaml
name: Security Tests

on: [push, pull_request]

jobs:
  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      - name: Install dependencies
        run: |
          pip install pytest
      - name: Run security tests
        run: |
          pytest tests/test_validation.py -v
```

## Security Test Checklist

When implementing security fixes, ensure tests cover:

- [ ] Valid inputs pass correctly
- [ ] Invalid inputs are rejected with appropriate errors
- [ ] Path traversal attacks are blocked
- [ ] Command injection is prevented
- [ ] SQL injection is prevented (if applicable)
- [ ] SSRF attacks are blocked
- [ ] XSS attacks are sanitized (if applicable)
- [ ] Rate limiting works (if applicable)
- [ ] Authentication is required (if applicable)
- [ ] Authorization is enforced (if applicable)

## Related Documentation

- `/opt/rag-scan-stack/COMPREHENSIVE_ANALYSIS.md` - Full security analysis
- `/opt/rag-scan-stack/SECURITY_SETUP.md` - Credential management guide
- `/opt/rag-scan-stack/common/validation.py` - Validation utility module

## Contact

For security issues, please report privately to the security team.
