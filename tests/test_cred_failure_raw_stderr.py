"""A failed credential attempt must carry the tool's RAW output to the audit.

WHY THIS EXISTS
---------------
The open item "most services never produce a usable failure signature" traced to
the raw output being discarded once `cred_checker._classify_hydra_failure`
returned ``"unknown"``: only the coarse ``failure_mode`` label and a ~180-char
salient excerpt survived, so telnet/mysql/postgres/vnc failures the classifier
did not recognise all hashed to the same ``failure_signature`` and the learner
had nothing to distinguish.

The fix carries the RAW tool output (best-effort redacted, capped) into the
per-attempt audit record as ``raw_stderr``, and `_method_error_text` prefers it,
so ``error_signature()`` is computed from what the tool actually said.

SABOTAGE PROOF
--------------
- Delete the ``attempt["raw_stderr"] = _raw_failure_output(...)`` assignment in
  `_check_credentials_slotted` -> ``raw_stderr`` stays ``None`` and
  ``test_unknown_failure_carries_raw_output`` fails (``None`` is not a str).
- Make `_raw_failure_output` return ``""`` -> the same test fails.
- Drop the ``raw_stderr`` branch from `_method_error_text` -> the raw text no
  longer reaches the signature input and ``test_method_error_text_prefers_raw``
  fails.
"""
import ast
import importlib.util
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CRED = os.path.join(REPO, "nmap_scanner", "cred_checker.py")


# A realistic hydra "unknown" failure: the constant banner (which used to BE the
# 180-char excerpt for every service) followed by a protocol-level error the
# classifier recognises as none of kex / connection / auth.  The login line
# echoes the pair that was tried, so it also exercises redaction.
UNKNOWN_MYSQL_STDERR = (
    "Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - for legal "
    "purposes only. Hydra (https://github.com/vanhauser-thc/thc-hydra) "
    "starting at 2026-09-21 22:00:00\n"
    "[DATA] attacking mysql://172.18.0.32:3306/\n"
    "[3306][mysql] host: 172.18.0.32   login: root   password: s3cr3tpw\n"
    "[ERROR] mysql: unsupported authentication protocol requested by server; "
    "consider upgrading the MySQL client\n"
)


def _load_module():
    """Load cred_checker by file path; skip cleanly if it cannot be imported.

    cred_checker imports the scope gate inside a try/except, so a missing etl/
    mount does not break the import, but stay defensive: a skip says "cannot run
    here", not "broken"."""
    if not os.path.exists(CRED):
        pytest.skip("cred_checker.py not present")
    spec = importlib.util.spec_from_file_location("cred_checker_under_test", CRED)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:  # pragma: no cover - deployment-dependent
        pytest.skip(f"cred_checker not importable here: {e}")
    return mod


class _FakeProc:
    def __init__(self, stdout="", stderr=""):
        self.stdout = stdout
        self.stderr = stderr


def test_raw_failure_output_keeps_diagnostic_redacts_and_caps():
    """The helper preserves the raw text, masks the password, and never raises."""
    m = _load_module()
    got = m._raw_failure_output(UNKNOWN_MYSQL_STDERR, "root", "s3cr3tpw")
    assert "unsupported authentication protocol" in got, (
        f"the diagnostic line was dropped from the raw excerpt: {got!r}")
    assert "s3cr3tpw" not in got, f"the password survived into raw_stderr: {got!r}"
    # Bounded to RAW_STDERR_CHARS, and much larger than the 180-char excerpt.
    big = "x" * 5000
    assert len(m._raw_failure_output(big)) == m.RAW_STDERR_CHARS
    assert m.RAW_STDERR_CHARS > 180
    # Never raises into the cred-check flow, whatever it is handed.
    assert m._raw_failure_output(None) == ""
    assert m._raw_failure_output("") == ""


def test_unknown_failure_carries_raw_output(monkeypatch):
    """The record-building path: an 'unknown' hydra failure must reach the audit
    with its raw output, not just the coarse failure_mode label."""
    m = _load_module()
    monkeypatch.setattr(
        m.subprocess, "run",
        lambda *a, **k: _FakeProc(stdout="", stderr=UNKNOWN_MYSQL_STDERR))

    _results, audit = m._check_credentials_slotted(
        "172.18.0.32", 3306, "mysql", [("root", "s3cr3tpw")], timeout=1)

    assert audit["attempts"], "no attempt was recorded"
    attempt = audit["attempts"][0]
    assert attempt["success"] is False
    # The classification is preserved, NOT replaced ...
    assert attempt["failure_mode"] == "unknown"
    # ... and the raw output is carried ALONGSIDE it.
    assert isinstance(attempt["raw_stderr"], str) and attempt["raw_stderr"], (
        "raw_stderr was discarded for an 'unknown' failure — the learner has "
        "nothing to distinguish this service from any other")
    assert "unsupported authentication protocol" in attempt["raw_stderr"], (
        f"the raw diagnostic did not reach the audit: {attempt['raw_stderr']!r}")
    assert "s3cr3tpw" not in attempt["raw_stderr"], "password leaked into the audit"


def test_method_error_text_prefers_raw(monkeypatch):
    """The signature input is built from raw_stderr when present, so what the tool
    actually said drives error_signature()."""
    m = _load_module()
    m_audit = {
        "method": "hydra",
        "attempts": [{
            "username": "root",
            "success": False,
            "failure_mode": "unknown",
            "error_excerpt": "attempt failed: unknown",
            "raw_stderr": "[ERROR] mysql: unsupported authentication protocol",
        }],
    }
    text = m._method_error_text(m_audit)
    assert "unsupported authentication protocol" in text, (
        "the raw output is not fed to the signature, so unknown failures still "
        f"collapse to one bucket: {text!r}")


def test_module_parses():
    """Guard against a syntax defect that ast alone would miss at runtime."""
    ast.parse(open(CRED, encoding="utf-8").read())


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
