"""Read-only MSF auxiliary scanners must take the SAFE lane, not human approval.

Run on demand (inside autogen-agents, which has the deps):

    pytest tests/test_msf_readonly_scanners_are_safe.py -v

WHY THIS EXISTS
---------------
A robots.txt fetch (auxiliary/scanner/http/robots_txt), a version/header grab, a
cert read and a directory listing are purely informational HTTP/TLS retrievals —
curl/sslscan/gobuster can do them. They were queued as IMPACTFUL metasploit tests
requiring human approval and an MSF session, so the operator had to approve a
robots.txt fetch. _safe_alt_for_msf maps these to their read-only equivalent so
_classify puts them in the SAFE autonomous lane. Anything that authenticates,
brute-forces, writes or executes stays IMPACTFUL (fail-safe by omission).

SABOTAGE PROOF
--------------
Drop robots_txt from _safe_alt_for_msf's table and test_readonly_scanner_is_safe
fails; add http_login to it and test_login_and_exploit_stay_impactful fails.
"""
import pytest

le = pytest.importorskip(
    "langgraph_engine",
    reason="autogen deps not present in this tier — run inside autogen-agents",
)

IP, PORT, SCHEME = "10.0.0.5", 80, "http"


@pytest.mark.parametrize("module", [
    "auxiliary/scanner/http/robots_txt",
    "auxiliary/scanner/http/http_version",
    "auxiliary/scanner/http/dir_scanner",
    "auxiliary/scanner/http/files_dir",
    "auxiliary/scanner/http/cert",
])
def test_readonly_scanner_is_safe(module):
    alt = le._safe_alt_for_msf(module, IP, PORT, SCHEME)
    assert alt is not None, f"{module} should map to a safe equivalent"
    category, command = alt
    # The safe equivalent uses an allowlisted read-only tool …
    assert le._tool_head(command) in le._SAFE_TOOL_HINTS, command
    # … and classifies into the autonomous SAFE lane (no exploit ref).
    assert le._classify(category, command, has_exploit_ref=False) == "safe", (category, command)


@pytest.mark.parametrize("module", [
    "auxiliary/scanner/http/http_login",     # credential brute — active
    "auxiliary/scanner/http/tomcat_mgr_login",
    "auxiliary/scanner/http/jenkins_enum",
    "exploit/multi/http/php_cgi_arg_injection",  # real RCE
])
def test_login_and_exploit_stay_impactful(module):
    assert le._safe_alt_for_msf(module, IP, PORT, SCHEME) is None, (
        f"{module} authenticates/executes — it must stay IMPACTFUL, not be "
        "auto-run in the safe lane.")


def test_robots_txt_is_a_curl_get():
    cat, cmd = le._safe_alt_for_msf("auxiliary/scanner/http/robots_txt", IP, PORT, SCHEME)
    assert le._tool_head(cmd) == "curl" and "robots.txt" in cmd, cmd
