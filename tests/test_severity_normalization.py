"""Guard: nuclei (and other nested-severity) findings must keep their real
severity through parse_tool_output, not collapse to 'info'.

Nuclei puts severity at info.severity, NOT top-level. A naive
rec.get("severity") fell through to the "info" default, so every nuclei
web_finding — including high/critical CVEs (CVE-2012-1823, CVE-2020-1938) — was
stored as info, hiding the exploitable ones behind a severity filter.

Source-read with no imports so it runs on a bare checkout.

Sabotage proof: drop `_rec_info.get("severity")` from the rec_severity
resolution -> this test goes RED.
"""
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]


def _parse_src() -> str:
    return (REPO / "etl" / "parse_tool_output.py").read_text(encoding="utf-8")


def test_nested_nuclei_severity_is_read():
    src = _parse_src()
    # the rec_severity resolution must consult the nested info.severity
    assert "_rec_info" in src and '_rec_info.get("severity")' in src, (
        "parse_tool_output must read nuclei's nested info.severity, or every "
        "nuclei finding stores as 'info' (the top-level severity key is absent)")
    # and it must still fall back to a default only AFTER trying the nested form
    i_nested = src.index('_rec_info.get("severity")')
    i_default = src.index('rec_severity = "info"')
    assert i_nested < i_default, (
        "the info-default must come AFTER the nested-severity read")


def test_curl_is_allowlisted_for_safe_web_tests():
    """The WSTG safe lane (lfi_read, header_check, tls_check) runs curl. If curl
    is not in the kali-listener allow-list, every such test skips [400]. Guards
    the fallback set. Sabotage: remove 'curl' -> fails."""
    import pathlib
    src = (REPO / "kali_listener" / "listener_service.py").read_text(encoding="utf-8")
    fset = src[src.index("_FALLBACK_ALLOWED_TOOLS"):]
    fset = fset[:fset.index("}")]
    assert '"curl"' in fset, "curl must be allow-listed for the WSTG safe lane"


def test_passing_test_confirms_its_source_finding():
    """A finding-driven test that PASSES must mark THAT scanner finding confirmed
    (verified by proof), closing the loop from 'new' to 'confirmed'. Guards the
    record_test_run UPDATE. Sabotage: remove the web_findings UPDATE -> fails."""
    import pathlib
    src = (REPO / "autogen_agents" / "db_utils.py").read_text(encoding="utf-8")
    fn = src[src.index("def record_test_run("):]
    nxt = fn.find("\ndef ", 1)
    fn = fn[:nxt] if nxt != -1 else fn   # record_test_run may be the last fn
    assert "source_finding_id" in fn, "record_test_run must read the test's source_finding_id"
    assert "UPDATE public.web_findings" in fn and "workflow_status = 'confirmed'" in fn, (
        "a passing finding-driven test must mark its source finding confirmed")
    # must only fire on a pass and never override operator triage
    assert 'status == "pass"' in fn, "confirm only on a genuine pass"
    assert "IN ('new','triaging')" in fn, "must not override an operator's own triage"
