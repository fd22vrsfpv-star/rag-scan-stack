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
