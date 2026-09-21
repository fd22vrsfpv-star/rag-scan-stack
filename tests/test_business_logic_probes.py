"""Guard: business-logic web probes (POST-body IDOR + value tampering).

Verifies the RAG data (business_logic_tests.yaml), the response oracle behavior
on real-shape fixtures, and that both probes are wired into the authenticated
crawl. The probe functions themselves need Playwright + a DB, so the oracle is
exercised through the SAME markers the probe loads from the YAML (data + logic
contract), and the wiring is checked at the source level.

Sabotage-proven: weaken an oracle marker set or drop a wire and a case flips.
Self-contained; needs only pyyaml.
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).parent))
from _ast_assert import (defines, calls, call_kwarg, call_order,  # noqa: E402
                         string_constants)
PW = ROOT / "playwright_scanner/playwright_scanner.py"
yaml = pytest.importorskip("yaml")


def _cfg():
    return yaml.safe_load((ROOT / "knowledge/business_logic_tests.yaml").read_text())["business_logic_tests"]


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


# ── YAML data contract ───────────────────────────────────────────────────────

def test_yaml_has_idor_value_and_oracle():
    d = _cfg()
    assert any("account" in n.lower() for n in d["idor"]["name_patterns"])
    assert -1 in [int(x) for x in d["idor"]["mutations"]]
    vals = d["value_tamper"]["values"]
    assert any(str(v).startswith("-") for v in vals), "must include a NEGATIVE tamper value"
    assert "0" in [str(v) for v in vals], "must include zero"
    assert any(m.lower() in ("amount", "transferamount", "price", "qty", "quantity")
               for m in d["value_tamper"]["name_patterns"])
    o = d["oracle"]
    assert o["blocked_markers"] and o["success_markers"] and o["error_markers"]


# ── oracle behavior (the markers the probe loads) ────────────────────────────

def _blocked(body):
    return any(m.lower() in body.lower() for m in _cfg()["oracle"]["blocked_markers"])


def _tamper_flags(baseline, resp, minb=500):
    o = _cfg()["oracle"]
    succ = [m.lower() for m in o["success_markers"]]
    errm = [m.lower() for m in o["error_markers"]]
    low = resp.lower()
    return (len(resp) > minb and not _blocked(resp)
            and any(m in low for m in succ) and not any(m in low for m in errm)
            and resp != baseline)


LOGIN = '<form><input type="password" name="passw"></form> Please log in'
ACCOUNT = '<a id="LoginLink" href="/logout.jsp">Sign Off</a> Account 800001 Balance $10 ' + "x" * 600
SUCCESS = "Transfer complete. The amount has been transferred. " + "y" * 600
VALIDATION = "Error: transfer amount must be greater than zero (invalid). " + "z" * 600


def test_blocked_oracle_distinguishes_login_from_data():
    assert _blocked(LOGIN) is True
    assert _blocked(ACCOUNT) is False


def test_value_tamper_flags_success_not_validation_error():
    base = "Enter a transfer amount. " + "b" * 600
    # a negative amount ACCEPTED (success markers, no error) -> flag
    assert _tamper_flags(base, SUCCESS) is True
    # a negative amount REJECTED (validation error) -> no flag
    assert _tamper_flags(base, VALIDATION) is False
    # identical-to-baseline response (testfire doTransfer shape) -> no flag
    assert _tamper_flags(SUCCESS, SUCCESS) is False
    # a login/blocked response -> no flag
    assert _tamper_flags(base, LOGIN + "q" * 600) is False


# ── source wiring (structural — see tests/_ast_assert) ───────────────────────
#
# These previously pinned source substrings like "'value_tamper','business_logic'"
# and "_bl_discovered_paths(cur, host, root)" — exact argument spellings that a
# reformat breaks and a comment satisfies. They now assert the structure.

def test_post_body_idor_wired():
    assert defines(PW, "_idor_post_body_pass"), "POST-body object refs need their own pass"
    assert calls(PW, "_idor_post_body_pass"), "the IDOR probe must actually call it"
    assert defines(PW, "_bl_body_params"), "the POST body is reconstructed from discovered_params"
    assert any("param_location" in c and "body" in c for c in string_constants(PW)), \
        "body params are selected by param_location"
    assert any("POST body" in c for c in string_constants(PW)), \
        "the finding must name itself as a POST-body IDOR"


def test_value_tamper_probe_wired_into_crawl():
    assert defines(PW, "_value_tamper_probe")
    assert call_order(PW, "_idor_mutate_probe", "_value_tamper_probe", within="_perform_crawl"), \
        "the value-tamper probe runs in the authenticated crawl, after the IDOR probe"
    consts = string_constants(PW)
    assert any("value_tamper" in c for c in consts) and any("business_logic" in c for c in consts), \
        "findings are recorded with source=value_tamper / issue_type=business_logic"
    # replayed in the authenticated context so the session is reused
    assert calls(PW, "request.post") or calls(PW, "post"), "must replay POSTs"


def test_probes_are_data_driven_by_yaml():
    assert defines(PW, "_bl_config"), "probe data comes from YAML, not literals in code"
    assert any(c.endswith("business_logic_tests.yaml") for c in string_constants(PW)), \
        "the YAML that drives the probes must be named"


def test_forced_browsing_wired():
    d = _cfg()
    fb = d["forced_browsing"]
    assert fb["privileged_paths"] and any("admin" in p.lower() for p in fb["privileged_paths"])
    assert any("/bank" in p.lower() for p in fb["authenticated_path_patterns"])

    assert defines(PW, "_forced_browsing_probe")
    assert calls(PW, "_forced_browsing_probe"), "must run in the crawl"
    consts = string_constants(PW)
    assert any("forced_browsing" in c for c in consts) and any("access_control" in c for c in consts), \
        "findings recorded as source=forced_browsing / issue_type=access_control"
    # anonymous: a redirect means the resource IS enforced, so following one
    # would turn a protected page into a false positive.
    assert call_kwarg(PW, "AsyncClient", "follow_redirects"), \
        "the anonymous client must not follow redirects"
    # every anonymous request is scope-gated
    assert calls(PW, "_scope_refusal_for_url"), "anon requests must be scope-gated"
    # and it consumes what the content-discovery tools already found
    assert defines(PW, "_bl_discovered_paths")
    assert calls(PW, "_bl_discovered_paths"), "gobuster/ffuf discoveries feed the anon check"
    for tool in ("ffuf", "gobuster", "feroxbuster"):
        assert any(tool in c for c in consts), f"{tool} discoveries must be a source of candidates"


def test_wstg_map_covers_probe_findings():
    """The surface-test tier maps a finding to WSTG guidance by issue_type; the new
    BUSL/ATHZ entries must match exactly what the probes emit, or the LLM tier
    never authors a business-logic confirmation test for them."""
    m = yaml.safe_load((ROOT / "knowledge/wstg_map.yaml").read_text())
    entries = m if isinstance(m, list) else next((v for v in m.values() if isinstance(v, list)), [])
    by_id = {e["id"]: e for e in entries if isinstance(e, dict) and "id" in e}
    # value_tamper probe emits issue_type='business_logic'
    assert "business_logic" in by_id["business_logic_value"]["match"]["issue_type"]
    assert "WSTG-BUSL-01" in by_id["business_logic_value"]["wstg_id"]
    # forced_browsing probe emits issue_type='access_control'
    assert "access_control" in by_id["access_control_forced_browsing"]["match"]["issue_type"]
    assert "WSTG-ATHZ-02" in by_id["access_control_forced_browsing"]["wstg_id"]
    # POST-body IDOR emits issue_type='idor' — already covered by the idor entry
    assert "idor" in by_id["idor"]["match"]["issue_type"]


def test_rag_renderer_present():
    s = _src("etl/load_knowledge_documents.py")
    assert "_render_business_logic_tests" in s
    assert '"business_logic_tests": _render_business_logic_tests' in s


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
