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
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
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


# ── source wiring ────────────────────────────────────────────────────────────

def test_post_body_idor_wired():
    s = _src("playwright_scanner/playwright_scanner.py")
    assert "async def _idor_post_body_pass(" in s
    assert "_idor_post_body_pass(ctx, host" in s, "POST-body pass must be called from the IDOR probe"
    assert "'Potential IDOR (object reference, POST body)'" in s
    # reconstructs the full body from discovered_params
    assert "def _bl_body_params(" in s and "param_location='body'" in s


def test_value_tamper_probe_wired_into_crawl():
    s = _src("playwright_scanner/playwright_scanner.py")
    assert "async def _value_tamper_probe(" in s
    assert "_value_tamper_probe(ctx, req.url" in s, "value-tamper probe must run in the crawl"
    assert "'value_tamper','business_logic'" in s
    # runs authenticated via the context request (shares cookies)
    assert "ctx.request.post(" in s and "ctx.request.get(" in s


def test_probes_are_data_driven_by_yaml():
    s = _src("playwright_scanner/playwright_scanner.py")
    assert "business_logic_tests.yaml" in s
    assert "def _bl_config(" in s


def test_forced_browsing_wired():
    d = _cfg()
    fb = d["forced_browsing"]
    assert fb["privileged_paths"] and any("admin" in p.lower() for p in fb["privileged_paths"])
    assert any("/bank" in p.lower() for p in fb["authenticated_path_patterns"])
    s = _src("playwright_scanner/playwright_scanner.py")
    assert "async def _forced_browsing_probe(" in s
    assert "_forced_browsing_probe(" in s and "discovered_urls=list(visited)" in s
    assert "'forced_browsing','access_control'" in s
    # anonymous check: no cookies, don't follow redirects (a redirect = enforced)
    assert "follow_redirects=False" in s
    # every anonymous request is scope-gated
    assert '_scope_refusal_for_url(url, f"forced-browsing' in s
    # consumes gobuster/ffuf-discovered paths (content discovery) for the anon check
    assert "def _bl_discovered_paths(" in s
    assert "'ffuf','gobuster','feroxbuster'" in s
    assert "_bl_discovered_paths(cur, host, root)" in s


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
