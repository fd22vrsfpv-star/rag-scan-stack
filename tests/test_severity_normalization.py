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


def test_zap_adds_discovered_sites_to_scope_before_scanning():
    """gobuster/katana-discovered URLs must be put in a ZAP context/scope and the
    seeds spidered BEFORE the active scan — otherwise ascan only attacks the base
    URL and the app-layer surface (DVWA/Mutillidae) is never tested. Guards the
    zap_scan_with_urls scope+spider wiring. Sabotage: drop include_in_context, or
    spider only the base -> fails."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parents[1] / "web_scanner" / "web_scan.py").read_text(encoding="utf-8")

    def _slice(name):
        body = src[src.index(f"def {name}("):]
        return body[:body.index("\ndef ", 1)]

    # zap_scan_with_urls now only builds the client and delegates: the scope and
    # spider wiring lives in _zap_scan_with_urls_inner, which runs inside
    # bounded_zap_http() so no ZAP API call can block for ever. Both halves are
    # the same code path, so the guard reads both.
    # _run_active_pass is the third half: the active scan was split into
    # per-category passes, so ascan.scan() and its inscopeonly flag now live
    # there rather than inline in _zap_scan_with_urls_inner.
    fn = (_slice("zap_scan_with_urls") + _slice("_zap_scan_with_urls_inner")
          + _slice("_run_active_pass"))
    assert "bounded_zap_http" in fn, (
        "the ZAP scan path must run inside bounded_zap_http() — the zapv2 client "
        "issues every API call with no timeout and will otherwise hang for ever")
    assert "include_in_context" in fn, "discovered sites must be added to a ZAP context/scope"
    assert "for s in seeds" in fn, "each seed (not just the base) must be spidered"
    assert "inscopeonly=True" in fn, "active scan must run over the in-scope tree"
    # and the pipeline seeds known vulnerable apps generic wordlists miss
    assert "_seed_known_apps" in src and "_KNOWN_VULN_APP_PATHS" in src, (
        "the pipeline must seed known vulnerable-app roots (DVWA/Mutillidae/...)")


def test_playwright_covers_the_second_client_side_tier():
    """Tier 3b: CLNT-03/05/06/08. Each needs a signal in dom_analyzer, an emitter
    in security_checks, AND a rule in the coverage map — a signal with no rule is
    collected and never credited, and a rule with no signal inflates nothing but
    reads as covered work that does not exist.

    CLNT-03 must key on REFLECTION, not the innerHTML sinks: those are already
    CLNT-01, and crediting one observation to two ids raises the number without
    testing anything more."""
    import pathlib
    repo = pathlib.Path(__file__).resolve().parents[1]
    dom = (repo / "playwright_scanner" / "dom_analyzer.py").read_text(encoding="utf-8")
    sc = (repo / "playwright_scanner" / "security_checks.py").read_text(encoding="utf-8")
    cov = (repo / "knowledge" / "wstg_coverage_map.yaml").read_text(encoding="utf-8")

    for signal in ("reflectedParams", "cssSinks", "resourceSinks", "flashObjects"):
        assert signal in dom, f"dom_analyzer does not collect {signal}"
    for ft in ("html-injection-reflected", "css-injection-sink",
               "client-resource-manipulation", "flash-object"):
        assert ft in sc, f"security_checks does not emit {ft}"
    for wid in ("CLNT-03", "CLNT-05", "CLNT-06", "CLNT-08"):
        assert wid in sc, f"check_client_side must name WSTG-{wid}"
        assert wid in cov, f"the coverage map has no rule for WSTG-{wid}"

    # CLNT-03 must not simply re-report the CLNT-01 sinks. Anchor on the EMITTER
    # (the finding title), not on the first mention of the id — that is in the
    # docstring, which is what an earlier version of this assertion matched.
    i = sc.index("(WSTG-CLNT-03)")
    block = sc[max(0, i - 700):i]
    assert "reflectedParams" in block, (
        "CLNT-03 is not driven by reflection — if it keys on the innerHTML sinks "
        "it is reporting the CLNT-01 signal twice"
    )
    assert "domSinks" not in block, (
        "the CLNT-03 emitter reads domSinks, which is the CLNT-01 signal"
    )


def test_playwright_covers_client_side_wstg():
    """Tier 3: the Playwright scanner must emit the client-side WSTG family
    (CLNT-01/02/10/11/12/13) from live-browser signals, and the coverage map must
    classify those findings. Sabotage: drop check_client_side or the CLNT rules."""
    import pathlib
    repo = pathlib.Path(__file__).resolve().parents[1]
    sc = (repo / "playwright_scanner" / "security_checks.py").read_text(encoding="utf-8")
    assert "def check_client_side(" in sc, "SecurityChecker must have check_client_side"
    for wid in ("CLNT-01", "CLNT-02", "CLNT-10", "CLNT-11", "CLNT-12", "CLNT-13"):
        assert wid in sc, f"check_client_side must emit WSTG-{wid}"
    # the analyzer collects the signals in the live browser
    da = (repo / "playwright_scanner" / "dom_analyzer.py").read_text(encoding="utf-8")
    assert "get_client_security_signals" in da, "DOMAnalyzer must collect client signals"
    # the coverage map classifies the client-side findings
    import yaml
    cov = yaml.safe_load((repo / "knowledge" / "wstg_coverage_map.yaml").read_text(encoding="utf-8"))
    clnt = {r["wstg_id"] for r in cov["rules"] if r["wstg_id"].endswith(("CLNT-01","CLNT-10","CLNT-11","CLNT-12"))}
    assert {"WSTG-CLNT-01","WSTG-CLNT-10","WSTG-CLNT-11","WSTG-CLNT-12"} <= clnt, "coverage map must classify CLNT findings"


def test_wstg_manual_checklist_feeds_coverage():
    """Tier 4: the 25 manual WSTG tests get an operator checklist (backed by
    ingested guidance) and a review sign-off that COUNTS toward coverage.
    Sabotage: drop the reviewed_ids handling in compute(), or the endpoints."""
    import pathlib
    repo = pathlib.Path(__file__).resolve().parents[1]
    api = (repo / "app" / "rag-api" / "api.py").read_text(encoding="utf-8")
    assert '/wstg/checklist/{engagement_id}' in api, "checklist endpoint missing"
    assert 'wstg_manual_reviews' in api, "review must persist to wstg_manual_reviews"
    assert "doc_kind='wstg'" in api, "checklist must attach ingested WSTG guidance"
    wc = (repo / "app" / "rag-api" / "wstg_coverage.py").read_text(encoding="utf-8")
    assert "reviewed_ids" in wc and "manual_reviewed" in wc, (
        "compute() must count reviewed manual tests as covered")
    # table declared in db_init (SQL-column guard also enforces this)
    ddl = (repo / "db_init" / "ensure_all_tables.sql").read_text(encoding="utf-8")
    assert "wstg_manual_reviews" in ddl, "table must be declared in db_init"
