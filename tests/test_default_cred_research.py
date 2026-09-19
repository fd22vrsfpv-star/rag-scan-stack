"""Default-credential WEB RESEARCH: DuckDuckGo + LLM, proxy-configurable, with an
LLM-web-search backup; discovered pairs stored as UNVALIDATED accounts.

Run on demand:

    pytest tests/test_default_cred_research.py -v

WHY THIS EXISTS
---------------
For any item in the software inventory (tomcat, apache, wordpress, an app
fingerprint like 'Altoro Mutual'), the platform researches documented DEFAULT
credentials on the web (DuckDuckGo + LLM), stores them as UNVALIDATED accounts,
and feeds them to the default-credential check — so app-specific creds are
DISCOVERED, not hardcoded. Includes: a fixed ddg_search (the lite endpoint now
answers 202→empty; use the html POST endpoint), a configurable egress proxy
(web_research.proxy), and an LLM-as-web-search backup routed via task='web_search'.

SABOTAGE PROOF
--------------
- Revert ddg_search to only the lite GET / reject 202 → test_ddg_uses_html_endpoint fails.
- Remove the task='web_search' backup → test_llm_websearch_backup fails.
- Drop the proxy setting → test_proxy_configurable fails.
- Remove the check's research call → test_check_uses_research fails.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")
CHECK = os.path.join(REPO, "etl", "default_cred_check.py")


def _src(p):
    if not os.path.exists(p):
        pytest.skip(f"{p} missing")
    return open(p, encoding="utf-8").read()


def test_ddg_uses_html_endpoint_and_tolerates_202():
    s = _src(API)
    assert "html.duckduckgo.com/html/" in s, "ddg_search must use the html POST endpoint"
    assert "requests.post(\"https://html.duckduckgo.com/html/\"" in s
    assert "result__a" in s and "result__snippet" in s, "must parse the html result blocks"
    # lite fallback accepts 202 (the anti-bot interstitial) rather than returning nothing
    assert "(200, 202)" in s, "lite fallback must accept 200/202"


def test_proxy_configurable():
    s = _src(API)
    assert 'web_research.proxy' in s, "the DDG egress proxy must be an operator setting"
    fn = next(n for n in ast.walk(ast.parse(s)) if isinstance(n, ast.FunctionDef) and n.name == "ddg_search")
    body = ast.get_source_segment(s, fn)
    assert '_get_setting("web_research.proxy"' in body, "ddg_search must read the proxy setting"


def test_research_and_websearch_backup():
    s = _src(API)
    assert "def research_default_credentials" in s
    fn = next(n for n in ast.walk(ast.parse(s)) if isinstance(n, ast.FunctionDef) and n.name == "research_default_credentials")
    body = ast.get_source_segment(s, fn)
    assert "ddg_search(" in body, "primary path is DuckDuckGo"
    assert 'task="web_search"' in body or "task='web_search'" in body, \
        "must have the routable LLM-as-web-search backup (task='web_search')"


def test_stores_unvalidated_candidates():
    s = _src(API)
    assert "def _store_researched_cred_candidates" in s
    fn = next(n for n in ast.walk(ast.parse(s)) if isinstance(n, ast.FunctionDef) and n.name == "_store_researched_cred_candidates")
    body = ast.get_source_segment(s, fn)
    assert "credential_findings" in body and "false" in body and "'unvalidated'" in body, \
        "researched pairs must be stored as UNVALIDATED credential candidates"
    assert "detected_software" in body, "candidates are stored for assets running the product"


def test_software_research_pulls_default_creds():
    s = _src(API)
    # the software research (_do_ddg_search) also pulls default creds
    assert "research_default_credentials(product, version)" in s
    assert "_store_researched_cred_candidates(product, version" in s
    # on-demand endpoint
    assert '"/software/default-credentials"' in s


def test_check_uses_research():
    s = _src(CHECK)
    assert "def _research_host_default_creds" in s
    assert "_research_host_default_creds(cur, host, html)" in s, "the check must research this host's app defaults"
    assert "/software/default-credentials" in s, "the check calls the research endpoint"
    # researched candidates come before the static set
    assert "researched + candidate_pairs" in s
