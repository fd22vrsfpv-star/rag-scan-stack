"""Guard: the AI-agent-test "primarily a website" flag.

When an operator marks a session target as primarily a website, the session must
(a) cap the port scan at top-1000 (no 1-65535 deep sweep) and (b) kick the web
pipeline off at the START of the scan phase. This proves the flag is threaded end
to end (frontend form -> BFF -> autogen service -> LangGraph) and that the two
behaviors are wired.

Source-level guards (the LangGraph engine can't be imported in the slim test
container — heavy deps), plus a focused check of the port-profile default rule.
Sabotage-proven: drop any wire and the matching assertion fails.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


FIELD = "primarily_website"


def test_flag_threads_through_backend_chain():
    # autogen service request model + config + call + delegate
    s = _src("autogen_agents/autogen_service.py")
    assert f"{FIELD}: bool = Field(" in s, "PentestRequest must declare the flag"
    assert f'"{FIELD}": bool(request.{FIELD})' in s, "flag must be persisted in the session config"
    assert f"bool(request.{FIELD})" in s and f"{FIELD}=primarily_website" in s, \
        "flag must be forwarded to run_pentest_session_sync and on to the engine"


def test_bff_model_declares_flag():
    s = _src("dashboard/bff/routers/agent_sessions.py")
    # a field missing from the BFF model is silently dropped by model_dump()
    assert re.search(rf"{FIELD}:\s*bool\s*=\s*False", s), "BFF StartSessionRequest must declare the flag"


def test_langgraph_engine_wires_flag():
    s = _src("autogen_agents/langgraph_engine.py")
    # state field + run param + seeded into the graph state
    assert f"{FIELD}: bool" in s, "PentestState must carry the flag"
    assert f"{FIELD}: bool = False" in s, "run_langgraph_session_sync must accept the flag"
    assert f'"{FIELD}": bool(primarily_website)' in s, "flag must be seeded into the graph state"


def test_port_scan_capped_at_top_1000_when_website():
    """(a) the flag forces port_profile=top-1000 when no explicit profile is set —
    which scan_tools then uses to skip the 1-65535 deep sweep."""
    s = _src("autogen_agents/langgraph_engine.py")
    assert re.search(r"if\s+primarily_website\s+and\s+not\s+port_profile\s*:", s), \
        "must default port_profile when the website flag is set and none was chosen"
    # the default value must be top-1000 (nmap's top 1000 ports)
    m = re.search(r"if\s+primarily_website\s+and\s+not\s+port_profile\s*:\s*\n\s*port_profile\s*=\s*[\"']([^\"']+)[\"']", s)
    assert m and m.group(1) == "top-1000", f"expected top-1000, got {m and m.group(1)}"


def test_web_pipeline_kicked_off_early_when_website():
    """(b) the scan phase dispatches the web pipeline early when the flag is set."""
    s = _src("autogen_agents/langgraph_engine.py")
    assert "def _early_website_web_pipeline(" in s
    # called inside scan(), gated on the flag, before the LLM scanner task is built
    assert 'state.get("primarily_website")' in s
    i_call = s.index("_early_website_web_pipeline(sid")
    i_llm = s.index("_llm_phase(sid, agent_name=\"Scanner\"")
    assert i_call < i_llm, "early web dispatch must run before the LLM scan step"
    # fresh-target fallback: scan http/https directly when no web ports are known yet
    assert 'f"https://{host}"' in s and 'f"http://{host}"' in s


def test_frontend_form_and_api_carry_flag():
    api = _src("dashboard/frontend/src/api/agentSessions.ts")
    assert f"{FIELD}?: boolean" in api, "StartSessionParams must include the flag"
    page = _src("dashboard/frontend/src/pages/AgentSessions.tsx")
    assert f"{FIELD}: false" in page, "form state must initialise the flag"
    assert f"form.{FIELD}" in page and f"{FIELD}: e.target.checked" in page, \
        "the checkbox must be bound to the form field"


if __name__ == "__main__":
    import pytest
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
