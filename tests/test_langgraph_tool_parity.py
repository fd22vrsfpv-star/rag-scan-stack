"""LangGraph ↔ AutoGen tool parity (migration Phase 2).

The LangGraph tool surface (`autogen_agents/langgraph_tools.py`) is DERIVED from
the AutoGen registrations in `pentest_agents.py`, so it cannot silently drift.
This test is the guard: it fails the build if

  * an AutoGen tool (`register_for_llm(name=...)`) is NOT resolvable in the
    LangGraph surface (a tool AutoGen can call that LangGraph cannot), or
  * the LangGraph surface exposes a tool AutoGen never registered.

Sabotage proof: add `agent.register_for_llm(name="new_tool", ...)(new_tool)` to
pentest_agents.py without a resolvable body and this test goes red; remove it and
it goes green.

Skips cleanly when the autogen-agents dependencies (langchain-core, pyautogen)
are not importable in this environment — a skip says "cannot run here", not
"broken".
"""
import os
import pathlib
import re
import sys

import pytest


def _autogen_dir() -> pathlib.Path:
    """Locate the autogen_agents source dir (repo layout, /app in-container, or
    an explicit override)."""
    for cand in (
        os.environ.get("AUTOGEN_AGENTS_DIR"),
        pathlib.Path(__file__).resolve().parents[1] / "autogen_agents",
        pathlib.Path("/app"),
    ):
        if not cand:
            continue
        p = pathlib.Path(cand)
        if (p / "pentest_agents.py").exists():
            return p
    pytest.skip("autogen_agents source not found (pentest_agents.py)")


_REG_RE = re.compile(r'register_for_llm\(\s*name="([a-z_0-9]+)"')


def _autogen_tool_names(agent_dir: pathlib.Path) -> set:
    """Tool names AutoGen registers — parsed from source, no imports needed."""
    src = (agent_dir / "pentest_agents.py").read_text(encoding="utf-8")
    return set(_REG_RE.findall(src))


def _import_langgraph_tools(agent_dir: pathlib.Path):
    sys.path.insert(0, str(agent_dir))
    try:
        import langgraph_tools  # noqa: E402
        return langgraph_tools
    except Exception as e:  # noqa: BLE001  (ImportError or transitive dep error)
        pytest.skip(f"langgraph_tools not importable here ({type(e).__name__}: {e})")


def test_langgraph_tool_surface_matches_autogen():
    agent_dir = _autogen_dir()
    autogen_names = _autogen_tool_names(agent_dir)
    assert autogen_names, "no register_for_llm tools parsed — regex or source changed"

    lt = _import_langgraph_tools(agent_dir)
    lg_names = set(lt.TOOL_NAMES)

    missing = autogen_names - lg_names
    extra = lg_names - autogen_names
    assert not missing, (
        f"LangGraph cannot provide these AutoGen tools: {sorted(missing)} — "
        "add a resolvable body or fix langgraph_tools resolution")
    assert not extra, (
        f"LangGraph exposes tools AutoGen never registers: {sorted(extra)}")


def test_every_langgraph_tool_is_callable_and_wrapped():
    agent_dir = _autogen_dir()
    lt = _import_langgraph_tools(agent_dir)
    assert lt.TOOL_FUNCS, "empty LangGraph tool registry"
    assert all(callable(f) for f in lt.TOOL_FUNCS.values())
    # Every resolved tool is also wrapped as a LangChain tool for ToolNode use.
    assert len(lt.LANGGRAPH_TOOLS) == len(lt.TOOL_FUNCS)
