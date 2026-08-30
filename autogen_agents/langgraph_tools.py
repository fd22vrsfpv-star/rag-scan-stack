"""LangGraph tool surface — LangChain-wrapped tools for `ToolNode` / react agents.

Single source of truth: `tool_registry.TOOL_SPECS`. This module only wraps those
specs; it does not decide what exists.

History worth keeping, because it explains two bugs:

  * Until AutoGen was retired, the roster existed only as a side effect of
    building AutoGen agents, so this module PARSED `pentest_agents.py` for
    `register_for_llm(name=...)` calls and resolved each callable out of that
    module's namespace. Parity was "by construction", but the construction was a
    regex over another module's source — and deleting AutoGen would have deleted
    the tool surface along with it.
  * That parsing recovered the tool NAME but not the curated `description`, so
    the wrapper substituted `inspect.getdoc(fn)`. The description is what the
    model reads when deciding which tool to call, so LangGraph agents were
    choosing tools from Python docstrings while the tuned text sat unused in
    `pentest_agents.py`. Reading the registry fixes that: one description, used
    by every consumer.

Tool BODIES are unchanged — the scope gate, MAX_CONCURRENT_SCANS and webhook
contracts do not depend on which framework wraps them.
"""
from __future__ import annotations

from typing import Callable, Dict, List

from tool_registry import (  # noqa: F401  (re-exported for existing callers)
    DISPATCH_TOOL_NAMES,
    TOOL_BY_NAME,
    TOOL_FUNCS,
    TOOL_NAMES,
    TOOL_SPECS,
    ToolSpec,
)


# name -> why it could not be wrapped. Empty in a healthy build.
_UNWRAPPABLE: Dict[str, str] = {}


def build_langgraph_tools() -> List[object]:
    """Wrap every registry spec as a LangChain StructuredTool.

    A spec whose signature cannot be introspected is COLLECTED, not silently
    dropped: `unwrappable_tools()` reports it and `tests/test_tool_registry.py`
    fails on it. Dropping one quietly is how a phase's toolset shrinks to
    nothing while every check still passes.
    """
    from langchain_core.tools import StructuredTool
    tools: List[object] = []
    for spec in TOOL_SPECS:
        try:
            tools.append(StructuredTool.from_function(
                spec.func, name=spec.name, description=spec.description[:1000]))
        except Exception as e:  # noqa: BLE001
            _UNWRAPPABLE[spec.name] = f"{type(e).__name__}: {e}"
    return tools


def unwrappable_tools() -> Dict[str, str]:
    """Registry tools that exist but cannot be exposed to an LLM, and why."""
    return dict(_UNWRAPPABLE)


LANGGRAPH_TOOLS = build_langgraph_tools()


def tools_named(names) -> List[object]:
    """The wrapped tools whose names are in `names`.

    Filtering by name means a typo yields FEWER tools rather than an error, so
    every caller's name set is pinned by tests/test_langgraph_phases.py against
    the registry.
    """
    wanted = set(names)
    return [t for t in LANGGRAPH_TOOLS if getattr(t, "name", None) in wanted]
