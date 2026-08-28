"""LangGraph tool surface — Phase 2 of the AutoGen → LangGraph migration.

Single source of truth: the tools the AutoGen agents register via
`agent.register_for_llm(name=...)(func)` in `pentest_agents.py`. Rather than
hand-maintaining a parallel list (which would silently drift), this module PARSES
those registrations and resolves each callable from the `pentest_agents`
namespace, then wraps them as LangChain `StructuredTool`s for LangGraph nodes /
`ToolNode`.

Because the surface is DERIVED from the AutoGen source, parity is by
construction; `tests/test_langgraph_tool_parity.py` fails the build if the two
ever diverge (a tool added to AutoGen but not resolvable here, or vice-versa).

Tool BODIES are unchanged — the scope gate, concurrency and webhook contracts are
identical whether a tool is called by AutoGen or LangGraph.
"""
from __future__ import annotations

import importlib
import inspect
import pathlib
import re
from typing import Callable, Dict, List

# `register_for_llm(name="tool")( ... )(the_callable)` — anchored on the `)(`
# decorator-application so a `)` inside a description can't end the match early.
_REG_RE = re.compile(
    r'register_for_llm\(\s*name="([a-z_0-9]+)".*?\)\(\s*([\w.]+)\s*\)',
    re.DOTALL,
)


def _resolve(mod, dotted: str):
    obj = mod
    for part in dotted.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj


def canonical_tool_funcs() -> Dict[str, Callable]:
    """{name: callable} for every tool the AutoGen agents register.

    Parsed from pentest_agents.py and resolved from that module's namespace, so
    it is exactly the AutoGen roster — the same functions, the same bodies."""
    pa = importlib.import_module("pentest_agents")
    src = pathlib.Path(pa.__file__).read_text(encoding="utf-8")
    out: Dict[str, Callable] = {}
    for name, expr in _REG_RE.findall(src):
        fn = _resolve(pa, expr)
        if callable(fn):
            out[name] = fn
    return out


def build_langgraph_tools() -> List["object"]:
    """Wrap the canonical tools as LangChain StructuredTools for LangGraph."""
    from langchain_core.tools import StructuredTool
    tools = []
    for name, fn in canonical_tool_funcs().items():
        try:
            tools.append(StructuredTool.from_function(
                fn, name=name,
                description=(inspect.getdoc(fn) or name).strip()[:400]))
        except Exception:
            # A tool whose signature can't be introspected is reported by the
            # parity test as uncovered rather than silently dropped.
            pass
    return tools


# Built once at import. TOOL_FUNCS is the authoritative name→callable map;
# LANGGRAPH_TOOLS is the LangChain-wrapped surface for binding to a ToolNode.
TOOL_FUNCS: Dict[str, Callable] = canonical_tool_funcs()
TOOL_NAMES: List[str] = sorted(TOOL_FUNCS)
LANGGRAPH_TOOLS = build_langgraph_tools()
