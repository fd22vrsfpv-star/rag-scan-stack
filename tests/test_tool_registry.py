"""The agent tool registry is the single source of truth for what an LLM can call.

Run on demand:

    pytest tests/test_tool_registry.py -v

WHY THIS EXISTS
---------------
This replaces `tests/test_langgraph_tool_parity.py`, whose job was to prove the
LangGraph tool surface matched the AutoGen registrations. AutoGen is retired
(Docs/LANGGRAPH_MIGRATION_PLAN.md, Phase 5), so there is nothing left to be at
parity WITH — but the failure it guarded against is still live, and got worse
with a single source: if the registry loses a tool, or a spec stops resolving,
every consumer loses that tool at once and nothing else complains. Filtering by
name means a bad name yields FEWER tools, not an error.

The roster used to exist in THREE hand-maintained places — the AutoGen
`register_for_llm` calls, `langgraph_tools`' parse of them, and
`mcp_tools_bridge.NATIVE_TOOL_NAMES`. The third had already drifted: it listed
`start_nikto_scan`, which no tool provides (so a real MCP tool of that name
would have been skipped as a "native duplicate"), and omitted `get_attack_vectors`
and `start_subdomain_takeover`, which an MCP server could therefore shadow —
replacing a scope-gated local body with a remote one. All three now derive from
`tool_registry`, and these tests hold that line.

Checks that need the agent dependencies (langchain-core, psycopg2) skip cleanly;
the source-level checks run anywhere.

Sabotage proofs performed:
  * deleted a ToolSpec's `description`      -> test_every_tool_has_an_llm_description RED
  * pointed a spec at a non-existent body   -> test_registry_specs_all_resolve RED
  * re-hardcoded NATIVE_TOOL_NAMES          -> test_native_tool_names_is_derived RED
"""
import ast
import os
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

# Floor for the roster size. Not a style rule: the registry is the ONLY place the
# surface is declared now, so a silent shrink is invisible without a number to
# compare against. Raise it deliberately when tools are added.
#   49 = the roster when AutoGen was retired
#   50 = + get_tool_recommendations (structured, agent-actionable tests)
#   51 = + analyze_attack_surface (one-host surface enumeration)
MIN_TOOLS = 52


def _agent_dir() -> pathlib.Path:
    for cand in (os.environ.get("AUTOGEN_AGENTS_DIR"),
                 REPO / "autogen_agents",
                 pathlib.Path("/app")):
        if not cand:
            continue
        p = pathlib.Path(cand)
        if (p / "tool_registry.py").exists():
            return p
    pytest.skip("tool_registry.py not found")


# ── source-level: runs on a bare checkout ───────────────────────────────────
def _spec_nodes(path: pathlib.Path):
    """Every `ToolSpec(...)` call in the registry, via ast (no imports)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "ToolSpec"):
            kw = {k.arg: k.value for k in node.keywords}
            out.append(kw)
    return out


@pytest.fixture(scope="module")
def specs():
    nodes = _spec_nodes(_agent_dir() / "tool_registry.py")
    assert nodes, "no ToolSpec entries parsed — the registry format changed and " \
                  "these tests would pass vacuously"
    return nodes


def test_registry_declares_the_whole_surface(specs):
    assert len(specs) >= MIN_TOOLS, (
        f"the registry declares {len(specs)} tools, fewer than the {MIN_TOOLS} "
        "the agents had when AutoGen was retired — a tool was dropped. If that "
        "was deliberate, lower MIN_TOOLS in the same commit and say why.")


def test_tool_names_are_unique(specs):
    names = []
    for kw in specs:
        node = kw.get("name")
        assert isinstance(node, ast.Constant), "a ToolSpec name is not a literal"
        names.append(node.value)
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, (
        f"duplicate tool names in the registry: {dupes} — TOOL_FUNCS is a dict, "
        "so the later entry silently wins and one body becomes unreachable")


def test_every_tool_has_an_llm_description(specs):
    """The description is what the model reads when choosing a tool.

    An empty one does not fail anything at runtime; it just makes the tool
    invisible to the model's reasoning, which is indistinguishable from the tool
    not existing.
    """
    missing = []
    for kw in specs:
        name = kw["name"].value if isinstance(kw.get("name"), ast.Constant) else "?"
        d = kw.get("description")
        try:
            text = ast.literal_eval(d) if d is not None else ""
        except Exception:
            text = "<non-literal>"
        if not str(text).strip():
            missing.append(name)
    assert not missing, f"tools with no LLM-facing description: {missing}"


def test_native_tool_names_is_derived():
    """mcp_tools_bridge must NOT hand-maintain a second copy of the roster.

    The hardcoded set had drifted in both directions (a phantom tool, and two
    real tools omitted), which silently changed which MCP tools are allowed to
    shadow a scope-gated local body.
    """
    src = (_agent_dir() / "mcp_tools_bridge.py").read_text(encoding="utf-8")
    assert "from tool_registry import" in src, (
        "mcp_tools_bridge no longer derives NATIVE_TOOL_NAMES from tool_registry")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "NATIVE_TOOL_NAMES"):
            assert not isinstance(node.value, (ast.Set, ast.List, ast.Tuple)), (
                "NATIVE_TOOL_NAMES was re-hardcoded as a literal — derive it from "
                "tool_registry.TOOL_NAMES so it cannot drift from the real roster")
            return
    pytest.fail("NATIVE_TOOL_NAMES assignment not found in mcp_tools_bridge.py")


def test_autogen_is_really_gone():
    """Phase 5 retired AutoGen. Nothing may import it, and it is not installed.

    A stray `import autogen` would be an ImportError at runtime in a module that
    might only be reached on an error path — the worst place to find out.
    """
    offenders = []
    for path in sorted(_agent_dir().glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                if any(a.name == "autogen" or a.name.startswith("autogen.")
                       for a in node.names):
                    offenders.append(path.name)
            if isinstance(node, ast.ImportFrom):
                if node.module and (node.module == "autogen"
                                    or node.module.startswith("autogen.")):
                    offenders.append(path.name)
    assert not offenders, (
        f"these modules still import the retired `autogen` package: "
        f"{sorted(set(offenders))} — pyautogen is not in requirements.txt, so "
        "this is an ImportError waiting for the right code path")

    req_path = _agent_dir() / "requirements.txt"
    if not req_path.exists():
        # In-container the source dir is /app and requirements.txt is not copied.
        # The import scan above is the load-bearing half; this is "cannot check
        # here", not a failure.
        pytest.skip("requirements.txt not present in this source dir")
    reqs = req_path.read_text(encoding="utf-8")
    live = [ln for ln in reqs.splitlines()
            if ln.strip() and not ln.strip().startswith("#")
            and "autogen" in ln.lower()]
    assert not live, f"pyautogen is back in requirements.txt: {live}"


# ── import-level: needs the agent dependencies ──────────────────────────────
@pytest.fixture(scope="module")
def registry():
    agent_dir = _agent_dir()
    sys.path.insert(0, str(agent_dir))
    try:
        import tool_registry
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"tool_registry not importable here ({type(e).__name__}: {e})")
    return tool_registry


def test_registry_specs_all_resolve(registry):
    """Every spec must point at a real callable in scan_tools."""
    bad = [t.name for t in registry.TOOL_SPECS if not callable(t.func)]
    assert not bad, f"registry tools that do not resolve to a callable: {bad}"
    assert len(registry.TOOL_FUNCS) == len(registry.TOOL_SPECS), (
        "TOOL_FUNCS lost entries to duplicate names")


def test_every_registry_tool_is_wrapped_for_langgraph(registry):
    """A tool that cannot be wrapped is reported, never silently dropped."""
    try:
        import langgraph_tools as lt
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"langgraph_tools not importable here ({type(e).__name__}: {e})")
    assert not lt.unwrappable_tools(), (
        f"registry tools that could not be exposed to an LLM: {lt.unwrappable_tools()}")
    assert len(lt.LANGGRAPH_TOOLS) == len(registry.TOOL_SPECS), (
        f"{len(lt.LANGGRAPH_TOOLS)} wrapped tools for "
        f"{len(registry.TOOL_SPECS)} registry specs")


def test_wrapped_tools_use_the_curated_description(registry):
    """The LangChain wrapper must carry the registry description.

    It used to substitute `inspect.getdoc(fn)`, so the model chose tools from
    Python docstrings while the tuned text sat unused.
    """
    try:
        import langgraph_tools as lt
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"langgraph_tools not importable here ({type(e).__name__}: {e})")
    mismatched = []
    for tool in lt.LANGGRAPH_TOOLS:
        spec = registry.TOOL_BY_NAME.get(tool.name)
        if spec and not tool.description.startswith(spec.description[:60]):
            mismatched.append(tool.name)
    assert not mismatched, (
        f"wrapped tools whose description is not the registry's: {mismatched}")


def test_dispatch_tool_names_are_real_tools(registry):
    unknown = sorted(set(registry.DISPATCH_TOOL_NAMES) - set(registry.TOOL_NAMES))
    assert not unknown, f"DISPATCH_TOOL_NAMES lists non-tools: {unknown}"
    assert registry.DISPATCH_TOOL_NAMES, "no dispatch tools — the filter broke"
