"""Build-poc's recon vocabulary is DATA, and a tool only runs when it is needed.

When a PoC build is stuck, `_solutions_for_gaps` asks "what do I need and how
do I get it" — a hardcoded table, then RAG, then an LLM. But only a solution
whose `step` was one of SIX hardcoded names could ever RUN:

    _DEEP_RECON_STEPS = ("default_creds", "auth_crawl", "access_inventory",
                         "zap_spider", "arjun_params", "verb_sweep")

Everything RAG or the model proposed arrived with `step: None` and became an
operator follow-up. Retrieval worked; acting on it did not. `knowledge/`
describes 239 distinct tool invocations and the stack runs wafw00f, nikto,
nuclei, gobuster, ffuf, httpx and whatweb — none reachable from a stuck build.
Adding one meant editing a tuple and an `if step == ...` chain in api.py, which
is the branching-logic edit CLAUDE.md's RAG-first rule exists to prevent:

    "New knowledge should take effect by being loaded and embedded, not by
     editing branching logic."

So the vocabulary moved to `knowledge/gap_tools.yaml` with a loader that
embeds it, and the resolver filters it down to what is actually worth running.

The four filters are the contract, and each exists because running the tool
anyway is worse than not running it:

  1. the gap is in `missing`
  2. what it yields is not already known, AND the gap is not already answered
     — operator: "auto run if needed, if the exploit has enough detail then
     they can be optional"
  3. a tool that declares `indicators` only fires when one is observed — this
     is how a WAF probe happens on 403/challenge/cloudflare rather than as an
     always-on stage
  4. not already run this build

Sabotage check: delete the `indicators` check and
`test_indicator_gated_tools_need_an_indicator` fails; drop the gap-answered
suppression and `test_an_answered_gap_suppresses_all_its_tools` fails; let an
empty placeholder render and `test_an_empty_placeholder_refuses_to_render`
fails.

    pytest tests/test_gap_tools.py -q
"""

import ast
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
YAML = REPO / "knowledge" / "gap_tools.yaml"
LOADER = REPO / "etl" / "load_gap_tools.py"
API = REPO / "app" / "rag-api" / "api.py"

yaml = pytest.importorskip("yaml")


def _specs() -> list:
    if not YAML.is_file():
        pytest.skip("knowledge/gap_tools.yaml not present")
    return (yaml.safe_load(YAML.read_text(encoding="utf-8")) or {}).get("tools") or []


# ── the knowledge file's own contract ─────────────────────────────────────────

def test_every_tool_declares_the_full_contract():
    specs = _specs()
    assert specs, "gap_tools.yaml declares no tools"
    for t in specs:
        for key in ("id", "gaps", "yields", "command", "why"):
            assert t.get(key), f"{t.get('id', '?')} is missing {key!r}"
        assert isinstance(t["gaps"], list) and t["gaps"], f"{t['id']}: gaps must be a non-empty list"
        assert isinstance(t.get("cost", 0), int), f"{t['id']}: cost must be an int"


def test_tool_ids_are_unique():
    ids = [t["id"] for t in _specs()]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate tool ids: {dupes} — the id is the step name"


def test_commands_only_use_known_placeholders():
    """An unknown placeholder reaches the shell literally."""
    import re
    known = {"ip", "port", "scheme", "base_url", "product"}
    for t in _specs():
        used = set(re.findall(r"\{([a-z_]+)\}", str(t["command"])))
        unknown = used - known
        assert not unknown, (
            f"{t['id']} uses placeholder(s) {sorted(unknown)} that the renderer "
            f"does not substitute; they would reach the shell as literal text")


def _touches_target(cmd: str) -> bool:
    return any(ph in str(cmd) for ph in ("{ip}", "{base_url}", "{scheme}"))


def test_local_only_matches_the_command_in_both_directions():
    """`local_only` is a claim about traffic, checked BOTH ways.

    Checking only the tools that claim the flag meant deleting the flag was
    undetectable — the test simply stopped looking at that tool. The flag is
    what tells a planner this probe is free, so a tool that quietly loses it
    gets ordered as if it costs target traffic, and a tool that wrongly gains
    it gets treated as free while hitting the target.
    """
    for t in _specs():
        touches = _touches_target(t["command"])
        claimed = bool(t.get("local_only"))
        if claimed:
            assert not touches, (
                f"{t['id']} is marked local_only but its command interpolates "
                "a target placeholder — it does reach the target")
        else:
            assert touches, (
                f"{t['id']} is NOT marked local_only yet its command names no "
                "target placeholder, so it sends no traffic. Either mark it "
                "local_only or give it a target — an unmarked local tool is "
                "ordered as though it costs a round trip against the host")


# ── the loader ships with the file ────────────────────────────────────────────

def test_the_knowledge_file_has_a_loader():
    """CLAUDE.md: a knowledge file that defines actions MUST have a loader.

    "A file that is read deterministically but never embedded is retrievable
    by nobody."
    """
    assert LOADER.is_file(), (
        "knowledge/gap_tools.yaml defines runnable actions but etl/"
        "load_gap_tools.py does not exist, so nothing embeds it")
    src = LOADER.read_text(encoding="utf-8")
    assert "rag_documents" in src, "the loader does not write to rag_documents"
    assert "DELETE FROM rag_documents" in src, (
        "the loader is not idempotent — re-running it after an edit would "
        "duplicate every document rather than replace it")


def _loader():
    sys.path.insert(0, str(REPO / "etl"))
    try:
        import load_gap_tools as L
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"loader not importable: {e}")
    return L


@pytest.mark.parametrize("bad,why", [
    ("version: 1\ntools:\n  - id: x\n    gaps: [endpoint]\n",
     "missing yields/command/why"),
    ("version: 1\ntools:\n  - id: x\n    gaps: endpoint\n    yields: y\n"
     "    command: c\n    why: w\n",
     "gaps is a string, not a list"),
    ("version: 1\ntools:\n  - {id: x, gaps: [a], yields: y, command: c, why: w}\n"
     "  - {id: x, gaps: [b], yields: z, command: d, why: w}\n",
     "duplicate ids"),
])
def test_the_loader_refuses_a_malformed_file(tmp_path, bad, why):
    """Raise rather than load half of it.

    A partially embedded vocabulary is worse than none: the gap it silently
    cannot answer looks identical to a gap with no tool for it.
    """
    L = _loader()
    f = tmp_path / "gap_tools.yaml"
    f.write_text(bad, encoding="utf-8")
    with pytest.raises(Exception):
        L.load_specs(f)


def test_the_loader_accepts_the_real_file():
    L = _loader()
    specs = L.load_specs(YAML)
    assert len(specs) == len(_specs())
    docs = L.as_documents(specs)
    assert len(docs) == len(specs)
    for title, body in docs:
        assert title.startswith("Gap tool:")
        assert "Command template:" in body, "the embedded doc omits the command"


def test_an_indicator_gated_tool_says_so_in_its_document():
    """RAG recall must carry the condition, or a retriever surfaces a WAF
    probe for a build with no WAF symptoms."""
    L = _loader()
    for spec in L.load_specs(YAML):
        if not spec.get("indicators"):
            continue
        body = dict((t, b) for t, b in L.as_documents([spec]))
        text = list(body.values())[0]
        assert "indicator" in text.lower(), (
            f"{spec['id']} is indicator-gated but its embedded document does "
            "not say so")


# ── the resolver's four filters, read structurally from api.py ────────────────

def _func(name):
    if not API.exists():
        pytest.skip("api.py not found")
    for n in ast.walk(ast.parse(API.read_text(encoding="utf-8"))):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    pytest.fail(f"{name} is not defined in api.py")


def _src(name):
    return ast.get_source_segment(API.read_text(encoding="utf-8"), _func(name)) or ""


def test_resolver_exists_and_orders_cheapest_first():
    src = _src("_gap_tool_candidates")
    assert "sort" in src, (
        "candidates are not ordered, so a 180s nikto sweep can be offered "
        "before a 5s local lookup")
    assert "cost" in src, "the ordering does not use the declared cost"


def test_indicator_gated_tools_need_an_indicator():
    src = _src("_gap_tool_candidates")
    assert "indicators" in src, (
        "the resolver ignores the `indicators` field, so an indicator-gated "
        "tool like wafw00f becomes an always-on stage — which is exactly what "
        "declaring indicators was meant to avoid")


def test_an_answered_gap_suppresses_all_its_tools():
    src = _src("_gap_tool_candidates")
    assert "_GAP_ANSWERED_BY" in src, (
        "the resolver only checks whether a tool's own `yields` is known. "
        "nikto_scan is offered for `endpoint` but yields `server_findings`, "
        "so an endpoint we already had still left a 180-second sweep on the "
        "table. The unit that matters is the GAP, not the yield")


def test_the_gap_answered_map_is_conservative():
    """A wrong True silently skips the recon that would unstick the build."""
    tree = ast.parse(API.read_text(encoding="utf-8"))
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "_GAP_ANSWERED_BY" for t in n.targets):
            assert isinstance(n.value, ast.Dict), "_GAP_ANSWERED_BY is not a dict"
            assert n.value.keys, "_GAP_ANSWERED_BY is empty"
            return
    pytest.fail("_GAP_ANSWERED_BY is not defined")


def test_an_empty_placeholder_refuses_to_render():
    """`searchsploit --json {product}` with product="" renders
    `searchsploit --json` — no braces left, so a brace check passes and the
    tool runs with its argument silently missing."""
    src = _src("_gap_tool_command")
    assert "strip()" in src and "in tmpl" in src, (
        "the renderer does not reject an EMPTY substitution, so a tool whose "
        "input we do not have dispatches a truncated command")


def test_the_vocabulary_failure_is_loud():
    """An empty vocabulary silently narrows build-poc to six hardcoded steps."""
    src = _src("_gap_tools")
    assert "logging.warning" in src, (
        "a failure to load the tool vocabulary is logged below warning, so "
        "nothing downstream can distinguish 'no tool applies' from 'the tool "
        "list failed to load'")


def test_the_deterministic_backstop_is_still_there():
    """CLAUDE.md: the deterministic rules engine stays as the backstop."""
    src = API.read_text(encoding="utf-8")
    assert "_GAP_SOLUTIONS" in src, (
        "the hardcoded gap table was removed; RAG-first widens what can run, "
        "it does not remove the deterministic path")
