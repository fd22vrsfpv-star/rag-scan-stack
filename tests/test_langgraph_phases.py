"""LangGraph phase contracts + the exploit-approval interrupt (migration Phase 4).

Run on demand:

    pytest tests/test_langgraph_phases.py -v
    AGENT_API=https://localhost:3002 pytest tests/test_langgraph_phases.py -v

WHY THIS EXISTS
---------------
Phase 4 flipped the default engine to LangGraph and turned scan/analyze into LLM
agents. Three things now hold the safety properties, and all three are the kind
that pass every static check while being wrong at runtime:

  1. **The toolset, not the prompt, enforces the auto_execute contract.** With
     auto_execute off the scan agent is handed NO `start_*` tool, so it cannot
     dispatch even if it decides to. A rename that quietly drops a name from
     `SCAN_TOOLS_DISPATCH` into nothing, or one that adds a dispatcher to a
     read-only phase, is invisible otherwise.
  2. **`execute_approved_exploit` must be unreachable by any LLM.** It is called
     only by the `exploit_exec` node, which is reachable only after the operator
     answers the interrupt. If it ever appeared in a phase toolset, an agent
     could execute an exploit with no human in the loop.
  3. **The interrupt must actually park and actually resume.** A graph that runs
     straight through the approval node looks identical from the outside to one
     that paused and was approved.

The set constants are read from `langgraph_engine.py` with `ast` rather than by
importing it, so this guard runs on a bare checkout (no langgraph, no pyautogen)
instead of skipping everywhere — a guard that cannot run is not a guard. The
interrupt test does need langgraph and skips cleanly without it.

Sabotage proofs performed:
  * moved "start_nmap_scan" into SCAN_TOOLS_READONLY  -> test_readonly_phases_have_no_dispatchers RED
  * added "execute_approved_exploit" to EXPLOIT_PLAN_TOOLS -> test_no_llm_phase_can_execute_an_exploit RED
  * replaced interrupt() with a plain return          -> test_approval_node_parks_the_graph RED
"""
import ast
import os
import pathlib
import re
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


# ── source-only readers (no imports, so this runs anywhere) ──────────────────
def _autogen_dir() -> pathlib.Path:
    for cand in (os.environ.get("AUTOGEN_AGENTS_DIR"),
                 REPO / "autogen_agents",
                 pathlib.Path("/app")):
        if not cand:
            continue
        p = pathlib.Path(cand)
        if (p / "langgraph_engine.py").exists():
            return p
    pytest.skip("autogen_agents source not found (langgraph_engine.py)")


def _set_constants(path: pathlib.Path) -> dict:
    """Module-level `NAME = {...}` / `NAME = A | {...}` string sets, via ast.

    literal_eval alone cannot read `_READ_ONLY | {"x"}`, and importing the module
    would drag in langgraph + pyautogen + a live DB. So resolve set literals and
    `|` unions over already-seen names, and nothing else.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: dict = {}

    def value_of(node):
        if isinstance(node, ast.Set):
            items = [ast.literal_eval(e) for e in node.elts]
            return set(items)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left, right = value_of(node.left), value_of(node.right)
            if left is None or right is None:
                return None
            return left | right
        if isinstance(node, ast.Name):
            return out.get(node.id)
        return None

    for node in tree.body:
        if not (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            continue
        val = value_of(node.value)
        if isinstance(val, set) and all(isinstance(v, str) for v in val):
            out[node.targets[0].id] = val
    return out


def _registry_tool_names(agent_dir: pathlib.Path) -> set:
    """Every tool name the registry declares — read with ast, no imports.

    Was parsed out of `pentest_agents.py`'s `register_for_llm` calls until
    AutoGen was retired; `tool_registry.py` is the single source of truth now.
    """
    tree = ast.parse((agent_dir / "tool_registry.py").read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "ToolSpec"):
            for kw in node.keywords:
                if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                    names.add(kw.value.value)
    return names


@pytest.fixture(scope="module")
def phases():
    agent_dir = _autogen_dir()
    consts = _set_constants(agent_dir / "langgraph_engine.py")
    expected = {"RECON_TOOLS", "SCAN_TOOLS_READONLY", "SCAN_TOOLS_DISPATCH",
                "ANALYZE_TOOLS", "EXPLOIT_PLAN_TOOLS"}
    missing = expected - set(consts)
    assert not missing, (
        f"langgraph_engine.py no longer declares {sorted(missing)} as a module-level "
        "set of tool names. This guard would pass vacuously — fix the reader or the "
        "engine, do not delete the assertion.")
    return {k: consts[k] for k in expected}


# ── 1. parity: every phase name is a real AutoGen tool ──────────────────────
def test_every_phase_tool_exists_in_the_registry(phases):
    """A typo silently shrinks a phase's toolset instead of failing.

    `_tools_for()` filters the registry-backed tools by name, so a misspelled
    name is not an error — it just is not there. A phase can quietly lose every tool and the
    only symptom is an LLM that answers from nothing.
    """
    roster = _registry_tool_names(_autogen_dir())
    assert roster, "no ToolSpec entries parsed — tool_registry format changed"
    bad = {name: sorted(s - roster) for name, s in phases.items() if s - roster}
    assert not bad, (
        "phase toolsets name tools the registry does not declare "
        f"(so _tools_for silently drops them): {bad}")


def test_no_phase_toolset_is_empty(phases):
    for name, s in phases.items():
        assert s, f"{name} is empty — that phase's agent would have no tools"


# ── 2. the auto_execute contract lives in the toolset ───────────────────────
DISPATCH_PREFIX = "start_"


def test_readonly_phases_have_no_dispatchers(phases):
    """Read-only phases must not be able to send traffic at all.

    With auto_execute off, `scan()` binds SCAN_TOOLS_READONLY only. If a
    `start_*` tool leaks into it, a session the operator explicitly asked NOT to
    execute scans would dispatch them — and the prompt saying "do not launch
    anything" is not a control.
    """
    for name in ("RECON_TOOLS", "SCAN_TOOLS_READONLY", "ANALYZE_TOOLS",
                 "EXPLOIT_PLAN_TOOLS"):
        leaked = sorted(t for t in phases[name] if t.startswith(DISPATCH_PREFIX))
        assert not leaked, (
            f"{name} is a read-only phase toolset but contains dispatchers: {leaked}")


def test_dispatch_set_is_only_dispatchers(phases):
    stray = sorted(t for t in phases["SCAN_TOOLS_DISPATCH"]
                   if not t.startswith(DISPATCH_PREFIX))
    assert not stray, (
        f"SCAN_TOOLS_DISPATCH should hold only start_* tools; found {stray}")


# Credential brute force is not enumeration. It stays out of the autonomous scan
# phase deliberately, so the blast radius of an unattended session is bounded.
BRUTE_FORCE = {"start_brutus", "start_credential_check"}


def test_scan_phase_excludes_credential_brute_force(phases):
    leaked = sorted(phases["SCAN_TOOLS_DISPATCH"] & BRUTE_FORCE)
    assert not leaked, (
        f"credential brute-force tools in the autonomous scan phase: {leaked} — "
        "these belong behind the human-approved exploit gate")


# ── 3. exploit execution is unreachable without a human ─────────────────────
def test_no_llm_phase_can_execute_an_exploit(phases):
    """`execute_approved_exploit` must appear in NO phase toolset.

    Its only caller is the `exploit_exec` node, reached only after the operator
    answers the interrupt. In a toolset it would be one tool call away from an
    LLM at any time — an override of the operator's authorization, which the
    platform is never allowed to do.
    """
    for name, s in phases.items():
        assert "execute_approved_exploit" not in s, (
            f"{name} exposes execute_approved_exploit to an LLM — exploit "
            "execution must stay behind the approval interrupt")


def test_exploit_planning_can_only_queue(phases):
    """The exploit planner may queue for approval; that is a DB row, not a shot."""
    assert "queue_exploit_for_approval" in phases["EXPLOIT_PLAN_TOOLS"], (
        "the exploit planner cannot queue anything, so the approval gate can "
        "never be reached and the phase is dead code")


def test_engine_source_calls_execute_only_in_the_exec_node():
    """Belt and braces: one call site, and it is exploit_exec.

    The toolset check above stops an LLM from calling it; this stops a later edit
    from calling it directly from an earlier node, which would execute before the
    interrupt ever runs.
    """
    src = (_autogen_dir() / "langgraph_engine.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    callers = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for sub in ast.walk(node):
            if (isinstance(sub, ast.Attribute)
                    and sub.attr == "execute_approved_exploit"):
                callers.append(node.name)
    # exploit_exec / surface_exec run after the human approval interrupt.
    # _exec_one_impactful is the shared executor; its only auto-mode caller is
    # surface_auto_exec, whose authorization is the runner's scope gate (which
    # fails CLOSED on out-of-scope) rather than a human interrupt. It must NEVER
    # be reachable from a planning or safe-execution node — enforced by the graph
    # topology test (surface_auto_exec is opt-in behind the auto_exploit flag).
    assert set(callers) <= {"exploit_exec", "surface_exec", "_exec_one_impactful"}, (
        f"scan_tools.execute_approved_exploit is called from {callers}; it must be "
        "called only from exploit_exec / surface_exec / _exec_one_impactful, which "
        "run AFTER an approval gate (human interrupt) or the runner's fail-closed "
        "scope gate — never from a planning or safe-execution node")


# ── 4. engine resolution (the canary control) ───────────────────────────────
def _repo_file(name: str) -> pathlib.Path:
    """A repo-root file, or a skip. In-container the source dir is /app and the
    repo root does not exist, so this is 'cannot run here', not a failure."""
    p = REPO / name
    if not p.exists():
        pytest.skip(f"{name} not present (running outside a repo checkout)")
    return p


def _resolve_source():
    """Read resolve_agent_engine's contract from source constants.

    The function itself lives in autogen_service.py, which cannot be imported
    without the whole agent stack; the values it depends on are what matter here.
    """
    svc = _autogen_dir() / "autogen_service.py"
    if not svc.exists():
        pytest.skip("autogen_service.py not present in this source dir")
    src = svc.read_text(encoding="utf-8")
    default = re.search(r'^DEFAULT_AGENT_ENGINE = "([a-z]+)"', src, re.M)
    valid = re.search(r'^VALID_AGENT_ENGINES = \(([^)]*)\)', src, re.M)
    assert default and valid, "engine constants not found in autogen_service.py"
    return default.group(1), tuple(re.findall(r'"([a-z]+)"', valid.group(1)))


def test_langgraph_is_the_only_engine():
    """Phase 4 flipped the default; Phase 5 retired AutoGen.

    `autogen` must no longer be a VALID engine — if it were, a request could
    select an engine whose dependency is not installed and fail at import time
    deep inside a background thread. It should still be RECOGNISED as retired,
    so an old launch preset gets a warning rather than "unknown engine".
    """
    default, valid = _resolve_source()
    assert default == "langgraph", f"default engine is {default!r}, expected 'langgraph'"
    assert "langgraph" in valid
    assert "autogen" not in valid, (
        "autogen is still a selectable engine, but pyautogen is not installed — "
        "a session requesting it would fail at import time")

    src = (_autogen_dir() / "autogen_service.py").read_text(encoding="utf-8")
    assert "RETIRED_AGENT_ENGINES" in src, (
        "a request naming 'autogen' should be warned about as retired, not "
        "reported as an unknown engine")


def test_compose_and_env_example_agree_with_the_default():
    """A compose default of 'autogen' with a code default of 'langgraph' means
    the flip only happened in one of the two places anyone reads."""
    compose = _repo_file("docker-compose.yml").read_text(encoding="utf-8")
    m = re.search(r'AGENT_ENGINE:\s*\$\{AGENT_ENGINE:-([a-z]+)\}', compose)
    assert m, "AGENT_ENGINE not declared in docker-compose.yml"
    assert m.group(1) == "langgraph", (
        f"docker-compose default is {m.group(1)!r} but the code default is 'langgraph'")

    example = REPO / ".env.example"
    if example.exists():
        m2 = re.search(r'^AGENT_ENGINE=([a-z]+)', example.read_text(encoding="utf-8"), re.M)
        assert m2 and m2.group(1) == "langgraph", (
            ".env.example does not document AGENT_ENGINE=langgraph")


# ── 5. the interrupt actually parks and resumes (needs langgraph) ───────────
@pytest.fixture(scope="module")
def graph_mod():
    """Import langgraph_engine with the phases stubbed out.

    The point is the control flow around the interrupt, not the LLM: stubbing
    the phase nodes keeps the test hermetic (no model, no scan, no DB writes)
    while exercising the REAL graph, the REAL interrupt and the REAL resume.
    """
    agent_dir = _autogen_dir()
    sys.path.insert(0, str(agent_dir))
    try:
        import langgraph_engine as lge
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"langgraph_engine not importable here ({type(e).__name__}: {e})")
    return lge


def _stub_graph(lge, monkeypatch, *, queued=True, executed):
    """Compile the real graph with the phase bodies replaced by stubs."""
    from langgraph.checkpoint.memory import MemorySaver

    def phase(next_phase, **extra):
        def _node(state):
            return {"phase": next_phase, "findings": [], "log": [], **extra}
        return _node

    monkeypatch.setattr(lge, "recon", phase("scan"))
    monkeypatch.setattr(lge, "scan", phase("analyze"))
    monkeypatch.setattr(lge, "analyze", phase("exploit"))
    monkeypatch.setattr(lge, "exploit_plan",
                        phase("exploit_approval",
                              exploit_candidate="CVE-0000-0000 on 10.0.0.1:80" if queued else None))
    monkeypatch.setattr(lge, "report", lambda s: {"phase": "done", "report": "stub report",
                                                 "log": []})

    def _exec(state):
        """Records what reached the executor instead of running an exploit."""
        executed.append(state.get("exploit_decision"))
        return {"phase": "report", "findings": [], "log": []}

    monkeypatch.setattr(lge, "exploit_exec", _exec)
    # The approval node is NOT stubbed — it is what is under test. Its side
    # effects (session message, webhook) are muted so nothing touches the stack.
    monkeypatch.setattr(lge, "_msg", lambda *a, **k: None)
    monkeypatch.setattr(lge, "_emit", lambda *a, **k: None)
    return lge.build_graph(MemorySaver())


def _initial(exploit_phase=True):
    return {"session_id": "00000000-0000-0000-0000-0000000000ff",
            "target": "10.0.0.1", "task": "test", "auto_execute": False,
            "exploit_phase": exploit_phase, "phase": "recon",
            "findings": [], "log": [], "exploit_candidate": None,
            "exploit_decision": None, "report": None}


def test_approval_node_parks_the_graph(graph_mod, monkeypatch):
    """With the exploit phase on and a candidate queued, invoke() must PAUSE."""
    executed = []
    graph = _stub_graph(graph_mod, monkeypatch, executed=executed)
    cfg = {"configurable": {"thread_id": "park-test"}}
    out = graph.invoke(_initial(), cfg)

    payload = graph_mod._interrupt_payload(out, graph, cfg)
    assert payload, (
        "the graph ran to completion instead of pausing — the approval interrupt "
        f"did not fire. final state phase={out.get('phase')!r}")
    assert payload.get("kind") == "exploit_approval"
    assert not executed, "an exploit executed before the operator answered"
    assert out.get("report") is None, "the report was written before approval"


def test_resume_approved_executes_then_reports(graph_mod, monkeypatch):
    """Command(resume=...) continues the SAME thread from its checkpoint."""
    from langgraph.types import Command
    executed = []
    graph = _stub_graph(graph_mod, monkeypatch, executed=executed)
    cfg = {"configurable": {"thread_id": "resume-approved"}}
    graph.invoke(_initial(), cfg)

    final = graph.invoke(Command(resume={"approved": True,
                                        "pending_exploit_id": "dead-beef",
                                        "note": "ok"}), cfg)
    assert graph_mod._interrupt_payload(final, graph, cfg) is None, "still parked"
    assert executed and executed[0]["approved"] is True
    assert executed[0]["pending_exploit_id"] == "dead-beef", (
        "the id the operator approved did not reach the executor")
    assert final.get("report"), "no report after a completed run"


def test_resume_declined_skips_execution(graph_mod, monkeypatch):
    """A declined approval must reach the report WITHOUT executing anything."""
    from langgraph.types import Command
    executed = []
    graph = _stub_graph(graph_mod, monkeypatch, executed=executed)
    cfg = {"configurable": {"thread_id": "resume-declined"}}
    graph.invoke(_initial(), cfg)

    final = graph.invoke(Command(resume={"approved": False,
                                        "pending_exploit_id": "dead-beef"}), cfg)
    assert not executed, "an exploit executed after the operator declined"
    assert final.get("report"), "no report after a declined run"


def test_exploit_phase_off_never_parks(graph_mod, monkeypatch):
    """The default session must not stop for an approval nobody asked for."""
    executed = []
    graph = _stub_graph(graph_mod, monkeypatch, executed=executed)
    cfg = {"configurable": {"thread_id": "no-exploit"}}
    out = graph.invoke(_initial(exploit_phase=False), cfg)
    assert graph_mod._interrupt_payload(out, graph, cfg) is None, (
        "a session with exploit_phase=False parked on an approval")
    assert out.get("report"), "the session did not reach the report"
    assert not executed


def test_no_candidate_skips_the_gate(graph_mod, monkeypatch):
    """Nothing queued means nothing to approve — go to the report, do not park.

    Otherwise an LLM that declined to queue anything would leave the session
    waiting forever for an approval of a candidate that does not exist.
    """
    executed = []
    graph = _stub_graph(graph_mod, monkeypatch, queued=False, executed=executed)
    cfg = {"configurable": {"thread_id": "no-candidate"}}
    out = graph.invoke(_initial(), cfg)
    assert graph_mod._interrupt_payload(out, graph, cfg) is None, (
        "parked on an approval with no queued candidate")
    assert out.get("report")


# ── 6. the endpoints execute (live; skips when the stack is down) ───────────
BASE = os.environ.get("AGENT_API", "https://localhost:3002")


def _client():
    requests = pytest.importorskip("requests")
    try:
        requests.packages.urllib3.disable_warnings()  # self-signed stack cert
    except Exception:
        pass
    return requests


def _get(path, **kw):
    requests = _client()
    try:
        return requests.get(f"{BASE}{path}", timeout=25, verify=False, **kw)
    except Exception as e:  # pragma: no cover
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def _post(path, payload):
    requests = _client()
    try:
        return requests.post(f"{BASE}{path}", json=payload, timeout=25, verify=False)
    except Exception as e:  # pragma: no cover
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def test_engine_endpoint_executes():
    """GET /api/agent-sessions/engine must run and report a valid engine.

    Also proves the route is declared BEFORE /api/agent-sessions/{session_id}:
    after it, "engine" would be parsed as a session id.
    """
    r = _get("/api/agent-sessions/engine")
    if r.status_code in (401, 403):
        pytest.skip(f"auth required at {BASE} (HTTP {r.status_code})")
    assert r.status_code == 200, f"HTTP {r.status_code}: {r.text[:300]}"
    body = r.json()
    assert body.get("engine") in ("langgraph", "autogen"), body
    assert body["availability"]["langgraph"]["available"] is True, (
        f"the langgraph engine is not loadable in the service: {body['availability']}")


def test_approve_rejects_a_malformed_session_id():
    r = _post("/api/agent-sessions/not-a-uuid/approve", {"approved": False})
    if r.status_code in (401, 403):
        pytest.skip(f"auth required at {BASE}")
    assert r.status_code == 400, f"expected 400, got {r.status_code}: {r.text[:300]}"


def test_approve_404s_on_an_unknown_session():
    r = _post("/api/agent-sessions/00000000-0000-0000-0000-000000000000/approve",
              {"approved": False})
    if r.status_code in (401, 403):
        pytest.skip(f"auth required at {BASE}")
    assert r.status_code == 404, f"expected 404, got {r.status_code}: {r.text[:300]}"


def test_pending_approval_executes_for_a_real_session():
    """The route must run against a real session and say 'nothing pending',
    rather than 404/500 — the difference between 'not parked' and 'broken'."""
    r = _get("/api/agent-sessions?limit=1")
    if r.status_code in (401, 403):
        pytest.skip(f"auth required at {BASE}")
    if r.status_code != 200:
        pytest.skip(f"cannot list sessions (HTTP {r.status_code})")
    body = r.json()
    rows = body if isinstance(body, list) else (
        body.get("sessions") or body.get("items") or body.get("data") or [])
    if not rows:
        pytest.skip("no agent sessions to sample")
    sid = rows[0].get("id") or rows[0].get("session_id")
    if not sid:
        pytest.skip("session rows carry no id")

    r2 = _get(f"/api/agent-sessions/{sid}/pending-approval")
    assert r2.status_code == 200, f"HTTP {r2.status_code}: {r2.text[:300]}"
    body2 = r2.json()
    assert "awaiting_approval" in body2 and isinstance(body2["awaiting_approval"], bool)
    assert body2["session_id"] == str(sid)


def test_approve_409s_on_a_session_that_is_not_parked():
    """An approval is meaningless unless the session is actually waiting.

    Returning 200 here would tell an operator an exploit was approved and run
    when nothing happened at all.
    """
    r = _get("/api/agent-sessions?limit=1")
    if r.status_code in (401, 403):
        pytest.skip(f"auth required at {BASE}")
    if r.status_code != 200:
        pytest.skip(f"cannot list sessions (HTTP {r.status_code})")
    body = r.json()
    rows = body if isinstance(body, list) else (
        body.get("sessions") or body.get("items") or body.get("data") or [])
    parked = [x for x in rows if x.get("status") == "awaiting_approval"]
    if parked:
        pytest.skip("sampled session is genuinely parked; not the case under test")
    if not rows:
        pytest.skip("no agent sessions to sample")
    sid = rows[0].get("id") or rows[0].get("session_id")
    if not sid:
        pytest.skip("session rows carry no id")
    r2 = _post(f"/api/agent-sessions/{sid}/approve", {"approved": False})
    assert r2.status_code == 409, f"expected 409, got {r2.status_code}: {r2.text[:300]}"


# ── 6. surface-test phase ───────────────────────────────────────────────────
# The surface-test agent generates custom tests, runs SAFE ones autonomously and
# gates IMPACTFUL ones on the same interrupt() the exploit phase uses. Two
# properties are load-bearing and easy to break with a later edit:
#   * classification cannot let an impactful test into the safe lane;
#   * safe execution (real scans) must sit BEFORE the checkpointed interrupt, so
#     a resume never re-runs it.
# These read source with ast, so they run on a bare checkout.

def _engine_src():
    return (_autogen_dir() / "langgraph_engine.py").read_text(encoding="utf-8")


def _engine_sets():
    return _set_constants(_autogen_dir() / "langgraph_engine.py")


def test_surface_categories_are_disjoint_and_correctly_tiered():
    sets = _engine_sets()
    safe = sets.get("_SAFE_CATEGORIES")
    imp = sets.get("_IMPACTFUL_CATEGORIES")
    assert safe and imp, "surface category sets missing — guard would pass vacuously"
    assert not (safe & imp), f"categories in both tiers: {safe & imp}"
    # the dangerous categories must be impactful
    assert {"rce", "shell", "msf_exploit", "file_write", "cred_bruteforce"} <= imp, (
        "a destructive category is not classified impactful")
    # the read-only ones must be safe
    assert {"version_probe", "nuclei_detect", "tls_check", "lfi_read",
            "sqli_detect"} <= safe, "a read-only probe is not classified safe"


def test_classify_fails_safe():
    """_classify must never call an exploit-sourced or non-allowlisted-tool test
    safe. Behavioral, via ast-extraction of the function."""
    import ast as _ast
    src = _engine_src()
    tree = _ast.parse(src)
    ns = {"os": __import__("os")}
    # pull the constants + helpers _classify depends on
    want = {"_SAFE_CATEGORIES", "_IMPACTFUL_CATEGORIES", "_SAFE_TOOL_HINTS"}
    for n in tree.body:
        if isinstance(n, _ast.Assign) and getattr(n.targets[0], "id", "") in want:
            exec(compile(_ast.Module([n], []), "<c>", "exec"), ns)
        if isinstance(n, _ast.FunctionDef) and n.name in ("_tool_head", "_classify"):
            exec(compile(_ast.Module([n], []), "<f>", "exec"), ns)
    c = ns["_classify"]
    assert c("nuclei_detect", "nuclei -u http://x", False) == "safe"
    assert c("rce", "curl x", False) == "impactful"          # bad category
    assert c("nuclei_detect", "nuclei -u x", True) == "impactful"   # exploit ref
    assert c("nuclei_detect", "msfconsole x", False) == "impactful"  # non-allowlisted tool
    assert c("version_probe", "sslscan 1.2.3.4:443", False) == "safe"


def test_run_custom_test_is_in_no_agent_toolset():
    """run_custom_test takes an arbitrary command; handing it to an LLM would
    launder any command through the gate. It must be in NO phase toolset and NOT
    registered as a ToolSpec."""
    src = _engine_src()
    for m in re.finditer(r"([A-Z_]+_TOOLS)\s*=\s*", src):
        # crude: no toolset literal should contain run_custom_test
        pass
    assert '"run_custom_test"' not in src or "run_custom_test" not in _engine_sets().get("SCAN_TOOLS_READONLY", set()), \
        "run_custom_test leaked into a phase toolset"
    reg = (_autogen_dir() / "tool_registry.py").read_text(encoding="utf-8")
    assert '"run_custom_test"' not in reg, (
        "run_custom_test is registered as an agent tool — it must stay off the "
        "LLM surface (deterministic-only)")


def test_surface_approval_is_the_only_interrupt_node():
    """interrupt() must live only in the two approval nodes; the plan/exec nodes
    must not contain it, or a resume would re-run their side effects."""
    tree = ast.parse(_engine_src())
    interrupt_nodes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and getattr(sub.func, "id", "") == "interrupt":
                    interrupt_nodes.append(node.name)
    assert set(interrupt_nodes) == {"exploit_approval", "surface_approval"}, (
        f"interrupt() is called in {interrupt_nodes}; only the two *_approval "
        "nodes may pause — a plan/exec node with interrupt() re-runs its side "
        "effects on resume")


def test_safe_execution_runs_before_the_interrupt():
    """run_custom_test (real scans) must be called from surface_safe_exec, which
    the graph places BEFORE surface_approval. If safe exec moved into or after
    the interrupt node, every resume would re-run the scans."""
    tree = ast.parse(_engine_src())
    callers = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Attribute) and sub.attr == "run_custom_test":
                    callers.append(node.name)
    assert set(callers) <= {"surface_safe_exec"}, (
        f"run_custom_test is called from {callers}; safe execution must live only "
        "in surface_safe_exec, before the checkpointed interrupt")
    # and the edge order: surface_safe_exec is wired before surface_approval
    src = _engine_src()
    i_safe = src.index('g.add_node("surface_safe_exec"')
    i_appr = src.index('g.add_node("surface_approval"')
    assert i_safe < i_appr, "surface_safe_exec must be declared before surface_approval"


def test_safe_lane_bounds_and_strips_exploit_nse_from_nmap():
    """A safe-lane nmap probe must be routed through _bound_safe_command, which
    strips `-sC`/`--script=<glob>` (exploit/brute NSE like ftp-vsftpd-backdoor —
    hangs the sequential lane AND crosses the safe/impactful boundary) and adds a
    `--host-timeout`. Guards the wiring (recommender cmd → _bound_safe_command)
    and the strip/rebuild. Sabotage: drop the _bound_safe_command call, or make
    it a passthrough → fails."""
    src = _engine_src()
    # 1) the resolved recommender command is passed through the bounder
    build = src[src.index("def _build_surface_tests("):]
    build = build[:build.index("\ndef ", 1)]
    assert "_bound_safe_command(cmd" in build, (
        "recommender-supplied safe commands must go through _bound_safe_command")
    # 2) the bounder rebuilds aggressive nmap to a bounded version scan
    fn = src[src.index("def _bound_safe_command("):]
    fn = fn[:fn.index("\ndef ", 1)]
    assert "--host-timeout" in fn, "bounder must add a host-timeout"
    assert 'return f"nmap -sV -Pn --host-timeout' in fn, (
        "aggressive nmap (-sC/--script glob) must be rebuilt as a bounded "
        "version scan")
    assert "-sC" in fn and "_SAFE_NSE_SCRIPTS" in fn, (
        "bounder must detect -sC and screen scripts against the safe allow-set")


def test_webshell_upload_is_impactful():
    """WSTG-CONF-06 webshell upload MUST be an impactful category so it can never
    run in the autonomous safe lane — it uploads code and gets a shell."""
    sets = _engine_sets()
    assert "webshell_upload" in sets.get("_IMPACTFUL_CATEGORIES", set()), (
        "webshell_upload must be impactful (human-gated), never safe")


def test_wstg_conf06_probe_is_scope_gated_before_traffic():
    """The WSTG-CONF-06 method probe sends real OPTIONS traffic, so it MUST pass
    the scope gate first. Assert _host_in_scope is checked before _detect_webdav
    in the probe loop. Sabotage: remove the _host_in_scope guard → fails."""
    src = _engine_src()
    fn = src[src.index("def _wstg_conf06_webshell_tests("):]
    fn = fn[:fn.index("\ndef ", 1)]
    assert "_host_in_scope(" in fn, "WSTG-CONF-06 probe must scope-check the host"
    assert fn.index("_host_in_scope(") < fn.index("_detect_webdav("), (
        "scope check must precede the OPTIONS probe (authorisation before traffic)")
    # and the scope helper fails closed
    hs = src[src.index("def _host_in_scope("):]
    hs = hs[:hs.index("\ndef ", 1)]
    assert "return False" in hs, "_host_in_scope must fail closed (return False on error)"


def test_webshell_ref_dispatches_as_webshell_with_valid_type():
    """A webshell test's ref must dispatch under source 'webshell' (what
    exploit-runner branches on) and a DB-valid exploit_type. Sabotage: change
    dispatch_source or use a type outside the CHECK constraint → fails."""
    src = _engine_src()
    fn = src[src.index("def _webshell_ref_from_url("):]
    fn = fn[:fn.index("\ndef ", 1)]
    assert '"dispatch_source": "webshell"' in fn
    assert '"vector": "webdav_put"' in fn
    # file_upload is in the pending_exploits.exploit_type CHECK set; webshell_upload is NOT.
    assert '"exploit_type": "file_upload"' in fn, (
        "exploit_type must satisfy the pending_exploits CHECK constraint")


def test_exploit_runner_webshell_branch_scope_gated():
    """exploit-runner's source=webshell branch sends a PUT, so it MUST refuse an
    out-of-scope target BEFORE deploying. Sabotage: drop the scope refusal, or
    call _deploy_webshell before it → fails."""
    er = (REPO / "exploit_runner" / "exploit_runner.py").read_text(encoding="utf-8")
    assert 'elif source == "webshell":' in er, "webshell dispatch branch missing"
    branch = er[er.index('elif source == "webshell":'):]
    branch = branch[:branch.index("\n        else:")]
    assert "_exploit_scope_refusal(" in branch, "webshell branch must scope-check"
    assert branch.index("_exploit_scope_refusal(") < branch.index("_deploy_webshell("), (
        "scope refusal must precede the webshell PUT")
    # and it proves EXECUTION, not just upload
    dep = er[er.index("def _deploy_webshell("):]
    dep = dep[:dep.index("\ndef ", 1)]
    assert "_WEBSHELL_MARKER" in dep, "deploy must verify command execution, not just a 201"


def test_run_custom_test_resolves_the_listener_execution_id():
    """kali-listener's /tools/execute returns the id in the `id` field (it runs
    the tool in a BackgroundTask), never `exec_id`/`execution_id`. run_custom_test
    MUST read `id` or exec_id is always None, the safe-lane poll loop is skipped,
    and every safe test records empty output as an error. Sabotage: drop
    `body.get("id")` from the exec_id resolution → this fails."""
    st_src = (_autogen_dir() / "scan_tools.py").read_text(encoding="utf-8")
    fn = st_src[st_src.index("def run_custom_test("):]
    fn = fn[:fn.index("\ndef ", 1)]
    # the exec_id value must fall back to the listener's `id` field
    assert re.search(r'"exec_id":\s*body\.get\([^)]*\)(\s*or\s*body\.get\([^)]*\))*\s*or\s*body\.get\(\s*["\']id["\']\s*\)', fn), (
        "run_custom_test must resolve exec_id from body.get('id') — the "
        "listener returns the execution id in the `id` field")


def test_safe_lane_poll_is_deadline_based_not_a_fixed_60s():
    """The safe-lane result poll must cover the tool's own timeout. A fixed
    20×3s=60s loop recorded slow scanners (nuclei/gobuster take minutes) as empty
    errors. Sabotage: revert surface_safe_exec to `for _ in range(20)` → fails."""
    src = _engine_src()
    fn = src[src.index("def surface_safe_exec("):]
    fn = fn[:fn.index("\ndef ", 1)]
    assert "_SAFE_TEST_POLL_SECONDS" in fn and "deadline" in fn, (
        "surface_safe_exec must poll to a wall-clock deadline "
        "(_SAFE_TEST_POLL_SECONDS), not a fixed iteration count")
    assert "for _ in range(20)" not in fn, (
        "the fixed 60s (20×3s) poll cap is back — slow safe tests will record "
        "empty errors")


def test_surface_event_types_are_in_the_allowlist():
    """A langgraph_surface_* event not in _ALL_EVENT_TYPES is emitted, 200'd and
    silently dropped from the Agent Activity timeline."""
    router = _autogen_dir().parent / "app" / "rag-api" / "webhooks" / "router.py"
    if not router.exists():
        pytest.skip("webhooks/router.py not present")
    src = router.read_text(encoding="utf-8")
    for ev in ("langgraph_surface_analyzed", "langgraph_surface_test_planned",
               "langgraph_surface_test_executed", "langgraph_surface_test_completed",
               "langgraph_surface_decision"):
        assert f'"{ev}"' in src, f"{ev} missing from _ALL_EVENT_TYPES — it will be dropped"


# ── 7. opt-in LLM synthesis in the surface phase ─────────────────────────────
# Synthesis authors a custom command per finding. Two properties keep it safe
# and non-breaking: it must be OPT-IN with a deterministic fallback, and its
# module (test_synth) imports the engine, so the engine must import it LAZILY
# (inside a function) or the process dies on an import cycle at startup.

def test_build_surface_tests_takes_a_synthesize_flag():
    src = _engine_src()
    assert re.search(r"def _build_surface_tests\(host[^)]*synthesize", src), (
        "_build_surface_tests must accept a `synthesize` flag — synthesis is "
        "opt-in, never the unconditional default")


def test_test_synth_is_imported_lazily_not_at_module_top():
    """test_synth imports langgraph_engine; if the engine imported test_synth at
    module level it would be a circular import that crashes startup. Every
    `import test_synth` must sit INSIDE a function."""
    tree = ast.parse(_engine_src())
    for node in tree.body:  # module-level statements only
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in getattr(node, "names", [])]
            mod = getattr(node, "module", None)
            assert "test_synth" not in names and mod != "test_synth", (
                "test_synth is imported at module top of langgraph_engine — that "
                "is a circular import; import it lazily inside the function")


def test_synthesis_helper_fails_safe_to_none():
    """_synthesize_finding_test must swallow failures and return None so the
    caller falls back to the deterministic map — synthesis can never break the
    phase. Checked structurally: the function body is wrapped in try/except."""
    tree = ast.parse(_engine_src())
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "_synthesize_finding_test"), None)
    assert fn is not None, "_synthesize_finding_test missing"
    assert any(isinstance(b, ast.Try) for b in fn.body), (
        "_synthesize_finding_test must wrap its body in try/except and return "
        "None on failure (deterministic fallback)")


# ── 8. auto-exploit is opt-in and never bypasses the scope gate ──────────────

def test_auto_exploit_routing_is_opt_in():
    """_after_surface_safe must route to surface_auto_exec ONLY behind the
    auto_exploit flag; with it off (the default) queued impactful tests go to the
    human approval gate. Source-checked so it runs on a bare checkout."""
    tree = ast.parse(_engine_src())
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "_after_surface_safe"), None)
    assert fn is not None, "_after_surface_safe missing"
    # collect (returned string constant, set of names guarding it)
    guarded = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant):
            guards = set()
            for anc in ast.walk(fn):
                if isinstance(anc, ast.If):
                    for sub in ast.walk(anc.test):
                        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                            guards.add(sub.value)
            guarded.setdefault(node.value.value, guards)
    src = _engine_src()
    # auto-exec is only returned inside a block testing surface_auto_exploit
    i_auto = src.index('"surface_auto_exec"')
    window = src[max(0, i_auto - 200):i_auto]
    assert "surface_auto_exploit" in window, (
        "surface_auto_exec must be routed to only under an if state.get("
        "'surface_auto_exploit') branch — auto-exploit has to be opt-in")
    assert "surface_approval" in src, "the human approval route must remain"


def test_auto_exec_executes_only_via_the_scope_gated_runner():
    """surface_auto_exec must reach execution ONLY through _exec_one_impactful
    (-> execute_approved_exploit -> the runner's fail-closed scope gate). It must
    NOT call run_custom_test or any other dispatch directly."""
    tree = ast.parse(_engine_src())
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "surface_auto_exec"), None)
    assert fn is not None, "surface_auto_exec missing"
    called = {s.attr for s in ast.walk(fn) if isinstance(s, ast.Attribute)}
    called |= {s.func.id for s in ast.walk(fn)
               if isinstance(s, ast.Call) and isinstance(s.func, ast.Name)}
    assert "run_custom_test" not in called, "auto-exec must not dispatch scans directly"
    assert "execute_approved_exploit" not in called, (
        "auto-exec must execute via the _exec_one_impactful helper, not call the "
        "runner directly")
    assert "_exec_one_impactful" in called, "auto-exec must use the shared gated executor"
    # and no interrupt in the auto path
    assert not any(isinstance(s, ast.Call) and getattr(s.func, "id", "") == "interrupt"
                   for s in ast.walk(fn)), "surface_auto_exec must not interrupt"
