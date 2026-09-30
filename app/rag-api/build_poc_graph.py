"""LangGraph refactor of `_build_poc_core` (in api.py).

Why this module exists: the build-poc pipeline in api.py grew to ~300 lines of hand-
wired conditionals (10 recon phases + hints + auth + research + strategist + plan
verifier + synth + refine loop + verify guards + save). New signals we add (like the
next feature — mining every response for bypass clues) risk being lost between phases
because every consumer reads from ONE hand-composed guidance string.

This module makes state explicit: every node reads from and writes to a `BuildPocState`
dict. Nodes are the existing helpers in api.py (unchanged); this module wires them.
The final `guidance` string handed to synth is composed by a dedicated
`assemble_guidance` node using the SAME concatenation order and formatting as today's
code — parity-tested byte-for-byte.

Rollout: `BUILD_POC_LANGGRAPH` env flag (default off). When on, `_build_poc_core`
calls `invoke_build_poc(state)`; when off, the existing monolith runs unchanged.
"""

from __future__ import annotations

import operator
import os
import time
from typing import Annotated, Any, Dict, List, Optional, TypedDict


# ── state ──────────────────────────────────────────────────────────────────────
class BuildPocState(TypedDict, total=False):
    # Immutable inputs (set at graph start; never mutated by nodes)
    cve: str
    ip: str
    port: int
    product: Optional[str]
    version: Optional[str]
    eid: Optional[str]
    max_iters: int
    model: Optional[str]
    research: bool
    recon_first: bool
    recon_source: str
    hint: Optional[str]
    run_id: str
    t0: float

    # Recon accumulators — each recon node appends into these. `segments` is the
    # ordered list of guidance strings; `assemble_guidance` joins them into the
    # final string handed to synth. Every accumulator uses operator.add so the
    # graph runtime merges concurrent-node contributions correctly (we're
    # sequential today but this keeps the door open for a fan-out later).
    segments: Annotated[List[str], operator.add]
    recon_metrics: Dict[str, Dict[str, Any]]
    intel_list: List[Dict[str, Any]]
    zap_paths: List[str]
    cred_hints: List[str]
    admin_paths_mined: List[str]
    detected_frameworks: List[str]
    waf_family: Optional[str]
    waf_characterization: Dict[str, Any]

    # Hint / auth / research
    auth: Dict[str, Any]
    auth_guidance: str
    session_info: Optional[Dict[str, Any]]
    hint_guidance: str
    research_out: Optional[Dict[str, Any]]

    # Strategy / synth
    strategy: str
    plan_verdicts: Dict[str, str]
    guidance: str
    built: Optional[Dict[str, Any]]

    # Refine loop state
    command: str
    assertion: Dict[str, Any]
    canary: Optional[str]
    output: str
    success: bool
    drifted: bool
    iters: int
    escalated: bool
    escalation_guidance: str
    metrics: Dict[str, Any]

    # Final verdict
    verified: bool
    reflection: bool
    off_target: bool
    exploit_store_id: Optional[str]


def enabled() -> bool:
    """True when the LangGraph build path should be used. Env-flag default off."""
    return os.environ.get("BUILD_POC_LANGGRAPH", "0").lower() in ("1", "true", "yes", "on")


def initial_state(cve: str, ip: str, port: int, product=None, version=None, eid=None,
                  max_iters: int = 3, research: bool = True, model=None, auth=None,
                  recon_first: bool = False, recon_source: str = "basic",
                  hint: Optional[str] = None) -> BuildPocState:
    """Build the initial state dict handed to the graph. Mirrors the argument shape
    of _build_poc_core so the wrapper is trivial."""
    return {
        "cve": cve, "ip": ip, "port": port,
        "product": product, "version": version, "eid": eid,
        "max_iters": max_iters, "model": model, "research": research,
        "recon_first": recon_first, "recon_source": recon_source, "hint": hint,
        "run_id": f"{cve}_{ip}_{int(time.time())}",
        "t0": time.time(),
        "segments": [], "recon_metrics": {}, "intel_list": [],
        "zap_paths": [], "cred_hints": [], "admin_paths_mined": [],
        "detected_frameworks": [], "waf_family": None, "waf_characterization": {},
        "auth": auth or {}, "auth_guidance": "", "session_info": None,
        "hint_guidance": "", "research_out": None,
        "strategy": "", "plan_verdicts": {}, "guidance": "", "built": None,
        "command": "", "assertion": {}, "canary": None, "output": "",
        "success": False, "drifted": False, "iters": 0, "escalated": False,
        "escalation_guidance": "", "metrics": {},
        "verified": False, "reflection": False, "off_target": False,
        "exploit_store_id": None,
    }


def build_graph():
    """Return the compiled StateGraph. Nodes are added incrementally as the
    migration progresses (Stage 2 -> Stage 4). Stage 1 builds a stub graph
    (START -> END) so the parity test can exercise the wrapper + state
    plumbing without any node logic yet."""
    from langgraph.graph import StateGraph, START, END
    g = StateGraph(BuildPocState)
    # Stage 1: no nodes yet. Direct START -> END so the graph invokes cleanly and
    # returns the initial state unchanged. Subsequent stages add nodes/edges.
    g.add_edge(START, END)
    return g.compile()


def invoke_build_poc(state: BuildPocState) -> Dict[str, Any]:
    """Run the graph and return the same dict shape _build_poc_core returns to
    its endpoint caller: {command, assertion, canary, success, verified,
    off_target, reflection, iterations, exploit_store_id, ...}.
    Stage 1: graph is a stub; this returns a failed-build sentinel so any early
    caller of the flag-on path sees a clear signal (not a silent empty)."""
    graph = build_graph()
    final = graph.invoke(state)
    # Stage 1 stub — no real nodes yet. Return a sentinel so the wrapper falls
    # back to the monolith on this call. Removed once Stage 2 nodes land.
    return {
        "ok": False, "cve": final.get("cve"), "verified": False,
        "iterations": 0, "off_target": False, "reflection": False,
        "exploit_store_id": None, "final_command": None,
        "final_assertion": None, "log_path": None,
        "_langgraph_stub": True,   # sentinel — wrapper falls back to monolith
    }
