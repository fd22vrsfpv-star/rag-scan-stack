"""Phase 0 spike — prove LangGraph can drive the existing pentest stack.

NOT wired into the service. This is the reversible spike from
Docs/LANGGRAPH_MIGRATION_PLAN.md §4. It proves three things before we commit to
the migration:

  1. TOOLS FIRE      — a LangGraph node calls a real, unchanged tool body
                       (`scan_tools.query_assets`) and gets live data.
  2. SCOPE GATE HOLDS — a node that attempts an OUT-OF-SCOPE dispatch is refused
                       (fail-closed). The gate is the SAME `enforce_target_scope`
                       the AutoGen tools use, so no new ungated path is created.
  3. CHECKPOINT/RESUME — the run persists to Postgres (PostgresSaver) and resumes
                       by thread_id after an interrupt, replacing the manual
                       message persistence + parent_session_id resume hack.

Run inside the autogen-agents container:
    python3 langgraph_spike.py
"""
from __future__ import annotations

import json
import operator
import os
from typing import Annotated, List, Optional, TypedDict

from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.postgres import PostgresSaver

import scan_tools

# TEST-NET-3 (RFC 5737 documentation range) — never in any engagement scope, so
# a dispatch against it MUST be refused. Using it means the proof contacts nothing.
OUT_OF_SCOPE_TARGET = "203.0.113.99"


class SpikeState(TypedDict):
    session_id: str
    phase: str
    assets_len: int
    scope_refused: Optional[str]
    report: Optional[str]
    log: Annotated[List[str], operator.add]


def recon(state: SpikeState) -> dict:
    """Node 1 — call a real, read-only tool body unchanged."""
    out = scan_tools.query_assets(limit=5) or ""
    return {"phase": "scan",
            "assets_len": len(out),
            "log": [f"recon: query_assets(limit=5) -> {len(out)} chars"]}


def scan_gate(state: SpikeState) -> dict:
    """Node 2 — attempt an out-of-scope dispatch; the scope gate must refuse it."""
    refusal = scan_tools._scope_refusal_for_payload(
        "nmap", {"targets": [OUT_OF_SCOPE_TARGET]})
    verdict = "REFUSED" if refusal else "ALLOWED"
    return {"phase": "report",
            "scope_refused": refusal or None,
            "log": [f"scan_gate: nmap {OUT_OF_SCOPE_TARGET} -> {verdict}"]}


def report(state: SpikeState) -> dict:
    """Node 3 — compose a summary from accumulated state (runs after resume)."""
    rpt = {
        "assets_chars": state.get("assets_len", 0),
        "scope_gate": "REFUSED (fail-closed)" if state.get("scope_refused") else "NOT REFUSED",
        "scope_msg": (state.get("scope_refused") or "")[:160],
    }
    return {"phase": "done", "report": json.dumps(rpt), "log": ["report: composed"]}


def build_graph(checkpointer):
    g = StateGraph(SpikeState)
    g.add_node("recon", recon)
    g.add_node("scan_gate", scan_gate)
    g.add_node("report", report)
    g.add_edge(START, "recon")
    g.add_edge("recon", "scan_gate")
    g.add_edge("scan_gate", "report")
    g.add_edge("report", END)
    # interrupt_before proves durable resume: the run stops with state persisted,
    # then a second invoke(None, cfg) continues from the checkpoint.
    return g.compile(checkpointer=checkpointer, interrupt_before=["report"])


def main() -> int:
    dsn = os.environ["DB_DSN"]
    thread_id = "langgraph-spike"
    ok = {"tools": False, "scope_gate": False, "resume": False}

    with PostgresSaver.from_conn_string(dsn) as saver:
        saver.setup()                       # idempotent: creates checkpoint tables
        graph = build_graph(saver)
        cfg = {"configurable": {"thread_id": thread_id}}

        # First invoke: runs recon + scan_gate, then STOPS before report.
        s1 = graph.invoke({"session_id": thread_id, "phase": "recon",
                           "assets_len": 0, "scope_refused": None,
                           "report": None, "log": []}, cfg)
        print("── after first invoke (interrupted before report) ──")
        for line in s1["log"]:
            print("   ", line)
        ok["tools"] = s1.get("assets_len", 0) > 0
        ok["scope_gate"] = bool(s1.get("scope_refused"))

        # The checkpoint must exist and the graph must know report is still pending.
        snap = graph.get_state(cfg)
        pending = tuple(snap.next)
        print(f"   checkpoint persisted; next pending node(s): {pending}")

        # Second invoke resumes FROM the Postgres checkpoint (no re-run of node 1/2).
        s2 = graph.invoke(None, cfg)
        print("── after resume ──")
        for line in s2["log"]:
            print("   ", line)
        ok["resume"] = s2.get("phase") == "done" and pending == ("report",)
        print("   report:", s2.get("report"))

        # Show the checkpoint history depth (durability evidence).
        history = list(graph.get_state_history(cfg))
        print(f"   postgres checkpoints for thread '{thread_id}': {len(history)}")

    print("\n── PROOFS ──")
    print(f"  1. tools fire        : {'PASS' if ok['tools'] else 'FAIL'}")
    print(f"  2. scope gate refuses: {'PASS' if ok['scope_gate'] else 'FAIL'}")
    print(f"  3. checkpoint+resume : {'PASS' if ok['resume'] else 'FAIL'}")
    return 0 if all(ok.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
