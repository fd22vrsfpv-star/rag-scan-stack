"""The PoC graph must record WHICH nodes ran, using LangGraph's own stream.

`.invoke()` returns the final state and nothing else. A build that exhausted
its iterations therefore left no record of which of the 35 nodes ran, how long
each took, or which one raised — and 61% of builds in the 14 days to
2026-10-17 stopped at off_target / axis_exhausted / max_iters, diagnosed only
from trace lines the nodes authored themselves. A node that never ran authors
none.

`stream_mode=["debug", "values"]` is built in, local, and needs neither a
checkpointer nor a hosted service. The switch is only safe because the last
"values" payload equals what `.invoke()` returns; that equivalence is asserted
here against the real langgraph, not assumed.

    docker run --rm -v /opt/rag-scan-stack:/repo -w /repo python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=.:tests \
      python -m pytest tests/test_graph_node_tracing.py -v'
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"


@pytest.fixture(scope="module")
def tree():
    return ast.parse(GRAPH.read_text(encoding="utf-8"))


def _func(tree, name):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    pytest.fail(f"{name} not found in build_poc_graph.py")


def _streaming_func(tree):
    """Whichever function actually calls graph.stream().

    The streaming body moved from `_run_graph_traced` into `_stream_graph`
    when checkpointing was added, and three guards silently pointed at the
    old location. Finding it by behaviour rather than by name keeps them
    pinned to the code instead of to a function name.
    """
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for c in ast.walk(n):
            if isinstance(c, ast.Call) and getattr(c.func, "attr", None) == "stream":
                return n
    pytest.fail("no function calls graph.stream()")


class TestTheGraphIsStreamed:
    def test_the_run_goes_through_the_traced_runner(self, tree):
        fn = _func(tree, "run_build_poc") if any(
            isinstance(n, ast.FunctionDef) and n.name == "run_build_poc"
            for n in ast.walk(tree)) else tree
        calls = {getattr(n.func, "id", None) or getattr(n.func, "attr", None)
                 for n in ast.walk(fn) if isinstance(n, ast.Call)}
        assert "_run_graph_traced" in calls, (
            "the graph is invoked directly again — per-node history is lost")

    def test_the_runner_streams_both_modes(self, tree):
        """debug alone yields no final state; values alone yields no nodes."""
        fn = _streaming_func(tree)
        modes = set()
        # Two shapes: a direct keyword, or a kwargs dict built then splatted
        # (which is how the config= argument is made conditional).
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "stream":
                for kw in n.keywords:
                    if kw.arg == "stream_mode" and isinstance(kw.value, ast.List):
                        modes |= {e.value for e in kw.value.elts
                                  if isinstance(e, ast.Constant)}
            if isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if (isinstance(k, ast.Constant) and k.value == "stream_mode"
                            and isinstance(v, ast.List)):
                        modes |= {e.value for e in v.elts
                                  if isinstance(e, ast.Constant)}
            if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant) \
                    and n.slice.value == "stream_mode":
                modes |= {"__assigned__"}
        assert {"debug", "values"} <= modes, (
            f"stream_mode must request both debug and values; got {modes}")

    def test_a_missing_final_state_falls_back_rather_than_half_building(self, tree):
        """Returning a partial dict would corrupt the build silently."""
        fn = _streaming_func(tree)
        invokes = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                   and getattr(n.func, "attr", None) == "invoke"]
        assert invokes, (
            "there must be an .invoke() fallback for the case where the "
            "stream yields no state at all")

    def test_tracing_cannot_break_the_build(self, tree):
        """Instrumentation must never take down what it observes."""
        fn = _func(tree, "_run_graph_traced")
        handlers = [h for n in ast.walk(fn) if isinstance(n, ast.Try)
                    for h in n.handlers]
        assert handlers, "the per-event tracing must be wrapped"
        assert any(
            (getattr(h.type, "id", None) == "Exception") for h in handlers), (
            "a narrow except would let a tracing bug kill the run")

    def test_both_task_and_task_result_are_handled(self, tree):
        """Only task_result gives timing; only task gives the start order."""
        fn = _streaming_func(tree)
        consts = {n.value for n in ast.walk(fn)
                  if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        assert "task" in consts and "task_result" in consts, (
            "both debug event types are needed: task for ordering, "
            "task_result for outcome and timing")


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("langgraph") is None,
    reason="langgraph not installed in this image — the equivalence check "
           "needs the real library (this is 'cannot run here', not a pass)")
def test_live_stream_final_state_equals_invoke():
    """The property the switch depends on, asserted against real langgraph.

    If a future version changed what the last `values` payload contains, every
    build would silently receive a different final state. That is worth one
    executing test rather than a comment.
    """
    from typing import TypedDict
    from langgraph.graph import StateGraph, START, END

    class S(TypedDict, total=False):
        a: int
        b: str
        trail: list

    def n1(s):
        return {"a": s.get("a", 0) + 1, "trail": (s.get("trail") or []) + ["n1"]}

    def n2(s):
        return {"b": "done", "trail": (s.get("trail") or []) + ["n2"]}

    g = StateGraph(S)
    g.add_node("n1", n1)
    g.add_node("n2", n2)
    g.add_edge(START, "n1")
    g.add_edge("n1", "n2")
    g.add_edge("n2", END)
    app = g.compile()

    invoked = app.invoke({"a": 0})
    last, names = None, []
    for mode, payload in app.stream({"a": 0}, stream_mode=["debug", "values"]):
        if mode == "values":
            last = payload
        elif mode == "debug" and payload.get("type") == "task_result":
            names.append(payload["payload"]["name"])
    assert last == invoked, (
        f"the last `values` payload diverged from invoke(): {last} != {invoked}")
    assert names == ["n1", "n2"], f"node order not reported: {names}"


# ---------------------------------------------------------------------------
# Checkpointing: a build killed mid-flight must resume, not restart
# ---------------------------------------------------------------------------
# On 2026-10-17 a rag-api restart during a focused-10 killed all ten in-flight
# builds (HTTP:000). Each had run 10+ minutes. With a checkpointer keyed on
# thread_id = run_id they resume from the last completed node.
#
# Proven against the real library (see test_live_checkpoint_resumes below):
#   run 1 died at n2  ->  state ['n1'], next ('n2',)
#   resumed           ->  ['n1','n2','n3'], n1 NOT re-run


class TestCheckpointing:
    def test_build_graph_accepts_a_checkpointer(self, tree):
        fn = _func(tree, "build_graph")
        names = [a.arg for a in fn.args.args]
        assert "checkpointer" in names, (
            f"build_graph must take a checkpointer; args={names}")

    def test_compile_is_given_the_checkpointer(self, tree):
        """`g.compile()` with no argument silently disables checkpointing."""
        fn = _func(tree, "build_graph")
        compiles = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                    and getattr(n.func, "attr", None) == "compile"]
        assert compiles, "build_graph no longer compiles a graph"
        assert any(kw.arg == "checkpointer" for c in compiles for kw in c.keywords), (
            "compile() is called without checkpointer= — state is not persisted")

    def test_the_saver_fails_soft(self, tree):
        """Losing recovery is acceptable; losing the build is not."""
        fn = _func(tree, "_saver_cm")
        rets = [r for r in ast.walk(fn) if isinstance(r, ast.Return)]
        none_rets = [r for r in rets
                     if isinstance(r.value, ast.Constant) and r.value.value is None]
        assert none_rets, (
            "_saver_cm must return None when checkpointing is unavailable, "
            "so the caller can run an uncheckpointed graph")

    def test_resume_passes_none_not_the_initial_state(self, tree):
        """THE correctness hinge.

        With a checkpointer, re-passing the initial state RESTARTS the graph;
        passing None resumes it. Backwards, a 12-iteration build silently
        re-runs from scratch and the recovery looks like it worked.
        """
        fn = _func(tree, "_stream_graph")
        ifexps = [n for n in ast.walk(fn) if isinstance(n, ast.IfExp)]
        ok = False
        for n in ifexps:
            body_is_none = (isinstance(n.body, ast.Constant)
                            and n.body.value is None)
            orelse_is_state = (isinstance(n.orelse, ast.Name)
                               and n.orelse.id == "state")
            if body_is_none and orelse_is_state:
                ok = True
        assert ok, (
            "the stream input must be `None if resuming else state`; anything "
            "else restarts the build instead of resuming it")

    def test_the_resume_decision_consults_the_checkpoint(self, tree):
        fn = _func(tree, "_stream_graph")
        calls = {getattr(n.func, "id", None) or getattr(n.func, "attr", None)
                 for n in ast.walk(fn) if isinstance(n, ast.Call)}
        assert "_has_checkpoint" in calls, (
            "resume must be decided by asking the checkpointer, not assumed")

    def test_has_checkpoint_requires_pending_work(self, tree):
        """A FINISHED thread has a checkpoint but nothing left to do; resuming
        it would pass None to a graph with no next node."""
        fn = _func(tree, "_has_checkpoint")
        dump = ast.dump(fn)
        assert "next" in dump, (
            "_has_checkpoint must look at snapshot.next — the presence of a "
            "checkpoint alone does not mean work remains")


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("langgraph.checkpoint.postgres") is None
    or not __import__("os").environ.get("DB_DSN"),
    reason="needs langgraph-checkpoint-postgres AND a DB_DSN — "
           "'cannot run here', not a pass")
def test_live_checkpoint_resumes_without_rerunning():
    """Kill a graph mid-run against a real Postgres, then resume it."""
    import os
    import uuid
    from typing import TypedDict
    from langgraph.graph import StateGraph, START, END
    from langgraph.checkpoint.postgres import PostgresSaver

    class S(TypedDict, total=False):
        trail: list
        boom: bool

    def n1(s):
        return {"trail": (s.get("trail") or []) + ["n1"]}

    def n2(s):
        if s.get("boom"):
            raise RuntimeError("simulated mid-run death")
        return {"trail": (s.get("trail") or []) + ["n2"]}

    def n3(s):
        return {"trail": (s.get("trail") or []) + ["n3"]}

    def build(cp):
        g = StateGraph(S)
        for n, f in (("n1", n1), ("n2", n2), ("n3", n3)):
            g.add_node(n, f)
        g.add_edge(START, "n1")
        g.add_edge("n1", "n2")
        g.add_edge("n2", "n3")
        g.add_edge("n3", END)
        return g.compile(checkpointer=cp)

    cfg = {"configurable": {"thread_id": f"test-{uuid.uuid4()}"}}
    with PostgresSaver.from_conn_string(os.environ["DB_DSN"]) as sv:
        sv.setup()
        g = build(sv)
        with pytest.raises(RuntimeError):
            g.invoke({"trail": [], "boom": True}, config=cfg)
        snap = g.get_state(cfg)
        assert snap.values.get("trail") == ["n1"], snap.values
        assert snap.next == ("n2",), snap.next
        g2 = build(sv)
        g2.update_state(cfg, {"boom": False})
        final = g2.invoke(None, config=cfg)
        assert final["trail"] == ["n1", "n2", "n3"], final
        assert final["trail"].count("n1") == 1, "n1 was re-run — that is a restart"


def test_rag_api_declares_a_working_postgres_driver():
    """Checkpointing needs psycopg3 WITH libpq, not just psycopg3.

    `langgraph-checkpoint-postgres` speaks psycopg v3. rag-api had a bare
    `psycopg` (no binary wheel), so `PostgresSaver.from_conn_string` raised
    "libpq library not found", `_saver_cm()` returned None, and checkpointing
    shipped INERT while every structural test above still passed. The
    fail-soft worked; the feature did not.
    """
    req = (REPO / "app" / "rag-api" / "requirements.txt").read_text(encoding="utf-8")
    pkgs = [l.split("#")[0].strip().lower()
            for l in req.splitlines() if l.strip() and not l.strip().startswith("#")]
    has_saver = any(p.startswith("langgraph-checkpoint-postgres") for p in pkgs)
    if not has_saver:
        pytest.skip("rag-api does not use the postgres checkpointer")
    assert any(p.startswith("psycopg[binary]") or p.startswith("psycopg-binary")
               for p in pkgs), (
        "langgraph-checkpoint-postgres needs psycopg[binary]; a bare psycopg "
        "has no libpq and the saver fails soft to None, disabling "
        f"checkpointing silently. Declared: {pkgs}")


class TestAPinnedRunIdMakesRecoveryReachable:
    """Checkpointing is only usable if a caller can ASK to resume.

    `initial_state` generated `run_id` as f"{cve}_{ip}_{int(time.time())}" —
    a fresh timestamp per call. A retry therefore got a new run_id, hence a
    new thread_id, hence a fresh build: the checkpointer would have worked
    perfectly and nothing could ever have reached it. The driver retry that
    makes a round survive a restart depends entirely on this.
    """

    def test_initial_state_accepts_a_run_id(self, tree):
        fn = _func(tree, "initial_state")
        names = [a.arg for a in fn.args.args] + [a.arg for a in fn.args.kwonlyargs]
        assert "run_id" in names, f"initial_state cannot be pinned; args={names}"

    def test_a_supplied_run_id_wins_over_the_generated_one(self, tree):
        """`run_id or f"..."` — not the other way round, which would ignore it."""
        fn = _func(tree, "initial_state")
        found = False
        for n in ast.walk(fn):
            if isinstance(n, ast.BoolOp) and isinstance(n.op, ast.Or):
                vals = n.values
                if (vals and isinstance(vals[0], ast.Name)
                        and vals[0].id == "run_id"):
                    found = True
        assert found, (
            "the supplied run_id must take precedence over the generated "
            "timestamp, or pinning it silently does nothing")

    def test_the_default_is_still_unique(self, tree):
        """Two builds of the same CVE must not collide when nothing is pinned."""
        fn = _func(tree, "initial_state")
        dump = ast.dump(fn)
        assert "time" in dump, (
            "the fallback must stay timestamped; a deterministic default "
            "would make every re-run of a CVE resume the previous build")
