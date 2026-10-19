"""The recon cache, wired into the graph: reuse, refresh, and never a wrong hit.

`tests/test_recon_cache.py` proves the policy. This proves the decorator that
acts on it, which is where the damage would be:

  * A reused result must carry its AGE, or the `fact_is_stale` rule downstream
    has nothing to downgrade and reuse silently becomes "trust yesterday".
  * An AUTHENTICATED crawl and an anonymous one must not share a cache entry.
    That is a wrong answer served fast — worse than re-running the tool.
  * A node that produced NOTHING must not be cached. The recon nodes swallow
    their own tool errors and return empty, so caching an empty result pins a
    broken tool for the whole TTL.
  * Only this node's metrics may be stored. Caching the merged dict would
    replay every earlier tool's numbers on a later run.

Run standalone:

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_recon_cache_wiring.py -v'
"""
from __future__ import annotations

import ast
import functools
import logging
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from etl import recon_cache as rc  # noqa: E402

GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"
GRAPH_SRC = GRAPH.read_text(encoding="utf-8")
GRAPH_TREE = ast.parse(GRAPH_SRC)


def _node(name):
    for n in ast.walk(GRAPH_TREE):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _decorators(name):
    n = _node(name)
    return [ast.unparse(d) for d in (n.decorator_list if n else [])]


# ── an executing copy of the decorator ─────────────────────────────────────

def _load():
    """Exec the real `_recon_cached` + helpers with `api` stubbed."""
    looked, stored, traced = [], [], []

    fake_api = types.ModuleType("api")
    state_box = {"hit": None}

    def _lookup(key, tool, mode=None):
        looked.append((key, tool, mode))
        h = state_box["hit"]
        if h is None:
            return rc.MISS, "nothing cached", None, None
        payload, age = h
        action, reason = rc.decide(mode or rc.AUTO, age, rc.ttl_for(tool))
        return action, reason, (payload if action == rc.REUSE else None), age

    fake_api._recon_cache_lookup = _lookup
    fake_api._recon_cache_store = lambda *a, **k: (stored.append((a, k)) or True)
    fake_api._poc_trace = lambda *a, **k: traced.append((a, k))
    sys.modules["api"] = fake_api

    ns = {"functools": functools, "logging": logging,
          "Dict": dict, "Any": object, "BuildPocState": dict,
          "Optional": object, "List": list,
          "_want": lambda src, what: what in str(src or "")}
    for fn in ("_recon_cached", "_worth_caching", "_auth_fingerprint"):
        node = _node(fn)
        assert node is not None, "%s missing from build_poc_graph.py" % fn
        exec(compile(ast.Module([node], []), "<graph>", "exec"), ns)
    ns.update(_looked=looked, _stored=stored, _traced=traced, _box=state_box)
    return ns


G = _load()


@pytest.fixture(autouse=True)
def _reset():
    G["_looked"].clear(); G["_stored"].clear(); G["_traced"].clear()
    G["_box"]["hit"] = None


def _make_node(tool="zap", variant=None, result=None, ran=None):
    def inner(state):
        if ran is not None:
            ran.append(state)
        return result if result is not None else {"segments": ["fresh output"],
                                                  "recon_metrics": {"zap": {"seconds": 9}}}
    inner.__name__ = "node_fake"
    return G["_recon_cached"](tool, variant=variant)(inner)


BASE = {"ip": "10.0.0.1", "port": 443, "run_id": "r1", "eid": "e1",
        "recon_metrics": {}, "reuse_recon": None}


# ── reuse ──────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestReuse:
    def test_a_fresh_hit_skips_the_tool(self):
        ran = []
        G["_box"]["hit"] = ({"segments": ["cached"], "recon_metrics": {"zap": {"seconds": 9}}}, 60)
        out = _make_node(ran=ran)(dict(BASE))
        assert ran == [], "the tool ran despite a fresh cache hit"
        assert out["segments"] == ["cached"]

    def test_a_reused_result_carries_its_age(self):
        """Without the age the downstream staleness rule has nothing to act
        on, and reuse quietly becomes 'trust yesterday'."""
        G["_box"]["hit"] = ({"segments": ["c"], "recon_metrics": {"zap": {"seconds": 9}}}, 1234)
        out = _make_node()(dict(BASE))
        m = out["recon_metrics"]["zap"]
        assert m["reused"] is True
        assert m["age_seconds"] == 1234
        assert "REUSED" in m["signal"]

    def test_a_reuse_is_traced_so_a_fast_build_is_explicable(self):
        G["_box"]["hit"] = ({"segments": ["c"]}, 60)
        _make_node()(dict(BASE))
        phases = [a[1] for a, _ in G["_traced"]]
        assert any("cache" in str(p) for p in phases)

    def test_a_stale_hit_runs_the_tool(self):
        ran = []
        G["_box"]["hit"] = ({"segments": ["old"]}, 10 ** 7)
        out = _make_node(ran=ran)(dict(BASE))
        assert len(ran) == 1
        assert out["segments"] == ["fresh output"]

    def test_never_runs_the_tool_even_on_a_fresh_hit(self):
        ran = []
        G["_box"]["hit"] = ({"segments": ["c"]}, 1)
        st = dict(BASE, reuse_recon="never")
        _make_node(ran=ran)(st)
        assert len(ran) == 1

    def test_always_accepts_a_stale_hit(self):
        ran = []
        G["_box"]["hit"] = ({"segments": ["ancient"]}, 10 ** 7)
        out = _make_node(ran=ran)(dict(BASE, reuse_recon="always"))
        assert ran == [] and out["segments"] == ["ancient"]

    def test_the_existing_state_metrics_survive_a_reuse(self):
        G["_box"]["hit"] = ({"segments": ["c"], "recon_metrics": {"zap": {"seconds": 1}}}, 10)
        st = dict(BASE, recon_metrics={"port_sweep": {"seconds": 3}})
        out = _make_node()(st)
        assert out["recon_metrics"]["port_sweep"] == {"seconds": 3}
        assert out["recon_metrics"]["zap"]["reused"] is True


# ── storing ────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestStore:
    def test_a_fresh_run_is_stored_with_its_engagement(self):
        _make_node()(dict(BASE))
        assert len(G["_stored"]) == 1
        args, kwargs = G["_stored"][0]
        assert kwargs["engagement_id"] == "e1"
        assert kwargs["run_id"] == "r1"

    def test_only_this_nodes_metrics_are_stored(self):
        """Storing the merged dict would replay every earlier tool's numbers."""
        st = dict(BASE, recon_metrics={"port_sweep": {"seconds": 3}})
        node = _make_node(result={"segments": ["x"],
                                  "recon_metrics": {"port_sweep": {"seconds": 3},
                                                    "zap": {"seconds": 9}}})
        node(st)
        payload = G["_stored"][0][0][4]
        assert set(payload["recon_metrics"]) == {"zap"}, payload["recon_metrics"]

    def test_an_empty_result_is_not_cached(self):
        """The nodes swallow their own tool errors, so an all-empty result is
        as likely a broken tool as a clean target. Caching it pins the failure."""
        _make_node(result={"segments": [], "recon_metrics": {"zap": {"seconds": 0}}})(dict(BASE))
        assert G["_stored"] == []

    def test_a_result_with_only_side_outputs_is_cached(self):
        _make_node(result={"segments": [], "zap_paths": ["/a", "/b"]})(dict(BASE))
        assert len(G["_stored"]) == 1

    def test_worth_caching_rejects_a_non_dict(self):
        assert G["_worth_caching"](None) is False
        assert G["_worth_caching"]("nope") is False


# ── the key ────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestVariant:
    def test_authenticated_and_anonymous_do_not_share_an_entry(self):
        """The one failure worse than re-running: a wrong answer, served fast."""
        v = lambda st: {"auth": G["_auth_fingerprint"](st)}  # noqa: E731
        _make_node(variant=v)(dict(BASE, session_info={}))
        anon_key = G["_looked"][0][0]
        G["_looked"].clear()
        _make_node(variant=v)(dict(BASE, session_info={"cookie_header": "JSESSIONID=x",
                                                       "user": "alice"}))
        assert G["_looked"][0][0] != anon_key

    def test_two_different_users_do_not_share_an_entry(self):
        v = lambda st: {"auth": G["_auth_fingerprint"](st)}  # noqa: E731
        keys = []
        for user in ("alice", "bob"):
            G["_looked"].clear()
            _make_node(variant=v)(dict(BASE, session_info={"cookie_header": "c", "user": user}))
            keys.append(G["_looked"][0][0])
        assert keys[0] != keys[1], "two accounts see different things"

    def test_the_credential_never_enters_the_key(self):
        fp = G["_auth_fingerprint"]({"auth": {"username": "alice", "password": "hunter2"},
                                     "session_info": {"cookie_header": "c"}})
        assert "hunter2" not in str(fp)

    def test_a_variant_that_raises_does_not_break_the_node(self):
        ran = []
        def boom(st):
            raise RuntimeError("nope")
        _make_node(variant=boom, ran=ran)(dict(BASE))
        assert len(ran) == 1, "a broken variant must not stop the recon"

    def test_a_dynamic_tool_name_is_resolved_from_the_state(self):
        _make_node(tool=lambda st: "zap_active" if st.get("x") else "zap")(dict(BASE, x=True))
        assert G["_looked"][0][1] == "zap_active"


@pytest.mark.unit
class TestFailSoft:
    def test_an_unavailable_cache_still_runs_the_tool(self):
        ran = []
        orig = sys.modules["api"]._recon_cache_lookup
        sys.modules["api"]._recon_cache_lookup = \
            lambda *a, **k: (rc.UNAVAILABLE, "cache unreadable (RuntimeError)", None, None)
        try:
            _make_node(ran=ran)(dict(BASE))
        finally:
            sys.modules["api"]._recon_cache_lookup = orig
        assert len(ran) == 1

    def test_an_unavailable_cache_is_traced_as_such_not_as_a_miss(self):
        orig = sys.modules["api"]._recon_cache_lookup
        sys.modules["api"]._recon_cache_lookup = \
            lambda *a, **k: (rc.UNAVAILABLE, "cache unreadable (RuntimeError)", None, None)
        try:
            _make_node()(dict(BASE))
        finally:
            sys.modules["api"]._recon_cache_lookup = orig
        actions = [kw.get("extra", {}).get("action") for _, kw in G["_traced"]]
        assert rc.UNAVAILABLE in actions, (
            "a broken cache reported as a miss is a cache that never works "
            "and nobody notices")

    def test_a_store_failure_does_not_fail_the_node(self):
        orig = sys.modules["api"]._recon_cache_store
        sys.modules["api"]._recon_cache_store = \
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("disk full"))
        try:
            out = _make_node()(dict(BASE))
        finally:
            sys.modules["api"]._recon_cache_store = orig
        assert out["segments"] == ["fresh output"]


# ── which nodes are wired ──────────────────────────────────────────────────

@pytest.mark.unit
class TestWiring:
    EXPENSIVE = ["node_zap_recon", "node_playwright_recon", "node_arjun_recon",
                 "node_port_sweep", "node_framework_deep_enum", "node_openapi_recon",
                 "node_waf_detect"]

    def test_the_expensive_nodes_are_cached(self):
        for name in self.EXPENSIVE:
            assert any("_recon_cached" in d for d in _decorators(name)), (
                "%s re-runs its tool on every build" % name)

    def test_the_nodes_keep_their_names(self):
        """functools.wraps, so the routing guards still resolve them."""
        assert "functools.wraps" in GRAPH_SRC
        for name in self.EXPENSIVE:
            assert _node(name) is not None

    def test_every_crawling_node_keys_on_the_session(self):
        for name in ("node_zap_recon", "node_playwright_recon", "node_arjun_recon",
                     "node_framework_deep_enum", "node_openapi_recon"):
            d = " ".join(_decorators(name))
            assert "_auth_fingerprint" in d, (
                "%s would serve an anonymous crawl to an authenticated run" % name)

    def test_an_active_zap_scan_has_its_own_shelf_life(self):
        d = " ".join(_decorators("node_zap_recon"))
        assert "zap_active" in d, (
            "an active scan and a passive spider must not share a TTL")
        assert rc.ttl_for("zap_active") < rc.ttl_for("zap")

    def test_the_state_field_is_declared(self):
        """An undeclared key in BuildPocState is silently dropped, so the mode
        would never reach the decorator."""
        for n in ast.walk(GRAPH_TREE):
            if isinstance(n, ast.ClassDef) and n.name == "BuildPocState":
                names = {t.target.id for t in n.body
                         if isinstance(t, ast.AnnAssign) and isinstance(t.target, ast.Name)}
                assert "reuse_recon" in names
                return
        raise AssertionError("BuildPocState not found")

    def test_initial_state_threads_the_mode(self):
        fn = _node("initial_state")
        src = ast.unparse(fn)
        assert "reuse_recon" in src
