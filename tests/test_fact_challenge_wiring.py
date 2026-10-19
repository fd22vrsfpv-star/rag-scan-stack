"""The challenger, wired: actions applied, gate re-decided, modes honoured.

`tests/test_fact_contradictions.py` proves the rules. This proves the part that
acts on them — which is where the damage would be, because a contradiction
nobody applies is a log line.

Three things are easy to get wrong here and each has a case below:

  * "high severity" is NOT one behaviour. `relax_auth` must UNBLOCK a build.
    A single "high means stop" would stall the builds the rule exists to free.
  * The gate decided BEFORE the challenge ran, so clearing a fact without
    re-deciding leaves a build "ready" on a fact that was just deleted.
  * A challenger that could not run must not read as a clean bill of health.

Run standalone:

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest pyyaml && \
      PYTHONPATH=. python -m pytest tests/test_fact_challenge_wiring.py -v'
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"
API_SRC = API.read_text(encoding="utf-8")
GRAPH_SRC = GRAPH.read_text(encoding="utf-8")
API_TREE = ast.parse(API_SRC)
GRAPH_TREE = ast.parse(GRAPH_SRC)


def _func(tree, name):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _calls(node, name):
    return any(isinstance(n, ast.Call)
               and getattr(n.func, "id", getattr(n.func, "attr", None)) == name
               for n in ast.walk(node))


# ── a real, executing copy of the apply logic ──────────────────────────────

def _load_challenger():
    """Exec the real `_challenge_derived_facts` with the surrounding service
    stubbed out. Executing the shipped source beats re-typing it: a re-typed
    copy only ever tests the copy."""
    from etl.fact_contradictions import evaluate, summarize  # noqa: F401

    traces, webhooks = [], []
    decided = {"calls": 0}

    def _gather_decide(items, vuln_class, privileges_required=""):
        decided["calls"] += 1
        missing = [str(i["item"]) for i in items if i.get("status") == "missing"]
        return {"ready": not missing, "missing": missing,
                "gathered": [str(i["item"]) for i in items
                             if i.get("status") == "gathered"]}

    ns = {
        "os": __import__("os"),
        "logging": __import__("logging"),
        "_gather_decide": _gather_decide,
        "_poc_trace": lambda *a, **k: traces.append((a, k)),
        "_PROVENANCE_FOR_MANIFEST_SOURCE": {
            "probe": "probe_confirmed", "nvd+classifier": "advisory_derived",
            "research": "advisory_derived", "llm_fallback": "model_inferred"},
        "_FACT_CHALLENGE_MODE": "auto",
    }
    for name in ("_probe_result_shape", "_challenge_intel", "_challenge_derived_facts"):
        fn = _func(API_TREE, name)
        assert fn is not None, "%s missing from api.py" % name
        exec(compile(ast.Module([fn], []), "<api>", "exec"), ns)
    ns["_traces"], ns["_decided"] = traces, decided
    return ns


CH = _load_challenger()


def _man(items, vuln_class="", facts=None):
    return {"items": [dict(i) for i in items], "vuln_class": vuln_class,
            "facts": dict(facts or {}), "missing": [], "ready": True}


def _item(name, status, value, source="probe"):
    return {"item": name, "status": status, "value": value, "source": source}


# ── applying the actions ───────────────────────────────────────────────────

@pytest.mark.unit
class TestApply:
    def test_a_template_endpoint_is_cleared_and_the_gate_re_decided(self):
        """The gate decided before the challenge ran. Clearing a fact without
        re-deciding leaves the build 'ready' on a fact just deleted."""
        man = _man([_item("endpoint", "gathered",
                          "/s/{resourceKey}/_/download/resources/a:b", "llm_fallback")])
        before = CH["_decided"]["calls"]
        res = CH["_challenge_derived_facts"](man, "CVE-2026-21589", "10.0.0.1", 443)
        assert res["ran"] is True
        assert any(a["action"] == "clear" for a in res["applied"]), res["applied"]
        ep = man["items"][0]
        assert ep["status"] == "missing"
        assert ep["source"].startswith("challenge:")
        assert CH["_decided"]["calls"] > before, "the gate was not re-decided"
        assert man["ready"] is False
        assert "endpoint" in man["missing"]

    def test_a_cleared_fact_is_removed_from_the_facts_map(self):
        """A stale value left in `facts` is read by every downstream block."""
        man = _man([_item("endpoint", "gathered", "/a/{b}", "llm_fallback")],
                   facts={"endpoint": "/a/{b}"})
        CH["_challenge_derived_facts"](man, "CVE-X", "10.0.0.1", 443)
        assert "endpoint" not in man["facts"]

    def test_another_products_route_is_downgraded_not_deleted(self):
        man = _man([_item("endpoint", "gathered", "/bamboo/browse", "probe")])
        res = CH["_challenge_derived_facts"](man, "CVE-X", "10.0.0.1", 443,
                                             product="jira")
        assert any(a["action"] == "downgrade" for a in res["applied"]), res["applied"]
        ep = man["items"][0]
        assert ep["status"] == "unverified", "downgrade must not delete the value"
        assert ep["value"] == "/bamboo/browse"
        assert "challenged" in ep["source"]

    def test_relax_auth_unblocks_rather_than_blocks(self):
        """The regression this exists to prevent: treating every high-severity
        finding as a blocker stalls the build this rule exists to release."""
        man = _man([_item("auth", "missing", "no session established", "probe"),
                    _item("target_reachable", "gathered", "HTTP 200", "probe")])
        res = CH["_challenge_derived_facts"](
            man, "CVE-X", "10.0.0.1", 443, auth_required=True,
            auth_observations=[{"item": "target_reachable", "status": 200}])
        assert any(a["action"] == "relax_auth" for a in res["applied"]), res["applied"]
        auth = [i for i in man["items"] if i["item"] == "auth"][0]
        assert auth["status"] == "n/a", "the auth precondition was not released"
        assert man["ready"] is True

    def test_a_warn_changes_nothing(self):
        man = _man([_item("input_field", "gathered", "url", "probe")], "sqli")
        res = CH["_challenge_derived_facts"](man, "CVE-X", "10.0.0.1", 443)
        assert any(f["action"] == "warn" for f in res["findings"]), res["findings"]
        assert man["items"][0]["status"] == "gathered"
        assert res["applied"] == [] or all(a["action"] != "warn" for a in res["applied"])

    def test_an_uncontrolled_probe_warns_rather_than_blocking(self):
        """A matched control means "I could not establish this", NOT "this is
        false" — and the gate reads an unverified REQUIRED item as missing.

        Observed live: on an app that soft-404s the control matches every
        time, so `downgrade` made the item permanently missing and the build
        stopped at gather with 0 iterations, where the previous run had
        reached refine with 6. Blocking forever on an unprovable-here fact
        makes the class unbuildable against that whole family of targets.
        """
        man = _man([_item("endpoint", "gathered", "/download/x", "probe")])
        res = CH["_challenge_derived_facts"](
            man, "CVE-X", "10.0.0.1", 443,
            probe_results={"endpoint": {
                "status": "unverified",
                "evidence": "probe ran, control matched: a nonsense path "
                            "answered HTTP 200 with a same-size body"}})
        assert "fact_survived_no_control" in {f["rule_id"] for f in res["findings"]}
        # Recorded, and the item still usable — the confidence floor renders
        # it as an ASSUMPTION in the prompt, which is the honest treatment.
        assert man["items"][0]["status"] == "gathered"
        assert man["ready"] is not False

    def test_a_clean_fact_set_changes_nothing(self):
        man = _man([_item("endpoint", "gathered", "/plugins/servlet/fetch", "probe"),
                    _item("input_field", "gathered", "url", "probe")], "ssrf")
        res = CH["_challenge_derived_facts"](man, "CVE-X", "10.0.0.1", 443,
                                             product="jira")
        assert res["ran"] is True
        assert res["findings"] == [], res["findings"]
        assert man["items"][0]["status"] == "gathered"
        assert man["ready"] is True

    def test_every_run_is_traced_even_when_clean(self):
        before = len(CH["_traces"])
        CH["_challenge_derived_facts"](
            _man([_item("endpoint", "gathered", "/ok", "probe")]),
            "CVE-X", "10.0.0.1", 443)
        assert len(CH["_traces"]) > before, (
            "a challenge that found nothing still has to leave a record — "
            "otherwise 'it found nothing' and 'it never ran' look identical")

    def test_a_bare_status_string_is_accepted(self):
        """THE SHAPE PRODUCTION ACTUALLY USES. `_preflight_prove_facts` returns
        {claim: status string}; the normaliser handled ProbeResult objects and
        dicts and raised AttributeError on a string. The gather node's
        `except` swallowed it, so the challenger reported "(skipped:
        AttributeError: 'str' object has no attribute 'get')" and never ran on
        a real build — while every test here passed.
        """
        man = _man([_item("endpoint", "gathered", "/a/{b}", "llm_fallback")])
        probes = {"endpoint_exists": "unverified", "target_reachable": "confirmed"}
        res = CH["_challenge_derived_facts"](
            man, "CVE-X", "10.0.0.1", 443, probe_results=probes)
        assert res["ran"] is True, "the challenger did not run: %s" % res.get("error")
        assert any(f["rule_id"] == "placeholder_unsubstituted"
                   for f in res["findings"])
        # Not merely "it did not crash": the STATUS must survive. Dropping the
        # string branch degrades it to None silently, which is a dead rule
        # rather than a loud failure.
        intel = CH["_challenge_intel"](man, probes)
        assert intel["probe_results"]["target_reachable"]["status"] == "confirmed"
        assert intel["probe_results"]["endpoint_exists"]["status"] == "unverified"

    def test_every_shape_normalises_to_status_and_evidence(self):
        class PR:
            status = "unverified"
            evidence = "probe ran, control matched: nonsense answered the same"
        shape = CH["_probe_result_shape"]
        assert shape("confirmed") == {"status": "confirmed", "evidence": ""}
        assert shape({"status": "refuted", "evidence": "x"})["status"] == "refuted"
        assert "control matched" in shape(PR())["evidence"]
        assert shape(None)["status"] is None

    def test_probe_result_objects_are_accepted_as_well_as_dicts(self):
        """`run_probes` returns ProbeResult objects, not dicts. Reading only
        dicts would make the control check silently dead in production."""
        class PR:
            status = "unverified"
            evidence = "probe ran, control matched: nonsense answered the same"
        man = _man([_item("endpoint", "gathered", "/x", "probe")])
        res = CH["_challenge_derived_facts"](man, "CVE-X", "10.0.0.1", 443,
                                             probe_results={"endpoint": PR()})
        assert "fact_survived_no_control" in {f["rule_id"] for f in res["findings"]}


@pytest.mark.unit
class TestFailSoft:
    def test_a_challenger_that_cannot_run_is_not_a_clean_bill_of_health(self):
        man = _man([_item("endpoint", "gathered", "/a/{b}", "llm_fallback")])
        ns = dict(CH)
        ns["_FACT_CHALLENGE_MODE"] = "off"
        fn = _func(API_TREE, "_challenge_derived_facts")
        exec(compile(ast.Module([fn], []), "<api>", "exec"), ns)
        res = ns["_challenge_derived_facts"](man, "CVE-X", "1.1.1.1", 80)
        assert res["ran"] is False
        assert res["error"], "a disabled challenger must say so"
        assert man["items"][0]["status"] == "gathered", "off must change nothing"
        assert man["challenge"]["ran"] is False


# ── wiring ─────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestWiring:
    def test_the_gather_node_invokes_the_challenger(self):
        node = _func(GRAPH_TREE, "node_gather_check")
        assert node is not None
        assert _calls(node, "_challenge_derived_facts"), (
            "node_gather_check does not call the challenger — the rules run "
            "nowhere")

    def test_the_challenger_runs_after_the_probes(self):
        """It reads probe results, so running first would read an empty dict."""
        node = _func(GRAPH_TREE, "node_gather_check")
        src = ast.unparse(node)
        assert src.index("_preflight_prove_facts") < src.index("_challenge_derived_facts")

    def test_the_state_field_is_declared(self):
        """An undeclared key in BuildPocState is silently dropped, so the
        verdict would never reach the result."""
        for n in ast.walk(GRAPH_TREE):
            if isinstance(n, ast.ClassDef) and n.name == "BuildPocState":
                names = {t.target.id for t in n.body
                         if isinstance(t, ast.AnnAssign) and isinstance(t.target, ast.Name)}
                assert "fact_challenge" in names
                return
        raise AssertionError("BuildPocState not found")

    def test_review_mode_blocks_and_auto_does_not(self):
        node = _func(GRAPH_TREE, "node_gather_check")
        src = ast.unparse(node)
        assert "'review'" in src or '"review"' in src, (
            "no review-mode branch — the operator has no way to sign off")
        assert "gather_blocked" in src
        assert "intel_review" in src, (
            "review mode must name itself in `missing` or the operator sees a "
            "blocked build with no stated reason")

    def test_auto_is_the_default_mode(self):
        """The operator asked for the review to be skippable and automatic by
        default; a default of `review` would stall every build."""
        for n in ast.walk(API_TREE):
            if (isinstance(n, ast.Assign)
                    and any(getattr(t, "id", "") == "_FACT_CHALLENGE_MODE" for t in n.targets)
                    and isinstance(n.value, ast.Call)):
                src = ast.unparse(n)
                assert "'auto'" in src, src
                return
        raise AssertionError("_FACT_CHALLENGE_MODE assignment not found")

    def test_the_mode_vocabulary_is_closed(self):
        """An unrecognised env value must fall back, not disable the check."""
        for n in ast.walk(API_TREE):
            if (isinstance(n, ast.If)
                    and "_FACT_CHALLENGE_MODE" in ast.unparse(n.test)
                    and "not in" in ast.unparse(n.test)):
                assert "'auto'" in ast.unparse(n.body)
                return
        raise AssertionError("no fallback for an unrecognised challenge mode")


# ── the confidence floor ───────────────────────────────────────────────────

@pytest.mark.unit
class TestConfidenceFloor:
    def test_the_floor_exists_and_is_env_tunable(self):
        assert _func(API_TREE, "_fact_confidence") is not None
        assert "BUILD_POC_FACT_FLOOR" in API_SRC

    def test_the_manifest_text_renders_assumptions_separately(self):
        node = _func(API_TREE, "_gather_manifest_text")
        src = ast.unparse(node)
        assert "_FACT_CONFIDENCE_FLOOR" in src, (
            "the manifest text does not consult the floor, so a 0.45 "
            "advisory-only fact still reads like a 0.9 probed one")
        assert "ASSUMPTIONS" in src

    def test_the_manifest_text_renders_the_challenge(self):
        src = ast.unparse(_func(API_TREE, "_gather_manifest_text"))
        assert "challenge" in src
        assert "DID NOT RUN" in src, (
            "a challenger that could not run must say so in the prompt the "
            "model reads, not only in the trace")

    def test_a_low_confidence_fact_scores_below_the_floor(self):
        """Executing, not structural: an advisory-derived unverified fact is
        0.6 * 0.5 = 0.3, which must land under the 0.6 default."""
        sys.path.insert(0, str(REPO / "app" / "rag-api"))
        from fact_provenance import confidence_for
        assert confidence_for("advisory_derived", "unverified") < 0.6
        assert confidence_for("model_inferred", "confirmed") < 0.6
        assert confidence_for("probe_confirmed", "confirmed") >= 0.6
