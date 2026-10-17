"""The challenger: contradictions only visible when facts are read together.

Every probe judges one claim. A real build's ledger held four facts, all at
confidence 0.9, every one wrong, and no single probe was in a position to
notice:

    endpoint     a TEMPLATE with an unsubstituted placeholder
    method       OPTIONS accepted on a route belonging to ANOTHER product
    input_field  'command' — a command-injection parameter on a traversal CVE
    (and)        an auth gate held open while the endpoint answered 200

`etl/fact_contradictions.py` reads the set. These cases are built from that
ledger, so a regression reproduces the exact failure rather than a sketch of it.

Run standalone:

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest pyyaml && \
      PYTHONPATH=. python -m pytest tests/test_fact_contradictions.py -v'
"""
from __future__ import annotations

import ast
import importlib.util
import os
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from etl import fact_contradictions as fc  # noqa: E402

YAML_PATH = REPO / "knowledge" / "fact_contradictions.yaml"
RULES = fc.load_rules(str(YAML_PATH))


def _rule(rid):
    for r in RULES:
        if r.get("id") == rid:
            return r
    raise AssertionError("no rule %r in %s" % (rid, YAML_PATH.name))


def _ids(res):
    return {f["rule_id"] for f in res["findings"]}


# ── the knowledge file itself ──────────────────────────────────────────────

@pytest.mark.unit
class TestKnowledgeFile:
    def test_rules_load(self):
        assert RULES, "no rules loaded from %s" % YAML_PATH

    def test_every_rule_names_an_implemented_check(self):
        """A rule naming a check nobody wrote is a rule the operator believes
        is protecting them."""
        missing = sorted({r.get("id"): r.get("check") for r in RULES
                          if r.get("check") not in fc.CHECKS}.items())
        assert not missing, "rules naming unimplemented checks: %s" % missing

    def test_every_rule_declares_a_known_action(self):
        """Severity says how bad; action says what to do. One of these
        findings must UNBLOCK a build, so they cannot share a behaviour."""
        for r in RULES:
            assert r.get("action") in fc.ACTIONS, (
                "rule %r declares action %r, not one of %s"
                % (r.get("id"), r.get("action"), list(fc.ACTIONS)))

    def test_the_auth_contradiction_relaxes_rather_than_blocks(self):
        """The regression this guards: treating every high-severity finding as
        a blocker would stall the build this rule exists to release."""
        assert _rule("auth_required_but_answered_unauthenticated")["action"] == fc.RELAX_AUTH

    def test_an_unusable_value_is_cleared_not_merely_warned(self):
        for rid in ("placeholder_unsubstituted", "path_class_with_a_query_parameter"):
            assert _rule(rid)["action"] == fc.CLEAR, rid

    def test_an_unprovable_fact_is_not_treated_as_a_false_one(self):
        """"The control matched" means the probe could not establish the fact.
        Acting on it as if the fact were WRONG blocks every build against an
        app that answers everything identically."""
        assert _rule("fact_survived_no_control")["action"] == fc.WARN
        assert _rule("route_belongs_to_another_product")["action"] == fc.DOWNGRADE

    def test_every_action_is_exercised_by_some_rule(self):
        used = {r.get("action") for r in RULES}
        assert used == set(fc.ACTIONS), (
            "actions with no rule: %s" % sorted(set(fc.ACTIONS) - used))

    def test_every_rule_carries_id_severity_message_and_why(self):
        for r in RULES:
            for field in ("id", "check", "severity", "message", "why"):
                assert str(r.get(field) or "").strip(), (
                    "rule %r is missing %s" % (r.get("id"), field))
            assert r["severity"] in (fc.HIGH, fc.MEDIUM), r["severity"]

    def test_rule_ids_are_unique(self):
        ids = [r["id"] for r in RULES]
        assert len(ids) == len(set(ids)), "duplicate rule ids: %s" % ids

    def test_every_check_is_reachable_from_the_yaml(self):
        """A check with no rule is dead code that reads as coverage."""
        used = {r.get("check") for r in RULES}
        unused = sorted(set(fc.CHECKS) - used)
        assert not unused, "checks no rule invokes: %s" % unused


# ── the four real ledger rows ──────────────────────────────────────────────

@pytest.mark.unit
class TestTheRealLedger:
    def test_the_template_endpoint_is_caught(self):
        res = fc.evaluate(
            {"facts": {"endpoint": "/s/{resourceKey}/_/download/resources/a:b"}},
            RULES)
        assert "placeholder_unsubstituted" in _ids(res)
        hit = [f for f in res["findings"] if f["rule_id"] == "placeholder_unsubstituted"][0]
        assert hit["severity"] == fc.HIGH
        assert hit["remedy"], "a finding without a remedy is a complaint"

    def test_another_products_route_is_caught(self):
        res = fc.evaluate(
            {"product": "jira", "facts": {"endpoint": "/bamboo/browse"}}, RULES)
        assert "route_belongs_to_another_product" in _ids(res)

    def test_the_matching_products_route_is_not_flagged(self):
        res = fc.evaluate(
            {"product": "Atlassian Jira", "facts": {"endpoint": "/jira/browse/X"}},
            RULES)
        assert "route_belongs_to_another_product" not in _ids(res)

    def test_a_command_parameter_on_a_traversal_is_caught(self):
        res = fc.evaluate(
            {"vuln_class": "path-traversal", "facts": {"input_field": "command"}},
            RULES)
        ids = _ids(res)
        assert "path_class_with_a_query_parameter" in ids
        assert "parameter_name_belongs_to_another_class" in ids

    def test_the_auth_contradiction_is_caught(self):
        res = fc.evaluate(
            {"auth_required": True,
             "auth_observations": [{"item": "endpoint", "status": 200,
                                    "value": "/download/x"}]}, RULES)
        assert "auth_required_but_answered_unauthenticated" in _ids(res)

    def test_a_genuinely_protected_endpoint_is_not_flagged(self):
        res = fc.evaluate(
            {"auth_required": True,
             "auth_observations": [{"item": "endpoint", "status": 401}]}, RULES)
        assert "auth_required_but_answered_unauthenticated" not in _ids(res)


# ── per-check behaviour ────────────────────────────────────────────────────

@pytest.mark.unit
class TestChecks:
    def test_the_path_is_the_field_upgrade_is_not_a_contradiction(self):
        """The fix that records the ROUTE as the input field is the correct
        state, not something to flag."""
        res = fc.evaluate(
            {"vuln_class": "path-traversal",
             "facts": {"input_field": "/download/resources/x (the URL path is "
                                      "the injection point; there is no parameter)"}},
            RULES)
        assert "path_class_with_a_query_parameter" not in _ids(res)

    def test_a_parameter_belonging_to_its_own_class_is_not_flagged(self):
        res = fc.evaluate(
            {"vuln_class": "ssrf", "facts": {"input_field": "url"}}, RULES)
        assert "parameter_name_belongs_to_another_class" not in _ids(res)

    def test_a_probe_whose_control_matched_is_not_a_gathered_fact(self):
        res = fc.evaluate(
            {"facts": {"endpoint": "/download/x"},
             "gathered_items": ["endpoint"],
             "probe_results": {"endpoint": {
                 "status": "unverified",
                 "evidence": "probe ran, control matched: a nonsense path "
                             "answered HTTP 200 with a same-size body"}}},
            RULES)
        assert "fact_survived_no_control" in _ids(res)

    def test_an_ordinary_unverified_probe_is_not_flagged_as_uncontrolled(self):
        """`could not run` and `inconclusive` are different outcomes from
        `the control matched`, and only the last one means the probe was blind."""
        for ev in ("probe did not run: missing input(s): endpoint",
                   "probe ran, inconclusive: parameter neither reflected nor changed"):
            res = fc.evaluate(
                {"facts": {"endpoint": "/x"}, "gathered_items": ["endpoint"],
                 "probe_results": {"endpoint": {"status": "unverified", "evidence": ev}}},
                RULES)
            assert "fact_survived_no_control" not in _ids(res), ev

    def test_an_unobserved_model_endpoint_is_flagged(self):
        res = fc.evaluate(
            {"facts": {"endpoint": "/secret/admin"},
             "fact_sources": {"endpoint": "llm_fallback"},
             "observed_paths": ["/", "/login", "/download/resources/x"]}, RULES)
        assert "endpoint_never_observed_live" in _ids(res)

    def test_an_observed_endpoint_is_not_flagged(self):
        res = fc.evaluate(
            {"facts": {"endpoint": "/download/resources/x"},
             "fact_sources": {"endpoint": "llm_fallback"},
             "observed_paths": ["/", "/download/resources/x"]}, RULES)
        assert "endpoint_never_observed_live" not in _ids(res)

    def test_no_recon_is_not_an_accusation(self):
        """Unreachable is not absent: with no crawl to compare against, the
        check must say nothing rather than call the endpoint invented."""
        res = fc.evaluate(
            {"facts": {"endpoint": "/secret/admin"},
             "fact_sources": {"endpoint": "llm_fallback"},
             "observed_paths": []}, RULES)
        assert "endpoint_never_observed_live" not in _ids(res)

    def test_a_probe_confirmed_endpoint_is_not_second_guessed(self):
        res = fc.evaluate(
            {"facts": {"endpoint": "/secret/admin"},
             "fact_sources": {"endpoint": "probe"},
             "observed_paths": ["/", "/login"]}, RULES)
        assert "endpoint_never_observed_live" not in _ids(res)

    def test_a_stale_fact_is_flagged_with_its_age(self):
        res = fc.evaluate(
            {"facts": {"session_valid": "JSESSIONID=x"},
             "fact_ages": {"session_valid": 4000}}, RULES)
        assert "fact_is_stale" in _ids(res)
        hit = [f for f in res["findings"] if f["rule_id"] == "fact_is_stale"][0]
        assert "4000" in hit["message"], hit["message"]

    def test_a_fresh_fact_is_not_flagged(self):
        res = fc.evaluate(
            {"facts": {"session_valid": "x"}, "fact_ages": {"session_valid": 60}},
            RULES)
        assert "fact_is_stale" not in _ids(res)

    def test_an_unknown_age_is_not_treated_as_stale(self):
        res = fc.evaluate({"facts": {"session_valid": "x"}}, RULES)
        assert "fact_is_stale" not in _ids(res)


# ── contract ───────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestContract:
    def test_a_clean_fact_set_produces_nothing(self):
        res = fc.evaluate(
            {"product": "jira", "vuln_class": "ssrf",
             "facts": {"endpoint": "/plugins/servlet/fetch", "input_field": "url"},
             "fact_sources": {"endpoint": "probe"},
             "observed_paths": ["/plugins/servlet/fetch"]}, RULES)
        assert res["findings"] == [], res["findings"]
        assert res["ran"] is True

    def test_a_challenger_that_could_not_run_says_so(self):
        """`no contradictions` and `the challenger never ran` must not look
        the same — this repo's most expensive recurring bug."""
        res = fc.evaluate({"facts": {"endpoint": "/x"}}, [])
        assert res["ran"] is False
        assert "DID NOT RUN" in fc.summarize(res)

    def test_an_unimplemented_check_is_reported_not_skipped(self):
        res = fc.evaluate({"facts": {}}, [{"id": "r", "check": "does_not_exist",
                                           "severity": "high", "message": "m",
                                           "why": "w"}])
        assert res["unimplemented"] == [{"id": "r", "check": "does_not_exist"}]
        assert res["rules_evaluated"] == 0

    def test_a_check_that_raises_is_reported_not_fatal(self):
        bad = dict(_rule("fact_is_stale"))
        bad["ttl_seconds"] = "not-a-dict"
        res = fc.evaluate({"facts": {}, "fact_ages": {"x": 1}}, [bad])
        assert res["unimplemented"], "a raising check must be reported"

    def test_evaluation_is_deterministic(self):
        intel = {"product": "jira", "vuln_class": "path-traversal",
                 "facts": {"endpoint": "/bamboo/{k}/browse", "input_field": "command"}}
        a = fc.evaluate(intel, RULES)
        b = fc.evaluate(intel, RULES)
        assert a["findings"] == b["findings"]
        sev = [f["severity"] for f in a["findings"]]
        assert sev == sorted(sev, key=lambda s: 0 if s == fc.HIGH else 1), (
            "high-severity findings must sort first")

    def test_actions_index_matches_the_findings(self):
        res = fc.evaluate({"product": "jira", "vuln_class": "path-traversal",
                           "facts": {"endpoint": "/bamboo/{k}/x",
                                     "input_field": "command"}}, RULES)
        assert set(res["actions"]) == set(fc.ACTIONS)
        flat = [i for items in res["actions"].values() for i in items]
        assert len(flat) == len(res["findings"])
        for f in res["findings"]:
            assert f["item"] in res["actions"][f["action"]]

    def test_an_unknown_action_is_reported_and_downgraded_to_warn(self):
        """Guessing at a typo'd action is how a `warn` becomes a `clear` that
        deletes a correct fact."""
        r = dict(_rule("placeholder_unsubstituted"))
        r["action"] = "delete_everything"
        res = fc.evaluate({"facts": {"endpoint": "/a/{b}"}}, [r])
        assert res["findings"][0]["action"] == fc.WARN
        assert any(u.get("reason") == "unknown action" for u in res["unimplemented"])

    def test_counts_match_the_findings(self):
        res = fc.evaluate({"product": "jira", "vuln_class": "path-traversal",
                           "facts": {"endpoint": "/bamboo/{k}/x",
                                     "input_field": "command"}}, RULES)
        assert res["high"] + res["medium"] == len(res["findings"])

    def test_a_broken_message_template_does_not_suppress_the_finding(self):
        r = dict(_rule("placeholder_unsubstituted"))
        r["message"] = "{item} -> {no_such_key}"
        res = fc.evaluate({"facts": {"endpoint": "/a/{b}"}}, [r])
        assert len(res["findings"]) == 1
        assert "endpoint" in res["findings"][0]["message"]

    def test_summarize_names_every_finding(self):
        res = fc.evaluate({"product": "jira", "vuln_class": "path-traversal",
                           "facts": {"endpoint": "/bamboo/{k}/x",
                                     "input_field": "command"}}, RULES)
        text = fc.summarize(res)
        for f in res["findings"]:
            assert f["rule_id"] in text


# ── agreement with the probe module's own copy ─────────────────────────────

@pytest.mark.unit
def test_placeholder_detection_agrees():
    """`fact_probes` keeps its own copy so it stays dependency-free. Two
    implementations of the same judgement drift; pin them to one case table."""
    spec = importlib.util.spec_from_file_location(
        "fact_probes_agree", REPO / "app" / "rag-api" / "fact_probes.py")
    fp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fp)
    cases = ["/s/{resourceKey}/_/download", "/api/<id>/edit", "/download/.../f",
             "/s/%7Bkey%7D/x", "%3Cscript%3E", "/download/resources/x",
             "/api/12/edit", "", "x?a=1", "/a/b/c.json"]
    for c in cases:
        assert fp.has_placeholder(c) == fc.has_placeholder(c), (
            "placeholder detection disagrees on %r: fact_probes=%s "
            "fact_contradictions=%s" % (c, fp.has_placeholder(c), fc.has_placeholder(c)))


# ── the RAG loader ─────────────────────────────────────────────────────────

@pytest.mark.unit
def test_the_renderer_emits_one_document_per_rule():
    """CLAUDE.md: a knowledge file ships its loader in the same change. A file
    read deterministically but never embedded is retrievable by nobody."""
    src = (REPO / "etl" / "load_knowledge_documents.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef)
               and n.name == "_render_fact_contradictions"), None)
    assert fn is not None, "no renderer for fact_contradictions.yaml"

    registry = next(
        (n.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
         and any(getattr(t, "id", "") == "RENDERERS" for t in n.targets)), None)
    assert registry is not None
    keys = {k.value for k in registry.keys if isinstance(k, ast.Constant)}
    assert "fact_contradictions" in keys, (
        "the renderer exists but is not registered, so the file is never embedded")

    # Execute the renderer against the real YAML.
    ns = {"Dict": dict, "Any": object, "List": list, "Doc": tuple}
    helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_s")
    exec(compile(ast.Module([helper, fn], []), "<r>", "exec"), ns)
    docs = ns["_render_fact_contradictions"](
        yaml.safe_load(YAML_PATH.read_text(encoding="utf-8")))
    assert len(docs) == len(RULES)
    for title, body in docs:
        assert title.strip() and len(body) > 80, (title, body)
    joined = " ".join(b for _, b in docs)
    for r in RULES:
        assert r["id"] in " ".join(t for t, _ in docs) or r["id"] in joined, r["id"]
