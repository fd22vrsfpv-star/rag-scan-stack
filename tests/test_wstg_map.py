"""WSTG finding->test map consistency.

knowledge/wstg_map.yaml turns a web finding into a security test. Three ways it
silently breaks, each caught here on a bare checkout (no stack needed):

  * a `category` the surface-test engine does not know -> _classify can never
    call it safe, so the test is silently forced impactful (or rejected);
  * a tier/category that disagree (safe entry with an impactful category, or a
    safe entry whose tool is not on the /tools/execute allowlist) -> the safe
    lane runs something it should not, or the classifier drops it;
  * a `wstg_id` with no ingested WSTG doc -> the guidance prose comes back empty
    and the operator gets a test with no methodology behind it.

Sabotage check: flip a safe entry's category to 'rce' -> test_map_tiers RED.
"""
import ast
import os
import re

import pytest

yaml = pytest.importorskip("yaml")

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
MAP = os.path.join(REPO, "knowledge", "wstg_map.yaml")
SEED = os.path.join(REPO, "knowledge", "seed", "wstg.yaml")
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")
# The assertion clause keys the evaluator understands (app/rag-api/security_tests.py).
CLAUSE_KEYS = {
    "expect_exit_code", "expect_substring", "expect_not_substring",
    "expect_regex", "expect_status", "expect_shell", "expect_screenshot",
    "min_output_bytes",
}


def _set_const(name):
    """Read a module-level `name = {...}` set literal from the engine via ast."""
    tree = ast.parse(open(ENGINE, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == name:
            return set(ast.literal_eval(node.value))
    raise AssertionError(f"{name} not found in langgraph_engine.py")


def _map():
    return yaml.safe_load(open(MAP, encoding="utf-8"))


def test_map_loads_and_is_shaped():
    d = _map()
    entries = d.get("entries")
    assert entries, "map has no entries — guard would pass vacuously"
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids)), "duplicate entry ids"
    for e in entries:
        assert e.get("wstg_id") and isinstance(e["wstg_id"], list), f"{e['id']}: wstg_id must be a non-empty list"
        m = e.get("match") or {}
        assert any(m.get(k) for k in ("issue_type", "cwe", "nuclei_tags", "name_contains")), \
            f"{e['id']}: match block has no keys — nothing could ever match it"
        assert e.get("tier") in ("safe", "impactful"), f"{e['id']}: bad tier"
        assert e.get("category") and e.get("tool") and e.get("command"), f"{e['id']}: missing category/tool/command"
        assert isinstance(e.get("assertion"), dict) and e["assertion"], f"{e['id']}: assertion must be a non-empty dict"
        bad = set(e["assertion"]) - CLAUSE_KEYS
        assert not bad, f"{e['id']}: unknown assertion clause(s) {bad}"


def test_map_categories_are_known_to_the_engine():
    safe = _set_const("_SAFE_CATEGORIES")
    imp = _set_const("_IMPACTFUL_CATEGORIES")
    known = safe | imp
    for e in _map()["entries"]:
        assert e["category"] in known, (
            f"{e['id']}: category '{e['category']}' is not in the engine's "
            "_SAFE_/_IMPACTFUL_CATEGORIES — _classify can never place it")


def test_map_tiers_agree_with_category_and_tool():
    safe = _set_const("_SAFE_CATEGORIES")
    imp = _set_const("_IMPACTFUL_CATEGORIES")
    hints = _set_const("_SAFE_TOOL_HINTS")
    for e in _map()["entries"]:
        head = re.split(r"\s+", e["command"].strip())[0].split("/")[-1]
        if e["tier"] == "safe":
            assert e["category"] in safe, f"{e['id']}: safe entry has impactful category '{e['category']}'"
            assert head in hints, f"{e['id']}: safe entry uses non-allowlisted tool '{head}'"
        else:
            assert e["category"] in imp, f"{e['id']}: impactful entry has safe category '{e['category']}'"


def test_every_wstg_id_has_an_ingested_seed_doc():
    """Each mapped WSTG-ID must exist in the generated seed corpus, so the
    guidance prose is never empty. Pins map <-> seed agreement offline."""
    if not os.path.exists(SEED):
        pytest.skip("knowledge/seed/wstg.yaml not generated")
    seed = yaml.safe_load(open(SEED, encoding="utf-8"))
    titles = " ".join(e.get("title", "") for e in seed.get("service_docs", []))
    missing = []
    for e in _map()["entries"]:
        for wid in e["wstg_id"]:
            if wid not in titles:
                missing.append((e["id"], wid))
    assert not missing, f"WSTG ids in the map with no ingested seed doc: {missing}"
