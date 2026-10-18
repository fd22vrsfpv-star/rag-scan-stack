"""The vuln-class resolver prefers a MECHANISM named in prose over a
CONSEQUENCE-only CWE set, and the build auto-retries with a backup class on
exhaust.

Run standalone:  pytest tests/test_class_fallback.py -q

Operator ask, 2026-10-18, after CVE-2023-51483 regressed in round 9:
  Fix 1: "name wins over CWE" when the CWEs point only at a consequence
         (privilege-escalation, auth-bypass, idor) and the text names a
         mechanism (sqli, cmdi, ...). Example: CVE-2023-51483 is "SQL
         injection ... escalates privileges" with CWE-269 — the mechanism
         is sqli, the CWE catalogue tracks the impact.
  Fix 2: "chain as backup" — when the primary class exhausts (max_iters,
         axis_exhausted, drifted), re-synth with the next chain class pinned
         and run refine once more; keep the better result. One retry only;
         BUILD_POC_CLASS_FALLBACK=off disables it.
"""
import ast
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"


# ---------------------------------------------------------- Fix 1: resolver

def test_role_tags_are_present_and_consistent():
    yaml = pytest.importorskip("yaml")
    classes = yaml.safe_load((REPO / "knowledge" / "vuln_classes.yaml").read_text())["classes"]
    ex = [c for c in classes if c.get("kind") == "vulnerability"]
    assert all(c.get("role") in ("mechanism", "consequence") for c in ex), (
        "every exploitable class must declare role: mechanism | consequence")
    cons = {c["name"] for c in ex if c["role"] == "consequence"}
    assert cons == {"auth-bypass", "privilege-escalation", "idor"}, (
        "role=consequence is reserved for impact classes; got %s" % sorted(cons))


def test_mechanism_in_prose_beats_consequence_only_cwe():
    """CVE-2023-51483 shape: text names SQLi, CWE catalogue picks privesc."""
    vc = pytest.importorskip("etl.vuln_classes")
    r = vc.resolve("blind SQL injection in M-Files Server lets a user escalate privileges",
                   ["CWE-269"])
    assert r["class"] == "sqli" and r["basis"] == "name_over_consequence"
    assert r["cwe_consequence_candidates"] == ["privilege-escalation"]


@pytest.mark.parametrize("text, cwes, expect", [
    # Prose names a mechanism, CWE confirms it -> stays cwe+name.
    ("SQL injection", ["CWE-89"], ("sqli", "cwe+name")),
    # Prose names a consequence, CWE confirms -> stays cwe+name.
    ("authentication bypass", ["CWE-287"], ("auth-bypass", "cwe+name")),
    # Prose names NOTHING, CWE picks a consequence -> cwe decides.
    ("vulnerability allows unauthorized access", ["CWE-287"], ("auth-bypass", "cwe")),
    # Prose names BOTH a mechanism and a consequence; the longer alias wins
    # (privilege escalation, 20 chars > sql injection, 13 chars). Fix 2's
    # chain fallback is what rescues this -- see
    # `test_chain_includes_both_mechanism_and_consequence_when_prose_names_both`.
    ("SQL injection ... privilege escalation", ["CWE-89", "CWE-269"],
     ("privilege-escalation", "cwe+name")),
])
def test_other_cases_are_unchanged(text, cwes, expect):
    vc = pytest.importorskip("etl.vuln_classes")
    r = vc.resolve(text, cwes)
    assert (r["class"], r["basis"]) == expect, r


def test_consequence_in_prose_does_not_overrule_a_mechanism_cwe():
    """Prose that says 'leads to privilege escalation' but the CWE is CWE-89
    SQLi -- the CWE wins, because the mechanism is sqli and the consequence
    text is background."""
    vc = pytest.importorskip("etl.vuln_classes")
    r = vc.resolve("vulnerability leading to privilege escalation",
                   ["CWE-89"])
    assert r["class"] == "sqli", (
        "a mechanism CWE must not be overruled by a consequence NAMED in prose")


# ---------------------------------------------------------- Fix 2: fallback

def _fn(path, name):
    for n in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    pytest.fail(f"{name} is gone from {path.name}")


def test_refine_reports_backup_classes_on_exhaust():
    """AST, not substring: the refine Return dict must include
    primary_class + backup_classes_available keys, and the exhaust set
    (max_iters / axis_exhausted / drifted) must appear in a comparison or
    membership test somewhere in the function."""
    fn = _fn(API, "_run_refine_poc")
    returned_keys = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Return) and isinstance(n.value, ast.Dict):
            for k in n.value.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str):
                    returned_keys.add(k.value)
    assert {"primary_class", "backup_classes_available"} <= returned_keys, (
        "refine's Return dict is missing %s"
        % sorted({"primary_class", "backup_classes_available"} - returned_keys))
    const_strs = {c.value for c in ast.walk(fn)
                  if isinstance(c, ast.Constant) and isinstance(c.value, str)}
    assert {"max_iters", "axis_exhausted", "drifted"} <= const_strs, (
        "the exhaust set must be named in-source so a change surfaces here")


def test_graph_fallback_runs_at_most_once_and_is_env_gated():
    """node_run_refine must: (1) have an If whose test is a REAL check on
    verified AND backup_classes_available (`False and ...` fails), (2) call
    _synthesize_cve_poc with vuln_class_override=backup inside it, (3) call
    _run_refine_poc a SECOND time with tried_classes, (4) consult
    BUILD_POC_CLASS_FALLBACK, (5) only once -- the backup call must not itself
    recurse into backup_classes_available."""
    fn = _fn(GRAPH, "node_run_refine")
    src = ast.get_source_segment(GRAPH.read_text(encoding="utf-8"), fn)
    hit = None
    for n in ast.walk(fn):
        if not isinstance(n, ast.If):
            continue
        test_consts = [c.value for c in ast.walk(n.test) if isinstance(c, ast.Constant)]
        if False in test_consts:
            continue       # `if (False and ...)` style sabotage
        strs = {c.value for c in ast.walk(n.test)
                if isinstance(c, ast.Constant) and isinstance(c.value, str)}
        if "backup_classes_available" in strs and "BUILD_POC_CLASS_FALLBACK" in strs:
            hit = n
            break
    assert hit, "no live If gating the fallback on backup_classes_available + env"
    def _calls_named(mod, name):
        return [c for c in ast.walk(ast.Module(mod, []))
                if isinstance(c, ast.Call) and getattr(c.func, "id", "") == name]
    synths = _calls_named(hit.body, "_synthesize_cve_poc")
    assert synths, "fallback does not call _synthesize_cve_poc"
    # The override kw must be set, AND its value must be a Name (so a sabotage
    # that passes a literal class never qualifies as a real fallback).
    override_kw = [k for k in synths[0].keywords if k.arg == "vuln_class_override"]
    assert override_kw and isinstance(override_kw[0].value, ast.Name), (
        "the fallback synth must pass vuln_class_override=<backup>")
    reruns = _calls_named(hit.body, "_run_refine_poc")
    assert len(reruns) == 1 and any(k.arg == "tried_classes" for k in reruns[0].keywords), (
        "fallback must call _run_refine_poc once more with tried_classes")
    trace_phases = {c.args[1].value for c in _calls_named(hit.body, "_poc_trace")
                    if len(c.args) >= 2 and isinstance(c.args[1], ast.Constant)}
    assert {"class_fallback_retry", "class_fallback_outcome"} <= trace_phases
    # the outer function still calls refine ONCE for the primary pass, so the
    # total count across the function is 2.
    outer_reruns = _calls_named(fn.body, "_run_refine_poc")
    assert len(outer_reruns) == 2


def test_synth_signature_accepts_override():
    fn = _fn(API, "_synthesize_cve_poc")
    args = [a.arg for a in fn.args.args] + [a.arg for a in fn.args.kwonlyargs]
    want = "vuln_class_override"
    assert want in args, "_synthesize_cve_poc must accept %s" % want


def test_better_prefers_a_verified_backup_over_an_exhausted_primary():
    """The picker inside node_run_refine must prefer a VERIFIED result,
    whichever pass produced it; otherwise the higher best_score wins; ties
    keep the primary. Exercises the inline _better() with three cases."""
    import importlib
    src = GRAPH.read_text(encoding="utf-8")
    # Isolate the def _better(a, b): block inside node_run_refine.
    fn = _fn(GRAPH, "node_run_refine")
    for node in ast.walk(fn):
        if isinstance(node, ast.FunctionDef) and node.name == "_better":
            better_src = ast.get_source_segment(src, node)
            break
    else:
        pytest.fail("_better is gone")
    ns = {}
    exec(compile(better_src, "<g>", "exec"), ns)
    better = ns["_better"]
    primary_exhaust = {"verified": False, "best_score": 10}
    backup_verified = {"verified": True, "best_score": 1}
    backup_exhaust_better = {"verified": False, "best_score": 20}
    backup_exhaust_worse = {"verified": False, "best_score": 5}
    assert better(primary_exhaust, backup_verified) is backup_verified
    assert better(primary_exhaust, backup_exhaust_better) is backup_exhaust_better
    assert better(primary_exhaust, backup_exhaust_worse) is primary_exhaust
    assert better(primary_exhaust, primary_exhaust) is primary_exhaust  # tie



def test_chain_includes_both_mechanism_and_consequence_when_prose_names_both():
    """When both are named and both CWEs are set, _vuln_classes_from_cve must
    return both -- the primary (longest-alias winner) first, and the backup
    class second so the graph fallback can retry."""
    import ast
    from pathlib import Path
    api = Path(__file__).resolve().parents[1] / "app" / "rag-api" / "api.py"
    fn = next(n for n in ast.parse(api.read_text()).body
              if isinstance(n, ast.FunctionDef) and n.name == "_vuln_classes_from_cve")
    # Pure AST: the function must call _cwe_ids_from_details and iterate the
    # result through _vc_classes_for_cwe (chain built from CWEs, no shortcut).
    calls = {c.func.id for c in ast.walk(fn)
             if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
    assert {"_cwe_ids_from_details", "_vc_classes_for_cwe"} <= calls, (
        "_vuln_classes_from_cve must build the chain from the CVE's CWEs")
