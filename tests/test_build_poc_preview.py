"""POST /software/build-poc/preview shows what a build WOULD do -- and sends
nothing to the target.

Run standalone:  pytest tests/test_build_poc_preview.py -q

WHY THIS EXISTS
---------------
The operator wants to see the class, ATT&CK techniques, reading hints, the
requirements read from the description, the graded goal and the scope verdict
BEFORE an attempt, and to correct hints against them. The one property that
must not slip is that a preview is not an attack: no listener call, no pre-run
probe, no recon, no grader request. A preview that quietly probed the target
would be the repo's recurring failure in a new form -- an action dressed up as
a read. Both shared helpers that DO contact the target (`_extract_target_spec`
pings the grader port; `_benchmark_profile` reads /done) take `probe=False`.
"""
import ast
import pathlib
import sys
import types

import pytest

API = pathlib.Path(__file__).resolve().parents[1] / "app" / "rag-api" / "api.py"

FORBIDDEN = {"_listener_vectors_run", "_postex_run", "_fetch_preconditions",
             "_benchmark_oracle", "_timing_confirmation_rerun", "_run_refine_poc",
             "_synthesize_cve_poc", "_known_good_probe", "_establish_session_for_build"}


def _tree():
    return ast.parse(API.read_text(encoding="utf-8"))


def _fn(name, tree=None):
    for n in (tree or _tree()).body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    pytest.fail(name + " is gone from api.py")


def test_preview_calls_nothing_that_contacts_the_target():
    called = {c.func.id for c in ast.walk(_fn("_build_poc_preview"))
              if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
    bad = called & FORBIDDEN
    assert not bad, "the preview calls target-contacting function(s): %s" % sorted(bad)


@pytest.mark.parametrize("helper", ["_extract_target_spec", "_benchmark_profile"])
def test_preview_passes_probe_false_to_helpers_that_can_contact_the_target(helper):
    calls = [c for c in ast.walk(_fn("_build_poc_preview"))
             if isinstance(c, ast.Call) and getattr(c.func, "id", "") == helper]
    assert calls, "the preview no longer calls %s" % helper
    for c in calls:
        kw = {k.arg: k.value for k in c.keywords}
        assert isinstance(kw.get("probe"), ast.Constant) and kw["probe"].value is False, (
            "%s is called without probe=False -- it would contact the target" % helper)


def test_profile_without_probe_never_reads_the_oracle():
    tree = _tree()
    ns = {"_benchmark_oracle": lambda *a, **k: pytest.fail("oracle contacted in a preview"),
          "_cvebench_challenge": lambda cve: {"metadata": {"secret_table_name": "secret"}},
          "_bench_pick_goal": lambda offered, vc: offered[0] if offered else None,
          "_BENCH_GOAL_LADDER": next(ast.literal_eval(n.value) for n in tree.body
                                     if isinstance(n, ast.Assign) and any(
                                         getattr(t, "id", "") == "_BENCH_GOAL_LADDER"
                                         for t in n.targets))}
    exec(compile(ast.Module([_fn("_benchmark_profile", tree)], []), "api.py", "exec"), ns)
    prof = ns["_benchmark_profile"]("172.19.0.9", 9090, {"cve": "CVE-2024-1"}, probe=False)
    assert prof.get("harness") == "cve-bench" and prof.get("goal")


def test_executed_preview_sends_nothing_to_the_target(monkeypatch):
    """Run the preview with every dependency stubbed and a network stub that
    records every host contacted."""
    tree = _tree()
    contacted = []

    class _Net(types.ModuleType):
        def __getattr__(self, verb):
            def _call(url, *a, **k):
                contacted.append(str(url))
                raise AssertionError("network call from the preview: %s" % url)
            return _call
    monkeypatch.setitem(sys.modules, "httpx", _Net("httpx"))
    monkeypatch.setitem(sys.modules, "requests", _Net("requests"))

    class _VC:
        def mitre_for(self, c): return ["T1190"]
        def reading_hints(self, c): return {"look_for": ["x"], "implies": ["y"]}
        def graded_goals(self, c): return ["database_access"]

    class _Cur:
        def __enter__(self): return self
        def __exit__(self, *a): return False
    seen = {}
    ns = {
        "os": __import__("os"),
        "_fetch_cve_details": lambda cve: {"description": "SQLi in id", "cwe": ["CWE-89"],
                                           "advisory_poc": "GET /x?id=1"},
        "_extract_target_spec": lambda *a, **k: (seen.setdefault("spec_probe", k.get("probe")),
                                                 {"vuln_class": "sqli"})[1],
        "_vc": lambda: _VC(),
        "_attack_technique_names": lambda: {"T1190": "Exploit Public-Facing Application"},
        "get_db": lambda: (_ for _ in ()).throw(RuntimeError("no db in test")),
        "_benchmark_profile": lambda ip, port, spec, probe=True: (
            seen.setdefault("profile_probe", probe), {})[1],
        "_benchmark_goal_block": lambda spec: "",
        "_read_description_requirements": lambda *a, **k: {"parameter": "id"},
        "_class_guidance_block": lambda vc, chain: "GUIDANCE\n",
        "_requirements_block": lambda req: "REQS\n",
        "_llm_for_model": lambda *a, **k: {"response": '{"command": "curl x"}'},
        "_poc_extract_json": lambda t: {"command": "curl x"},
    }
    exec(compile(ast.Module([_fn("_build_poc_preview", tree)], []), "api.py", "exec"), ns)
    out = ns["_build_poc_preview"]("CVE-2024-1", "172.19.0.9", 9090, "eid",
                                   suggest_command=True)
    assert not contacted, contacted
    assert out["sent_to_target"] is False
    assert seen == {"spec_probe": False, "profile_probe": False}
    assert out["vuln_class"] == "sqli" and out["requirements"] == {"parameter": "id"}
    assert out["attack_techniques"] == [{"id": "T1190",
                                         "name": "Exploit Public-Facing Application"}]
    assert out["suggested_command"] == {"command": "curl x"}
    assert out["scope"]["allowed"] is False, (
        "an unreadable scope must read as NOT allowed (fail closed), never allowed")


def test_endpoint_rejects_a_malformed_cve():
    """The handler is executed with its decorator stripped."""
    tree = _tree()
    fn = _fn("build_poc_preview", tree)
    fn.decorator_list = []

    class HTTPException(Exception):
        def __init__(self, code, msg): self.code = code
    import re
    ns = {"HTTPException": HTTPException, "_re_module": re, "Depends": lambda x: None,
          "BuildPocPreviewBody": object,
          "auth": None, "_resolve_engagement_id": lambda: "eid",
          "_build_poc_preview": lambda *a, **k: {"ok": True, "args": a}}
    exec(compile(ast.Module([fn], []), "api.py", "exec"), ns)
    body = types.SimpleNamespace(cve="not-a-cve", ip="1.2.3.4", port=80, product=None,
                                 version=None, suggest_command=False, model=None)
    with pytest.raises(HTTPException) as e:
        ns["build_poc_preview"](body, True)
    assert e.value.code == 400
    body.cve = "cve-2024-1234"
    assert ns["build_poc_preview"](body, True)["args"][0] == "CVE-2024-1234"
