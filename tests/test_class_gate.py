"""An `unknown` vulnerability class is resolved -- or the exploit is blocked --
before any attempt.

Run standalone:  pytest tests/test_class_gate.py -q

Operator ask, 2026-10-18: "in a class unknown, that should be resolved first
before trying an exploit". An unknown class means no class guidance, no
reading hints, no graded-goal preference and no proof template, so the build
is a guess; and round 8's follow-through never engaged because its class came
back `unknown`. The class gate resolves it from a CLOSED vocabulary, stores the
answer where every re-derivation site reads it, or blocks run_refine with
stop_reason=class_unresolved. Functions are EXECUTED, compiled out of source.
"""
import ast
import json
import os
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"


def _fn(path, name):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    pytest.fail(f"{name} is gone from {path.name}")


class _VC:
    VOCAB = {"sqli", "ssrf", "privilege-escalation", "auth-bypass"}

    def names(self): return sorted(self.VOCAB | {"misconfiguration"})
    def is_exploitable(self, c): return c in self.VOCAB


def _resolver(reply, stored):
    ns = {"_vc": lambda: _VC(), "_vc_canonical": lambda c: (c or "").strip().lower() or "unknown",
          "_llm_for_model": lambda *a, **k: {"response": reply, "model": "m"},
          "_poc_extract_json": lambda t: (json.loads(t) if t.strip().startswith("{") else None),
          "_store_class_resolution": lambda *a, **k: stored.append(a) or True,
          "_poc_trace": lambda *a, **k: None}
    exec(compile(ast.Module([_fn(API, "_resolve_unknown_class")], []), "api.py", "exec"), ns)
    return ns["_resolve_unknown_class"]


DETAILS = {"description": "The plugin lets an unauthenticated user register as administrator.",
           "cwe": ["CWE-269"]}


def test_a_vocabulary_answer_resolves_and_is_stored():
    stored = []
    r = _resolver('{"class": "privilege-escalation", "evidence": "register as administrator"}',
                  stored)("CVE-2023-1", DETAILS)
    assert r["class"] == "privilege-escalation" and r["source"] == "llm"
    assert stored and stored[0][1] == "privilege-escalation" and stored[0][2] == "llm"


@pytest.mark.parametrize("reply", ['{"class": "unknown"}', '{"class": "misconfiguration"}',
                                   '{"class": "buffer-overflow"}', "", "I think it is SQLi"])
def test_anything_outside_the_exploitable_vocabulary_is_no_answer(reply):
    stored = []
    r = _resolver(reply, stored)("CVE-2023-1", DETAILS)
    assert r["class"] == "unknown" and not stored


def test_the_preview_resolves_without_storing():
    stored = []
    r = _resolver('{"class": "sqli"}', stored)("CVE-2023-1", DETAILS, store=False)
    assert r["class"] == "sqli" and not stored


def test_nothing_to_classify_from_is_unresolved_without_a_model_call():
    called = []
    f = _resolver('{"class": "sqli"}', [])
    f.__globals__["_llm_for_model"] = lambda *a, **k: called.append(1)
    assert f("CVE-2023-1", {})["class"] == "unknown" and not called


# --------------------------------------------------------------- the gate

def _gate(classify, resolve_to, cve="CVE-2023-9"):
    import sys
    import types
    fake_api = types.ModuleType("api")
    fake_api._fetch_cve_details = lambda c: DETAILS
    fake_api._vuln_class_from_cve = lambda c, d: classify
    fake_api._resolve_unknown_class = lambda *a, **k: {"class": resolve_to, "evidence": "e"}
    fake_api._poc_trace = lambda *a, **k: None
    sys.modules["api"] = fake_api
    ns = {"os": os, "CLASS_UNRESOLVED": "class_unresolved", "Dict": dict, "Any": object,
          "BuildPocState": dict}
    exec(compile(ast.Module([_fn(GRAPH, "_class_gate")], []), "graph.py", "exec"), ns)
    try:
        return ns["_class_gate"]({"cve": cve, "run_id": "r", "model": None})
    finally:
        sys.modules.pop("api", None)


def test_a_known_class_passes():
    assert _gate("sqli", "unknown") == {}


def test_an_unknown_class_that_resolves_passes():
    assert _gate("unknown", "privilege-escalation") == {}


def test_an_unresolvable_class_blocks_the_exploit():
    out = _gate("unknown", "unknown")
    assert out.get("readiness_blocked") is True
    assert out["readiness_blockers"][0].startswith("class_unresolved")


def test_a_product_only_build_is_not_gated():
    assert _gate("unknown", "unknown", cve="NOCVE-1792000000") == {}


def test_the_gate_runs_before_the_precondition_gate_can_switch_off():
    body = _fn(GRAPH, "node_readiness_gate").body
    calls = [i for i, st in enumerate(body)
             if any(isinstance(c, ast.Call) and getattr(c.func, "id", "") == "_class_gate"
                    for c in ast.walk(st))]
    offs = [i for i, st in enumerate(body)
            if isinstance(st, ast.If) and "off" in {c.value for c in ast.walk(st.test)
                                                      if isinstance(c, ast.Constant)}]
    assert calls and offs and calls[0] < offs[0], (
        "the class gate must run before BUILD_POC_PRECONDITION_GATE=off returns early")


def test_a_blocked_run_reports_class_unresolved():
    src = ast.get_source_segment(GRAPH.read_text(encoding="utf-8"), _fn(GRAPH, "node_run_refine"))
    assert "CLASS_UNRESOLVED if _cls" in src


def test_the_classifier_consults_stored_resolutions_last():
    fn = _fn(API, "_vuln_class_from_cve")
    calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call)
             and getattr(c.func, "id", "") == "_class_resolution_lookup"]
    assert calls, "_vuln_class_from_cve never reads stored resolutions"
    resolve_line = min(c.lineno for c in ast.walk(fn) if isinstance(c, ast.Call)
                       and getattr(c.func, "id", "") == "_vc_resolve")
    assert calls[0].lineno > resolve_line, "a stored class must not outrank the advisory"


def test_an_llm_resolution_never_overwrites_an_operator_one():
    src = ast.get_source_segment(API.read_text(encoding="utf-8"),
                                 _fn(API, "_store_class_resolution"))
    assert "WHERE cve_class_resolutions.source <> 'operator'" in src


def test_set_endpoint_rejects_a_non_exploitable_class():
    fn = _fn(API, "set_cve_class")
    fn.decorator_list = []

    class HTTPException(Exception):
        def __init__(self, code, msg): self.code = code
    import re
    import types
    ns = {"HTTPException": HTTPException, "_re_module": re, "Depends": lambda x: None,
          "auth": None, "CveClassBody": object, "_vc": lambda: _VC(),
          "_vc_canonical": lambda c: c.strip().lower(),
          "_store_class_resolution": lambda *a, **k: True}
    exec(compile(ast.Module([fn], []), "api.py", "exec"), ns)
    with pytest.raises(HTTPException) as e:
        ns["set_cve_class"]("CVE-2024-12345", types.SimpleNamespace(vuln_class="misconfiguration", note=None), True)
    assert e.value.code == 400
    ok = ns["set_cve_class"]("cve-2024-12345", types.SimpleNamespace(vuln_class="SQLi", note=None), True)
    assert ok == {"ok": True, "cve": "CVE-2024-12345", "vuln_class": "sqli", "source": "operator"}
