"""Class reading hints, and the description-read step that applies them.

Run standalone:  pytest tests/test_reading_hints.py -q

WHY THIS EXISTS
---------------
A build learned what an exploit REQUIRES only by failing: CVE-2023-37999
(registration privilege escalation) re-sent one email for 10 iterations because
"this creates an account" was never stated -- only discovered, too late, as
"Email Already in Use". Every exploitable class in knowledge/vuln_classes.yaml
now carries `reading_hints` (what to look for in a description, what it
implies), they reach every craft prompt deterministically, and one LLM call
reads the description into structured requirements that every refine prompt of
the same run repeats. Helpers are EXECUTED, compiled out of api.py.
"""
import ast
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
VC_YAML = REPO / "knowledge" / "vuln_classes.yaml"


def _classes():
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(VC_YAML.read_text(encoding="utf-8"))["classes"]


def test_every_exploitable_class_has_reading_hints():
    bad = [c["name"] for c in _classes() if c.get("kind") == "vulnerability"
           and not ((c.get("reading_hints") or {}).get("look_for")
                    and (c.get("reading_hints") or {}).get("implies"))]
    assert not bad, "exploitable class(es) with no reading_hints look_for+implies: %s" % bad


def test_privilege_escalation_hints_say_it_creates_state():
    pe = next(c for c in _classes() if c["name"] == "privilege-escalation")
    text = " ".join(pe["reading_hints"]["implies"]).lower()
    assert "unique" in text and "creates state" in text


def test_accessor_returns_the_hints():
    vc = pytest.importorskip("etl.vuln_classes")
    rh = vc.reading_hints("sqli")
    assert rh["look_for"] and rh["implies"]
    assert vc.reading_hints("no-such-class") == {"look_for": [], "implies": []}


def test_hints_are_in_the_embedded_class_document():
    pytest.importorskip("yaml")
    from etl import load_knowledge_documents as lk
    import yaml
    docs = lk._render_vuln_classes(yaml.safe_load(VC_YAML.read_text(encoding="utf-8")))
    body = next(str(d) for d in docs if "(privilege-escalation)" in str(d))
    assert "look for:" in body and "What that means:" in body, (
        "reading hints are not embedded, so retrieval can never surface them")


# --------------------------------------------------------- executed helpers

def _load(llm_reply=None):
    tree = ast.parse(API.read_text(encoding="utf-8"))
    fns = {"_class_reading_hints_block", "_read_description_requirements",
           "_requirements_block"}
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in fns]
    assert {n.name for n in body} == fns, "helper(s) gone from api.py"
    _want = ("_RUN_REQUIREMENTS", "_RUN_REQUIREMENTS_MAX", "_REQUIREMENT_KEYS")
    body += [n for n in tree.body
             if (isinstance(n, ast.Assign)
                 and any(getattr(t, "id", "") in _want for t in n.targets))
             or (isinstance(n, ast.AnnAssign) and getattr(n.target, "id", "") in _want)]
    vc = pytest.importorskip("etl.vuln_classes")
    traces = []
    import logging

    def _extract(t):
        try:
            return json.loads(t)
        except Exception:  # noqa: BLE001
            return None
    ns = {"_vc": lambda: vc, "logging": logging, "_poc_extract_json": _extract,
          "_llm_for_model": lambda *a, **k: {"response": llm_reply or ""},
          "_poc_trace": lambda run_id, phase, **k: traces.append((phase, k))}
    exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])),
                 "<api-subset>", "exec"), ns)
    ns["_traces"] = traces
    return ns


DESC_37999 = ("The HT Mega plugin for WordPress is vulnerable to privilege "
              "escalation: the htmega_ajax_register action lets an unauthenticated "
              "visitor register with an arbitrary role, including administrator.")

REPLY = json.dumps({
    "endpoint": "/wp-admin/admin-ajax.php?action=htmega_ajax_register",
    "parameter": None, "auth_required": False, "creates_state": True,
    "identity_fields": ["reg_email", "reg_name"], "role_parameter": "reg_role",
    "output_visible": True, "proof": "log in as the new user and reach wp-admin",
    "preconditions": []})


def test_hints_block_renders_for_a_class():
    ns = _load()
    blk = ns["_class_reading_hints_block"]("privilege-escalation")
    assert "Look for:" in blk and "This means:" in blk
    assert ns["_class_reading_hints_block"]("no-such-class") == ""


def test_read_step_returns_structured_requirements_and_keeps_them_for_the_run():
    ns = _load(REPLY)
    req = ns["_read_description_requirements"]("CVE-2023-37999", DESC_37999,
                                               "privilege-escalation", run_id="r1")
    assert req["creates_state"] is True and req["role_parameter"] == "reg_role"
    assert "parameter" not in req and "preconditions" not in req, "nulls must be dropped"
    assert ns["_RUN_REQUIREMENTS"]["r1"] == req
    assert ns["_traces"][-1][0] == "description_read"


def test_requirements_block_states_the_fresh_identity_rule():
    ns = _load(REPLY)
    req = ns["_read_description_requirements"]("CVE-2023-37999", DESC_37999,
                                               "privilege-escalation", run_id="r2")
    blk = ns["_requirements_block"](req)
    assert "reg_email" in blk and "UNIQUE" in blk


@pytest.mark.parametrize("reply", ["", "I cannot help with that.", "{not json"])
def test_an_unusable_reply_changes_nothing(reply):
    ns = _load(reply)
    assert ns["_read_description_requirements"]("CVE-X", DESC_37999, "sqli",
                                                run_id="r3") == {}
    assert "r3" not in ns["_RUN_REQUIREMENTS"]
    assert ns["_requirements_block"]({}) == ""


# ----------------------------------------------------------------- wiring

def _fn(name):
    src = API.read_text(encoding="utf-8")
    for n in ast.parse(src).body:
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    pytest.fail(name + " is gone")


def _calls(node):
    return {c.func.id for c in ast.walk(node)
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}


def test_synthesis_reads_the_description():
    assert "_read_description_requirements" in _calls(_fn("_synthesize_cve_poc"))


def test_class_guidance_carries_the_hints():
    assert "_class_reading_hints_block" in _calls(_fn("_class_guidance_block"))


def test_refine_prompt_carries_the_requirements():
    node = _fn("_run_refine_poc")
    assert "_requirements_block" in _calls(node)
    names = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "rprompt" for t in n.targets):
            names |= {x.id for x in ast.walk(n.value) if isinstance(x, ast.Name)}
    assert "_req_note" in names, "requirements are built but never reach the refine prompt"
