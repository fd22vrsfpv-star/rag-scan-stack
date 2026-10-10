"""2026-10-10: cross-app learning system — extract, store, recall, render lessons.

Validates the learning pipeline that lets future builds on the same product
recall what prior builds discovered (CSRF fields, auth forms, endpoints,
parameters, preconditions, auth methods). All functions are pure/deterministic
and AST-loaded for standalone execution.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=. python -m pytest tests/test_build_poc_cross_app_learning.py -v'
"""
from __future__ import annotations

import ast as _ast
import logging
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"

_CONSTS = ("_LESSON_TYPES",)
_FUNCS = ("_extract_lessons", "_render_lessons_note")


def _func_src(name: str, path=API) -> str | None:
    src = path.read_text()
    tree = _ast.parse(src)
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and node.name == name:
            return _ast.get_source_segment(src, node)
    return None


def _load(names=_FUNCS) -> dict:
    src = API.read_text()
    tree = _ast.parse(src)
    ns: dict = {"os": os, "logging": logging}
    for node in tree.body:
        if isinstance(node, _ast.Assign) and any(getattr(t, "id", "") in _CONSTS for t in node.targets):
            exec(_ast.get_source_segment(src, node), ns)
    for n in names:
        node = next(x for x in _ast.walk(tree) if isinstance(x, _ast.FunctionDef) and x.name == n)
        exec(_ast.get_source_segment(src, node), ns)
    return ns


@pytest.fixture(scope="module")
def ns():
    return _load()


# ── _LESSON_TYPES completeness ─────────────────────────────────────────────

def test_lesson_types_has_all_expected(ns):
    """The 8 lesson types must all be present."""
    expected = {"csrf_field", "auth_form", "endpoint", "parameter",
                "error_pattern", "precondition", "tool_config", "auth_method"}
    actual = set(ns["_LESSON_TYPES"])
    assert expected == actual, f"missing: {expected - actual}, extra: {actual - expected}"


# ── _extract_lessons ───────────────────────────────────────────────────────

def test_extract_lessons_csrf_field(ns):
    """A run with CSRF tokens in the gather manifest produces csrf_field lessons."""
    state_bits = {
        "product": "cacti",
        "vuln_class": "sqli",
        "cve": "CVE-2024-1234",
        "gather_manifest": {
            "facts": {
                "csrf_tokens": {
                    "endpoint": "/host.php",
                    "tokens": ["__csrf_magic=sid:abc123"]
                }
            }
        }
    }
    lessons = ns["_extract_lessons"]("run-1", {"verified": False}, state_bits)
    csrf = [l for l in lessons if l["lesson_type"] == "csrf_field"]
    assert len(csrf) >= 1
    assert "cacti" in csrf[0]["lesson_key"]
    assert "__csrf_magic" in csrf[0]["lesson_value"]


def test_extract_lessons_auth_form(ns):
    """A successful session produces an auth_form lesson."""
    state_bits = {
        "product": "dolibarr",
        "session_info": {"ok": True, "method": "supplied", "login_url": "/index.php",
                         "cookie_header": "DOLSESSID=abc"}
    }
    lessons = ns["_extract_lessons"]("run-2", {"verified": False}, state_bits)
    auth = [l for l in lessons if l["lesson_type"] == "auth_form"]
    assert len(auth) >= 1
    assert "dolibarr" in auth[0]["lesson_key"]
    assert "supplied" in auth[0]["lesson_value"]


def test_extract_lessons_endpoint_from_verified(ns):
    """A verified run extracts the endpoint from the final command."""
    state_bits = {"product": "cacti", "vuln_class": "sqli", "cve": "CVE-2024-25641"}
    result = {"verified": True,
              "final_command": "curl -s 'http://target/host.php?action=edit&id=1%27+OR+1=1--'"}
    lessons = ns["_extract_lessons"]("run-3", result, state_bits)
    ep = [l for l in lessons if l["lesson_type"] == "endpoint"]
    assert len(ep) >= 1
    assert "/host.php" in ep[0]["lesson_value"]
    assert ep[0]["confidence"] == 0.95


def test_extract_lessons_parameter_from_verified(ns):
    """A verified run extracts the injectable parameter."""
    state_bits = {"product": "cacti", "vuln_class": "sqli"}
    result = {"verified": True,
              "final_command": "curl -s http://target/host.php -d 'id=1%27+OR+1=1'"}
    lessons = ns["_extract_lessons"]("run-4", result, state_bits)
    param = [l for l in lessons if l["lesson_type"] == "parameter"]
    assert len(param) >= 1
    assert "id" in param[0]["lesson_value"]


def test_extract_lessons_precondition_from_failure(ns):
    """A failed run with failure analysis produces precondition lessons."""
    state_bits = {"product": "cacti", "vuln_class": "sqli"}
    fa = {
        "blockers": [
            {"item": "input_field", "why": "no injectable param found",
             "what_live_recon_found": "arjun: id, host_id on /host.php"}
        ]
    }
    lessons = ns["_extract_lessons"]("run-5", {"verified": False}, state_bits,
                                     failure_analysis=fa)
    pre = [l for l in lessons if l["lesson_type"] == "precondition"]
    assert len(pre) >= 1
    assert "input_field" in pre[0]["lesson_key"]


def test_extract_lessons_auth_method(ns):
    """When auth succeeds, an auth_method lesson is extracted."""
    state_bits = {
        "product": "zabbix",
        "auth": {"username": "Admin", "password": "zabbix"},
        "session_info": {"ok": True, "method": "api_jsonrpc",
                         "cookie_header": "zbx_session=xyz"}
    }
    lessons = ns["_extract_lessons"]("run-6", {"verified": False}, state_bits)
    am = [l for l in lessons if l["lesson_type"] == "auth_method"]
    assert len(am) >= 1
    assert "zabbix" in am[0]["lesson_key"]


def test_extract_lessons_requires_product(ns):
    """No product → no lessons (can't key without it)."""
    lessons = ns["_extract_lessons"]("run-0", {"verified": True},
                                     {"product": "", "vuln_class": "sqli"})
    assert lessons == []


def test_extract_lessons_verified_confidence_higher(ns):
    """CSRF lessons from a verified run get higher confidence than unverified."""
    state_bits = {
        "product": "cacti",
        "gather_manifest": {"facts": {"csrf_tokens": {"tokens": ["tok=val"]}}}
    }
    lessons_v = ns["_extract_lessons"]("v", {"verified": True}, state_bits)
    lessons_u = ns["_extract_lessons"]("u", {"verified": False}, state_bits)
    csrf_v = [l for l in lessons_v if l["lesson_type"] == "csrf_field"]
    csrf_u = [l for l in lessons_u if l["lesson_type"] == "csrf_field"]
    assert csrf_v and csrf_u
    assert csrf_v[0]["confidence"] > csrf_u[0]["confidence"]


# ── _render_lessons_note ───────────────────────────────────────────────────

def test_render_lessons_note_empty():
    ns = _load(("_render_lessons_note",))
    assert ns["_render_lessons_note"]([]) == ""
    assert ns["_render_lessons_note"](None) == ""


def test_render_lessons_note_formats_correctly():
    ns = _load(("_render_lessons_note",))
    lessons = [
        {"lesson_type": "csrf_field", "lesson_value": "CSRF field __csrf_magic on /host.php",
         "confidence": 0.8, "times_confirmed": 3, "source_cve": "CVE-2024-25641"},
        {"lesson_type": "endpoint", "lesson_value": "Verified endpoint /host.php for sqli",
         "confidence": 0.95, "times_confirmed": 1}
    ]
    note = ns["_render_lessons_note"](lessons)
    assert "LESSONS FROM PRIOR BUILDS" in note
    assert "[csrf_field]" in note
    assert "[endpoint]" in note
    assert "80%" in note
    assert "3x" in note
    assert "CVE-2024-25641" in note


def test_render_lessons_note_caps_at_max_items():
    ns = _load(("_render_lessons_note",))
    lessons = [{"lesson_type": "endpoint", "lesson_value": f"ep-{i}",
                "confidence": 0.5, "times_confirmed": 1} for i in range(30)]
    note = ns["_render_lessons_note"](lessons, max_items=5)
    assert note.count("[endpoint]") == 5


# ── Wiring checks (AST) ───────────────────────────────────────────────────

def test_gather_manifest_text_recalls_lessons():
    """_gather_manifest_text must call _recall_lessons and _render_lessons_note."""
    src = _func_src("_gather_manifest_text")
    assert src is not None, "_gather_manifest_text not found"
    assert "_recall_lessons" in src, "gather manifest text must recall lessons for the product"
    assert "_render_lessons_note" in src, "gather manifest text must render recalled lessons"


def test_graph_node_failure_analysis_extracts_and_stores():
    """node_failure_analysis must call _extract_lessons and _store_lessons."""
    src = _func_src("node_failure_analysis", GRAPH)
    assert src is not None, "node_failure_analysis not found in graph"
    assert "_extract_lessons" in src, "node must extract lessons on completion"
    assert "_store_lessons" in src, "node must store extracted lessons"


def test_key_trace_includes_lessons_extracted():
    """_KEY_TRACE_PHASES must include 'lessons_extracted'."""
    api_src = API.read_text()
    tree = _ast.parse(api_src)
    for node in tree.body:
        if isinstance(node, _ast.Assign) and any(
            getattr(t, "id", "") == "_KEY_TRACE_PHASES" for t in node.targets
        ):
            seg = _ast.get_source_segment(api_src, node)
            assert "lessons_extracted" in seg, "lessons_extracted must be in _KEY_TRACE_PHASES"
            return
    pytest.fail("_KEY_TRACE_PHASES not found in api.py")


def test_lessons_table_in_ddl():
    """build_poc_lessons must be in ensure_all_tables.sql."""
    ddl = (REPO / "db_init" / "ensure_all_tables.sql").read_text()
    assert "build_poc_lessons" in ddl, "table not declared in DDL"
    assert "ux_bpl_type_key" in ddl, "unique index not declared"


def test_lessons_table_in_health_check():
    """build_poc_lessons must be in the health check table list."""
    hc = (REPO / "scripts" / "post-install-check.sh").read_text()
    assert "build_poc_lessons" in hc, "table not in health check"


def test_lessons_table_in_schema_script():
    """build_poc_lessons must be in ensure_db_schema.sh."""
    sc = (REPO / "scripts" / "ensure_db_schema.sh").read_text()
    assert "build_poc_lessons" in sc, "table not in schema script"


def test_bff_proxies_exist():
    """BFF must proxy /api/build-poc/lessons and /api/build-poc/lessons/{lesson_id}."""
    bff = (REPO / "dashboard" / "bff" / "routers" / "exploits.py").read_text()
    assert '"/api/build-poc/lessons"' in bff, "GET proxy missing"
    assert '"/api/build-poc/lessons/{lesson_id}"' in bff, "DELETE proxy missing"


def test_list_endpoint_exists():
    """rag-api must declare GET /build-poc/lessons."""
    api_src = API.read_text()
    assert '"/build-poc/lessons"' in api_src
    assert "list_build_poc_lessons" in api_src or "def list_build_poc" in api_src


def test_delete_endpoint_exists():
    """rag-api must declare DELETE /build-poc/lessons/{lesson_id}."""
    api_src = API.read_text()
    assert '"/build-poc/lessons/{lesson_id}"' in api_src
    assert "deactivate_lesson" in api_src or "def deactivate" in api_src
