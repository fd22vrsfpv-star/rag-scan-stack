"""Security-test persistence: the assertion evaluator, the two-copy agreement,
the record_test_run lane invariant, and the live endpoints (incl. that an
impactful re-run cannot bypass approval).

Run on demand:
    pytest tests/test_security_tests.py -v
    ST_URL=https://localhost:3002 pytest tests/test_security_tests.py

WHY THIS EXISTS
---------------
`security_tests`/`security_test_runs` turn one-shot exploit checks into
re-runnable, evidence-backed proof records. Three properties must hold and are
easy to get wrong at runtime:

  1. The assertion evaluator is deterministic and total (pass/fail/error).
  2. Two copies of it exist — app/rag-api/security_tests.py (the API + re-run
     path) and autogen_agents/db_utils._eval_assertion_local (the agent, a
     different container that cannot import the first). They MUST agree, or the
     same test scores differently depending on who ran it.
  3. record_test_run must refuse a safe run carrying impactful proof, or vice
     versa — otherwise a scope-gated probe could be recorded as an exploit.

And the load-bearing security property: re-running an IMPACTFUL test via
POST /security-tests/{id}/run must NOT execute — it returns requires_approval,
so a proven exploit still passes the human gate on every replay.

The evaluators are extracted with `ast` (no psycopg2/fastapi import), so the
pure checks run on a bare checkout. The endpoint checks skip without a stack.
"""
import ast
import os
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
API_MOD = REPO / "app" / "rag-api" / "security_tests.py"
DB_MOD = REPO / "autogen_agents" / "db_utils.py"


def _extract(path, fn_name, extra_consts=()):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    import typing as _t
    ns = {"re": __import__("re"), "List": _t.List, "Dict": _t.Dict, "Any": _t.Any,
          "Optional": _t.Optional, "Tuple": _t.Tuple}
    got = False
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and n.name == fn_name:
            exec(compile(ast.Module([n], []), "<f>", "exec"), ns); got = True
        if (isinstance(n, ast.Assign) and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)
                and n.targets[0].id in extra_consts):
            exec(compile(ast.Module([n], []), "<c>", "exec"), ns)
    assert got, f"{fn_name} not found in {path.name} — this guard would pass vacuously"
    return ns[fn_name]


@pytest.fixture(scope="module")
def api_eval():
    if not API_MOD.exists():
        pytest.skip("security_tests.py not present")
    return _extract(API_MOD, "evaluate_assertion", ("_CLAUSE_KEYS",))


@pytest.fixture(scope="module")
def db_eval():
    if not DB_MOD.exists():
        pytest.skip("db_utils.py not present")
    return _extract(DB_MOD, "_eval_assertion_local")


# Shared case table: (assertion, kwargs, expected_status)
CASES = [
    ({"expect_substring": ["root:x:0"]}, {"exit_code": 0, "output": "root:x:0:0:root"}, "pass"),
    ({"expect_substring": ["root:x:0"]}, {"exit_code": 0, "output": "nope"}, "fail"),
    ({"expect_substring": ["x"]}, {}, "error"),
    ({"expect_shell": True}, {"has_shell": True, "output": "id: uid=0"}, "pass"),
    ({"expect_shell": True}, {"exit_code": 0, "output": "no shell here"}, "fail"),
    ({}, {"exit_code": 0, "output": "ok"}, "pass"),
    ({"expect_not_substring": ["command not found"]},
     {"exit_code": 127, "output": "bash: sqlmap: command not found"}, "fail"),
    ({"expect_exit_code": 0}, {"exit_code": 1, "output": "x"}, "fail"),
    ({"expect_status": 200}, {"http_status": 200, "output": "x"}, "pass"),
    ({"expect_status": 200}, {"http_status": 500, "output": "x"}, "fail"),
    ({"expect_regex": r"uid=\d+"}, {"exit_code": 0, "output": "uid=0(root)"}, "pass"),
    ({"expect_screenshot": True}, {"has_screenshot": True, "output": "x"}, "pass"),
    ({"min_output_bytes": 10}, {"exit_code": 0, "output": "short"}, "fail"),
]


@pytest.mark.parametrize("assertion,kw,expected", CASES)
def test_api_evaluator(api_eval, assertion, kw, expected):
    status, _eval, _summary = api_eval(assertion, **kw)
    assert status == expected, f"{assertion} {kw} -> {status}, want {expected}"


@pytest.mark.parametrize("assertion,kw,expected", CASES)
def test_the_two_evaluators_agree(api_eval, db_eval, assertion, kw, expected):
    """The API copy and the agent copy must return the same verdict, or a test
    scores differently depending on which container ran it."""
    a = api_eval(assertion, **kw)[0]
    d = db_eval(assertion, **kw)[0]
    assert a == d == expected, f"{assertion} {kw}: api={a} db={d} want={expected}"


def test_record_test_run_refuses_lane_evidence_mismatch():
    """The invariant checks must fire BEFORE any DB access, so a bad call raises
    without a connection. Extract the function and call it with conn=None."""
    if not API_MOD.exists():
        pytest.skip("security_tests.py not present")
    tree = ast.parse(API_MOD.read_text(encoding="utf-8"))
    import typing as _t
    ns = {"re": __import__("re"), "List": _t.List, "Dict": _t.Dict, "Any": _t.Any,
          "Optional": _t.Optional, "Tuple": _t.Tuple}
    for n in tree.body:
        if isinstance(n, ast.ClassDef) and n.name == "TestRunError":
            exec(compile(ast.Module([n], []), "<c>", "exec"), ns)
        if isinstance(n, ast.FunctionDef) and n.name in ("evaluate_assertion", "record_test_run"):
            exec(compile(ast.Module([n], []), "<f>", "exec"), ns)
    rtr = ns["record_test_run"]
    Err = ns["TestRunError"]
    # safe run carrying impactful proof
    with pytest.raises(Err):
        rtr(None, test_id="x", lane="safe", exploit_result_id="e1")
    # impactful run carrying safe proof
    with pytest.raises(Err):
        rtr(None, test_id="x", lane="impactful", tool_execution_id="t1")
    # both set
    with pytest.raises(Err):
        rtr(None, test_id="x", lane="safe", tool_execution_id="t1", exploit_result_id="e1")
    # bad lane
    with pytest.raises(Err):
        rtr(None, test_id="x", lane="bogus")


# ── live endpoints (skip cleanly without a stack) ───────────────────────────
BASE = os.environ.get("ST_URL", "https://localhost:3002")


def _api():
    requests = pytest.importorskip("requests")
    try:
        requests.packages.urllib3.disable_warnings()
    except Exception:
        pass
    return requests


def _key():
    env = REPO / ".env"
    if env.exists():
        import re
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def _get(path):
    r = _api()
    try:
        return r.get(f"{BASE}{path}", headers={"x-api-key": _key()}, timeout=25, verify=False)
    except Exception as e:  # pragma: no cover
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def _post(path, body):
    r = _api()
    try:
        return r.post(f"{BASE}{path}", json=body, headers={"x-api-key": _key()},
                      timeout=25, verify=False)
    except Exception as e:  # pragma: no cover
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def test_list_executes():
    r = _get("/api/security-tests")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, r.text[:300]
    assert "tests" in r.json()


def test_create_get_and_patch_a_safe_test():
    body = {"name": "pytest-safe-probe", "tier": "safe", "category": "version_probe",
            "target_ip": "127.0.0.1", "target_port": 80, "tool": "curl",
            "command": "curl -s http://127.0.0.1/",
            "assertion": {"expect_exit_code": 0}}
    r = _post("/api/security-tests", body)
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, r.text[:300]
    tid = r.json()["id"]
    g = _get(f"/api/security-tests/{tid}")
    assert g.status_code == 200 and g.json()["tier"] == "safe"
    # runs list executes (empty is fine)
    rr = _get(f"/api/security-tests/{tid}/runs")
    assert rr.status_code == 200 and "runs" in rr.json()


def test_impactful_create_requires_pending_exploit():
    r = _post("/api/security-tests",
              {"name": "pytest-bad-impactful", "tier": "impactful",
               "category": "rce", "target_ip": "127.0.0.1"})
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 400, f"expected 400, got {r.status_code}: {r.text[:200]}"


def test_impactful_rerun_cannot_bypass_approval():
    """The load-bearing property: re-running an impactful test never executes —
    it returns requires_approval. Build one referencing a throwaway pending
    exploit, then hit /run and assert 202 skipped requires_approval."""
    # need a pending_exploit to reference; query the existing list endpoint
    pe = _get("/api/exploits/pending")
    if pe.status_code in (401, 403):
        pytest.skip("auth required")
    if pe.status_code != 200:
        pytest.skip(f"cannot list pending exploits (HTTP {pe.status_code})")
    body = pe.json()
    rows = body if isinstance(body, list) else (body.get("exploits") or body.get("pending")
             or body.get("items") or body.get("data") or [])
    if not rows:
        pytest.skip("no pending exploit to reference")
    pid = rows[0].get("id") or rows[0].get("pending_exploit_id")
    if not pid:
        pytest.skip("pending exploit rows carry no id")
    c = _post("/api/security-tests",
              {"name": "pytest-impactful", "tier": "impactful", "category": "rce",
               "target_ip": "127.0.0.1", "pending_exploit_id": pid})
    if c.status_code != 200:
        pytest.skip(f"could not create impactful test: {c.text[:200]}")
    tid = c.json()["id"]
    run = _post(f"/api/security-tests/{tid}/run", {"triggered_by": "operator"})
    assert run.status_code == 202, f"expected 202, got {run.status_code}: {run.text[:300]}"
    j = run.json()
    assert j.get("requires_approval") is True and j.get("status") == "skipped", j
