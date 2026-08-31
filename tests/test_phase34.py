"""Phase 3 (validation + report) and Phase 4 (measure the loop).

- findings verification: a scanner finding is 'confirmed' only when a proof test
  passed on its host — the join must EXECUTE (it's the column-mismatch-500 class).
- learning status: surfaces the three honest signals (test outcomes, feedback,
  eval) so 'is it improving?' is answered with numbers.
- report node: wires the full generator with the step summary as fallback.
"""
import ast
import os
import re
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
BASE = os.environ.get("P34_URL", "https://localhost:8000")


def _key():
    env = REPO / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def _get(path):
    requests = pytest.importorskip("requests")
    try:
        return requests.get(f"{BASE}{path}", headers={"x-api-key": _key()},
                            timeout=25, verify=False)
    except Exception as e:
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def _an_engagement():
    r = _get("/engagements")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    if r.status_code != 200:
        pytest.skip(f"engagements HTTP {r.status_code}")
    engs = r.json().get("engagements") or r.json().get("items") or r.json()
    if not engs:
        pytest.skip("no engagements")
    return engs[0].get("id") or engs[0].get("engagement_id")


def test_findings_verification_executes():
    eid = _an_engagement()
    r = _get(f"/findings/verification/{eid}")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, f"verification 500/err: {r.text[:300]}"
    s = r.json()["summary"]
    for k in ("findings", "confirmed", "unverified", "pct_confirmed"):
        assert k in s
    assert s["confirmed"] + s["unverified"] == s["findings"]


def test_learning_status_measures_the_loop():
    r = _get("/learning/status")
    if r.status_code in (401, 403):
        pytest.skip("auth required")
    assert r.status_code == 200, r.text[:200]
    b = r.json()
    assert "generated_tests" in b and "retrieval_feedback" in b and "retrieval_eval" in b
    assert "prove_rate_pct" in b["generated_tests"]
    assert isinstance(b["retrieval_eval"]["measured"], bool)
    assert b["assessment"]  # an honest one-line read


def test_report_node_wires_the_full_generator():
    src = (REPO / "autogen_agents" / "langgraph_engine.py").read_text(encoding="utf-8")
    node = next((n for n in ast.walk(ast.parse(src))
                 if isinstance(n, ast.FunctionDef) and n.name == "report"), None)
    assert node is not None
    body = ast.get_source_segment(src, node)
    assert "generate_full_report" in body, "report node must call the full generator"
    # fallback: the step summary (rpt) must remain the default on failure
    assert "final = full if" in body or "else rpt" in body, (
        "the step summary must be the fallback so a generator hiccup never fails "
        "the session")
