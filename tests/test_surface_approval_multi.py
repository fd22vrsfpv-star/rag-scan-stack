"""Approving impactful surface tests must execute ALL of them, not one/none.

WHY: the /pentest/{id}/approve endpoint sends `pending_exploit_ids` (a LIST),
but surface_approval/surface_exec read the singular `pending_exploit_id`, so an
operator who approved 4 impactful surface tests got "[approved but no
pending_exploit_id] Nothing executed" and the session ended having run none.
Both now read the plural list (singular still accepted) and surface_exec loops.

SABOTAGE PROOF: revert surface_exec to a single `pending_id` and this fails.
"""
import ast, os, pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")

def _fn(name):
    if not os.path.exists(ENGINE): pytest.skip("engine missing")
    src = open(ENGINE, encoding="utf-8").read()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name:
            return ast.get_source_segment(src, n)
    return None

def test_surface_approval_reads_plural_ids():
    b=_fn("surface_approval"); assert b
    assert 'decision.get("pending_exploit_ids")' in b, "surface_approval must read the plural list"
    assert '"pending_exploit_ids": pending_ids' in b, "must store the list in surface_decision"

def test_surface_exec_executes_all_ids():
    b=_fn("surface_exec"); assert b
    assert 'decision.get("pending_exploit_ids")' in b, "surface_exec must read the plural list"
    assert "for pending_id in pending_ids:" in b, "surface_exec must loop over all approved ids"
    assert "executed.append(pending_id)" in b, "surface_exec must run each id"
