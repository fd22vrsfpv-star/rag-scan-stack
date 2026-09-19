"""OWASP parameter tests are DATA (YAML/RAG), not hardcoded in the engine.

WHY: the SQLi/XSS/LFI/SSI/HPP/IDOR probe commands + payloads + assertions used to
be hardcoded in langgraph_engine._owasp_param_tests. They now live in
knowledge/owasp_param_tests.yaml (embedded into rag_documents), read at plan time
— so a payload/probe can be added or reclassified without a code change.

SABOTAGE PROOF: re-hardcode a `sqlmap -u ...` command in _owasp_param_tests and
test_engine_reads_yaml_not_hardcoded fails.
"""
import ast, os, re, pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")
YAML = os.path.join(REPO, "knowledge", "owasp_param_tests.yaml")

def test_yaml_has_the_param_test_categories():
    if not os.path.exists(YAML): pytest.skip("yaml missing")
    import yaml
    d = yaml.safe_load(open(YAML, encoding="utf-8"))
    cats = {r["category"] for r in d.get("param_tests", []) if isinstance(r, dict)}
    for c in ("sqli_detect", "xss_detect", "lfi_read", "ssi_detect",
              "format_string", "hpp_detect", "idor"):
        assert c in cats, f"owasp_param_tests.yaml missing {c}"
    # sqlmap for SQLi must be in the YAML, not the code
    sqli = next(r for r in d["param_tests"] if r["category"] == "sqli_detect")
    assert "sqlmap" in sqli["command"], "sqli_detect should use sqlmap (from YAML)"

def test_engine_reads_yaml_not_hardcoded():
    src = open(ENGINE, encoding="utf-8").read()
    fn = next((n for n in ast.walk(ast.parse(src))
               if isinstance(n, ast.FunctionDef) and n.name == "_owasp_param_tests"), None)
    assert fn, "_owasp_param_tests not found"
    body = ast.get_source_segment(src, fn)
    assert "_load_owasp_param_tests()" in body, "must read the YAML specs"
    assert "sqlmap -u" not in body, "sqlmap command must NOT be hardcoded in the engine"
    assert 'curl -sk' not in body, "curl probe commands must NOT be hardcoded in the engine"
