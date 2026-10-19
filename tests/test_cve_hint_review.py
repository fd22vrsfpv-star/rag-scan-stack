"""scripts/cve_hint_review.py: aggregation and resumability (pure parts).

Run standalone:  pytest tests/test_cve_hint_review.py -q
"""
import importlib.util
import json
import pathlib

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "cve_hint_review.py"


def _mod():
    spec = importlib.util.spec_from_file_location("cve_hint_review", SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_aggregate_counts_keys_per_class_and_ignores_empties():
    m = _mod()
    rows = [
        {"cve": "A", "vuln_class": "privilege-escalation",
         "requirements": {"creates_state": True, "role_parameter": "reg_role"}},
        {"cve": "B", "vuln_class": "privilege-escalation",
         "requirements": {"creates_state": True, "auth_required": False}},
        {"cve": "C", "vuln_class": "privilege-escalation", "requirements": {}},
        {"cve": "D", "vuln_class": "sqli", "requirements": {"parameter": "id"}},
    ]
    a = m.aggregate(rows)
    pe = a["privilege-escalation"]
    assert pe["cves"] == 3 and pe["with_requirements"] == 2
    assert pe["keys"] == {"creates_state": 2, "role_parameter": 1}, (
        "a False/empty value must not count as a recurring requirement")
    assert a["sqli"]["samples"]["parameter"] == ["id"]


def test_done_set_makes_a_phase_resumable(tmp_path):
    m = _mod()
    p = tmp_path / "enrich.jsonl"
    m._append(str(p), {"cve": "CVE-2026-1"})
    p.write_text(p.read_text() + "not json\n")
    m._append(str(p), {"cve": "CVE-2026-2"})
    assert m._done(str(p)) == {"CVE-2026-1", "CVE-2026-2"}
    assert m._done(str(tmp_path / "missing.jsonl")) == set()


def test_failed_fetch_is_not_recorded_so_it_is_retried():
    """Unreachable is not absent: an errored enrich row must not be written,
    or the resume logic would skip that CVE forever with no class. The
    `_append(path, row)` must sit in the ELSE of the `if row.get("error")`."""
    import ast
    fn = next(n for n in ast.parse(SCRIPT.read_text(encoding="utf-8")).body
              if isinstance(n, ast.FunctionDef) and n.name == "phase_enrich")
    ok = False
    for n in ast.walk(fn):
        if isinstance(n, ast.If) and any(isinstance(c, ast.Constant) and c.value == "error"
                                         for c in ast.walk(n.test)):
            in_body = any(isinstance(c, ast.Call) and getattr(c.func, "id", "") == "_append"
                          for c in ast.walk(ast.Module(n.body, [])))
            in_else = any(isinstance(c, ast.Call) and getattr(c.func, "id", "") == "_append"
                          for c in ast.walk(ast.Module(n.orelse, [])))
            ok = ok or (in_else and not in_body)
    assert ok, "an errored enrich row is appended -- resume would skip it forever"


def test_writeups_merge_only_fills_missing_advisories():
    m = _mod()
    enrich = [{"cve": "A", "advisory_poc": ""}, {"cve": "B", "advisory_poc": "ghsa text"},
              {"cve": "C", "advisory_poc": ""}]
    writeups = [{"cve": "A", "advisory_poc": "blog post"},
                {"cve": "B", "advisory_poc": "other"}, {"cve": "C", "advisory_poc": ""}]
    got = {r["cve"]: r for r in m.merged_rows(enrich, writeups)}
    assert got["A"]["advisory_poc"] == "blog post" and got["A"]["writeup_from"] == "search"
    assert got["B"]["advisory_poc"] == "ghsa text", "an enrich advisory must not be overwritten"
    assert "writeup_from" not in got["C"]


def test_enrich_disables_the_web_search():
    """80 of 82 s per CVE was the DuckDuckGo search; enrich must turn it off."""
    import ast
    fn = next(n for n in ast.parse(SCRIPT.read_text(encoding="utf-8")).body
              if isinstance(n, ast.FunctionDef) and n.name == "phase_enrich")
    assert any(isinstance(n, ast.Assign) and any(getattr(t, "attr", "") == "_BUILD_POC_WEB_SEARCH"
                                                 for t in n.targets)
               and isinstance(n.value, ast.Constant) and n.value.value is False
               for n in ast.walk(fn)), "phase_enrich leaves the web search on"
