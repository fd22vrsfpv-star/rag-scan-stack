"""Historical-URL phases of passive-recon must INGEST, not just count.

WHY THIS EXISTS
---------------
The gau phase of `_run_passive_recon` ran the tool, read the output file,
recorded `phases["gau"] = {"urls": N}` and appended the path to
`all_output_files` -- and then never called `_ingest_results`. Every other
producing phase in the same function (subfinder, dnsx, crtsh, httpx, tlsx,
whatweb) does ingest. So a passive recon reported "found 4,812 historical URLs"
and stored none of them: nothing in `recon_findings`, nothing on the Recon
Explorer, nothing any agent could retrieve. The count made it look like it had
worked, which is why it survived.

Two further things this pins:

1. `gau --o` TRUNCATES its output file. The loop pointed every domain at one
   path, so a multi-domain run kept only the LAST domain's URLs and silently
   lost the rest. Each domain now writes its own file and the union is
   accumulated.

2. waybackurls is a SECOND source, not a rename. gau queries Wayback +
   Common Crawl + URLScan + OTX and drops a provider that errors; waybackurls
   queries the Wayback CDX API directly, so it backstops gau's most important
   provider. Both feed etl/parse_gau.py, which keys rows on `source`, so the
   UI can still say which archive produced a URL.

Static (ast) rather than import-based: osint_runner.py imports FastAPI and
sibling modules by bare name and is not importable outside its container.

SABOTAGE PROOF
--------------
* Delete the `_ingest_results("gau", ...)` call    -> test_gau_output_is_ingested fails.
* Delete the waybackurls ingest                    -> test_waybackurls_output_is_ingested fails.
* Point both domains at one `gau --o` path again   -> test_gau_writes_one_file_per_domain fails.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
RUNNER = os.path.join(REPO, "osint_runner", "osint_runner.py")


def _func_src():
    if not os.path.exists(RUNNER):
        pytest.skip("osint_runner.py not present")
    src = open(RUNNER, encoding="utf-8").read()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "_run_passive_recon":
            return ast.get_source_segment(src, n)
    pytest.fail("_run_passive_recon not found")


def _ingested_tools(fn_src):
    """Every literal first argument to _ingest_results(...) in the function."""
    tools = set()
    for n in ast.walk(ast.parse(fn_src.lstrip())):
        if not isinstance(n, ast.Call):
            continue
        name = getattr(n.func, "id", None) or getattr(n.func, "attr", None)
        if name != "_ingest_results":
            continue
        if n.args and isinstance(n.args[0], ast.Constant):
            tools.add(n.args[0].value)
    return tools


def test_gau_output_is_ingested():
    tools = _ingested_tools(_func_src())
    assert "gau" in tools, (
        "the gau phase counts its URLs but never calls _ingest_results, so a "
        "passive recon reports historical URLs it did not store — nothing "
        "reaches recon_findings or the Recon Explorer")


def test_waybackurls_output_is_ingested():
    tools = _ingested_tools(_func_src())
    assert "waybackurls" in tools, (
        "waybackurls runs in the pipeline but its output is never ingested")


def test_the_other_producing_phases_still_ingest():
    """Guard the premise: these were already ingesting, and must keep doing so."""
    tools = _ingested_tools(_func_src())
    for t in ("subfinder", "dnsx", "crtsh", "httpx"):
        assert t in tools, f"{t} no longer ingests its results"


def test_gau_writes_one_file_per_domain():
    """`gau --o` truncates, so a shared path keeps only the last domain."""
    fn = _func_src()
    tree = ast.parse(fn.lstrip())
    # find the loop that runs gau, and assert the -o target is built INSIDE it
    gau_loops = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.For):
            continue
        body = ast.dump(n)
        if "'gau'" in body or '"gau"' in body:
            gau_loops.append(n)
    assert gau_loops, "no per-domain gau loop found"
    built_inside = any(
        isinstance(x, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "one" for t in x.targets)
        for loop in gau_loops for x in ast.walk(loop))
    assert built_inside, (
        "the gau output path is not constructed per-domain inside the loop — "
        "`gau --o` truncates, so every domain but the last is discarded")


def test_the_union_is_deduplicated_before_ingest():
    """gau and waybackurls overlap heavily; storing both copies inflates
    recon_findings, which is already dominated by URL inventory rows."""
    fn = _func_src()
    assert "only_wb" in fn or "-" in fn, "no set difference between the two sources"
    tree = ast.parse(fn.lstrip())
    has_diff = any(
        isinstance(n, ast.BinOp) and isinstance(n.op, ast.Sub)
        and isinstance(n.left, ast.Name) and isinstance(n.right, ast.Name)
        for n in ast.walk(tree))
    assert has_diff, (
        "the waybackurls result is not reduced by what gau already returned")


# ── "has this already been run for this site?" ───────────────────────────────
#
# gau and waybackurls can each be started from TWO places (the passive-recon
# pipeline and their own /jobs/* endpoints), so the coverage answer must hold
# whichever was used. Findings alone cannot answer it: no rows may mean "never
# queried" OR "queried, archive empty", and this repo has shipped that confusion
# repeatedly. A tool_executions row is the third state.


def _module_src():
    if not os.path.exists(RUNNER):
        pytest.skip("osint_runner.py not present")
    return open(RUNNER, encoding="utf-8").read()


def _fn(name):
    src = _module_src()
    for n in ast.walk(ast.parse(src)):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return ast.get_source_segment(src, n)
    return None


def test_the_pipeline_records_each_run():
    fn = _func_src()
    calls = [n for n in ast.walk(ast.parse(fn.lstrip()))
             if isinstance(n, ast.Call)
             and (getattr(n.func, "id", None) == "_record_run")]
    tools = {c.args[0].value for c in calls
             if c.args and isinstance(c.args[0], ast.Constant)}
    assert {"gau", "waybackurls"} <= tools, (
        f"the pipeline does not record a run for both tools (got {tools}) — a site "
        "queried here would read as never queried")


def test_the_standalone_endpoints_record_too():
    """Otherwise coverage reports never_run after a standalone job and the
    operator is sent to repeat work."""
    src = _module_src()
    tree = ast.parse(src)
    wrapped = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        name = getattr(n.func, "id", None) or getattr(n.func, "attr", None)
        if name != "add_task":
            continue
        if not n.args:
            continue
        task = getattr(n.args[0], "id", None)
        if task == "_run_tool_job_recorded" and len(n.args) > 2 \
                and isinstance(n.args[2], ast.Constant):
            wrapped.add(n.args[2].value)
    assert {"gau", "waybackurls"} <= wrapped, (
        f"these standalone endpoints still use the unrecorded runner: "
        f"{ {'gau','waybackurls'} - wrapped }")


def test_a_refused_run_is_not_recorded_as_an_empty_result():
    """THE bug this caught in practice.

    _run_tool_job does not RAISE on a scope refusal — it marks the job failed and
    returns. Trusting "no exception" recorded a scope-REFUSED waybackurls run as
    completed with 0 findings, i.e. "the archive has nothing for this site": a
    negative result for a query that was never sent. Observed live against
    example.com, then fixed by reading the job's own status back.
    """
    fn = _fn("_run_tool_job_recorded")
    assert fn, "_run_tool_job_recorded not found"
    calls = {(getattr(c.func, "id", None) or getattr(c.func, "attr", None))
             for c in ast.walk(ast.parse(fn.lstrip())) if isinstance(c, ast.Call)}
    assert "get_job" in calls, (
        "the wrapper does not read the job's own status back, so a refusal that "
        "does not raise is recorded as a successful empty run")


def test_coverage_endpoint_distinguishes_three_states():
    fn = _fn("historical_url_coverage")
    assert fn, "the coverage endpoint is gone"
    consts = {n.value for n in ast.walk(ast.parse(fn.lstrip()))
              if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    for state in ("never_run", "ran_empty", "ran", "failed"):
        assert state in consts, f"the coverage endpoint cannot report {state!r}"


def test_coverage_says_unavailable_rather_than_never_run_on_a_db_error():
    """An unreadable database is not evidence that nothing ran."""
    fn = _fn("historical_url_coverage")
    assert "503" in fn, (
        "a DB failure does not surface as unavailable — the caller would read "
        "the empty result as 'never run' and repeat work, or worse, trust it")


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
