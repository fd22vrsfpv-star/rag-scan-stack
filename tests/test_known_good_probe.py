"""Run the known-good check first, and try the product's past CVEs too.

The pipeline asked "does projectdiscovery ship a check for this CVE", wrote the
answer into the trace, and synthesised from scratch regardless. Its own comment
said so: `# Advisory only -- never gates the build`. Measured 2026-10-15:

    CVE-2024-3408   severity=critical  verified=TRUE   http/cves/2024/CVE-2024-3408.yaml
    CVE-2024-22120  severity=critical  verified=False  code/cves/2024/CVE-2024-22120.yaml

CVE-2024-3408 carried a community-VERIFIED template. That build ran nine
commands, ended max_iters, verified=False, and never executed it.

A known-good payload is not just a shortcut, it is a CONTROL. Without one a
failed build cannot separate:

    * the exploit is genuinely hard,
    * the target is not actually vulnerable,
    * our plumbing is broken (wrong port, no session, a WAF, CSRF handling).

A verified template that ALSO fails points at the target or the plumbing. One
that PASSES while our PoC fails isolates the failure to synthesis exactly.

SIBLING CVEs (operator, 2026-10-15: "also consider past cve's that are similar
for the same product, some of those might have similar faults") are found by
TAG, which is the only axis that works. The obvious route --
`/templates/search?q=<product>` -- matches on FILENAME, and a CVE template is
named CVE-2024-22120.yaml with no product name in it: measured, it returns ZERO
CVE templates for Zabbix, WordPress, Apache and Jenkins alike, while
`-tags zabbix` returns 6 including that CVE's own plus 2016/2019/2022 siblings.

The cap is load-bearing. Critical/high CVE templates per tag: zabbix 5,
jenkins 7, php 19, microsoft 20, apache 104, **wordpress 600**. Running 600
templates at a host is a vulnerability scan, not a control experiment.

Sabotage check: remove the scope-gate call from the probe and
`test_the_probe_is_scope_gated` fails; drop the cap and
`test_the_sibling_run_is_bounded` fails; stop prepending the evidence and
`test_a_template_hit_reaches_synthesis` fails.

    pytest tests/test_known_good_probe.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
GRAPH = REPO / "app" / "rag-api" / "build_poc_graph.py"
RUNNER = REPO / "nuclei" / "nuclei_runner.py"


def _src(path: Path) -> str:
    if not path.exists():
        pytest.skip(f"{path.name} not found")
    return path.read_text(encoding="utf-8")


def _func(path: Path, name: str):
    for n in ast.walk(ast.parse(_src(path))):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    pytest.fail(f"{name} is not defined in {path.name}")


def _fsrc(path: Path, name: str) -> str:
    return ast.get_source_segment(_src(path), _func(path, name)) or ""


# ── the probe runs, and is gated like any other target traffic ────────────────

def test_the_probe_exists_and_runs_the_template():
    src = _fsrc(API, "_known_good_probe")
    assert "nuclei -id" in src, (
        "the probe does not actually RUN a template — noting that one exists "
        "is what the pipeline already did")
    assert "vectors/run" in src, "the probe never dispatches anything"


def test_the_probe_is_scope_gated():
    """A template id is not permission to send traffic."""
    src = _fsrc(API, "_known_good_probe")
    assert "check_dispatch" in src and "load_dispatch_scope" in src, (
        "the probe dispatches at a target without consulting the scope gate")
    i_gate = src.find("check_dispatch")
    i_send = src.find("vectors/run")
    assert 0 < i_gate < i_send, (
        "the scope check comes AFTER the dispatch, which is not a gate")


def test_the_probe_never_gates_the_build():
    """Advisory in the other direction: it must not be able to stop a build."""
    fn = _func(API, "_known_good_probe")
    assert any(isinstance(n, ast.ExceptHandler) for n in ast.walk(fn)), (
        "the probe has no exception handler, so a failed control run would "
        "abort the build it was meant to inform")
    src = _fsrc(API, "_known_good_probe")
    assert "skipped" in src, "the probe cannot report that it did not run"


def test_a_hit_is_recorded_as_a_probe_confirmed_fact():
    src = _fsrc(API, "_known_good_probe")
    assert "_record_confirmation" in src, (
        "a template hit is not written to the fact ledger, so nothing "
        "downstream can enforce or cite it")
    assert "probe_confirmed" in src, (
        "the hit is not recorded with probe provenance — a third-party "
        "template firing on THIS host is an observation, not an inference")


# ── siblings: found by tag, and bounded ───────────────────────────────────────

def test_siblings_are_found_by_tag_not_filename():
    src = _fsrc(API, "_nuclei_ids_for_tag")
    assert "by-tag" in src, (
        "sibling lookup does not use the tag endpoint. /templates/search "
        "matches on FILENAME and returns zero CVE templates for every product "
        "tested, because a CVE template is named CVE-YYYY-NNNN.yaml")


def test_the_sibling_lookup_is_a_query_not_a_dispatch():
    """It sends nothing to a target, so it needs no scope decision.

    The first version shelled `nuclei -tl` through the listener and was
    refused: "out of scope: target 127.0.0.1 is not in the configured scope".
    """
    src = _fsrc(API, "_nuclei_ids_for_tag")
    assert "vectors/run" not in src, (
        "the sibling lookup dispatches through the target runner; it is a "
        "corpus query and will be refused for having no in-scope target")


def test_the_sibling_run_is_bounded():
    api_src = _src(API)
    assert "_KNOWN_GOOD_SIBLINGS" in api_src, "there is no sibling cap"
    probe = _fsrc(API, "_known_good_probe")
    assert "_KNOWN_GOOD_SIBLINGS" in probe, (
        "the probe does not apply the cap, so a product like wordpress (600 "
        "critical/high CVE templates) turns a control experiment into an "
        "estate-wide vulnerability scan")


def test_the_tag_mapper_rejects_non_products():
    """`https`/`server`/`unknown` are not products; matching them is noise."""
    ns = {}
    exec(compile(ast.Module([_func(API, "_nuclei_product_tag")], []), "<t>", "exec"), ns)
    f = ns["_nuclei_product_tag"]
    for junk in ("unknown", "", "https", "server", "linux", None):
        assert f(junk) == "", f"{junk!r} produced a tag"
    for real, want in (("Zabbix", "zabbix"), ("WordPress", "wordpress"),
                       ("Apache httpd", "apache"), ("PHP", "php")):
        assert f(real) == want, f"{real!r} -> {f(real)!r}, expected {want!r}"


def test_the_runner_endpoint_exists_and_caps():
    src = _fsrc(RUNNER, "templates_by_tag")
    assert "limit" in src, "the corpus endpoint has no limit parameter"
    assert "/cves/" in src, (
        "the endpoint does not restrict to CVE templates; a detection panel "
        "is not evidence of a FAULT")


# ── the result reaches synthesis ──────────────────────────────────────────────

def test_the_probe_is_wired_into_the_graph():
    src = _src(GRAPH)
    assert "_known_good_probe" in src, "the graph never calls the probe"
    node = _fsrc(GRAPH, "node_research")
    assert "_known_good" in node, "node_research does not collect the result"
    # LangGraph propagates only through the RETURN
    rets = [n for n in ast.walk(_func(GRAPH, "node_research")) if isinstance(n, ast.Return)]
    assert rets, "node_research has no return"
    assert '"known_good"' in node, (
        "the result is not carried on the return, so assigning it to `state` "
        "would be silently discarded and synthesis would never see it")


def test_known_good_is_declared_on_the_state():
    tree = ast.parse(_src(GRAPH))
    fields = {n.target.id for cls in ast.walk(tree)
              if isinstance(cls, ast.ClassDef) and cls.name == "BuildPocState"
              for n in cls.body
              if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name)}
    assert "known_good" in fields, (
        "BuildPocState has no known_good field, so LangGraph drops it between "
        f"nodes. Declared: {sorted(fields)[:8]}...")


def test_a_template_hit_reaches_synthesis():
    """The whole point. A fact gathered and not read is worth nothing — the
    `input_field = listingfields` lesson."""
    src = _fsrc(GRAPH, "node_assemble_guidance")
    assert "known_good" in src, (
        "the guidance assembly never reads known_good, so a template that "
        "fired stays in the trace while synthesis guesses")
    assert "kg_guidance" in src
    i_kg = src.find("kg_guidance = (")
    assert i_kg > 0, "kg_guidance is never built"
    # BOTH composition branches must prepend it. `node_assemble_guidance` has
    # an if/else on recon_guidance, and sabotaging only the first branch left
    # this test passing because it found the name in the second — the "both
    # call sites counted" lesson from the assertion-drift guard.
    uses = src.count("kg_guidance + hint_guidance")
    assert uses >= 2, (
        f"kg_guidance is prepended on {uses} of the 2 composition paths; a "
        "build taking the other path would never see the evidence")


@pytest.mark.parametrize("state,expect_empty", [
    ({"known_good": {"hit": [{"template": "CVE-2024-3408"}], "evidence": "x"},
      "cve": "CVE-2024-3408"}, False),
    ({"known_good": {"hit": [], "evidence": ""}, "cve": "CVE-X"}, True),
    ({"cve": "CVE-X"}, True),
])
def test_the_guidance_block_renders(state, expect_empty):
    """Silent when there is nothing to say, loud when a template fired."""
    seg = _fsrc(GRAPH, "node_assemble_guidance")
    start = seg.index('    kg = state.get("known_good")')
    end = seg.index("    if recon_guidance:")
    block = "\n".join(l[4:] if l.startswith("    ") else l
                      for l in seg[start:end].split("\n"))
    ns = {"state": state}
    exec(block, ns)
    got = ns["kg_guidance"]
    if expect_empty:
        assert got == "", f"expected nothing prepended, got {got[:80]!r}"
    else:
        assert "KNOWN-GOOD EVIDENCE" in got
        assert "CVE-2024-3408" in got
