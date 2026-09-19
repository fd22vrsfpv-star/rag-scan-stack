"""Safe surface probes are DATA (YAML/RAG), not hardcoded in the engine.

Run on demand:

    pytest tests/test_safe_service_probes_yaml.py -v

WHY THIS EXISTS
---------------
The service-family -> [(category, tool)] safe-probe mapping and the per-tool
default command templates (whatweb/nuclei/gobuster/sslscan/enum4linux-ng/
ssh-audit/snmpwalk/nmap) used to be hardcoded in langgraph_engine
(`_surface_categories_for` and an inline default-command dict). They now live in
knowledge/safe_service_probes.yaml, read at plan time and embedded into
rag_documents by etl/load_knowledge_documents.py — so a probe or default command
can be added/reclassified without a code change (CLAUDE.md "Knowledge is
RAG-first").

SABOTAGE PROOF
--------------
Re-inline the whatweb/nuclei/gobuster default-command dict into the surface
builder, or drop `_load_safe_service_probes()` from `_surface_categories_for`,
and the corresponding case fails.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENGINE = os.path.join(REPO, "autogen_agents", "langgraph_engine.py")
YAML = os.path.join(REPO, "knowledge", "safe_service_probes.yaml")
LOADER = os.path.join(REPO, "etl", "load_knowledge_documents.py")


def _yaml():
    if not os.path.exists(YAML):
        pytest.skip("safe_service_probes.yaml missing")
    import yaml
    return yaml.safe_load(open(YAML, encoding="utf-8")) or {}


def test_yaml_has_the_probe_families_and_commands():
    d = _yaml()
    fams = {f["family"]: f for f in d.get("safe_service_probes", []) if isinstance(f, dict)}
    for fam in ("web", "smb", "ssh", "snmp", "default"):
        assert fam in fams, f"safe_service_probes.yaml missing family {fam}"
    # web family must carry the four read-only web probes, keyed on the _web_family sentinel
    web = fams["web"]
    assert "_web_family" in (web.get("services") or []), "web family must use the _web_family sentinel"
    tools = {p["tool"] for p in web["probes"]}
    assert {"whatweb", "nuclei", "gobuster", "sslscan"} <= tools, f"web probes incomplete: {tools}"
    # every probe carries a concrete command with placeholders (not empty)
    for fam in d["safe_service_probes"]:
        for p in fam.get("probes", []):
            assert p.get("category") and p.get("tool") and p.get("command"), \
                f"incomplete probe in {fam['family']}: {p}"
    # tls_check is TLS-only
    tls = next(p for p in web["probes"] if p["tool"] == "sslscan")
    assert tls.get("tls_only") is True, "sslscan probe must be tls_only"


def test_engine_reads_yaml_not_hardcoded():
    src = open(ENGINE, encoding="utf-8").read()
    tree = ast.parse(src)
    catfn = next((n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "_surface_categories_for"), None)
    assert catfn, "_surface_categories_for not found"
    body = ast.get_source_segment(src, catfn)
    assert "_load_safe_service_probes()" in body, \
        "_surface_categories_for must read the YAML specs, not hardcode the mapping"
    # the old hardcoded (category, tool) tuples must be gone from the function
    assert '("http_probe", "whatweb")' not in body, "hardcoded probe tuples still present"
    assert '("version_probe", "enum4linux-ng")' not in body, "hardcoded smb probe still present"
    # the inline default-command dict must no longer live in the surface builder
    assert 'f"whatweb -a 3 --color=never {scheme}://{ip}:{port}"' not in src, \
        "inline whatweb default command still hardcoded in the surface builder"
    # loader + fallback exist
    assert "def _load_safe_service_probes" in src
    assert "def _safe_probe_default_commands" in src


def test_loader_embeds_the_file_into_rag():
    if not os.path.exists(LOADER):
        pytest.skip("loader missing")
    s = open(LOADER, encoding="utf-8").read()
    assert '"safe_service_probes": _render_safe_service_probes' in s, \
        "safe_service_probes must be wired into RENDERERS so it is embedded into RAG"
    assert "def _render_safe_service_probes" in s
