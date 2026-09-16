"""Knowledge-is-RAG-first ratchet (CLAUDE.md ## In-scope ## Knowledge is RAG-first).

The YAML under `knowledge/` that defines what to scan and what to do next should
be LOADED into the RAG corpus (`rag_documents`) so the planner can retrieve it —
not only read deterministically. This guard makes that direction real: every
`knowledge/*.yaml` must either be embedded by a named loader OR carry a
`RAG_LOAD_DEBT` reason. The debt list ratchets — shrink it as loaders are added,
and a NEW undeclared YAML fails by name so the rule survives a large change.

It does not (and cannot cheaply) prove the embedding runs; it pins the intent so
a new knowledge file cannot silently land read-only. Pair a new loader with the
YAML the way an endpoint ships its test.

    pytest tests/test_knowledge_rag_coverage.py
"""
import os
import glob

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KNOWLEDGE = os.path.join(REPO, "knowledge")

# YAMLs that ARE embedded into rag_documents, mapped to the loader that does it.
# Add here (and remove the RAG_LOAD_DEBT entry) when you wire a file into RAG.
RAG_LOADED = {
    # load_rules() merges enumeration_rules.yaml, and sync_flows_to_rag /
    # _load_flow_into_rag embed every merged flow into rag_documents.
    "enumeration_rules.yaml": "app/rag-api/api.py",
}

# YAMLs read deterministically but not yet embedded into RAG. Each needs a reason,
# and the list is meant to SHRINK — the CLAUDE.md direction is to load these too.
RAG_LOAD_DEBT = {
    "service_tools.yaml":
        "per-service tool/module/nuclei mapping, read by scan_recommender/tool_kb.py; "
        "load into rag_documents so the planner can recall per-service tooling.",
    "credential_followups.yaml":
        "credential-reuse follow-up commands, read by etl/credential_followups.py; "
        "embed so 'what to do with a valid credential' is retrievable.",
    "default_credentials.yaml":
        "default credential sets for brutus; embed so the planner can recall "
        "which defaults to try per service.",
    "service_access_methods.yaml":
        "how to turn a service into access; embed so access methods are retrievable.",
    "cloud_scan_rules.yaml":
        "cloud-resource scan rules; embed so cloud follow-ups are retrievable.",
    "port_profiles.yaml":
        "port -> scan profile mapping; embed so profile choice can be recalled.",
    "scan_parameters.yaml":
        "per-scan tuning parameters; embed so parameter choices are retrievable.",
    "tool_options.yaml":
        "per-tool flag catalogue; embed so option guidance is retrievable.",
    "web_profiles.yaml":
        "web-scan profiles; embed so web profile choice can be recalled.",
    "wstg_map.yaml":
        "WSTG finding->test map; the WSTG guidance is served from exploit_chunks "
        "today (get_wstg_guidance), a separate corpus — fold into rag_documents "
        "or leave as the deliberate exception once decided.",
    "wstg_coverage_map.yaml":
        "WSTG coverage matrix; same exploit_chunks exception as wstg_map.yaml.",
    # Example/seed material, not live knowledge — kept out of RAG on purpose but
    # declared so a rename or a real file added here is not silently exempt.
    "seed_prompts.example.yaml":
        "EXAMPLE seed file for import-knowledge.sh, not live knowledge; the rules "
        "it seeds are embedded when imported, not the example itself.",
}


def _knowledge_yamls():
    files = glob.glob(os.path.join(KNOWLEDGE, "*.yaml")) + \
            glob.glob(os.path.join(KNOWLEDGE, "*.yml"))
    if not files:
        pytest.skip("no knowledge/*.yaml found — repo layout changed?")
    return sorted(os.path.basename(f) for f in files)


def test_every_knowledge_yaml_is_loaded_or_declared_debt():
    names = set(_knowledge_yamls())
    classified = set(RAG_LOADED) | set(RAG_LOAD_DEBT)
    undeclared = sorted(names - classified)
    assert not undeclared, (
        "these knowledge/*.yaml are neither embedded into rag_documents nor "
        "declared as RAG_LOAD_DEBT:\n  " + "\n  ".join(undeclared) +
        "\n\nAdd a loader that embeds it into rag_documents (see CLAUDE.md "
        "'Knowledge is RAG-first') and list it in RAG_LOADED, or add a "
        "RAG_LOAD_DEBT entry with a reason. Do not leave new knowledge read-only.")


def test_loaded_entries_point_at_a_real_loader_that_writes_rag_documents():
    for yaml_name, loader_rel in RAG_LOADED.items():
        path = os.path.join(REPO, loader_rel)
        assert os.path.exists(path), f"RAG_LOADED[{yaml_name}] loader missing: {loader_rel}"
        src = open(path, encoding="utf-8", errors="replace").read()
        assert "rag_documents" in src, (
            f"RAG_LOADED[{yaml_name}] -> {loader_rel} never writes rag_documents — "
            "it does not actually embed the knowledge")


def test_debt_and_loaded_are_disjoint():
    both = set(RAG_LOADED) & set(RAG_LOAD_DEBT)
    assert not both, f"a file is both loaded and debt: {sorted(both)}"


def test_debt_entries_reference_real_files_and_carry_a_reason():
    present = set(_knowledge_yamls())
    for yaml_name, why in RAG_LOAD_DEBT.items():
        assert yaml_name in present, f"RAG_LOAD_DEBT names a missing file: {yaml_name}"
        assert why and len(why) > 20, f"{yaml_name} needs a real reason, got {why!r}"
