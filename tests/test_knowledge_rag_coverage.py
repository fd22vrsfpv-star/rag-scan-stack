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
    # etl/load_knowledge_documents.py renders each of these into rag_documents
    # (source=knowledge_<stem>); POST /rag/knowledge/sync runs it.
    "service_tools.yaml": "etl/load_knowledge_documents.py",
    "credential_followups.yaml": "etl/load_knowledge_documents.py",
    "default_credentials.yaml": "etl/load_knowledge_documents.py",
    "service_access_methods.yaml": "etl/load_knowledge_documents.py",
    "cloud_scan_rules.yaml": "etl/load_knowledge_documents.py",
    "port_profiles.yaml": "etl/load_knowledge_documents.py",
    "scan_parameters.yaml": "etl/load_knowledge_documents.py",
    "tool_options.yaml": "etl/load_knowledge_documents.py",
    "web_profiles.yaml": "etl/load_knowledge_documents.py",
}

# YAMLs deliberately NOT embedded into rag_documents. Each needs a reason. This
# list is meant to stay small — a new knowledge file that defines scans/actions
# belongs in RAG_LOADED, not here.
RAG_LOAD_DEBT = {
    "wstg_map.yaml":
        "WSTG finding->test guidance is already retrievable from exploit_chunks "
        "via get_wstg_guidance (a separate embedded corpus), so re-embedding it "
        "into rag_documents would duplicate the same knowledge under two sources.",
    "wstg_coverage_map.yaml":
        "WSTG coverage matrix backing the same exploit_chunks-served guidance as "
        "wstg_map.yaml; retrievable there, not duplicated into rag_documents.",
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
