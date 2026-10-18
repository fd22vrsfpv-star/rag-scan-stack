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
import ast
import os
import glob

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KNOWLEDGE = os.path.join(REPO, "knowledge")

RENDERER_LOADER = "etl/load_knowledge_documents.py"


def _renderer_covered_yamls():
    """YAML stems the RENDERERS registry actually renders, DERIVED from the
    loader source via ast.

    This used to be a hand-copied list of 23 filenames that mirrored RENDERERS
    exactly. Mirroring a registry by hand is drift waiting to happen: the list
    and the registry can disagree, and every new knowledge file needed an edit
    here that is pure toil (four were added in one session). Deriving it keeps
    the guard's teeth — a YAML with no renderer is still undeclared and still
    fails — while removing the bookkeeping.
    """
    src = open(os.path.join(REPO, RENDERER_LOADER), encoding="utf-8").read()
    for node in ast.walk(ast.parse(src)):
        if (isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "RENDERERS" for t in node.targets)
                and isinstance(node.value, ast.Dict)):
            return {k.value + ".yaml" for k in node.value.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    raise AssertionError(f"RENDERERS registry not found in {RENDERER_LOADER}")


# Loaders that are NOT the renderer registry — one entry each, named explicitly
# because nothing else can derive them.
RAG_LOADED_OTHER = {
    # load_rules() merges enumeration_rules.yaml, and sync_flows_to_rag /
    # _load_flow_into_rag embed every merged flow into rag_documents.
    "enumeration_rules.yaml": "app/rag-api/api.py",
    # Refine-time error patterns + fix guidance: operator-extensible YAML, a
    # dedicated loader embeds (title + guidance) into rag_documents and copies
    # the structured triggers into refine_error_patterns table.
    "refine_error_patterns.yaml": "etl/load_refine_patterns.py",
    "build_poc_research_patterns.yaml": "etl/load_research_patterns.py",
    # Which TOOL answers which build-poc gap. Embedded so the planner can
    # RECALL a tool rather than only match the hardcoded _GAP_SOLUTIONS table —
    # before this, only six step names could ever run and anything RAG or the
    # LLM suggested arrived with step=None and became an operator follow-up.
    "gap_tools.yaml": "etl/load_gap_tools.py",
    # Post-run review criteria: _load_build_poc_review_knowledge embeds each
    # criterion into rag_documents so the review agent can retrieve them.
    "build_poc_review.yaml": "app/rag-api/api.py",
    # CAPEC attack patterns: DIR_RENDERERS["mitre"] -> _render_capec, one
    # document per pattern tagged with the vuln class its CWEs map to.
    "mitre/capec.yaml": "etl/load_knowledge_documents.py",
}

# YAMLs that ARE embedded into rag_documents, mapped to the loader that does it.
# Wiring a new file into RAG via a renderer needs NO edit here.
RAG_LOADED = {
    **{y: RENDERER_LOADER for y in _renderer_covered_yamls()},
    **RAG_LOADED_OTHER,
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

    # --- Subdirectories, surfaced 2026-10-17 when the glob above became
    # recursive. None of these is embedded; all are read deterministically.
    # They are declared, not exempted: the ratchet now SEES them, which is
    # the point. Shrink this list by adding renderers, directory at a time.
    'artifact_rules/builtin.yaml':
        'artifact action rules read by app/rag-api/artifact_actions.py; deterministic lookup only.',
    'detection_rules/builtin.yaml':
        'detection rule read by app/rag-api/rule_engine.py; deterministic lookup only, never embedded into rag_documents.',
    'detection_rules/cloud.yaml':
        'detection rule read by app/rag-api/rule_engine.py; deterministic lookup only, never embedded into rag_documents.',
    'detection_rules/custom/customer_hosted_sites.yaml':
        'operator-authored detection rule read by app/rag-api/rule_engine.py; deterministic lookup only, never embedded.',
    'detection_rules/custom/interesting_files.yaml':
        'operator-authored detection rule read by app/rag-api/rule_engine.py; deterministic lookup only, never embedded.',
    'detection_rules/custom/microburst.yaml':
        'operator-authored detection rule read by app/rag-api/rule_engine.py; deterministic lookup only, never embedded.',
    'detection_rules/custom/scoped_login_detection.yaml':
        'operator-authored detection rule read by app/rag-api/rule_engine.py; deterministic lookup only, never embedded.',
    'detection_rules/custom/security_controls.yaml':
        'operator-authored detection rule read by app/rag-api/rule_engine.py; deterministic lookup only, never embedded.',
    'detection_rules/custom/unified_login_detection.yaml':
        'operator-authored detection rule read by app/rag-api/rule_engine.py; deterministic lookup only, never embedded.',
    'extractors/_classes.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/enum4linux-ng.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/enum4linux.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/feroxbuster.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/ffuf.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/gobuster.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/hydra.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/medusa.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/netexec.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/onesixtyone.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/rpcinfo.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/smbclient.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/smbmap.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/smtp-user-enum.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/snmpwalk.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'extractors/sslscan.yaml':
        "tool-output extractor spec, read deterministically by app/rag-api/extractor_specs.py (SPEC_DIR=/knowledge/extractors) and never embedded. Surfaced 2026-10-17 when this guard's glob was made recursive; the whole directory was invisible to it before.",
    'mitre/attack_map.yaml':
        'MITRE technique map read by app/rag-api/attack_vectors.py as a deterministic lookup table; never embedded into rag_documents.',
    'playbooks/active_directory_attacks.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'playbooks/code_injection.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'playbooks/credential_dumping.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'playbooks/database_methodology.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'playbooks/defense_evasion.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'playbooks/lateral_movement.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'playbooks/metasploitable-2-exploitability-guide.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'playbooks/network_services.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'playbooks/persistence_techniques.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'playbooks/smb_methodology.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'playbooks/ssh_methodology.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'playbooks/web_methodology.yaml':
        'authored playbook, read by etl/playbooks.py. CLAUDE.md names playbooks explicitly as RAG-first knowledge, so this is real debt rather than an exemption — it should be embedded, not just read.',
    'scope_rules/builtin.yaml':
        'scope classification rules read by app/rag-api/scope_classifier.py; deterministic, and authorization-adjacent so it must stay a lookup — but it is still unembedded knowledge.',
    'scope_rules/custom.yaml':
        'scope classification rules read by app/rag-api/scope_classifier.py; deterministic, and authorization-adjacent so it must stay a lookup — but it is still unembedded knowledge.',
    'seed/gtfobins.yaml':
        'seed data imported by scan_recommender rather than embedded; the rules it seeds are embedded on import, the seed file itself is not.',
    'seed/htb-attack-paths.yaml':
        'seed data imported by scan_recommender rather than embedded; the rules it seeds are embedded on import, the seed file itself is not.',
    'seed/htb-web-cheatsheet.yaml':
        'seed data imported by scan_recommender rather than embedded; the rules it seeds are embedded on import, the seed file itself is not.',
    'seed/knowledge-base.yaml':
        'seed data imported by scan_recommender rather than embedded; the rules it seeds are embedded on import, the seed file itself is not.',
    'seed/metasploitable-2-exploitability-guide.yaml':
        'seed data imported by scan_recommender rather than embedded; the rules it seeds are embedded on import, the seed file itself is not.',
    'seed/native-tools-gaps.yaml':
        'seed data imported by scan_recommender rather than embedded; the rules it seeds are embedded on import, the seed file itself is not.',
    'seed/wstg.yaml':
        'seed data imported by scan_recommender rather than embedded; the rules it seeds are embedded on import, the seed file itself is not.',
}


def _knowledge_yamls():
    """Every knowledge YAML, RECURSIVELY, keyed by path relative to knowledge/.

    This globbed `knowledge/*.yaml` only — flat — so eight subdirectories
    escaped the rule entirely: 43 of 90 files were visible, and adding a spec
    under `knowledge/extractors/` raised no failure at all. The guard reported
    green because it could not see the files, which is worse than a known gap.

    Top-level names are unchanged (`relpath` of a top-level file IS its
    basename), so every pre-existing RAG_LOADED / RAG_LOAD_DEBT key still
    matches; subdirectory files now appear as `extractors/ffuf.yaml`.
    """
    files = glob.glob(os.path.join(KNOWLEDGE, "**", "*.yaml"), recursive=True) + \
            glob.glob(os.path.join(KNOWLEDGE, "**", "*.yml"), recursive=True)
    if not files:
        pytest.skip("no knowledge/*.yaml found — repo layout changed?")
    return sorted(os.path.relpath(f, KNOWLEDGE) for f in files)


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
