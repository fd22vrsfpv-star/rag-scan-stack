"""Test-side reader for knowledge/craft_guidance.yaml.

The guidance used to be a dict literal in app/rag-api/api.py and several tests
read it with `ast.literal_eval`. It is data now, so they read the YAML instead.

Duplicate keys are REJECTED rather than silently collapsed. A YAML mapping, like
a Python dict literal, keeps only the last of two identical keys — that is the
exact defect `test_craft_class_guidance_has_no_duplicate_keys` was written for
(a second `cmdi` entry once silently replaced the first), so the guarantee has
to survive the move rather than quietly disappear with it.
"""
from __future__ import annotations

from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PATH = REPO / "knowledge" / "craft_guidance.yaml"


def _loader():
    yaml = pytest.importorskip("yaml")

    class _NoDup(yaml.SafeLoader):
        pass

    def _mapping(loader, node, deep=False):
        keys = [loader.construct_object(k, deep=deep) for k, _ in node.value]
        dupes = sorted({str(k) for k in keys if keys.count(k) > 1})
        if dupes:
            raise ValueError(f"duplicate key(s) {dupes} in {PATH.name}")
        return yaml.SafeLoader.construct_mapping(loader, node, deep)

    _NoDup.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)
    return yaml, _NoDup


def load_guidance() -> dict:
    """{canonical_class: guidance_text}, raising on a duplicate key."""
    if not PATH.exists():
        pytest.fail(f"{PATH} is missing — class guidance has nowhere to live")
    yaml, loader = _loader()
    data = yaml.load(PATH.read_text(encoding="utf-8"), Loader=loader) or {}
    g = data.get("guidance")
    assert isinstance(g, dict) and g, "craft_guidance.yaml has no `guidance` map"
    return {str(k): str(v) for k, v in g.items()}
