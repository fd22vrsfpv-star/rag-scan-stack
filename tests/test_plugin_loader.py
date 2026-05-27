"""
Unit tests for plugin discovery, validation, and conflict resolution.
"""
import json
import os
import tempfile
from pathlib import Path

import pytest

from utils.plugin_loader import (
    discover_plugins_from_dir,
    register_discovered_plugins,
    clear_specs,
    get_enabled_specs,
)


def _write_plugin(dirpath: Path, name: str, version: str, enabled: bool, code: str, manifest_extra: dict | None = None):
    """
    Helper to write a plugin subdir with plugin.py and manifest.json.
    """
    pdir = dirpath / name
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "plugin.py").write_text(code)
    manifest = {
        "name": name,
        "version": version,
        "enabled": enabled,
        "module": "plugin.py",
        "entry": "run",
        "capabilities": {"services": ["^dummy$"], "banners": [], "ports": [], "artifacts": ["x"]},
        "limits": {"concurrency": 1},
    }
    if manifest_extra:
        manifest.update(manifest_extra)
    (pdir / "manifest.json").write_text(json.dumps(manifest))
    return pdir


def test_bad_manifest_rejected():
    """
    Missing required fields or invalid semver should be reported as errors.
    """
    clear_specs()
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        # Missing name
        bad = base / "bad"
        bad.mkdir()
        (bad / "manifest.json").write_text(json.dumps({"version": "1.0.0", "enabled": True, "module": "plugin.py", "capabilities": {"artifacts": []}}))
        res = discover_plugins_from_dir(td)
        assert res["errors"], "Expected errors for bad manifest"
        registered = register_discovered_plugins(res["specs"])
        assert not registered["registered"]  # nothing valid to register


def test_conflict_resolution_prefers_newer_version():
    """
    Two manifests with the same name: the newer semantic version should win.
    """
    clear_specs()
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        code = "async def run(host, port, proto, context):\n    return {'findings':[{'plugin':'p','title':'ok'}]}"
        _write_plugin(base, "p", "1.0.0", True, code)
        # Another copy with higher version
        _write_plugin(base, "p_v2", "1.2.0", True, code, manifest_extra={"name": "p"})
        res = discover_plugins_from_dir(td)
        assert not res["errors"]
        reg = register_discovered_plugins(res["specs"])
        assert "p" in reg["registered"]
        specs = get_enabled_specs()
        assert specs["p"].version == "1.2.0"


def test_disabled_plugin_skipped_but_kept_in_specs():
    """
    Disabled plugins should not be registered but remain in metadata registry.
    """
    clear_specs()
    with tempfile.TemporaryDirectory() as td:
        base = Path(td)
        code = "async def run(host, port, proto, context):\n    return {'findings':[{'plugin':'p','title':'ok'}]}"
        _write_plugin(base, "q", "0.1.0", False, code)
        res = discover_plugins_from_dir(td)
        reg = register_discovered_plugins(res["specs"])
        assert "q" in reg["skipped"]
        assert "q" not in reg["registered"]
        specs = get_enabled_specs()
        assert "q" not in specs  # not enabled
