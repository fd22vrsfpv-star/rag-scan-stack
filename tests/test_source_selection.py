"""Knowledge-source selector: skill | rag | yaml | all.

Run standalone:  pytest tests/test_source_selection.py -v

Guards the source-aware synthesis: the deterministic YAML spec builds from a WSTG
map entry with NO LLM, and `apply_skill=False` suppresses the skill source. Imports
are autogen-container-only, so this skips cleanly elsewhere.
"""
import os
import sys
import importlib

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for d in ("autogen_agents",):
    p = os.path.join(REPO, d)
    if p not in sys.path:
        sys.path.insert(0, p)
os.environ.setdefault("VULN_METHODOLOGY_PATH",
                      os.path.join(REPO, "knowledge", "vuln_class_methodology.yaml"))


def test_yaml_spec_is_deterministic():
    try:
        svc = importlib.import_module("autogen_service")
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"autogen_service not importable here: {e}")
    entry = {"wstg_id": "WSTG-INPV-05", "tool": "nuclei", "category": "sqli_detect",
             "tier": "safe", "command_rendered": "nuclei -u http://x -tags sqli",
             "assertion": {"expect_regex": "sqli"}}
    spec = svc._yaml_spec(entry, {"issue_type": "sqli"})
    assert spec and spec["tool"] == "nuclei"
    assert spec["command"] == "nuclei -u http://x -tags sqli"
    assert spec["metadata"]["knowledge_source"] == "yaml"
    assert svc._yaml_spec({}, {"issue_type": "sqli"}) is None  # no command -> None


def test_apply_skill_gate():
    try:
        ts = importlib.import_module("test_synth")
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"test_synth not importable here: {e}")
    captured = {}
    class _R:
        content = ('{"tool":"curl","command":"curl -s http://x","category":"http_probe",'
                   '"tier":"safe","assertion":{"expect_substring":"x"},"rationale":"t"}')
    class _Fake:
        def invoke(self, prompt):
            captured["p"] = prompt
            return _R()
    ts._chat_model = lambda: _Fake()
    os.environ["SYNTH_METHODOLOGY"] = "1"
    finding = {"issue_type": "sqli", "cwe": "CWE-89", "name": "SQLi"}
    ts.synthesize(finding, "WSTG", apply_skill=False)
    assert "=== Methodology" not in captured["p"], "apply_skill=False must suppress skill"
    ts.synthesize(finding, "WSTG", apply_skill=True)
    assert "=== Methodology (sqli) ===" in captured["p"], "apply_skill=True must prepend skill"
