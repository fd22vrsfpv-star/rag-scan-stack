"""Guard: content-discovery tool selection (1 of 3) + custom-attack RAG recipes."""
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]
yaml = pytest.importorskip("yaml")


def _cfg():
    return yaml.safe_load((ROOT / "knowledge/content_discovery.yaml").read_text())


def _src(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_yaml_selection_and_default():
    cd = _cfg()["content_discovery"]
    assert cd["default_tool"] == "gobuster"
    assert set(cd["tools"]) == {"gobuster", "ffuf", "feroxbuster"}
    assert cd["setting_key"] == "content_discovery.tool"
    # feroxbuster must filter the reserved-name noise
    assert "--filter-size 0" in cd["tools"]["feroxbuster"]["template"]
    # each tool injects the session cookie
    for t in cd["tools"].values():
        assert "{cookie}" in t["cookie_flag"]


def test_custom_attack_recipes_present():
    d = _cfg()
    recipes = d["custom_attacks"]
    names = [r["name"] for r in recipes]
    assert any("parameter" in n for n in names)
    assert any("vhost" in n or "virtual-host" in n for n in names)
    assert any("login" in n or "brute" in n for n in names)
    # a state-changing recipe must be marked impactful (approval-gated)
    assert any(r.get("impactful") for r in recipes)
    # every recipe carries a command template + wstg
    for r in recipes:
        assert r.get("template") and r.get("tool")


def test_directory_followup_selects_tool():
    s = _src("etl/directory_followup.py")
    assert "def _select_content_tool(" in s and "def _build_content_command(" in s
    assert "_build_content_command(_tool" in s
    # dispatch uses the selected tool name (not hardcoded gobuster)
    assert 'json={"tool": _tool,' in s


def test_renderer_emits_selection_and_recipes():
    s = _src("etl/load_knowledge_documents.py")
    assert "_render_content_discovery" in s
    assert '"content_discovery": _render_content_discovery' in s
    assert "custom_attacks" in s


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
