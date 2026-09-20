"""Guard: Active Directory attack methodology YAML + RAG (OCD mindmap ingest)."""
from pathlib import Path
import pytest
ROOT = Path(__file__).resolve().parents[1]
yaml = pytest.importorskip("yaml")


def _ad():
    return yaml.safe_load((ROOT / "knowledge/ad_attacks.yaml").read_text())["ad_attacks"]


def test_structure_and_required_fields():
    d = _ad()
    assert "mindmap" in d.get("source", "").lower()
    phases = d["phases"]
    assert len(phases) >= 6
    techniques = [t for ph in phases for t in ph.get("techniques", [])]
    assert len(techniques) >= 30
    for t in techniques:
        assert t.get("name") and t.get("tool") and t.get("command")
        assert t.get("tier") in ("safe", "impactful")
        assert t.get("mitre")


def test_key_techniques_present():
    names = {t["name"].lower() for ph in _ad()["phases"] for t in ph.get("techniques", [])}
    for k in ("kerberoasting", "as-rep roasting", "dcsync (dump krbtgt / all hashes)",
              "golden ticket", "pass-the-hash"):
        assert any(k in n for n in names), f"missing {k}"


def test_dangerous_techniques_are_impactful():
    """Ticket forging, DCSync, skeleton key, relay, spray must be approval-gated."""
    by = {t["name"].lower(): t for ph in _ad()["phases"] for t in ph.get("techniques", [])}
    for n, t in by.items():
        if any(k in n for k in ("golden ticket", "silver ticket", "dcsync", "skeleton key",
                                 "ntlm relay", "pass-the-hash", "password spray", "dcshadow")):
            assert t["tier"] == "impactful", f"{n} must be impactful"


def test_readonly_enum_is_safe():
    by = {t["name"].lower(): t for ph in _ad()["phases"] for t in ph.get("techniques", [])}
    for n, t in by.items():
        if any(k in n for k in ("bloodhound collection", "enumerate vulnerable templates",
                                "kerberoasting", "as-rep roasting")):
            assert t["tier"] == "safe", f"{n} should be safe (read-only-ish)"


def test_renderer_registered():
    s = (ROOT / "etl/load_knowledge_documents.py").read_text()
    assert "_render_ad_attacks" in s and '"ad_attacks": _render_ad_attacks' in s


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
