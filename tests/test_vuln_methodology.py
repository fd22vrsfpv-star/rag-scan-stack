"""Vuln-class methodology "skills": loader, injection, and drift guards.

Run standalone:

    pytest tests/test_vuln_methodology.py -v

WHY THIS EXISTS
---------------
`knowledge/vuln_class_methodology.yaml` + `common/vuln_skills.py` feed per-class
methodology into the exploit-building prompts (web payload gen/refine and the test
synthesizer). These guards pin the contract: the loader resolves real finding
signals to a class, the authored fields stay within the prompt-budget caps, the
web classes all carry a hint, and the two injection helpers are ON by default and
turn OFF only under an explicit 0/false/off flag.

SABOTAGE PROOF
--------------
Blank a class's `web_hint` in the YAML and `test_web_classes_have_hint` fails;
grow a field past its cap and `test_field_caps` fails; unset the flag handling and
the injection tests fail.
"""
import importlib
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_YAML = os.path.join(REPO, "knowledge", "vuln_class_methodology.yaml")

# Point the loader at the repo copy (its default is the container mount /knowledge).
os.environ.setdefault("VULN_METHODOLOGY_PATH", _YAML)

try:
    from common import vuln_skills
except Exception as e:  # noqa: BLE001
    pytest.skip(f"common.vuln_skills not importable: {e}", allow_module_level=True)

# The 8 web classes the payload generator/refiner will look up (must have a hint).
WEB_CLASSES = {"xss", "sqli", "command_injection", "ssrf", "lfi",
               "open_redirect", "csrf", "xxe"}
LOGIC_CLASSES = {"idor", "business_logic", "ssti"}


@pytest.fixture(autouse=True)
def _fresh_cache():
    """Reset the module cache + path around each test so path swaps take effect."""
    vuln_skills._MAP_PATH = os.environ["VULN_METHODOLOGY_PATH"]
    vuln_skills._cache = None
    vuln_skills._cache_mtime = 0.0
    yield
    vuln_skills._MAP_PATH = _YAML
    vuln_skills._cache = None
    vuln_skills._cache_mtime = 0.0


def test_all_expected_classes_present():
    ids = set(vuln_skills.load_pack().get("classes", {}))
    missing = (WEB_CLASSES | LOGIC_CLASSES) - ids
    assert not missing, f"methodology file is missing classes: {sorted(missing)}"


def test_web_classes_have_hint():
    for cid in WEB_CLASSES:
        entry = vuln_skills.get(cid) or {}
        assert (entry.get("web_hint") or "").strip(), (
            f"web class {cid} has no web_hint — the web generator/refiner would "
            f"inject nothing for it")


def test_all_classes_have_synth_methodology():
    for cid in WEB_CLASSES | LOGIC_CLASSES:
        entry = vuln_skills.get(cid) or {}
        assert (entry.get("synth_methodology") or "").strip(), (
            f"class {cid} has no synth_methodology")


def test_field_caps():
    for cid, entry in vuln_skills.load_pack().get("classes", {}).items():
        assert len(entry.get("web_hint") or "") <= 700, f"{cid} web_hint > 700"
        assert len(entry.get("synth_methodology") or "") <= 1500, \
            f"{cid} synth_methodology > 1500"


def test_canonical_ids_resolve_to_themselves():
    for cid in WEB_CLASSES | LOGIC_CLASSES:
        assert vuln_skills.resolve(issue_type=cid) == cid


@pytest.mark.parametrize("signals,expected", [
    ({"issue_type": "SQL Injection"}, "sqli"),
    ({"issue_type": "sqli_dump"}, "sqli"),            # wstg_map id alias
    ({"cwe": "CWE-89"}, "sqli"),
    ({"issue_type": "Reflected XSS"}, "xss"),
    ({"issue_type": "xss_reflected"}, "xss"),         # wstg_map id alias
    ({"nuclei_tags": ["xss"]}, "xss"),                # nuclei tag -> nuclei:xss
    ({"cwe": ["CWE-79"]}, "xss"),                     # cwe as list
    ({"issue_type": "os-command-injection"}, "command_injection"),
    ({"cwe": "CWE-918"}, "ssrf"),
    ({"issue_type": "path traversal"}, "lfi"),
    ({"issue_type": "directory-traversal"}, "lfi"),
    ({"cwe": "CWE-601"}, "open_redirect"),
    ({"name": "Cross-Site Request Forgery on transfer"}, "csrf"),
    ({"issue_type": "XML External Entity"}, "xxe"),
    ({"name": "Broken Object Level Authorization"}, "idor"),
    ({"issue_type": "server-side template injection"}, "ssti"),
])
def test_representative_signals_resolve(signals, expected):
    assert vuln_skills.resolve(**signals) == expected


def test_unknown_returns_none():
    assert vuln_skills.resolve(issue_type="totally-unknown-thing") is None
    assert vuln_skills.resolve() is None
    assert vuln_skills.match(issue_type="nope") is None


def test_code_like_alias_does_not_substring_match():
    # "cwe-89" / "nuclei:xss" must match only exactly, never as a substring inside
    # free text, or a finding name mentioning a CWE could mis-route.
    assert vuln_skills.resolve(name="see cwe-89 in the report") is None


def test_match_shape():
    m = vuln_skills.match(issue_type="sqli")
    assert m and m["canonical"] == "sqli"
    assert m["web_hint"] and m["synth_methodology"]


def test_mtime_reload(tmp_path):
    f = tmp_path / "m.yaml"
    f.write_text("version: 1\nclasses:\n  foo:\n    web_hint: A\n    synth_methodology: B\n")
    vuln_skills._MAP_PATH = str(f)
    vuln_skills._cache = None
    assert vuln_skills.resolve(issue_type="foo") == "foo"
    # rewrite with a different class + bumped mtime; loader must pick it up
    f.write_text("version: 2\nclasses:\n  bar:\n    web_hint: A\n    synth_methodology: B\n")
    os.utime(str(f), (f.stat().st_atime + 10, f.stat().st_mtime + 10))
    assert vuln_skills.resolve(issue_type="bar") == "bar"
    assert vuln_skills.resolve(issue_type="foo") is None


def test_enabled_default_on():
    import os as _os
    _os.environ.pop("X_METHOD_FLAG", None)
    assert vuln_skills.enabled("X_METHOD_FLAG") is True   # absent -> on by default
    for v, exp in [("1", True), ("true", True), ("on", True), ("yes", True),
                   ("0", False), ("false", False), ("off", False),
                   ("no", False), ("", False)]:
        _os.environ["X_METHOD_FLAG"] = v
        assert vuln_skills.enabled("X_METHOD_FLAG") is exp, (v, exp)
    _os.environ.pop("X_METHOD_FLAG", None)


# ── injection blocks (import-light logic in common — always run in-tier) ──────
def test_web_block_default_on_and_off(monkeypatch):
    monkeypatch.delenv("WEB_METHODOLOGY", raising=False)     # absent -> ON
    b = vuln_skills.web_block("sqli")
    assert b.startswith("\nMethodology (sqli)") and len(b) <= 760
    monkeypatch.setenv("WEB_METHODOLOGY", "0")               # explicit off
    assert vuln_skills.web_block("sqli") == ""
    monkeypatch.setenv("WEB_METHODOLOGY", "1")
    assert "Methodology (sqli)" in vuln_skills.web_block("sqli")
    assert vuln_skills.web_block("totally-unknown") == ""    # on, no class -> ""


def test_synth_block_prepends_and_respects_flag(monkeypatch):
    finding = {"issue_type": "sqli", "cwe": "CWE-89", "name": "SQLi"}
    monkeypatch.delenv("SYNTH_METHODOLOGY", raising=False)   # absent -> ON
    out = vuln_skills.synth_block("WSTG-PROSE", finding)
    assert out.startswith("=== Methodology (sqli) ===") and "WSTG-PROSE" in out
    monkeypatch.setenv("SYNTH_METHODOLOGY", "off")           # explicit off
    assert vuln_skills.synth_block("WSTG-PROSE", finding) == "WSTG-PROSE"
    monkeypatch.setenv("SYNTH_METHODOLOGY", "1")
    assert vuln_skills.synth_block("X", {"issue_type": "nope"}) == "X"  # no class -> unchanged


def test_synth_block_survives_caller_cap(monkeypatch):
    # methodology must PRECEDE large WSTG prose so a downstream [:3500] cap keeps it
    monkeypatch.setenv("SYNTH_METHODOLOGY", "1")
    out = vuln_skills.synth_block("W" * 5000, {"issue_type": "sqli"})
    assert out[:3500].startswith("=== Methodology (sqli) ===")


def test_synth_block_handles_bad_finding(monkeypatch):
    monkeypatch.setenv("SYNTH_METHODOLOGY", "1")
    assert vuln_skills.synth_block("G", None) == "G"    # not a dict -> unchanged
    assert vuln_skills.synth_block("G", {}) == "G"


# ── injection helpers (skip cleanly when a container-only dep is absent) ──────
def test_web_methodology_block_flagged(monkeypatch):
    pytest.importorskip("httpx")
    try:
        wpg = importlib.import_module("exploit_runner.web_payload_generator")
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"web_payload_generator not importable here: {e}")
    monkeypatch.setenv("VULN_METHODOLOGY_PATH", _YAML)
    vuln_skills._MAP_PATH = _YAML
    vuln_skills._cache = None
    monkeypatch.delenv("WEB_METHODOLOGY", raising=False)   # absent -> ON by default
    block = wpg._methodology_block("sqli")
    assert "Methodology (sqli)" in block and len(block) <= 760
    monkeypatch.setenv("WEB_METHODOLOGY", "0")             # explicit off disables
    assert wpg._methodology_block("sqli") == ""
    monkeypatch.setenv("WEB_METHODOLOGY", "1")
    assert "Methodology (sqli)" in wpg._methodology_block("sqli")
    assert wpg._methodology_block("totally-unknown") == ""


def test_synth_prepend_methodology_flagged(monkeypatch):
    try:
        ts = importlib.import_module("test_synth")
    except Exception:
        try:
            ts = importlib.import_module("autogen_agents.test_synth")
        except Exception as e:  # noqa: BLE001
            pytest.skip(f"test_synth not importable here (autogen-only deps): {e}")
    monkeypatch.setenv("VULN_METHODOLOGY_PATH", _YAML)
    vuln_skills._MAP_PATH = _YAML
    vuln_skills._cache = None
    finding = {"issue_type": "sqli", "name": "SQLi", "cwe": "CWE-89"}
    monkeypatch.delenv("SYNTH_METHODOLOGY", raising=False)   # absent -> ON by default
    out = ts._prepend_methodology("WSTG-PROSE", finding)
    assert out.startswith("=== Methodology (sqli) ==="), "must prepend, not append"
    assert "WSTG-PROSE" in out
    monkeypatch.setenv("SYNTH_METHODOLOGY", "0")             # explicit off disables
    assert ts._prepend_methodology("WSTG-PROSE", finding) == "WSTG-PROSE"
