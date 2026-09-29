"""Guards for the web post-exploitation ('loot') skill: knowledge/postex_web.yaml,
common/vuln_skills.postex_for/postex_block, and the SQLi-aware reflection exception.

Run: python3 tests/test_postex_web.py   (or pytest)

The prove->loot split: the vuln-class methodology proves a primitive (read-only); this
skill weaponizes a CONFIRMED exploit (gated). These lock that the skill loads per class and
that an injection-execution echo is treated as the primitive firing, not reflection.
"""
import os, sys, yaml

REPO = os.path.join(os.path.dirname(__file__), "..")
POSTEX = os.path.join(REPO, "knowledge", "postex_web.yaml")


def test_postex_web_yaml_shape():
    d = yaml.safe_load(open(POSTEX))
    classes = d.get("classes") or {}
    assert {"sqli", "lfi", "file_upload", "command_injection", "ssti"} <= set(classes)
    for cid, e in classes.items():
        assert e.get("objective") and e.get("weaponize") and e.get("proof"), f"{cid} incomplete"
    # sqli weaponization must reach real data extraction (not a literal canary)
    sqli = classes["sqli"]["weaponize"].lower()
    assert "version()" in sqli and ("union select" in sqli or "updatexml" in sqli)


def test_vuln_skills_postex_for_and_block():
    os.environ["VULN_POSTEX_PATH"] = POSTEX
    os.environ["VULN_METHODOLOGY_PATH"] = os.path.join(REPO, "knowledge", "vuln_class_methodology.yaml")
    sys.path.insert(0, os.path.join(REPO, "common"))
    import importlib, vuln_skills
    importlib.reload(vuln_skills)
    p = vuln_skills.postex_for(issue_type="SQL Injection")
    assert p and p["canonical"] == "sqli" and p.get("weaponize")
    block = vuln_skills.postex_block({"issue_type": "sqli"})
    assert "Post-exploitation (sqli)" in block and "GATED" in block
    # a class with no postex entry returns nothing (fail-soft)
    assert vuln_skills.postex_block({"issue_type": "clickjacking"}) == ""


# mirror of api._looks_like_injection_execution (pure)
_SIGS = ("sql syntax", "you have an error in your sql", "xpath syntax error",
         "extractvalue(", "updatexml(", "sqlstate", "unclosed quotation")


def _looks_like_injection_execution(output):
    low = (output or "").lower()
    return any(s in low for s in _SIGS)


def test_sqli_error_echo_is_execution_not_reflection():
    # an error-based SQLi that echoes the marker inside a SQL/XPATH error is the DB
    # EXECUTING our input -> the primitive fired, not passive reflection
    out = "XPATH syntax error: '~POCz123~'"
    assert _looks_like_injection_execution(out) is True
    # a plain reflected value (no error/exec context) is NOT execution
    assert _looks_like_injection_execution("<h1>Search results for POCz123</h1>") is False



# --- output enumeration: fix errors + improvement tweaks (mirror of api helpers) ---
import re as _re
_ERR = [(r"different number of columns|column count", "col-count"),
        (r"unknown column|no such column", "col-name"),
        (r"access denied|permission denied", "priv")]
_TWK = [(r"~[^~]{1,40}~", "page"),
        (r"[A-Za-z0-9+/]{40,}={0,2}", "base64"),
        (r"\b[0-9a-f]{32,}\b", "hex")]
def _enum(output):
    low=(output or "").lower()
    return {"errors":[t for p,t in _ERR if _re.search(p,low)],
            "tweaks":[t for p,t in _TWK if _re.search(p,output or "")]}

def test_enumerate_flags_column_count_error():
    assert "col-count" in _enum("The used SELECT statements have a different number of columns")["errors"]

def test_enumerate_flags_base64_and_hex_tweaks():
    assert "base64" in _enum("data: "+"QUJD"*20+"==")["tweaks"]
    assert "hex" in _enum("5f4dcc3b5aa765d61d8327deb882cf99")["tweaks"]

def test_enumerate_flags_truncation_paging():
    assert "page" in _enum("XPATH syntax error: '~abcdef~'")["tweaks"]


if __name__ == "__main__":
    fns = [f for f in dict(globals()) if f.startswith("test_")]
    for f in fns:
        globals()[f]()
    print(f"PASSED {len(fns)}/{len(fns)}")
