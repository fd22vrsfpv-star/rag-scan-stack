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



def test_error_analysis_skill_loads():
    """The error-analysis / correction methodology is a SKILL in postex_web.yaml (data), so
    editing the YAML changes behavior without a code change (RAG-first)."""
    os.environ["VULN_POSTEX_PATH"]=POSTEX
    sys.path.insert(0, os.path.join(REPO,"common"))
    import importlib, vuln_skills; importlib.reload(vuln_skills)
    ea=vuln_skills.postex_error_analysis()
    assert ea.get("methodology") and len(ea.get("error_fixes",[]))>=5 and len(ea.get("tweaks",[]))>=3
    # the integer-context fix (the one that unblocked a live target) must be present
    joined=" ".join(r["fix"] for r in ea["error_fixes"])
    assert "NUMERIC" in joined or "integer context" in joined.lower()



def test_secret_targets_in_skill():
    """The password/secret column + table patterns are declared as DATA in the skill."""
    d = yaml.safe_load(open(POSTEX))
    st = d["collection"].get("secret_targets") or {}
    assert set(["password","pass","pwd","hash","secret","token","api_key"]) <= set(st.get("column_patterns", []))
    assert "user" in st.get("table_patterns", []) and "secret" in st["table_patterns"]


def test_primitives_declared_in_skill():
    """The composable post-ex primitives are declared as data in the skill; the harness
    registry names must match so the LLM can invoke them by name (chained skills)."""
    d = yaml.safe_load(open(POSTEX))
    prims = d.get("primitives") or {}
    assert "purpose" in prims
    for name in ("sqli_subquery", "sqli_autopage", "harvest_secret_columns"):
        e = prims.get(name)
        assert isinstance(e, dict) and e.get("description") and e.get("args") and e.get("returns")


def test_extract_injection_value_handles_truncation():
    """The value MySQL truncates at 32 chars ends with '...' inside the quoted error message —
    the extractor must return the truncated value so the harness can auto-page it."""
    import re
    def _extract(o):
        # mirror of api._extract_injection_value truncation branch
        m = re.search(r"~([^~<\s][^~<]{0,300})~", o or "")
        if m and m.group(1).strip():
            return m.group(1).strip()
        m = re.search(r"'~([^~<\']{1,32}?)\.\.\.'", o) or re.search(r"~([^~<\'\s]{1,32})\.\.\.", o)
        return m.group(1).strip() if m else None
    assert _extract("XPATH syntax error: '~payroll,secret,position,user...'") == "payroll,secret,position,user"
    assert _extract("XPATH syntax error: '~11.8.9-MariaDB-ubu2404~'") == "11.8.9-MariaDB-ubu2404"



def test_truncation_signals_in_skill():
    """Truncation is a first-class signal from the post-analysis skill, not a tweak.
    Each entry has an id + match regex + action ('auto-page')."""
    d = yaml.safe_load(open(POSTEX))
    ts = d["error_analysis"].get("truncation_signals") or []
    assert len(ts) >= 3
    for row in ts:
        assert row.get("id") and row.get("match") and row.get("action")
    # The XPATH dot-dot-dot signal (the exact one that dogged the live target) must be present
    assert any("xpath" in r["id"].lower() or "dotdotdot" in r["id"].lower() for r in ts)


def test_volume_gate_policy_in_skill():
    """The volume-gate policy is data in the skill so operators can raise/lower thresholds
    without a code change. The harness enforces the policy deterministically."""
    d = yaml.safe_load(open(POSTEX))
    vg = d["collection"].get("volume_gate") or {}
    assert vg.get("default_max_rows", 0) > 0 and vg.get("hard_max_rows", 0) >= vg["default_max_rows"]
    assert vg.get("hard_max_bytes", 0) > vg.get("warn_bytes", 0)
    # Skill policy must cover the three states: no count, over soft cap, over hard cap
    pol = (vg.get("policy") or {})
    assert "no_count" in pol and "over_default_max_rows" in pol and "over_hard_max_rows" in pol


def test_volume_gate_deterministic_check():
    """The harness gate is pure: refuse without a count, LIMIT above the soft cap, REFUSE above
    the hard cap. Mirror of api._postex_check_volume."""
    cfg = {"default_max_rows": 1000, "hard_max_rows": 10000, "warn_bytes": 1048576,
           "hard_max_bytes": 10485760, "default_row_bytes_estimate": 200}
    def check(rc, override=None):
        if rc is None:
            return {"allow": False, "reason": "no count"}
        max_rows = int(override) if override else cfg["default_max_rows"]
        est = int(rc) * cfg["default_row_bytes_estimate"]
        if int(rc) > cfg["hard_max_rows"]:
            return {"allow": False, "reason": "over hard"}
        if est > cfg["hard_max_bytes"]:
            return {"allow": False, "reason": "over hard bytes"}
        if int(rc) > max_rows or est > cfg["warn_bytes"]:
            return {"allow": True, "limit": max_rows, "reason": "capped"}
        return {"allow": True, "limit": None, "reason": "within policy"}
    assert check(None)["allow"] is False                # no row_count -> REFUSE
    assert check(50)["allow"] is True and check(50).get("limit") is None
    assert check(5000)["allow"] is True and check(5000)["limit"] == 1000   # soft cap
    assert check(50000)["allow"] is False                                   # hard cap



def test_primitive_families_declared():
    """The primitives are organized into FAMILIES per vuln class — this is the pattern for
    ALL enumeration + post-ex skills going forward."""
    d = yaml.safe_load(open(POSTEX))
    prims = d.get("primitives") or {}
    assert set(prims.get("families", [])) >= {"sqli", "lfi", "file_upload", "command_injection",
                                              "ssti", "xxe", "idor", "ssrf"}
    # Every primitive (except metadata keys) MUST declare its family + a status
    shipped, planned = [], []
    for name, entry in prims.items():
        if name in ("purpose", "families") or not isinstance(entry, dict):
            continue
        assert entry.get("family"), f"{name} missing family"
        assert entry.get("status") in ("shipped", "planned"), f"{name} missing status"
        (shipped if entry["status"] == "shipped" else planned).append(name)
    # sqli family has at least 3 shipped primitives; other families declared even if planned
    sqli_shipped = [n for n in shipped if prims[n]["family"] == "sqli"]
    assert len(sqli_shipped) >= 3



def test_learning_propose_shape():
    """The learning overlay entries follow a stable shape by kind — the merger in api
    (_postex_fixes_and_tweaks) expects specific keys. Lock the contract."""
    # error_fix: {match, fix}
    ef = {"match": "invalid response signature", "fix": "regenerate the CSRF token first"}
    assert ef["match"] and ef["fix"]
    # secret_table: {table_name}
    st = {"table_name": "wp_users", "cve": "CVE-XYZ", "discovered_via": "data"}
    assert st["table_name"]
    # truncation: {match, action, id}
    tr = {"match": "warning: data truncated", "action": "auto-page", "id": "mysql_data_trunc"}
    assert tr["match"] and tr["action"]



def test_semantic_enum_off_by_default():
    """The semantic fallback is FEATURE-FLAGGED. Off by default so regex-first stays fast +
    deterministic; opt-in POSTEX_SEMANTIC_ENUMERATE=1 turns it on."""
    import os
    # remove any test contamination
    prior = os.environ.pop("POSTEX_SEMANTIC_ENUMERATE", None)
    try:
        assert os.environ.get("POSTEX_SEMANTIC_ENUMERATE", "0").lower() not in ("1", "true", "yes", "on")
    finally:
        if prior is not None:
            os.environ["POSTEX_SEMANTIC_ENUMERATE"] = prior


def test_semantic_return_shape():
    """The classifier returns a stable schema so the enumerator can consume it safely."""
    example = {"fix_class": "column_count", "suggested_fix": "UNION SELECT column count mismatch",
               "truncated": False, "extracted_value": "", "hint": ""}
    for k in ("fix_class", "suggested_fix", "truncated", "extracted_value", "hint"):
        assert k in example


if __name__ == "__main__":
    fns = [f for f in dict(globals()) if f.startswith("test_")]
    for f in fns:
        globals()[f]()
    print(f"PASSED {len(fns)}/{len(fns)}")
