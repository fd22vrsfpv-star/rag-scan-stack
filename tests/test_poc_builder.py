"""Pure-logic guards for the CVE PoC-builder (etl-independent bits).

Run: pytest tests/test_poc_builder.py -v

The builder itself needs NVD + an LLM + a target (integration), but its JSON
extraction and assertion evaluation are pure and must be correct — a bad regex or
a swallowed shell error would mark a failed PoC as a success.
"""
import importlib.util, os, types, sys

# Load only the two pure functions from api.py without importing the whole module
# (it pulls heavy deps). We copy their logic contract here via a tiny shim: the
# functions are simple enough to re-derive, so we test the CONTRACT the builder relies on.
import re


def _poc_extract_json(text):
    import json as _j
    if not text:
        return None
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return _j.loads(m.group(0))
    except Exception:
        return None


def _poc_assertion_passes(assertion, output, exit_code=None):
    a = assertion or {}
    out = output or ""
    low = out.lower()
    if any(m in low for m in ("/bin/sh:", "syntax error", "command not found")):
        return False
    canary = a.get("canary")
    if canary and canary not in out:
        return False
    rx = a.get("expect_regex")
    if rx:
        try:
            return bool(re.search(rx, out, re.I))
        except Exception:
            return bool(out.strip())
    if a.get("expect_shell"):
        return bool(re.search(r"uid=\d+|gid=\d+|root@", out))
    return bool(out.strip()) and exit_code in (None, 0)


def test_extract_json_from_prose_wrapper():
    t = 'Here is the PoC:\n{"command": "curl x", "assertion": {"expect_regex": "ok"}}\nDone.'
    o = _poc_extract_json(t)
    assert o and o["command"] == "curl x" and o["assertion"]["expect_regex"] == "ok"


def test_extract_json_none_on_garbage():
    assert _poc_extract_json("no json here") is None
    assert _poc_extract_json("") is None


def test_assertion_shell_error_never_passes():
    # a converged PoC must not be declared on a shell error (the #331 class)
    assert _poc_assertion_passes({"expect_regex": "root"}, "/bin/sh: 1: Syntax error") is False


def test_assertion_regex_match():
    assert _poc_assertion_passes({"expect_regex": "(?i)administrator created"}, "User Administrator created") is True
    assert _poc_assertion_passes({"expect_regex": "administrator created"}, "nothing here") is False


def test_assertion_nonzero_exit_no_regex():
    assert _poc_assertion_passes({}, "some output", 3) is False
    assert _poc_assertion_passes({}, "some output", 0) is True


# --- precondition detection (nonce/CSRF/session) drives the refine fetch ---
_POC_PRECOND_SIGNALS = ("nonce", "csrf", "xsrf", "token", "unauthorized", "forbidden",
                        "403", "invalid security", "login required", "authentication",
                        "permission", "not allowed", "missing", "expired", "denied")


def _poc_needs_precondition(output):
    low = (output or "").lower()
    return any(s in low for s in _POC_PRECOND_SIGNALS)


def test_precondition_detected_on_nonce_error():
    assert _poc_needs_precondition("Error: invalid nonce") is True
    assert _poc_needs_precondition("HTTP/1.1 403 Forbidden") is True
    assert _poc_needs_precondition("CSRF token mismatch") is True


def test_precondition_not_detected_on_clean_output():
    assert _poc_needs_precondition("User Administrator created; uid=0") is False


def test_precondition_quote_class_regex_compiles():
    # the fetch regexes are built with chr(34)/chr(39) quote classes — make sure the
    # pattern shape compiles (the bug that broke the module was a literal quote in a
    # raw string)
    import re
    Q = "[" + chr(34) + chr(39) + "]"
    NQ = "[^" + chr(34) + chr(39) + "]"
    pat = r"name=" + Q + "(" + NQ + r"*(?:nonce|token)" + NQ + r"*)" + Q + r"[^>]*value=" + Q + "(" + NQ + r"+)" + Q
    rx = re.compile(pat, re.I)
    m = rx.search('<input name="_wpnonce" value="abc123">')
    assert m and m.group(2) == "abc123"


# --- CVE-anchored assertion + anti-drift guard --------------------------------
# Mirror the real helpers in app/rag-api/api.py (the module pulls heavy deps, so we
# re-derive the pure logic here, the same pattern as the shims above). These lock the
# behavior that makes a PoC "success" mean the CVE's OWN effect, not adjacent state.

def _poc_target_family(command):
    m = re.search(r"https?://([^/\s'\"]+)(/[^\s'\"?]*)?", command or "")
    if not m:
        return ("", "")
    host = (m.group(1) or "").lower()
    path = (m.group(2) or "/")
    seg = "/" + (path.lstrip("/").split("/", 1)[0] if path.strip("/") else "")
    return (host, seg)


def _poc_assertion_is_anchored(assertion, canary):
    if not canary:
        return False
    a = assertion or {}
    if a.get("cve_anchored") and a.get("canary") == canary:
        return True
    rx = a.get("expect_regex") or ""
    return canary in rx


def test_canary_absent_from_output_never_passes():
    # The load-bearing case: _reanchor keeps whatever regex the LLM produced (here a
    # GENERIC one that a pre-existing admin list would match) but attaches the canary.
    # The dedicated canary guard MUST block it because the exploit's own marker is absent.
    canary = "POCz1a2b3c4d5e"
    a = {"expect_regex": r'"slug":\s*"[^"]+"', "canary": canary, "cve_anchored": True}
    pre_existing = '[{"id":1,"name":"admin","slug":"admin"}]'   # matches the generic regex...
    assert _poc_assertion_passes(a, pre_existing) is False       # ...but no canary -> blocked


def test_canary_present_passes():
    canary = "POCz1a2b3c4d5e"
    a = {"expect_regex": r'"slug":\s*"[^"]+"', "canary": canary, "cve_anchored": True}
    injected = '[{"id":2,"name":"%s","slug":"%s"}]' % (canary, canary)
    assert _poc_assertion_passes(a, injected) is True


def test_offtarget_userenum_is_not_verified():
    # THE bug this guard fixes: a refine that pivots to WP REST user-enum whose output
    # matches a generic '"slug":"..."' regex must NOT count as verifying the CVE.
    canary = "POCz9988776655"
    generic = {"expect_regex": r'"slug":\s*"[^"]+"'}       # non-anchored (what drift produced)
    # _reanchor wraps that generic regex with the canary (what the builder actually stores):
    anchored = {"expect_regex": r'"slug":\s*"[^"]+"', "canary": canary, "cve_anchored": True}
    userenum_out = '[{"id":1,"name":"admin","slug":"admin"}]'
    # generic assertion "passes" (that's the trap) ...
    assert _poc_assertion_passes(generic, userenum_out) is True
    # ... but it is NOT anchored, so it is not "verified" ...
    assert _poc_assertion_is_anchored(generic, canary) is False
    # ... and the anchored (canary-guarded) assertion does NOT pass on off-target output.
    assert _poc_assertion_passes(anchored, userenum_out) is False


def test_default_generic_assertion_is_not_anchored():
    generic = {"expect_regex": r"(?i)(uid=|root:|administrator|vulnerable)"}
    assert _poc_assertion_is_anchored(generic, "POCzdeadbeef00") is False


def test_anchored_assertion_recognized():
    canary = "POCzdeadbeef00"
    assert _poc_assertion_is_anchored({"expect_regex": canary, "canary": canary,
                                       "cve_anchored": True}, canary) is True
    # canary embedded in a richer regex is still anchored
    assert _poc_assertion_is_anchored({"expect_regex": r'"name":"%s"' % canary}, canary) is True


def test_drift_detection_by_path_family():
    origin = _poc_target_family("curl http://t:9090/wp-admin/admin-ajax.php?action=htmega")
    same = _poc_target_family("curl http://t:9090/wp-admin/admin-ajax.php?action=x")
    drifted = _poc_target_family("curl http://t:9090/wp-json/wp/v2/users?per_page=100")
    assert origin[1] == "/wp-admin"
    assert same[1] == origin[1]          # no drift within the CVE endpoint family
    assert drifted[1] == "/wp-json" and drifted[1] != origin[1]   # pivot detected


# --- reflection guard: canary sent in the request needs a reflection control ---
def _reflection_precondition(command, canary):
    """Mirror of the gate in _poc_reflection_detected: a reflection check is only needed
    when the canary was SENT in the request (could be echoed back). A canary that appears
    in output WITHOUT being in the request is already a genuine side-effect."""
    return bool(canary and command and canary in command)


def test_reflection_check_only_when_canary_in_request():
    c = "POCzabc123def"
    # Host-header injection (what the LLM produced on 37999) -> canary IS in the request
    host_inject = f"curl -sSi -H 'Host: {c}' http://t:9090/"
    assert _reflection_precondition(host_inject, c) is True
    # a real side-effect readback -> canary NOT in the request, appears only in output
    readback = "curl -s http://t:9090/wp-json/wp/v2/users"
    assert _reflection_precondition(readback, c) is False


def test_reflection_control_token_swap_changes_command():
    # the control probe swaps the canary for a fresh token; the probe command must differ
    c = "POCzabc123def"
    cmd = f"curl -H 'Host: {c}' http://t/"
    ctrl = "CTRLzdeadbeef1"
    probe = cmd.replace(c, ctrl)
    assert c not in probe and ctrl in probe and probe != cmd
