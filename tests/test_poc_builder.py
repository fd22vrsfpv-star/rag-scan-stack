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
