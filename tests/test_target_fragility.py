"""Target fragility classifier + mutating-endpoint gate.

Run standalone:

    pytest tests/test_target_fragility.py -v

WHY THIS EXISTS
---------------
A LangGraph session drove LoLLMs WebUI 9.5 (Alpha) into a persistent DoS by
exercising its config-mutating endpoints during the surface crawl — the app was
single-process (Server: uvicorn) and did not restart, foreclosing the higher-value
outcomes. `common/target_fragility.py` fingerprints such targets and drives them
with a NON-DESTRUCTIVE profile (skip/approval-gate config-mutating endpoints).
These guards pin that contract.

SABOTAGE PROOF
--------------
Drop "lollms" from `_KNOWN_FRAGILE_PRODUCTS` and `test_known_fragile_product`
fails; make `is_mutating_path` return False and `test_mutating_paths` +
`test_should_gate_fragile_mutating` fail; make `should_gate` ignore fragility and
`test_should_gate_normal_target` fails.
"""
from common import target_fragility as tf


def test_known_fragile_product():
    f = tf.classify(server_header="uvicorn", openapi_title="LoLLMS", version="9.5 (Alpha)")
    assert f.fragile is True
    assert f.profile == "non_destructive"
    assert any("lollms" in r.lower() for r in f.reasons)


def test_single_process_server():
    f = tf.classify(server_header="uvicorn")
    assert f.fragile is True
    assert any("single-process" in r for r in f.reasons)


def test_prerelease_version():
    f = tf.classify(server_header="nginx", version="9.5 (Alpha)")
    assert f.fragile is True
    assert any("pre-release" in r for r in f.reasons)


def test_normal_target_not_fragile():
    f = tf.classify(server_header="nginx/1.24.0", openapi_title="Payroll API",
                    version="2.1.0", product="nginx")
    assert f.fragile is False
    assert f.profile == "normal"
    assert f.reasons == []


def test_mutating_paths():
    for p in ("/set_config", "/api/update_settings", "/save_preset",
              "/apply_config", "/admin/delete", "/reload"):
        assert tf.is_mutating_path(p) is True, p
    for p in ("/search", "/index.html", "/get_version", "/products/42"):
        assert tf.is_mutating_path(p) is False, p


def test_mutating_methods():
    assert tf.is_mutating_method("POST") is True
    assert tf.is_mutating_method("delete") is True
    assert tf.is_mutating_method("GET") is False


def test_should_gate_fragile_mutating():
    f = tf.classify(server_header="uvicorn")
    # mutating PATH by GET still gated (the LoLLMs crash was a GET config route)
    assert tf.should_gate(f, method="GET", path="/set_config") is True
    # mutating METHOD gated
    assert tf.should_gate(f, method="POST", path="/whatever") is True
    # read-only on a fragile target is still fair game
    assert tf.should_gate(f, method="GET", path="/search") is False


def test_should_gate_normal_target():
    f = tf.classify(server_header="nginx", product="nginx")
    # a normal target's mutating endpoints are NOT gated by fragility
    assert tf.should_gate(f, method="POST", path="/set_config") is False


def test_as_dict_carries_fingerprint():
    f = tf.classify(server_header="uvicorn", openapi_title="LoLLMS", version="9.5 (Alpha)")
    d = f.as_dict()
    assert d["fragile"] is True
    assert d["fingerprint"]["server_header"] == "uvicorn"
    assert d["fingerprint"]["openapi_title"] == "LoLLMS"


# --- Source-analysis guards on the langgraph integration --------------------
# These catch the two defects the live retest found: a bare `logger` reference
# (the module's logger is `_log`) would NameError only when the fragile/skip path
# executes; ast checks the whole module without importing its heavy deps.
import ast
import os

_LG = os.path.join(os.path.dirname(__file__), "..", "autogen_agents", "langgraph_engine.py")


def test_langgraph_uses_defined_logger_not_bare_logger():
    """langgraph_engine defines `_log`, never `logger`. A bare `logger.<call>`
    passes ast.parse and import but NameErrors when that line runs — which is
    exactly how the fragile-target skip path crashed in the retest."""
    tree = ast.parse(open(_LG).read())
    assert not any(
        isinstance(n, ast.Name) and n.id == "logger"
        for n in ast.walk(tree)
    ), "langgraph_engine references undefined `logger` (use `_log`)"


def test_fragility_helpers_present():
    src = open(_LG).read()
    assert "def _target_fragility(" in src
    assert "def _probe_fingerprint(" in src
    # the ports read must join assets (ports has no `ip` column)
    assert "FROM ports p JOIN assets a" in src, "ports query must join through assets"


def test_throttle_halves_for_fragile():
    assert tf.throttle(10, True) == 5
    assert tf.throttle(3, True) == 2      # round(1.5) -> 2
    assert tf.throttle(1, True) == 1      # never below 1
    assert tf.throttle(0, True) == 1      # a scan is never throttled to zero


def test_throttle_noop_when_not_fragile():
    assert tf.throttle(10, False) == 10
    assert tf.throttle(50, False) == 50


def test_throttle_passthrough_non_int():
    assert tf.throttle("auto", True) == "auto"
    assert tf.throttle(None, True) is None


def test_probe_and_classify_exists_and_failsafe():
    f = tf.probe_and_classify("203.0.113.253", ports=[9], timeout=0.2)
    assert f.fragile is False
