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
