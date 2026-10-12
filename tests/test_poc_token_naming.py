"""The synthesized id for a build with no CVE names its target.

`POC-<ip>-<port>[-<product>]-NNN`, e.g. `POC-172.18.0.32-9090-lobechat-001`.
The predecessor was `NOCVE-<unix-epoch>` — unique, but it told the operator
nothing and sorted meaninglessly in the Store.

The counter is not cosmetic. This token keys `derived_cve_specs`, `poc_hints`,
`build_poc_error_memory` and the Store row, so a repeat against the same target
would overwrite the previous build's derived spec.

Guards `_synth_poc_token` + `_is_synthetic_cve` in `app/rag-api/api.py`, and
that the deep-dive gate in `build_poc_graph.py` routes through the helper
rather than one literal prefix. Source-extracted rather than imported: api.py
pulls in the whole service on import.
"""
import os
import re as _re_module

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")
GRAPH = os.path.join(REPO, "app", "rag-api", "build_poc_graph.py")


def _src(path):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    return open(path, encoding="utf-8").read()


def _load_helpers():
    """Exec the two helpers with a stub get_db, so the token logic is tested
    without a database. The stub returns the rows the caller seeds."""
    src = _src(API)
    try:
        start = src.index("def _is_synthetic_cve")
        end = src.index('@app.post("/software/build-poc"')
    except ValueError:
        pytest.skip("poc-token helpers not found in api.py")

    rows: list = []

    class _Cur:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def execute(self, *a, **k): pass
        def fetchall(self): return [(r,) for r in rows]

    class _Conn:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def cursor(self): return _Cur()

    import logging as _logging
    ns = {"_re_module": _re_module, "get_db": lambda: _Conn(), "logging": _logging}
    exec(compile(src[start:end], API, "exec"), ns)  # noqa: S102
    return ns["_synth_poc_token"], ns["_is_synthetic_cve"], rows


def test_token_names_the_target():
    synth, _, rows = _load_helpers()
    rows.clear()
    assert synth("172.18.0.32", 9090, "LobeChat") == \
        "POC-172.18.0.32-9090-lobechat-001"


def test_product_is_slugified():
    synth, _, rows = _load_helpers()
    rows.clear()
    tok = synth("10.0.0.5", 80, "Apache HTTP Server 2.4!!")
    assert tok == "POC-10.0.0.5-80-apache-http-server-2-4-001", tok
    assert " " not in tok and "!" not in tok


def test_product_omitted_when_absent():
    """No product is a legitimate case — the component is dropped, not blank."""
    synth, _, rows = _load_helpers()
    rows.clear()
    assert synth("172.19.14.251", 9090, None) == "POC-172.19.14.251-9090-001"
    assert synth("172.19.14.251", 9090, "") == "POC-172.19.14.251-9090-001"


def test_counter_increments_past_the_highest_existing():
    """Not a count of rows — the max suffix, so gaps do not cause a collision."""
    synth, _, rows = _load_helpers()
    rows.clear()
    rows.extend(["POC-172.18.0.32-9090-lobechat-001",
                 "POC-172.18.0.32-9090-lobechat-009"])
    assert synth("172.18.0.32", 9090, "LobeChat") == \
        "POC-172.18.0.32-9090-lobechat-010"


def test_counter_rolls_past_three_digits():
    synth, _, rows = _load_helpers()
    rows.clear()
    rows.append("POC-172.18.0.32-9090-lobechat-099")
    assert synth("172.18.0.32", 9090, "LobeChat") == \
        "POC-172.18.0.32-9090-lobechat-100"


def test_old_epoch_tokens_do_not_disturb_the_counter():
    synth, _, rows = _load_helpers()
    rows.clear()
    rows.append("NOCVE-1790970623")
    assert synth("172.18.0.32", 9090, "LobeChat").endswith("-001")


def test_is_synthetic_covers_both_prefixes():
    """Older rows carry NOCVE-; branching on one literal would send them
    researching a CVE that never existed."""
    _, is_syn, _ = _load_helpers()
    assert is_syn("POC-172.18.0.32-9090-lobechat-001") is True
    assert is_syn("NOCVE-1790970623") is True
    assert is_syn("CVE-2024-22120") is False
    assert is_syn("") is False
    assert is_syn(None) is False


def test_deep_dive_gate_uses_the_helper_not_a_literal():
    """build_poc_graph must not re-hardcode a single prefix."""
    src = _src(GRAPH)
    assert "_is_synthetic_cve" in src, (
        "build_poc_graph no longer routes the deep-dive gate through "
        "_is_synthetic_cve; a bare prefix check there silently breaks one of "
        "the two synthesized formats")
    assert 'startswith("NOCVE-")' not in src, (
        "a bare NOCVE- check came back in build_poc_graph")


def test_api_has_no_bare_nocve_checks_left():
    src = _src(API)
    assert 'startswith("NOCVE-")' not in src, (
        "api.py has a bare NOCVE- prefix check; use _is_synthetic_cve so the "
        "POC- form is recognised too")
