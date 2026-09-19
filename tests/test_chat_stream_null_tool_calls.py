"""Chat streaming must tolerate a present-but-null `delta`/`tool_calls`.

Run on demand:

    pytest tests/test_chat_stream_null_tool_calls.py -v

WHY THIS EXISTS
---------------
OpenAI-compatible backends stream chunks where `delta` and `delta.tool_calls`
are sometimes present with a JSON null (not absent). `dict.get(k, default)`
returns the default ONLY when the key is absent — for a present null it returns
None. So `for tc in delta.get("tool_calls", [])` raised
"'NoneType' object is not iterable", which killed the whole SSE stream after a
little text — every tool-using built-in chat returned only blank content while a
plain factual chat (no tool_calls delta) worked. The fix coalesces with `or`.

SABOTAGE PROOF
--------------
Change either coalesce back to `.get("tool_calls", [])` / `.get("delta", {})`
and this fails.
"""
import ast
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(REPO, "dashboard", "bff", "services", "ollama_chat.py")


def _src():
    if not os.path.exists(SRC):
        pytest.skip("ollama_chat.py not present")
    return open(SRC, encoding="utf-8").read()


def test_tool_calls_and_delta_are_null_coalesced():
    s = _src()
    assert "delta.get(\"tool_calls\") or []" in s or "delta.get('tool_calls') or []" in s, (
        "tool_calls iteration must coalesce None -> [] (a present-null tool_calls "
        "otherwise raises 'NoneType' object is not iterable and kills the stream).")
    assert 'choice.get("delta") or {}' in s or "choice.get('delta') or {}" in s, (
        "delta must coalesce None -> {} (final chunks can carry delta: null).")
    # The unsafe forms must be gone from the streaming path.
    assert 'delta.get("tool_calls", [])' not in s, (
        "unsafe delta.get('tool_calls', []) still present — returns None on a "
        "present-null key.")


def test_null_coalesce_behaviour_matches_the_fix():
    """The semantics the fix relies on: .get(k, default) returns None for a
    present-null key; `or default` is what actually protects the loop."""
    d = {"tool_calls": None, "delta": None}
    assert d.get("tool_calls", []) is None          # the bug
    assert (d.get("tool_calls") or []) == []         # the fix
    assert (d.get("delta") or {}) == {}
    # iterating the buggy form raises; the fixed form does not
    with pytest.raises(TypeError):
        list(d.get("tool_calls", []))
    assert list(d.get("tool_calls") or []) == []
