"""Data-query MCP servers must forward the active engagement to rag-api.

Run on demand:

    pytest tests/test_mcp_engagement_scope.py -v

WHY THIS EXISTS
---------------
The MCP servers reach collected data by calling rag-api, but sent only
`x-api-key` — never X-Engagement-Id — so their tools returned every engagement's
data regardless of which engagement the client was working. Each data-query MCP
server now derives ENGAGEMENT_ID (or MCP_ENGAGEMENT_ID) from the environment and
adds X-Engagement-Id via a shared `_api_headers()` helper; unset = platform-wide
(unchanged). No raw `{"x-api-key": API_KEY}` header dict may remain — it would
bypass the engagement header.

SABOTAGE PROOF
--------------
Reintroduce a raw `{"x-api-key": API_KEY}` header on a request in any listed
server (instead of `_api_headers()`) and its case fails.
"""
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVERS = ["mcp-recon", "mcp-sessions", "mcp-credentials", "mcp-burp", "mcp-zap"]


def _src(name):
    path = os.path.join(REPO, "mcp", f"{name}.py")
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    return open(path, encoding="utf-8").read()


@pytest.mark.parametrize("name", SERVERS)
def test_defines_engagement_aware_header_helper(name):
    s = _src(name)
    assert "def _api_headers" in s, f"{name} must define the _api_headers() helper"
    assert "ENGAGEMENT_ID" in s and "X-Engagement-Id" in s, (
        f"{name} must derive the engagement from env and set X-Engagement-Id")


@pytest.mark.parametrize("name", SERVERS)
def test_no_raw_api_key_header_at_call_sites(name):
    s = _src(name)
    # The helper body legitimately builds {"x-api-key": API_KEY}; what must be
    # gone is the CALL-SITE form that bypasses the engagement header.
    assert 'headers={"x-api-key": API_KEY}' not in s, (
        f"{name} still passes headers={{'x-api-key': API_KEY}} on a request — that "
        f"bypasses the engagement header; use headers=_api_headers().")
    # And the raw dict must appear at most once (inside the helper).
    assert s.count('{"x-api-key": API_KEY}') <= 1, (
        f"{name} has a raw x-api-key header dict outside the helper.")
