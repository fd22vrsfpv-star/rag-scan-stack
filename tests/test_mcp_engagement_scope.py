"""Data-query MCP servers scope to the active engagement — per request via mcpo.

Run on demand:

    pytest tests/test_mcp_engagement_scope.py -v

WHY THIS EXISTS
---------------
The MCP servers reached collected data via rag-api but sent only `x-api-key`, so
their tools returned every engagement's data. Now each data-query server carries
X-Engagement-Id via a shared `_api_headers()` that resolves the engagement from
`_engagement_mw.current_engagement()` — the PER-REQUEST value the streamable
server captures from the caller's `X-Engagement-Id` header / `?engagement_id`
(so the mcpo gateway can scope one tool call), else the ENGAGEMENT_ID env pin,
else unset = platform-wide. Servers run via `run_streamable(mcp)` which installs
the capture middleware.

Also pins the mcpo gateway config to http:// for the plain-HTTP streamable
servers — a https:// URL there made mcpo expose ZERO tools.

SABOTAGE PROOF
--------------
Put back a raw `headers={"x-api-key": API_KEY}` on a request, drop the middleware
run, or set an mcp-streamable URL back to https:// — the matching case fails.
"""
import json
import os

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SERVERS = ["mcp-recon", "mcp-sessions", "mcp-credentials", "mcp-burp", "mcp-zap"]


def _src(name):
    path = os.path.join(REPO, "mcp", f"{name}.py")
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    return open(path, encoding="utf-8").read()


def test_shared_middleware_module_present():
    path = os.path.join(REPO, "mcp", "_engagement_mw.py")
    assert os.path.exists(path), "mcp/_engagement_mw.py is missing"
    s = open(path, encoding="utf-8").read()
    for needle in ("class EngagementMiddleware", "def current_engagement",
                   "def run_streamable", "x-engagement-id", "ENGAGEMENT_ID"):
        assert needle in s, f"_engagement_mw.py missing {needle!r}"
    # Dockerfile must ship it into the streamable image.
    df = open(os.path.join(REPO, "mcp", "Dockerfile.streamable"), encoding="utf-8").read()
    assert "COPY _engagement_mw.py" in df, "Dockerfile.streamable must COPY _engagement_mw.py"


@pytest.mark.parametrize("name", SERVERS)
def test_uses_per_request_engagement(name):
    s = _src(name)
    assert "from _engagement_mw import current_engagement, run_streamable" in s, (
        f"{name} must import the shared per-request engagement helpers")
    assert "current_engagement()" in s, f"{name}'s _api_headers must use current_engagement()"
    assert "run_streamable(mcp)" in s and 'mcp.run(transport="streamable-http")' not in s, (
        f"{name} must run via run_streamable(mcp) so the capture middleware is installed")


@pytest.mark.parametrize("name", SERVERS)
def test_no_raw_api_key_header_at_call_sites(name):
    s = _src(name)
    assert 'headers={"x-api-key": API_KEY}' not in s, (
        f"{name} still passes a raw x-api-key header — use headers=_api_headers().")
    assert s.count('{"x-api-key": API_KEY}') <= 1, (
        f"{name} has a raw x-api-key header dict outside the helper.")


# Servers whose rag-api tools take a per-request engagement_id argument, and the
# minimum number of such tools each must expose (the reliable mcpo channel).
_PER_REQUEST = {"mcp-credentials": 4, "mcp-recon": 6, "mcp-sessions": 1,
                "mcp-burp": 10, "mcp-zap": 3}


@pytest.mark.parametrize("name", sorted(_PER_REQUEST))
def test_rag_api_tools_accept_per_request_engagement(name):
    """Every tool that touches rag-api exposes an engagement_id argument and
    binds it per call — the only channel mcpo forwards (declared tool args, not
    headers/query). Verified live on credentials: list_users 7 vs 5 scoped."""
    s = _src(name)
    assert "set_request_engagement" in s, f"{name} must import/use set_request_engagement"
    need = _PER_REQUEST[name]
    assert s.count("engagement_id: Annotated") >= need, (
        f"{name}: expected >= {need} tools with an engagement_id argument")
    # every engagement_id param must be bound for the request
    assert s.count("set_request_engagement(engagement_id)") == s.count("engagement_id: Annotated"), (
        f"{name}: every engagement_id argument must call set_request_engagement(engagement_id)")


def test_mcpo_config_uses_http_for_streamable():
    path = os.path.join(REPO, "mcpo", "config.json")
    if not os.path.exists(path):
        pytest.skip("mcpo/config.json not present")
    cfg = json.load(open(path, encoding="utf-8"))
    for name, spec in (cfg.get("mcpServers") or {}).items():
        url = spec.get("url", "")
        if "mcp-streamable" in url:
            assert url.startswith("http://"), (
                f"mcpo server {name!r} points at {url} — the streamable servers "
                f"serve plain HTTP, so a https:// URL makes mcpo expose zero tools.")
