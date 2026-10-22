"""The released exploitation run — phase two of the SQLi proof path.

Why this exists — see Docs/plans/SQLI_PROOF_PATH.md
--------------------------------------------------
Proving a CVE and exploiting it are different jobs. The proof path derives a
tool command (sqlmap and friends) and deliberately does NOT run it, recording
it with `deferred_to_release`. Before this endpoint existed, that command was
recorded and executed by nothing — a deliberate dead end waiting for phase two.

This endpoint is where an operator runs it, and every one of its refusals is
load-bearing:

* **409 on an unverified PoC.** Running an enumeration tool against a
  vulnerability we have not proven is a scan, not an exploitation.
* **The scope gate**, unconditional and fail-closed — including over an
  operator-supplied `command` override. CLAUDE.md: an override overrules the
  platform's SUPPRESSION judgement, never the operator's AUTHORIZATION.
* **MAX_CONCURRENT_SCANS**, because this initiates a scan. Shed with 429,
  never queue.
* **Recorded in `tool_executions`**, because a tool this platform ran is a
  scan — the whole point of step 5, where sqlmap had run 173 times and left
  zero rows.

The BFF half CHECKS the upstream status: httpx does not raise on 4xx/5xx, and
this endpoint's refusals are the interesting part. Returning a 409 as success
would report a refused exploitation as a completed one.
"""
from __future__ import annotations

import os
import sys

import pytest

pytest.importorskip("pydantic_settings", reason="BFF dependency; present in the image")
pytest.importorskip("psycopg2", reason="BFF dependency; present in the image")

from unittest.mock import AsyncMock, MagicMock, patch  # noqa: E402

from httpx import Response  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "dashboard", "bff"))

from fastapi.testclient import TestClient  # noqa: E402

with patch("main.poll_loop", new_callable=lambda: lambda: AsyncMock()):
    from main import app  # noqa: E402

client = TestClient(app, raise_server_exceptions=False)
EID = "11111111-2222-3333-4444-555555555555"
XID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _resp(json_data, status_code=200):
    r = MagicMock(spec=Response)
    r.status_code = status_code
    r.json.return_value = json_data
    r.text = str(json_data)
    r.headers = {"content-type": "application/json"}
    return r


def _client_cm(response):
    c = AsyncMock()
    c.post = AsyncMock(return_value=response)
    c.get = AsyncMock(return_value=response)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=c)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm, c


def test_a_successful_released_run_is_returned():
    cm, inner = _client_cm(_resp({"ok": True, "tool": "sqlmap", "exit_code": 0,
                                  "seconds": 42.0, "output": "Parameter: username"}))
    with patch("routers.exploits.httpx.AsyncClient", return_value=cm):
        r = client.post(f"/api/exploit-store/{XID}/released-run",
                        json={"tool": "sqlmap"},
                        headers={"X-Engagement-Id": EID})
    assert r.status_code == 200, r.text
    assert r.json()["tool"] == "sqlmap"
    # The engagement must reach rag-api, or the run lands unattributed.
    assert "X-Engagement-Id" in inner.post.call_args.kwargs["headers"]


@pytest.mark.parametrize("status,why", [
    (409, "unverified PoC"),
    (403, "out of scope"),
    (429, "at the concurrency limit"),
])
def test_a_refusal_is_reported_as_a_refusal(status, why):
    """httpx does not raise on 4xx/5xx. A proxy that does not check the status
    reports a refused exploitation to the operator as a completed one — and
    this endpoint's refusals are the whole safety story."""
    cm, _ = _client_cm(_resp({"detail": why}, status_code=status))
    with patch("routers.exploits.httpx.AsyncClient", return_value=cm):
        r = client.post(f"/api/exploit-store/{XID}/released-run", json={},
                        headers={"X-Engagement-Id": EID})
    assert r.status_code == status, f"{why} was not surfaced: {r.status_code}"


def test_an_empty_body_is_accepted():
    """`tool` and `command` are both optional — the default is the first
    derived command, which is the common case from the UI."""
    cm, inner = _client_cm(_resp({"ok": True, "tool": "sqlmap", "exit_code": 0}))
    with patch("routers.exploits.httpx.AsyncClient", return_value=cm):
        r = client.post(f"/api/exploit-store/{XID}/released-run",
                        headers={"X-Engagement-Id": EID})
    assert r.status_code == 200, r.text
    assert inner.post.call_args.kwargs["json"] == {}
