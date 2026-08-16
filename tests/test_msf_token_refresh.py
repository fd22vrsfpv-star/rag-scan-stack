"""MSF RPC stale-token handling.

MSF hands out a TEMPORARY token that expires after ~5 minutes of inactivity.
MsfRpcClient cached self.token for the process lifetime, and every caller guarded
with `if not msf.token: await msf.login()` — a guard that only fires when the
token is None, so it cannot distinguish "never logged in" from "token died an
hour ago". The first call after an idle period returned "Invalid Authentication
Token", and since nothing cleared the dead token, every later call failed
identically until the process restarted. /msf/jobs and /msf/sessions returned
HTTP 500 permanently.

These tests drive _call directly with a faked transport, because reproducing the
real bug otherwise means idling a live msfrpcd for five minutes.
"""
import os
import sys
import msgpack
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "exploit_runner"))

from msf_client import MsfRpcClient  # noqa: E402


class FakeResponse:
    status_code = 200

    def __init__(self, payload):
        self.content = msgpack.packb(payload)


class FakeClient:
    """Stands in for httpx.AsyncClient; scripts one reply per POST."""

    def __init__(self, replies, sent):
        self._replies = replies
        self._sent = sent

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, content=None, headers=None):
        self._sent.append(msgpack.unpackb(content, raw=False, strict_map_key=False))
        return FakeResponse(self._replies.pop(0))


@pytest.fixture
def client(monkeypatch):
    def make(replies, sent):
        monkeypatch.setattr(
            "msf_client.httpx.AsyncClient",
            lambda **kw: FakeClient(replies, sent),
        )
        c = MsfRpcClient(host="h", port=1, username="u", password="p")
        return c
    return make


@pytest.mark.asyncio
async def test_stale_token_triggers_relogin_and_retry(client):
    """The exact production failure: cached token is dead, call must still succeed."""
    sent = []
    replies = [
        {"error": True, "error_message": "Invalid Authentication Token"},  # job.list
        {"result": "success", "token": "fresh-token"},                     # auth.login
        {"jobs": {"0": "exploit/handler"}},                                # job.list retry
    ]
    c = client(replies, sent)
    c.token = "stale-token"

    result = await c.list_jobs()

    assert result == {"jobs": {"0": "exploit/handler"}}
    assert c.token == "fresh-token"
    assert [m[0] for m in sent] == ["job.list", "auth.login", "job.list"]
    # The retry must carry the NEW token, not the dead one it started with.
    assert sent[2][1] == "fresh-token"


@pytest.mark.asyncio
async def test_retry_happens_at_most_once(client):
    """A credential that is genuinely bad must surface, not loop."""
    sent = []
    replies = [
        {"error": True, "error_message": "Invalid Authentication Token"},
        {"result": "success", "token": "also-bad"},
        {"error": True, "error_message": "Invalid Authentication Token"},
    ]
    c = client(replies, sent)
    c.token = "stale-token"

    with pytest.raises(Exception, match="Invalid Authentication Token"):
        await c.list_sessions()

    assert [m[0] for m in sent] == ["session.list", "auth.login", "session.list"]


@pytest.mark.asyncio
async def test_failed_relogin_reports_the_real_cause(client):
    """When re-auth fails, say so — don't echo the token error and hide why."""
    sent = []
    replies = [
        {"error": True, "error_message": "Invalid Authentication Token"},
        {"result": "failure"},  # login rejected
    ]
    c = client(replies, sent)
    c.token = "stale-token"

    with pytest.raises(Exception, match="re-authentication failed"):
        await c.list_jobs()


@pytest.mark.asyncio
async def test_non_auth_errors_are_not_retried(client):
    """An unrelated RPC error must propagate immediately, with no extra calls."""
    sent = []
    replies = [{"error": True, "error_message": "Unknown module"}]
    c = client(replies, sent)
    c.token = "good-token"

    with pytest.raises(Exception, match="Unknown module"):
        await c.list_jobs()

    assert len(sent) == 1


@pytest.mark.asyncio
async def test_login_failure_is_not_itself_retried(client):
    """auth.login is excluded from the retry path, so a bad credential cannot loop."""
    sent = []
    replies = [{"error": True, "error_message": "Invalid Authentication Token"}]
    c = client(replies, sent)

    assert await c.login() is False
    assert len(sent) == 1


@pytest.mark.asyncio
async def test_missing_token_authenticates_first(client):
    """No token yet: log in, then run the call — without a token-less attempt."""
    sent = []
    replies = [
        {"result": "success", "token": "t1"},   # auth.login
        {"jobs": {}},                           # job.list
    ]
    c = client(replies, sent)
    assert c.token is None

    assert await c.list_jobs() == {"jobs": {}}
    assert [m[0] for m in sent] == ["auth.login", "job.list"]


@pytest.mark.asyncio
async def test_bad_credentials_report_auth_failure_not_token_error(client):
    """The production misdiagnosis: wrong password must NOT surface as a token error.

    login() returns False and every caller ignored it, so _call sent a token-less
    payload and MSF replied "Invalid Authentication Token". A plain wrong-password
    condition therefore presented as a token problem.
    """
    sent = []
    replies = [{"error": True, "error_message": "Login Failed"}]  # auth.login rejected
    c = client(replies, sent)

    with pytest.raises(Exception, match="MSF authentication failed"):
        await c.list_jobs()

    # Only the login was attempted — no misleading token-less call followed.
    assert [m[0] for m in sent] == ["auth.login"]
