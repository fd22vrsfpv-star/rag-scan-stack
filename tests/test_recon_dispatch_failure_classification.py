"""A failed dispatch must be retired only when retrying it is pointless.

The recon agent marks failed recommendations `status='failed'` so they stop
blocking the head of the priority-ordered queue. That is correct for
`Tool 'nc' is not in allowed list` — a 400 that returns the same answer forever.
It is WRONG for `ConnectError` or `HTTP 502` from a scanner container that
happened to be restarting: retiring those silently discards recon work the
operator never learns was dropped.

So failures are classified. Permanent ones retire immediately; transient ones
stay pending and are retried, bounded by MAX_DISPATCH_ATTEMPTS so an
unrecognised-but-permanent failure still cannot block the queue indefinitely.

The strings below are the real formats produced by `dispatch_rec` in
dashboard/bff/routers/assets.py, not invented ones.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "dashboard" / "bff"))


@pytest.fixture(scope="module")
def classify():
    """Import the classifier without dragging in the BFF's runtime deps."""
    import importlib.util

    src = (Path(__file__).parent.parent / "dashboard" / "bff" / "services"
           / "recon_agent.py")
    text = src.read_text()

    # The module imports httpx/config at import time; exec only the pure
    # helper plus the constants it closes over.
    ns: dict = {}
    exec("import re as _re", ns)
    start = text.index("MAX_DISPATCH_ATTEMPTS = ")
    end = text.index("class ReconAgent:")
    body = text[start:end].replace(
        'int(os.environ.get("RECON_AGENT_MAX_DISPATCH_ATTEMPTS", "3"))', "3"
    )
    exec(body, ns)
    return ns["_is_permanent_dispatch_failure"]


# ---------------------------------------------------------------- permanent

@pytest.mark.unit
@pytest.mark.parametrize("detail", [
    # The two seen live on 192.168.1.150.
    "Kali HTTP 400: {\"detail\":\"Tool 'nc' is not in allowed list (78 allowed;"
    " Metasploit excluded — use the Exploit Manager).\"}",
    "Kali HTTP 400: {\"detail\":\"Tool 'irssi' is not in allowed list (78 allowed",
    "No automated handler for 'exiftool'",
    "Manual tool — enable 'Use Kali' to run via internal Kali container",
    "HTTP 404: not found",
    "HTTP 422: validation error",
])
def test_permanent_failures_are_retired(classify, detail):
    assert classify(detail) is True


# ---------------------------------------------------------------- transient

@pytest.mark.unit
@pytest.mark.parametrize("detail", [
    # Real shapes: f"{type(e).__name__}: {str(e)[:80]}"
    "ConnectError: [Errno 111] Connection refused",
    "ConnectTimeout: timed out",
    "ReadTimeout: The read operation timed out",
    "RemoteProtocolError: Server disconnected without sending a response",
    "Kali: ConnectError: All connection attempts failed",
    "Node: ConnectTimeout",
    # Server-side HTTP — the request was fine, the peer was not.
    "HTTP 502: Bad Gateway",
    "HTTP 503: Service Unavailable",
    "Kali HTTP 500: internal error",
    # 4xx that are explicitly retryable.
    "HTTP 408: Request Timeout",
    "HTTP 429: Too Many Requests",
])
def test_transient_failures_stay_pending(classify, detail):
    assert classify(detail) is False


# ---------------------------------------------------------------- defaults

@pytest.mark.unit
@pytest.mark.parametrize("detail", ["", None, "something nobody anticipated"])
def test_unrecognised_failures_default_to_retryable(classify, detail):
    """Fail toward keeping work, not discarding it.

    A wrong retry costs one dispatch slot next cycle. A wrong retirement drops a
    recommendation with no operator-visible trace. The attempt counter is what
    bounds the downside of this default.
    """
    assert classify(detail) is False


@pytest.mark.unit
def test_a_5xx_is_not_misread_as_permanent_because_it_contains_a_4(classify):
    """Guards the numeric parse rather than a substring match on "4"."""
    assert classify("HTTP 504: Gateway Timeout") is False
    assert classify("HTTP 401: Unauthorized") is True


@pytest.mark.unit
def test_permanent_marker_wins_over_a_transient_looking_code(classify):
    """A 400 naming an unroutable tool is permanent even though 'timeout'
    appears elsewhere in the payload."""
    assert classify(
        "Kali HTTP 400: {\"detail\":\"Tool 'nc' is not in allowed list\","
        "\"hint\":\"timeout unrelated\"}"
    ) is True
