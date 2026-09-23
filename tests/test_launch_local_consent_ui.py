"""The BFF's 409 "confirm local execution" must be answered by the UI.

WHY THIS EXISTS
---------------
The BFF asks before running a passive-but-disclosing scan without a proxy: it
returns 409 with `needs_confirmation` and the caller re-sends with
`allow_local: true`. Shipping the asking half without the answering half is
strictly worse than the silent pass it replaced -- `block_local_scans` is TRUE
in this deployment, so ten tools that previously just ran (subfinder, dnsx,
crtsh, uncover, chaos, vulnx, recon-pipeline, greyhatwarfare, whois,
cloud-tenant) surfaced an unexplained API error instead. That regression is
exactly what this pins.

It is checked from the Python suite because there is no vitest job that runs on
every change, and the frontend half is the half that was missing.

SABOTAGE PROOF
--------------
* Remove the `allow_local: true` retry from useLaunchScan -> test_the_hook_retries_with_consent fails.
* Drop `status` from ApiError -> test_api_errors_keep_their_status fails.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
CLIENT = os.path.join(REPO, "dashboard", "frontend", "src", "api", "client.ts")
SCANS_API = os.path.join(REPO, "dashboard", "frontend", "src", "api", "scans.ts")
BFF = os.path.join(REPO, "dashboard", "bff", "routers", "scans.py")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{os.path.basename(path)} not present")
    return open(path, encoding="utf-8").read()


def _code(path):
    """Source with comments removed.

    Asserting on raw text is defeated by this repo's own habit of EXPLAINING the
    thing being asserted: the doc comment above useLaunchScan contains the
    literal `allow_local: true`, so a substring check passed while the actual
    retry had been sabotaged away. Strip comments and assert on code.
    """
    src = _read(path)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)      # block comments
    src = re.sub(r"(?m)^\s*//.*$", "", src)               # whole-line //
    src = re.sub(r"(?m)([^:'\"])//.*$", r"\1", src)        # trailing //
    return src


def test_api_errors_keep_their_status():
    """Without the status code the caller cannot tell 409 from any other failure
    except by regexing the message, which is how this stays broken."""
    src = _read(CLIENT)
    assert "class ApiError" in src, "there is no typed API error"
    assert re.search(r"readonly status\s*:\s*number", src), (
        "ApiError does not carry the HTTP status")
    assert "JSON.parse(text)" in src, (
        "the error body is never decoded, so the server's structured detail is "
        "thrown away")


def test_the_hook_asks_before_running_locally():
    src = _code(SCANS_API)
    assert "needs_confirmation" in src, (
        "the launch hook does not recognise the BFF's confirmation request, so "
        "it reaches the operator as a bare API error")
    assert "window.confirm" in src, "nothing actually asks the operator"


def test_the_hook_retries_with_consent():
    """A yes must re-send the SAME request with the consent flag."""
    src = _code(SCANS_API)
    assert "allow_local: true" in src, (
        "answering the prompt does not re-send with allow_local, so saying yes "
        "changes nothing")


def test_a_no_does_not_launch():
    src = _code(SCANS_API)
    assert re.search(r"if\s*\(\s*!window\.confirm", src), (
        "the confirm result is not checked — declining would still launch")


def test_other_errors_are_not_swallowed():
    """The catch must rethrow anything that is not this specific 409."""
    src = _code(SCANS_API)
    assert re.search(r"if\s*\(\s*!question\s*\)\s*throw", src), (
        "the launch hook swallows non-409 errors, so real failures disappear")


def test_the_two_halves_agree_on_the_flag_name():
    """The BFF names the field in `retry_with`; the UI must send that name."""
    bff = _read(BFF)
    ui = _code(SCANS_API)
    assert "allow_local" in bff, "the BFF no longer accepts a consent flag"
    assert "allow_local" in ui, "the UI no longer sends one"


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
