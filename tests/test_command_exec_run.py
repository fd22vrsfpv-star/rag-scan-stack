"""POST /command-exec/run — run a follow-up command through a proven command-exec
capability (webshell handle / live session / one-shot MSF module re-invoke).

Exercises the endpoint's guards without needing a live exploit: empty command ->
400, out-of-scope target -> 403 (fail-closed), unresolvable capability -> 422.
Hits the live exploit-runner; skips cleanly when it is unreachable.

    EXPLOIT_RUNNER_URL=https://localhost:8017 pytest tests/test_command_exec_run.py
"""
import os
import re
import pathlib

import pytest

requests = pytest.importorskip("requests")

BASE = os.environ.get("EXPLOIT_RUNNER_URL", "https://exploit-runner:8017")


def _key():
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def _post(body):
    try:
        return requests.post(f"{BASE}/command-exec/run", json=body,
                             headers={"x-api-key": _key()}, timeout=30, verify=False)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def test_empty_command_rejected():
    r = _post({"target": "192.0.2.1", "command": ""})
    if r.status_code in (401, 403) and "scope" not in r.text.lower():
        pytest.skip("auth required")
    assert r.status_code == 400, f"{r.status_code} {r.text[:200]}"


def test_out_of_scope_refused():
    # TEST-NET-1 is not in any engagement scope -> fail closed.
    r = _post({"target": "192.0.2.123", "command": "id"})
    if r.status_code in (401,):
        pytest.skip("auth required")
    assert r.status_code == 403, f"expected scope refusal, got {r.status_code} {r.text[:200]}"
    assert "scope" in r.text.lower()


def test_no_capability_is_422_or_403():
    # A target with no resolvable capability and (likely) out of scope: never 200.
    r = _post({"target": "192.0.2.200", "command": "id"})
    if r.status_code in (401,):
        pytest.skip("auth required")
    assert r.status_code in (403, 422), f"{r.status_code} {r.text[:200]}"
