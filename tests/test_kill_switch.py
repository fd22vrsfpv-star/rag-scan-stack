"""Global kill-switch: a halt must refuse every gated dispatch.

The switch is enforced at ONE chokepoint — etl/scope_gate.load_dispatch_scope
returns ([], "halted") when the platform is halted, and every caller treats an
empty scope as "refuse" (fail-closed). This pins that behaviour with a fake
cursor (offline) and round-trips the live control endpoints when a stack is up.

Sabotage: make load_dispatch_scope ignore is_halted -> test_halt_empties_the_
dispatch_scope RED (a halt would then leak scope rows and dispatch would run).
"""
import os
import re
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(REPO))

try:
    from etl import scope_gate as sg
except Exception as e:  # pragma: no cover
    pytest.skip(f"etl.scope_gate not importable: {e}", allow_module_level=True)


class FakeCursor:
    """Minimal cursor: answers the platform_control halt/budget queries and any
    scope_targets query from `scope_rows`."""
    def __init__(self, halted=False, reason="stop", scope_rows=None, over_budget=False):
        self.halted = halted
        self.reason = reason
        self.over = over_budget
        self.scope_rows = scope_rows if scope_rows is not None else [("1.2.3.4", "ip")]
        self._last = None

    def execute(self, sql, params=None):
        self._last = sql
        self._params = params

    def fetchone(self):
        if "platform_control" in self._last and "scan_budget" in self._last:
            # over_budget query
            return ("global", 5, 5) if self.over else None
        if "platform_control" in self._last:
            return ("global", self.reason) if self.halted else None
        return None

    def fetchall(self):
        if "scope_targets" in self._last:
            return list(self.scope_rows)
        return []


def test_is_halted_reads_the_flag():
    assert sg.is_halted(FakeCursor(halted=True, reason="pause"))[0] is True
    assert "pause" in sg.is_halted(FakeCursor(halted=True, reason="pause"))[1]
    assert sg.is_halted(FakeCursor(halted=False)) == (False, None)


def test_halt_empties_the_dispatch_scope():
    rows, source = sg.load_dispatch_scope(FakeCursor(halted=True))
    assert rows == [] and source == "halted", (
        "a halted platform must yield an EMPTY dispatch scope so every gated "
        "caller refuses; got rows=%r source=%r" % (rows, source))
    # and the fail-closed contract downstream: empty scope => refusal
    assert sg.check_dispatch("1.2.3.4", rows) is not None


def test_not_halted_returns_the_real_scope():
    rows, source = sg.load_dispatch_scope(FakeCursor(halted=False,
                                                     scope_rows=[("10.0.0.5", "ip")]))
    assert rows == [("10.0.0.5", "ip")] and source == "all-engagements"
    # a normal in-scope dispatch is allowed
    assert sg.check_dispatch("10.0.0.5", rows) is None


def test_over_budget_empties_the_dispatch_scope():
    assert sg.over_budget(FakeCursor(over_budget=True))[0] is True
    assert sg.over_budget(FakeCursor(over_budget=False)) == (False, None)
    rows, source = sg.load_dispatch_scope(FakeCursor(over_budget=True))
    assert rows == [] and source == "budget-exceeded", (
        "a scope past its scan_budget must yield an EMPTY dispatch scope so the "
        "autonomous loop stops; got rows=%r source=%r" % (rows, source))
    assert sg.check_dispatch("1.2.3.4", rows) is not None


# ── live control endpoints (skip without a stack) ────────────────────────────
BASE = os.environ.get("CTRL_URL", "https://localhost:8000")


def _key():
    env = REPO / ".env"
    if env.exists():
        m = re.search(r"^API_KEY=(.*)$", env.read_text(), re.M)
        if m:
            return m.group(1).strip()
    return os.environ.get("API_KEY", "changeme")


def _req(method, path, body=None):
    requests = pytest.importorskip("requests")
    try:
        return requests.request(method, f"{BASE}{path}",
                                headers={"x-api-key": _key(), "content-type": "application/json"},
                                json=body, timeout=15, verify=False)
    except Exception as e:
        pytest.skip(f"{BASE} unreachable: {type(e).__name__}")


def test_halt_status_resume_roundtrip():
    # use an engagement-scoped halt so we never disturb the global switch
    scope = "pytest-killswitch-scope"
    try:
        h = _req("POST", "/control/halt", {"scope": scope, "reason": "pytest"})
        if h.status_code in (401, 403):
            pytest.skip("auth required")
        assert h.status_code == 200 and h.json().get("halted") is True
        st = _req("GET", f"/control/status?engagement_id={scope}")
        assert st.status_code == 200 and st.json().get("halted") is True
        r = _req("POST", "/control/resume", {"scope": scope})
        assert r.status_code == 200 and r.json().get("halted") is False
        st2 = _req("GET", f"/control/status?engagement_id={scope}")
        assert st2.json().get("halted") is False
    finally:
        _req("POST", "/control/resume", {"scope": scope})


def test_budget_counts_and_reports_over():
    scope = "pytest-budget-scope"
    try:
        b = _req("POST", "/control/budget", {"scope": scope, "scan_budget": 2})
        if b.status_code in (401, 403):
            pytest.skip("auth required")
        assert b.status_code == 200 and b.json().get("scans_used") == 0
        n1 = _req("POST", "/control/note-dispatch", {"engagement_id": scope, "count": 1})
        assert n1.json().get("over_budget") is False
        n2 = _req("POST", "/control/note-dispatch", {"engagement_id": scope, "count": 1})
        assert n2.json().get("over_budget") is True, "2/2 dispatches must be over budget"
    finally:
        # clear the budget (also resets used to 0) and remove the test row
        _req("POST", "/control/budget", {"scope": scope, "scan_budget": None})
