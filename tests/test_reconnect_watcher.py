"""Executing tests for the Tier 1 reconnect watcher.

Run on demand:

    pytest tests/test_reconnect_watcher.py -v

WHY THIS EXISTS
---------------
A host reboot (patching) kills every live shell on it. The one access that can
come back on its own is `ssh_credential`, because refresh() re-opens SSH with the
stored credential. This watcher automates that re-probe. The rules it MUST obey:

  1. Scope gate, FAIL CLOSED — a refusal means refresh() never runs and the
     target is never touched. `test_scope_refusal_blocks_refresh`.
  2. A dead->live transition is MEASURED, not assumed — recovery is the
     intersection of what was dead before and live after.
     `test_recovered_access_emits_reconnected`.
  3. Nothing recovered emits a failure event, not a success.
     `test_no_recovery_emits_failed`.
  4. A target is retried no more often than MIN_ATTEMPT_INTERVAL.
     `test_throttle_skips_recent_target`.

SABOTAGE PROOF
--------------
Make `_reconnect_target` call refresh() before checking `_scope_refusal` and
`test_scope_refusal_blocks_refresh` fails (refresh ran while out of scope). Make
recovery ignore `dead_before` and count any live row and
`test_no_recovery_emits_failed` fails (a pre-existing live shell reads as a
reconnect).
"""
import asyncio
import os
import sys
import types

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "autogen_agents"))

rw = pytest.importorskip("reconnect_watcher",
                         reason="reconnect_watcher not importable (missing deps)")


def _install_fake_etl_access(monkeypatch, refresh_fn):
    """Make `from etl import access as ax` resolve to a stub with our refresh."""
    etl_mod = types.ModuleType("etl")
    access_mod = types.ModuleType("etl.access")
    access_mod.refresh = refresh_fn
    etl_mod.access = access_mod
    monkeypatch.setitem(sys.modules, "etl", etl_mod)
    monkeypatch.setitem(sys.modules, "etl.access", access_mod)


def _capture_webhooks(monkeypatch):
    events = []
    monkeypatch.setattr(rw, "_emit_webhook",
                        lambda et, data: events.append((et, data)))
    return events


def test_scope_refusal_blocks_refresh(monkeypatch):
    """Out of scope => refresh() is never called and a block event is emitted."""
    events = _capture_webhooks(monkeypatch)
    called = {"refresh": 0}

    def _refresh(*a, **k):
        called["refresh"] += 1
        return {"discovered": 1, "live": 1, "best": None}

    _install_fake_etl_access(monkeypatch, _refresh)
    w = rw.ReconnectWatcher()
    monkeypatch.setattr(w, "_scope_refusal",
                        lambda t, e: "target 192.168.1.150 is not in the configured scope")
    # If the gate were bypassed this stub would report a dead->live recovery.
    monkeypatch.setattr(w, "_access_state",
                        lambda t: {"dead": {("ssh_credential", "root:x")},
                                   "live": {("ssh_credential", "root:x")}})

    result = asyncio.run(w._reconnect_target("192.168.1.150", "eng-1"))

    assert called["refresh"] == 0, "refresh ran despite an out-of-scope refusal"
    assert "blocked" in result
    kinds = [et for et, _ in events]
    assert "access_reconnect_blocked" in kinds
    assert "access_reconnected" not in kinds


def test_recovered_access_emits_reconnected(monkeypatch):
    """A credential that was dead and answers after refresh counts as recovered."""
    events = _capture_webhooks(monkeypatch)
    _install_fake_etl_access(
        monkeypatch,
        lambda *a, **k: {"discovered": 2, "live": 1, "best": {"kind": "ssh_credential"}})

    w = rw.ReconnectWatcher()
    monkeypatch.setattr(w, "_scope_refusal", lambda t, e: None)

    states = iter([
        {"dead": {("ssh_credential", "root:x"), ("msf_session", "3")}, "live": set()},
        {"dead": {("msf_session", "3")}, "live": {("ssh_credential", "root:x")}},
    ])
    monkeypatch.setattr(w, "_access_state", lambda t: next(states))

    result = asyncio.run(w._reconnect_target("192.168.1.150", "eng-1"))

    assert result["recovered"] == 1
    assert result["kinds"] == ["ssh_credential"]
    payload = dict(events)["access_reconnected"]
    assert payload["recovered"] == 1
    assert payload["recovered_kinds"] == ["ssh_credential"]
    assert w._reconnected_total == 1


def test_no_recovery_emits_failed(monkeypatch):
    """A msf_session dead before and still dead after is NOT a reconnect."""
    events = _capture_webhooks(monkeypatch)
    _install_fake_etl_access(
        monkeypatch,
        lambda *a, **k: {"discovered": 1, "live": 0, "best": None})

    w = rw.ReconnectWatcher()
    monkeypatch.setattr(w, "_scope_refusal", lambda t, e: None)
    # A pre-existing live row that was NEVER dead must not read as recovered.
    monkeypatch.setattr(w, "_access_state",
                        lambda t: {"dead": {("msf_session", "3")},
                                   "live": {("bind_shell", "1524")}})

    result = asyncio.run(w._reconnect_target("192.168.1.150", "eng-1"))

    assert result["recovered"] == 0
    kinds = [et for et, _ in events]
    assert "access_reconnect_failed" in kinds
    assert "access_reconnected" not in kinds
    assert w._reconnected_total == 0


def test_throttle_skips_recent_target(monkeypatch):
    """A target attempted within MIN_ATTEMPT_INTERVAL is skipped, no refresh."""
    _capture_webhooks(monkeypatch)
    called = {"refresh": 0}
    _install_fake_etl_access(
        monkeypatch,
        lambda *a, **k: called.__setitem__("refresh", called["refresh"] + 1) or {})

    w = rw.ReconnectWatcher()
    monkeypatch.setattr(w, "_scope_refusal", lambda t, e: None)
    monkeypatch.setattr(w, "_access_state", lambda t: {"dead": set(), "live": set()})

    from datetime import datetime, timezone
    w._last_attempt["192.168.1.150"] = datetime.now(timezone.utc).timestamp()

    result = asyncio.run(w._reconnect_target("192.168.1.150", "eng-1"))

    assert result.get("skipped") == "throttled"
    assert called["refresh"] == 0


def test_watcher_module_is_scope_gated_and_emits():
    """Guard: the module must reference the scope gate and the webhook emitter.
    Deleting either would let it touch hosts silently — this fails if it does."""
    src = open(os.path.join(REPO, "autogen_agents", "reconnect_watcher.py"),
               encoding="utf-8").read()
    assert "scope_gate" in src, "reconnect watcher no longer references the scope gate"
    assert "check_dispatch" in src, "reconnect watcher no longer calls check_dispatch"
    assert "/webhooks/emit" in src, "reconnect watcher no longer emits webhooks"
