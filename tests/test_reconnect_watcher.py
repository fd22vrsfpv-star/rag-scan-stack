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


def test_live_shell_that_died_is_detected_as_dropped(monkeypatch):
    """GAP 2: a live shell that stops answering is flipped to dead and emits
    access_dropped — NOT a reconnect failure (nothing was dead before)."""
    events = _capture_webhooks(monkeypatch)
    _install_fake_etl_access(
        monkeypatch, lambda *a, **k: {"discovered": 1, "live": 0, "best": None})
    w = rw.ReconnectWatcher()
    monkeypatch.setattr(w, "_scope_refusal", lambda t, e: None)
    states = iter([
        {"dead": set(), "live": {("msf_session", "3")}},   # before: live
        {"dead": {("msf_session", "3")}, "live": set()},   # after: died
    ])
    monkeypatch.setattr(w, "_access_state", lambda t: next(states))

    result = asyncio.run(w._reconnect_target("192.168.1.150", "eng-1"))

    assert result["dropped"] == 1
    kinds = [et for et, _ in events]
    assert "access_dropped" in kinds
    assert "access_reconnect_attempted" not in kinds   # nothing was dead before
    assert "access_reconnect_failed" not in kinds
    assert w._dropped_total == 1


def test_healthy_live_target_is_quiet(monkeypatch):
    """A live shell that still answers emits nothing — a liveness re-probe of a
    healthy target must not look like a reconnect attempt or failure."""
    events = _capture_webhooks(monkeypatch)
    _install_fake_etl_access(
        monkeypatch, lambda *a, **k: {"discovered": 1, "live": 1, "best": None})
    w = rw.ReconnectWatcher()
    monkeypatch.setattr(w, "_scope_refusal", lambda t, e: None)
    monkeypatch.setattr(w, "_access_state",
                        lambda t: {"dead": set(), "live": {("ssh_credential", "root:x")}})

    result = asyncio.run(w._reconnect_target("192.168.1.150", "eng-1"))

    assert result["recovered"] == 0 and result["dropped"] == 0
    assert events == []   # completely silent for a healthy target
    assert w._probes_total == 1


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


def test_persisted_toggle_overrides_default(monkeypatch):
    """The operator toggle in app_settings wins over the env default, and an
    unset value falls back to the default — enabling/disabling without a restart."""
    w = rw.ReconnectWatcher()

    # Explicit off wins even though the env default is on.
    monkeypatch.setattr(w, "_read_settings",
                        lambda: {"reconnect_watcher.enabled": "false"})
    assert w.is_enabled() is False

    # Explicit on.
    monkeypatch.setattr(w, "_read_settings",
                        lambda: {"reconnect_watcher.enabled": "true"})
    assert w.is_enabled() is True

    # Unset => the env-derived default (ENABLED_DEFAULT).
    monkeypatch.setattr(w, "_read_settings", lambda: {})
    assert w.is_enabled() is rw.ENABLED_DEFAULT


def test_effective_config_reads_overrides(monkeypatch):
    """poll_interval / min_attempt_interval come from settings when present,
    clamped to a sane floor, else the env defaults."""
    w = rw.ReconnectWatcher()
    monkeypatch.setattr(w, "_read_settings", lambda: {
        "reconnect_watcher.poll_interval": "45",
        "reconnect_watcher.min_attempt_interval": "600",
    })
    cfg = w._effective_config()
    assert cfg["poll_interval"] == 45
    assert cfg["min_attempt_interval"] == 600

    # Garbage / below floor falls back or clamps, never crashes.
    monkeypatch.setattr(w, "_read_settings", lambda: {
        "reconnect_watcher.poll_interval": "nonsense",
        "reconnect_watcher.min_attempt_interval": "5",
    })
    cfg = w._effective_config()
    assert cfg["poll_interval"] == rw.POLL_INTERVAL
    assert cfg["min_attempt_interval"] == 30  # clamped to floor


def test_watcher_module_is_scope_gated_and_emits():
    """Guard: the module must reference the scope gate and the webhook emitter.
    Deleting either would let it touch hosts silently — this fails if it does."""
    src = open(os.path.join(REPO, "autogen_agents", "reconnect_watcher.py"),
               encoding="utf-8").read()
    assert "scope_gate" in src, "reconnect watcher no longer references the scope gate"
    assert "check_dispatch" in src, "reconnect watcher no longer calls check_dispatch"
    assert "/webhooks/emit" in src, "reconnect watcher no longer emits webhooks"


def test_settings_keys_are_namespaced_no_pk_collision():
    """app_settings.key is a GLOBAL primary key. A bare 'enabled'/'poll_interval'
    would clobber the exploit watcher's rows, so every reconnect key MUST carry the
    namespace. Drop the prefix and this fails."""
    keys = [rw._KEY_ENABLED, rw._KEY_POLL, rw._KEY_MIN_INTERVAL]
    bare_collisions = {"enabled", "poll_interval", "lookback_minutes",
                       "min_confidence", "max_exploits_per_vuln", "min_attempt_interval"}
    for k in keys:
        assert k.startswith("reconnect_watcher."), f"key {k!r} is not namespaced"
        assert k not in bare_collisions, f"key {k!r} collides with an exploit-watcher key"
    assert len(set(keys)) == 3, "namespaced keys must be distinct"


def test_ragapi_store_writes_the_keys_the_watcher_reads():
    """Agreement: the rag-api settings store and the watcher must use the SAME
    namespaced keys, or the toggle writes rows the watcher never reads. Pin both
    sides to the watcher's constants."""
    api = os.path.join(REPO, "app", "rag-api", "api.py")
    if not os.path.exists(api):
        pytest.skip("rag-api/api.py not present")
    src = open(api, encoding="utf-8").read()
    for k in (rw._KEY_ENABLED, rw._KEY_POLL, rw._KEY_MIN_INTERVAL):
        assert k in src, f"rag-api store does not write the watcher's key {k!r}"
