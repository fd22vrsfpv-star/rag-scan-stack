"""Scan initiators must be bounded by the engagement's concurrency limit.

Run on demand:

    pytest tests/test_scan_concurrency.py -v

WHY THIS EXISTS
---------------
Nothing bounded the tool runners. A caller could submit fifty jobs and fifty
tools would start — which is how the recommender's fan-out saturated the stack:
one call per open port, each launching a tool, each producing output that
triggered more calls, until dispatches timed out and were recorded as failures
for scans that had actually started.

The ceiling is MAX_CONCURRENT_SCANS, the number the operator already sets for
the engagement, rather than a new per-service knob.

Runs entirely in-process with a fake subprocess: no containers, no network, and
no real scanning.
"""
import importlib.util
import os
import threading
import time

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
_MODULE = os.path.join(REPO, "common", "tool_job.py")

# The module under test pulls in third-party packages a bare checkout does not
# have. Two different things can go wrong and they must not look the same:
#   * the FILE is gone            -> a real defect, fail loudly
#   * a DEPENDENCY is missing     -> "cannot run here", skip
# A bare ModuleNotFoundError at collection time collapses both into a red suite,
# and a permanently red baseline makes a new failure invisible.
if not os.path.exists(_MODULE):
    raise AssertionError(f"{_MODULE} is missing — common/tool_job.py was moved or deleted")


def _load(limit):
    """Fresh import with MAX_CONCURRENT_SCANS set — the semaphore is built at
    import time, so it has to be re-imported per limit."""
    if not os.path.exists(_MODULE):              # pragma: no cover
        pytest.skip("common/tool_job.py not present")
    os.environ["MAX_CONCURRENT_SCANS"] = str(limit)
    spec = importlib.util.spec_from_file_location(f"tool_job_{limit}", _MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Tracker:
    """Records terminal job states so refusals can be asserted."""
    def __init__(self):
        self.failures = {}
    def update_job(self, job_id, **kw):
        if kw.get("status") == "failed":
            self.failures[job_id] = kw.get("error", "")
    def push_command(self, *a, **k): pass
    def update_progress(self, *a, **k): pass


def _run_many(monkeypatch, mod, count, hold=0.25, **overrides):
    """Run `count` jobs concurrently against a fake subprocess; return peak."""
    peak = 0
    lock = threading.Lock()

    def fake_run(cmd, **kw):
        nonlocal peak
        with lock:
            peak = max(peak, mod.active_slot_count())
        time.sleep(hold)
        class CP:
            returncode, stdout, stderr = 0, "", ""
        return CP()

    # monkeypatch, NOT `mod.subprocess.run = ...`.
    #
    # `mod` is a fresh module object, but `mod.subprocess` is the SHARED
    # subprocess module — so a bare assignment replaces subprocess.run for the
    # WHOLE test session and never restores it. That leak sat here harmlessly
    # until another test used subprocess.run and started failing with
    # "RuntimeError: tool exploded" from a test that had already finished.
    monkeypatch.setattr(mod.subprocess, "run", fake_run)
    tracker = overrides.pop("job_tracker", None) or _Tracker()
    kwargs = dict(tool="x", cmd=["true"], targets_file="", output_file="",
                  service_name="t", session_label="t", job_tracker=tracker,
                  emit_webhook_event=lambda *a, **k: None,
                  write_audit=lambda *a, **k: None,
                  ingest_results=lambda *a, **k: None)
    kwargs.update(overrides)
    threads = [threading.Thread(target=mod.run_tool_job,
                                kwargs=dict(job_id=f"j{i}", **kwargs))
               for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return peak, tracker


@pytest.mark.parametrize("limit", [1, 2, 3])
def test_concurrent_tools_never_exceed_the_limit(limit, monkeypatch):
    mod = _load(limit)
    peak, _ = _run_many(monkeypatch, mod, count=limit * 3, hold=0.15)
    assert peak <= limit, f"limit={limit} but {peak} tools ran at once"


def test_the_test_would_notice_an_unbounded_runner(monkeypatch):
    """Guards the guard: with a high limit the peak must actually exceed 1.

    If the fake never overlaps, the assertions above would pass against a
    completely unbounded runner and prove nothing.
    """
    mod = _load(8)
    peak, _ = _run_many(monkeypatch, mod, count=8, hold=0.3)
    assert peak > 1, (
        f"peak was {peak}: the jobs never ran concurrently, so the bound tests "
        "above cannot distinguish a working limiter from no limiter at all")


def test_limit_comes_from_the_engagement_setting():
    """Not a private knob — the same variable the rest of the stack uses."""
    mod = _load(4)
    assert mod.MAX_CONCURRENT_SCANS == 4


def test_a_refused_job_does_not_consume_a_slot(monkeypatch):
    """An out-of-scope job must not occupy capacity it never used."""
    mod = _load(2)
    tracker = _Tracker()
    peak, tracker = _run_many(monkeypatch, mod, count=4, hold=0.15, job_tracker=tracker,
        scope_refusal=lambda _tf: "out of scope")
    assert peak == 0, f"refused jobs ran a tool anyway (peak {peak})"
    assert len(tracker.failures) == 4
    assert all("Out of scope" in e for e in tracker.failures.values())
    # Slots must be back, not leaked by the early return.
    assert mod.active_slot_count() == 0, "refusal leaked a slot"


def test_slots_are_released_when_a_tool_fails(monkeypatch):
    """A crashing tool must not permanently consume capacity."""
    mod = _load(2)

    def boom(cmd, **kw):
        raise RuntimeError("tool exploded")
    # monkeypatch, NOT `mod.subprocess.run = ...`.
    #
    # `mod` is a fresh module object, but `mod.subprocess` is the SHARED
    # subprocess module — so a bare assignment replaces subprocess.run for the
    # WHOLE test session and never restores it. That leak sat here harmlessly
    # until another test used subprocess.run and started failing with
    # "RuntimeError: tool exploded" from a test that had already finished.
    monkeypatch.setattr(mod.subprocess, "run", boom)
    tracker = _Tracker()
    mod.run_tool_job(job_id="j", tool="x", cmd=["true"], targets_file="",
                     output_file="", service_name="t", session_label="t",
                     job_tracker=tracker, emit_webhook_event=lambda *a, **k: None,
                     write_audit=lambda *a, **k: None,
                     ingest_results=lambda *a, **k: None)
    assert mod.active_slot_count() == 0, "a failed job leaked its slot"
    assert tracker.failures, "failure was not recorded on the job"


# ── One number, and it has to reach the services that read it ──────────────
#
# Two halves of the same defect, found 2026-09-09:
#
#   * dashboard/bff/services/recon_agent.py had its own ceiling,
#     RECON_AGENT_MAX_CONCURRENT default 3, resolved at IMPORT time. Raising
#     MAX_CONCURRENT_SCANS did nothing to the recon agent, and the UI's
#     set_max_concurrent() could not move it at all.
#   * pentest-dashboard, autogen-agents and playwright-scanner were never
#     PASSED MAX_CONCURRENT_SCANS in docker-compose.yml. Their code reads it
#     with a hardcoded "5" default, and .env happened to say 5 — so the wiring
#     gap was invisible until someone changed the number.
#
# Static: reads the source and the compose file. No BFF import (it needs
# fastapi + the app package), no docker.
import re

# Genuinely optional: only the compose-wiring tests below need it, and the
# concurrency tests above must still run without it. The comment here used to
# say "guarded below" while the import was bare, so a runner without PyYAML got
# a COLLECTION ERROR and lost the whole module — including the tests that had no
# use for yaml at all.
try:
    import yaml as _yaml  # noqa: E402
except ModuleNotFoundError:  # pragma: no cover - depends on the runner
    _yaml = None

_COMPOSE = os.path.join(REPO, "docker-compose.yml")
_RECON = os.path.join(REPO, "dashboard", "bff", "services", "recon_agent.py")

# Anything that means "this code consults the shared ceiling".
_LIMIT_MARKERS = ("MAX_CONCURRENT_SCANS", "get_max_concurrent", "run_tool_job",
                  "async_scan_slot", "scan_slot")

# Services bounded through a RUNTIME MOUNT of common/tool_job.py: their build
# context does not contain the marker, so scanning the source cannot see it.
#
# They are REQUIRED to have the env var, not exempt from the check. The first
# version of this list exempted them, and a sabotage that stripped the variable
# from web-scanner passed — these six are precisely the ones an earlier session
# bounded on purpose, so silently dropping their ceiling is the regression most
# worth catching.
_BOUNDED_VIA_MOUNTED_COMMON = {
    "pd-runner", "osint-runner", "web-scanner", "nmap_scanner",
    "brutus-runner", "node-manager",
}


def _read_compose():
    if _yaml is None:
        pytest.skip("PyYAML not installed; compose wiring cannot be parsed here")
    if not os.path.exists(_COMPOSE):
        pytest.skip("docker-compose.yml not present")
    with open(_COMPOSE, encoding="utf-8") as fh:
        return _yaml.safe_load(fh)["services"]


def _env_of(cfg):
    env = (cfg or {}).get("environment") or {}
    if isinstance(env, list):
        env = {e.split("=")[0]: (e.split("=", 1)[1] if "=" in e else "")
               for e in env}
    return env


def _build_root(cfg):
    build = (cfg or {}).get("build")
    if isinstance(build, dict):
        return (build.get("context") or "").lstrip("./")
    if isinstance(build, str):
        return build.lstrip("./")
    return ""


def _reads_the_limit(root):
    full = os.path.join(REPO, root)
    if not root or not os.path.isdir(full):
        return False
    for dirpath, dirnames, filenames in os.walk(full):
        dirnames[:] = [d for d in dirnames
                       if d not in {"__pycache__", "node_modules", ".git", "tests"}]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            try:
                with open(os.path.join(dirpath, fn), encoding="utf-8",
                          errors="ignore") as fh:
                    src = fh.read()
            except OSError:                       # pragma: no cover
                continue
            if any(m in src for m in _LIMIT_MARKERS):
                return True
    return False


def test_services_that_read_the_limit_are_given_it():
    """A service that reads MAX_CONCURRENT_SCANS but is not passed it silently
    uses its hardcoded default, so the operator's number does not apply to it.

    This is the ratchet: a new service that consults the ceiling fails here
    until docker-compose.yml passes it in.
    """
    services = _read_compose()
    required = {n for n, cfg in services.items()
                if _reads_the_limit(_build_root(cfg))}
    required |= _BOUNDED_VIA_MOUNTED_COMMON & set(services)
    assert len(required) >= 8, (
        f"only {len(required)} services detected as reading the ceiling — the "
        "marker scan is broken and this guard would pass vacuously"
    )
    missing = [n for n in required
               if "MAX_CONCURRENT_SCANS" not in _env_of(services[n])]
    assert not missing, (
        "these services read the shared concurrency ceiling but are never "
        "passed MAX_CONCURRENT_SCANS in docker-compose.yml, so they use a "
        "hardcoded default and ignore what the operator set:\n  "
        + "\n  ".join(sorted(missing))
    )


def test_the_recon_agent_has_no_private_ceiling():
    """It may narrow the shared cap, never replace or exceed it."""
    if not os.path.exists(_RECON):
        pytest.skip("recon_agent.py not present")
    with open(_RECON, encoding="utf-8") as fh:
        src = fh.read()
    code = "\n".join(ln for ln in src.splitlines()
                     if not ln.strip().startswith("#"))

    assert "get_max_concurrent" in code, (
        "recon_agent.py never consults the shared ceiling "
        "(routers.scans.get_max_concurrent)"
    )
    # A private knob is fine only as a bound applied WITH the shared value.
    own = re.search(r"^_RECON_OWN_CAP\s*=\s*(.+)$", code, re.M)
    if own:
        assert "min(" in code, (
            "recon_agent.py has a private cap but never takes the min() of it "
            "and the shared ceiling, so it can exceed the operator's limit"
        )
        assert not own.group(1).lstrip().startswith("int("), (
            "the private override is resolved as an int with a DEFAULT, which "
            "makes it a private number again — it must be optional (unset "
            "means 'use the shared ceiling')"
        )
    assert not re.search(r"^MAX_CONCURRENT_RECON_SCANS\s*=", code, re.M), (
        "MAX_CONCURRENT_RECON_SCANS is back: a module-level absolute ceiling, "
        "resolved at import time, that the operator's MAX_CONCURRENT_SCANS and "
        "the UI's set_max_concurrent() cannot move"
    )


def test_the_ceiling_is_read_at_call_time():
    """set_max_concurrent() rebinds the BFF's module global, so a value bound
    at import ignores every runtime change the operator makes."""
    if not os.path.exists(_RECON):
        pytest.skip("recon_agent.py not present")
    with open(_RECON, encoding="utf-8") as fh:
        src = fh.read()
    fn = re.search(r"def _recon_concurrency\(\).*?(?=\n\n\n|\nclass |\ndef )",
                   src, re.S)
    assert fn, "no _recon_concurrency() accessor in recon_agent.py"
    assert "get_max_concurrent()" in fn.group(0), (
        "_recon_concurrency() does not call get_max_concurrent(), so the "
        "ceiling is not resolved per call"
    )
    # Every use must go through the accessor, not a cached module global.
    users = re.findall(r"^\s*(?:if|kb_budget|max_concurrent)\b.*", src, re.M)
    assert any("_recon_concurrency()" in u for u in users), (
        "no call site uses _recon_concurrency()"
    )
