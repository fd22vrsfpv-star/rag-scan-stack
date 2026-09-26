"""Container-logs auto-discovery: the log viewer and service control must pick
up EVERY container in this compose project automatically, not a hand-maintained
allow-list of two.

Regression: container_logs.MONITORED_CONTAINERS listed only {zap, metasploit},
so the dashboard log viewer returned "Unknown container: autogen-agents" for
every other service and PROFILE_CONTAINERS silently omitted live services
(news-runner, burp-mcp-proxy, ...). These tests pin the dynamic behaviour:
discovery filters by the compose-project label, the log-target set is the union
of discovered + curated, and a brand-new service is both viewable and
controllable with no code change.

Runs standalone and skips cleanly where the service's deps (fastapi/docker) are
absent — importing the module is done with the docker socket mocked, so no real
Docker is required.
"""
import importlib.util
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

CL_PATH = Path(__file__).parent.parent / "container_logs" / "container_logs.py"


def _load_module():
    """Import container_logs.py with the docker SDK mocked (no real socket)."""
    fake_docker = types.ModuleType("docker")
    fake_docker.from_env = lambda: MagicMock()
    errors_mod = types.ModuleType("docker.errors")

    class NotFound(Exception):
        ...

    errors_mod.NotFound = NotFound
    fake_docker.errors = errors_mod
    sys.modules["docker"] = fake_docker
    sys.modules["docker.errors"] = errors_mod

    spec = importlib.util.spec_from_file_location("container_logs_under_test", CL_PATH)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:  # fastapi/pydantic/etc. not installed here
        pytest.skip(f"cannot import container_logs (deps missing): {e}")
    return mod


class _FakeContainer:
    def __init__(self, name, service, status="running", project="proj"):
        self.name = name
        self.short_id = name[:12]
        self.status = status
        self.labels = {
            "com.docker.compose.project": project,
            "com.docker.compose.service": service,
        }


def _client_with(containers):
    client = MagicMock()
    client.containers.list.return_value = containers
    return client


def test_discovery_filters_by_compose_project(monkeypatch):
    mod = _load_module()
    client = _client_with([])
    monkeypatch.setattr(mod, "docker_client", client)
    monkeypatch.setattr(mod, "COMPOSE_PROJECT", "myproj")

    mod._discover_project_containers()

    _, kwargs = client.containers.list.call_args
    assert kwargs["all"] is True, "must include stopped/exited containers"
    assert kwargs["filters"]["label"] == "com.docker.compose.project=myproj"


def test_log_targets_union_of_discovered_and_curated(monkeypatch):
    mod = _load_module()
    client = _client_with([
        _FakeContainer("autogen-agents", "autogen-agents"),
        _FakeContainer("exploit-runner", "exploit-runner"),
        _FakeContainer("brand-new-svc", "brand-new-svc"),
    ])
    monkeypatch.setattr(mod, "docker_client", client)
    monkeypatch.setattr(mod, "COMPOSE_PROJECT", "proj")

    targets = mod._log_targets()

    # Discovered non-curated services are viewable (the original bug).
    assert "autogen-agents" in targets
    assert "exploit-runner" in targets
    # A service that isn't curated anywhere still shows up automatically.
    assert "brand-new-svc" in targets
    # Curated entries are always present, even if not currently running.
    assert "zap" in targets and "metasploit" in targets
    # Every target carries a colour + description.
    for cfg in targets.values():
        assert cfg["color"] and cfg["description"]


def test_managed_names_includes_discovered_and_curated(monkeypatch):
    mod = _load_module()
    client = _client_with([_FakeContainer("brand-new-svc", "brand-new-svc")])
    monkeypatch.setattr(mod, "docker_client", client)
    monkeypatch.setattr(mod, "COMPOSE_PROJECT", "proj")

    names = mod._managed_names()

    assert "brand-new-svc" in names          # auto-discovered → controllable
    assert "rag-api" in names                 # curated baseline preserved


def test_profile_containers_cover_live_services(monkeypatch):
    """The curated grouping must include the services that were silently missing."""
    mod = _load_module()
    grouped = {name for group in mod.PROFILE_CONTAINERS.values() for name in group}
    for svc in ("news-runner", "burp-mcp-proxy", "embedder-gpu",
                "wg-server", "vault", "host-helper"):
        assert svc in grouped, f"{svc} missing from PROFILE_CONTAINERS"


def test_discovery_fail_soft(monkeypatch):
    """A docker error yields {} rather than raising into a caller."""
    mod = _load_module()
    client = MagicMock()
    client.containers.list.side_effect = RuntimeError("docker down")
    monkeypatch.setattr(mod, "docker_client", client)
    monkeypatch.setattr(mod, "COMPOSE_PROJECT", "proj")

    assert mod._discover_project_containers() == {}
    # _log_targets still returns the curated set when discovery fails.
    assert "zap" in mod._log_targets()
