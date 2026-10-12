"""Every service that sends traffic to a scan target must be on `test_net`.

Scan targets live on `test_net`. A service that executes tools but is not
attached to it has no route to a target address, so its packets are DROPPED
rather than refused: curl blocks for the full connect timeout (~135 s observed)
and reports "Failed to connect ... Could not connect to server". That is
indistinguishable from a target being down, and it is NOT what a refused
connection looks like (those return in milliseconds).

The failure is especially hard to see because `rag-api` is on BOTH networks:
its own prerun probe reaches the target and logs an HTTP status, while the tool
command dispatched to the listener times out on the same host, port and second.
Two containers, two routing tables, one confusing trace.

Reachability is NOT the authorization boundary -- `etl/scope_gate.py` is, and it
is bind-mounted into these containers. Removing a service from `test_net` does
not make it safer; it makes it broken in a way that reads as "target down".

*Enforced by:* this file.
*Why:* `kali-listener` -- the container that actually runs build-PoC commands --
declared only `agents_net`, while every sibling tool runner declared
`agents_net` + `test_net`. A focused-10 CVE-Bench run reported
`stop=target_unreachable` for 5 of 10 CVEs whose targets were up and serving;
from `rag-api` the same URL answered in 0.16 ms, from `kali-listener` it timed
out after 30 s having never completed a TCP connect.
"""
import os

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml not installed here")

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
COMPOSE = os.path.join(REPO, "docker-compose.yml")
TARGET_NET = "test_net"

# Services that send traffic to a scan target, each with why. A service here
# MUST declare TARGET_NET. Add a service when it starts dispatching tools;
# remove one only when it genuinely stops touching targets.
TARGET_REACHING = {
    "kali-listener": "runs build-PoC commands and generic tool execution",
    "exploit-runner": "executes exploit modules and command-exec against hosts",
    "nmap_scanner": "port/service scanning",
    "nuclei-runner": "template scanning",
    "web-scanner": "web content discovery and probes",
    "zap": "proxy + active/passive web scanning",
    "playwright-scanner": "browser crawl of target apps",
    "brutus-runner": "credential checks against services",
    "osint-runner": "service enumeration against hosts",
    "pd-runner": "tool dispatch against hosts",
    "rag-api": "prerun probes and recon fetches",
}


def _services():
    if not os.path.exists(COMPOSE):
        pytest.skip("docker-compose.yml not present")
    with open(COMPOSE, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return (doc or {}).get("services") or {}


def _networks_of(svc):
    nets = svc.get("networks")
    if nets is None:
        return []
    if isinstance(nets, dict):      # mapping form: {test_net: {...}}
        return list(nets)
    return [str(n) for n in nets]   # list form


def test_target_reaching_services_are_on_test_net():
    """A tool runner off test_net blackholes on every target address."""
    services = _services()
    missing = []
    for name, why in sorted(TARGET_REACHING.items()):
        svc = services.get(name)
        if svc is None:
            continue  # service not in this compose file; nothing to assert
        if TARGET_NET not in _networks_of(svc):
            missing.append(f"{name} ({why}) declares {_networks_of(svc)}")
    assert not missing, (
        f"these services send traffic to targets but are not on '{TARGET_NET}', "
        "so every connection to a target address will hang until timeout "
        "rather than fail fast:\n  " + "\n  ".join(missing)
    )


def test_harness_is_not_vacuous():
    """The guard must actually be inspecting real services."""
    services = _services()
    found = [n for n in TARGET_REACHING if n in services]
    assert len(found) >= 5, (
        f"only {len(found)} declared target-reaching services found in "
        f"docker-compose.yml ({found}); the guard is not inspecting the real "
        "service set"
    )
    # And the network itself must be declared.
    with open(COMPOSE, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    assert TARGET_NET in ((doc or {}).get("networks") or {}), (
        f"'{TARGET_NET}' is not declared in the compose file's networks block"
    )


def test_declared_services_exist():
    """A name in TARGET_REACHING that no longer exists should be removed."""
    services = _services()
    unknown = sorted(n for n in TARGET_REACHING if n not in services)
    assert not unknown, (
        "TARGET_REACHING names services that are not in docker-compose.yml; "
        "delete them or fix the spelling:\n  " + "\n  ".join(unknown)
    )
