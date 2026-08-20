"""Dispatch must refuse targets outside the engagement scope.

Run on demand:

    pytest tests/test_dispatch_scope.py -v

WHY THIS EXISTS
---------------
Dispatch had no scope check at all. Recommendations are generated from whatever
hosts turn up in scan output, so a redirect or a certificate SAN can put a third
party's address into the queue — and 14 recommendations targeting Cloudflare
addresses (104.20.44.163, 172.66.0.227) were sitting in the database, several
already marked completed. Scanning a host nobody authorised is the one failure
this tool must not have.

The BFF cannot import etl/scope_gate.py (it is not mounted into that container),
so the matching rules exist in two places. The final test here pins them
together on a shared table of cases so they cannot drift apart silently.
"""
import importlib.util
import os
import re

import pytest

# realpath, NOT a bare join: the unresolved form is ".../tests/..", whose
# own "/tests" segment matched the skip list below and caused the walk to
# skip EVERY file — the copy detector silently checked nothing.
REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
_GATE = os.path.join(REPO, "etl", "scope_gate.py")
_COMPOSE = os.path.join(REPO, "docker-compose.yml")

# Services that dispatch and therefore MUST be able to import the shared gate.
# A missing mount does not silently disable it — every gate fails closed — but
# that turns into "nothing runs", so the mount is worth asserting directly.
_DISPATCHING_SERVICES = (
    "kali-listener", "pentest-dashboard", "scan-recommender", "nmap_scanner",
    "pd-runner", "web-scanner", "osint-runner", "brutus-runner",
)


@pytest.fixture(scope="module")
def gate():
    if not os.path.exists(_GATE):                # pragma: no cover
        pytest.skip("scope_gate.py not present")
    spec = importlib.util.spec_from_file_location("scope_gate", _GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def in_scope(gate):
    """The single matcher. Was three copies; now one shared via the ./etl mount."""
    return gate.is_in_scope


SCOPE = [("192.168.1.150", "ip"), ("10.10.0.0/16", "cidr"), ("example.com", "domain")]


def test_exact_ip_is_in_scope(in_scope):
    assert in_scope("192.168.1.150", SCOPE) is True


@pytest.mark.parametrize("host", ["104.20.44.163", "172.66.0.227"])
def test_the_real_out_of_scope_hosts_are_refused(in_scope, host):
    """The exact Cloudflare addresses that were queued against this engagement."""
    assert in_scope(host, SCOPE) is False


def test_cidr_membership(in_scope):
    assert in_scope("10.10.5.9", SCOPE) is True
    assert in_scope("10.11.5.9", SCOPE) is False


def test_domain_and_subdomain(in_scope):
    assert in_scope("example.com", SCOPE) is True
    assert in_scope("api.example.com", SCOPE) is True
    assert in_scope("notexample.com", SCOPE) is False


def test_empty_scope_refuses_everything(in_scope):
    """Fail closed. An unconfigured scope must not mean 'scan anything' — that
    turns a setup mistake into unauthorised traffic."""
    assert in_scope("192.168.1.150", []) is False
    assert in_scope("192.168.1.150", None) is False


def test_blank_host_is_refused(in_scope):
    for host in ("", "   ", None):
        assert in_scope(host, SCOPE) is False


def test_near_miss_addresses_are_refused(in_scope):
    """Substring-ish neighbours must not slip through a sloppy comparison."""
    for host in ("192.168.1.15", "192.168.1.1500", "1192.168.1.150"):
        assert in_scope(host, SCOPE) is False


def test_malformed_scope_rows_do_not_crash(in_scope):
    """A bad row must not take out the gate — and must not authorise anything."""
    bad = [("", "ip"), (None, "cidr"), ("not-a-cidr", "cidr"), ("x", None)]
    assert in_scope("192.168.1.150", bad) is False


def test_trailing_dot_and_case_are_normalised(in_scope):
    assert in_scope("EXAMPLE.COM.", SCOPE) is True


# ── Drift guard ───────────────────────────────────────────────────────────

CASES = [
    ("192.168.1.150", True), ("104.20.44.163", False), ("172.66.0.227", False),
    ("10.10.5.9", True), ("10.11.5.9", False),
    ("example.com", True), ("api.example.com", True), ("notexample.com", False),
    ("", False), ("192.168.1.15", False),
]


@pytest.mark.parametrize("host,expected", CASES)
def test_canonical_gate_verdicts(gate, host, expected):
    """The shared implementation's verdicts, including the exact third-party
    addresses that were queued against this engagement."""
    assert gate.is_in_scope(host, SCOPE) is expected


def test_only_one_implementation_of_the_matching_rules():
    """No service may carry its own copy.

    Three copies existed at one point — etl, the BFF and kali-listener — because
    build contexts could not reach a shared file. ./etl is now mounted into every
    dispatching service, so a re-appearing local copy is a regression, not a
    workaround. Drift is prevented by construction here rather than policed by
    an agreement test.
    """
    offenders, scanned = [], 0
    for root, _dirs, files in os.walk(REPO):
        if any(skip in root for skip in
               ("/.git", "/node_modules", "/__pycache__", "/tests", "/etl")):
            continue
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            try:
                src = open(path, encoding="utf-8", errors="replace").read()
            except OSError:                      # pragma: no cover
                continue
            # The signature of a local copy: its own matching loop over
            # target_type values, rather than a call into the shared module.
            scanned += 1
            if 'tt == "cidr"' in src and "ip_network" in src:
                offenders.append(os.path.relpath(path, REPO))
    # A detector that scanned nothing passes trivially, which is how this test
    # first "passed" while a planted copy sat in dashboard/bff/.
    assert scanned > 50, f"copy detector only scanned {scanned} files — it is not looking"
    assert not offenders, (
        "these modules re-implement the scope matching rules instead of importing "
        "etl.scope_gate: " + ", ".join(offenders))


def test_every_dispatching_service_mounts_the_shared_gate():
    """Each service that dispatches must have ./etl mounted.

    Without it the import fails and the gate fails CLOSED — correct, but it
    presents as "every scan is refused", which is a confusing way to discover a
    missing volume.
    """
    if not os.path.exists(_COMPOSE):             # pragma: no cover
        pytest.skip("docker-compose.yml not present")
    compose = open(_COMPOSE).read()
    missing = []
    for svc in _DISPATCHING_SERVICES:
        # The lookahead must also accept end-of-file: the last service in the
        # compose file has no following block, and requiring one reported it as
        # "service not found" — a false alarm on a correctly-mounted service.
        m = re.search(r"\n  " + re.escape(svc) + r":\n(.*?)(?=\n  [a-z0-9_-]+:\n|\Z)",
                      compose, re.S)
        if not m:
            missing.append(f"{svc} (service not found)")
        elif "./etl:" not in m.group(1):
            missing.append(f"{svc} (no ./etl mount)")
    assert not missing, "shared scope gate not reachable by: " + ", ".join(missing)


def test_dispatch_check_rejects_command_hidden_targets(gate):
    """Naming the host in the command while leaving target blank must not pass."""
    assert gate.check_dispatch("", SCOPE, "rpcinfo -p 104.20.44.163")
    assert gate.check_dispatch("", SCOPE, "rpcinfo -p 192.168.1.150") is None


def test_dispatch_check_ignores_self_addresses(gate):
    """Loopback and 0.0.0.0 are the tool talking to itself, not a target."""
    assert gate.check_dispatch("192.168.1.150", SCOPE, "nc 127.0.0.1 4444") is None
    assert gate.check_dispatch("192.168.1.150", SCOPE, "bind 0.0.0.0:9001") is None


def test_dispatch_check_fails_closed_on_empty_scope(gate):
    assert gate.check_dispatch("192.168.1.150", [])

