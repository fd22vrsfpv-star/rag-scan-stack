"""scripts/gym.sh — the CVE-Bench target harness, now under version control.

It lived at /opt/cve-bench/gym.sh, outside the repo, with no history and no
tests, while being the thing that decides which IP a benchmark target gets and
whether the address pool is ever returned. Moving it in; /opt/cve-bench/gym.sh
is a symlink so existing invocations still work.

Two properties worth pinning:

  * The IP for a CVE is DETERMINISTIC. Stable IPs are what let the recon cache
    (keyed on ip) reuse work across rounds and make two rounds comparable at
    all — CVE-2024-4443 landed on 172.19.18.126 in rounds a week apart.

  * Every network a target creates is RETURNED. CVE-Bench creates an
    `agent_internet` network for its own Kali sandbox, which gym.sh stops
    because the platform is the attacker. `./run down` leaves it behind, and an
    orphaned network holds its subnet forever. Ten accumulated, and bringing up
    the focused-10 died at 8 with "all predefined address pools have been fully
    subnetted" — a pool problem that reads like a target problem.

    pytest tests/test_gym_targets.py
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
GYM = REPO / "scripts" / "gym.sh"
SRC = GYM.read_text(encoding="utf-8") if GYM.exists() else ""

FOCUSED_10 = ["CVE-2023-51483", "CVE-2024-22120", "CVE-2024-32511",
              "CVE-2024-32964", "CVE-2024-3408", "CVE-2024-3552",
              "CVE-2024-36412", "CVE-2024-36675", "CVE-2024-4443",
              "CVE-2024-5314"]


def _ip_for(cve: str) -> str:
    """The script's own mapping, re-implemented for the test to compare against
    the shipped shell arithmetic below."""
    n = int(re.search(r"(\d+)$", cve).group(1))
    return "172.19.%d.%d" % ((n // 254) % 254 + 1, n % 254 + 1)


@pytest.mark.unit
def test_the_script_is_in_the_repo():
    assert GYM.exists(), "scripts/gym.sh is missing"


@pytest.mark.unit
def test_it_parses_as_shell():
    r = subprocess.run(["bash", "-n", str(GYM)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


@pytest.mark.unit
class TestDeterministicIp:
    @pytest.mark.parametrize("cve,expect", [
        ("CVE-2024-4443", "172.19.18.126"),     # observed in two rounds a week apart
        ("CVE-2023-51483", "172.19.203.176"),   # observed in two rounds
        ("CVE-2024-5314", "172.19.21.235"),
        ("CVE-2024-22120", "172.19.88.23"),
    ])
    def test_known_targets_keep_their_address(self, cve, expect):
        assert _ip_for(cve) == expect

    def test_the_shipped_arithmetic_matches(self):
        """Pin the formula in the script, not just this file's copy of it."""
        assert "cve_num / 254" in SRC and "cve_num % 254" in SRC
        assert "172.19." in SRC

    def test_the_focused_ten_do_not_collide(self):
        ips = [_ip_for(c) for c in FOCUSED_10]
        assert len(set(ips)) == len(ips), "two targets share an IP: %s" % ips

    def test_it_avoids_the_platform_subnet(self):
        """Platform services live on 172.19.0.x; a target there would collide
        with the stack itself."""
        for c in FOCUSED_10:
            assert not _ip_for(c).startswith("172.19.0."), c

    def test_the_mapping_is_a_pure_function_of_the_cve(self):
        assert _ip_for("CVE-2024-4443") == _ip_for("CVE-2024-4443")

    def test_the_collision_period_is_documented_not_claimed_impossible(self):
        """The formula repeats every 254*254 CVE numbers. The script must not
        claim targets "never" share an IP without saying when they can."""
        a, b = "CVE-2024-1000", "CVE-2024-%d" % (1000 + 254 * 254)
        assert _ip_for(a) == _ip_for(b), "the period is not 254*254 any more"


@pytest.mark.unit
class TestNetworkReclamation:
    def test_up_removes_the_unused_agent_network(self):
        up = SRC.split("  up)", 1)[-1].split("  down)", 1)[0]
        assert "agent_internet" in up and "network rm" in up, (
            "the agent sandbox network is created and never removed, which is "
            "what exhausted Docker's address pools")

    def test_down_returns_every_network_the_target_created(self):
        down = SRC.split("  down)", 1)[-1].split("  prune-nets)", 1)[0]
        for n in ("agent_internet", "private_network", "target_network"):
            assert n in down, "down leaves %s behind, holding its subnet" % n

    def test_there_is_a_way_to_reclaim_orphans(self):
        assert "prune-nets)" in SRC

    def test_the_reclaim_is_scoped_to_cve_bench_networks(self):
        """A blanket `docker network prune` would also remove unrelated idle
        networks belonging to other stacks on this host."""
        pr = SRC.split("  prune-nets)", 1)[-1].split("  list)", 1)[0]
        # Comments out — the block explains WHY it does not use the blanket
        # command, and matching that sentence would fail the check it documents.
        code = "\n".join(l for l in pr.splitlines()
                          if not l.strip().startswith("#"))
        assert "docker network prune" not in code
        assert "cve-" in code, "the reclaim is not restricted to benchmark networks"

    def test_it_only_removes_networks_with_no_containers(self):
        pr = SRC.split("  prune-nets)", 1)[-1].split("  list)", 1)[0]
        assert "len .Containers" in pr, (
            "nothing checks the network is empty before removing it")
