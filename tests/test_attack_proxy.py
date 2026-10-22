"""Workbench attacks must select a proxy, and must not lie about it.

`exploit_runner` has enforced a node SOCKS proxy on every execute path since
2026-09. The Exploit Workbench never did: its refine loop POSTs straight to
`kali-listener /vectors/run` — a different service from the one holding
`_enforce_proxy` — so every build-PoC command egressed from the listener's own
address. `grep -c proxy kali_listener/listener_service.py` was **0**.

The fix is one shared module (`etl/` is bind-mounted into exploit-runner,
rag-api and kali-listener alike) rather than a second copy of the policy.

Pinned here, because each is a way for this to silently stop working:

  1. the ENGAGEMENT's selected node wins over every fallback — that is the
     operator's "select the proxy" control, and a fallback that outranks it
     would make the control decorative;
  2. a node that CANNOT reach the target is never returned — the original
     resolver's own docstring records the cost of that fallback ("an
     aws_us-east node cannot reach a 192.168.1.x lab host, so routing a local
     target through it timed out"), and a hanging proxy reads as a dead target;
  3. "could not ask" is never "no proxy needed" — an unreadable node list or
     an unreadable setting must not disable the control;
  4. fail-closed: policy on + no proxy available = refuse, not run direct;
  5. `socks5h`, not `socks5` — DNS must resolve AT the proxy;
  6. the note reports the MECHANISM: setting ALL_PROXY proxies curl and does
     nothing for nmap, and claiming "routed via" for nmap reports a control as
     applied when it was not.

Sabotage check: return the most-recent node for an own-network target and
`test_a_node_that_cannot_reach_the_target_is_not_returned` fails; let
`require_proxy` return False when the settings read raises and
`test_an_unreadable_setting_does_not_disable_the_control` fails.

    pytest tests/test_attack_proxy.py -q
"""

import importlib.util
import ipaddress
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MOD = REPO / "etl" / "attack_proxy.py"


def _load():
    if not MOD.exists():
        pytest.skip("etl/attack_proxy.py not found")
    spec = importlib.util.spec_from_file_location("attack_proxy", MOD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


ap = _load()


class _Cur:
    def __init__(self, answers): self.answers, self.last = answers, None
    def execute(self, sql, params=None): self.last = (sql, params)
    def fetchone(self):
        for key, val in self.answers.items():
            if key in (self.last[0] if self.last else ""):
                return val[0] if isinstance(val, list) else val
        return None
    def fetchall(self):
        for key, val in self.answers.items():
            if key in (self.last[0] if self.last else ""):
                return val
        return []
    def __enter__(self): return self
    def __exit__(self, *a): return False


class _Conn:
    def __init__(self, answers, raise_on=None):
        self.answers, self.raise_on = answers, raise_on
    def cursor(self):
        if self.raise_on == "cursor":
            raise RuntimeError("db down")
        return _Cur(self.answers)
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _factory(answers, raise_on=None):
    def f():
        if raise_on == "connect":
            raise RuntimeError("db down")
        return _Conn(answers, raise_on)
    return f


NODES = [("rt3_scan1", 10120, "3.15.200.93"),
         ("rt3_scan2", 10121, "54.165.76.119")]
LAB = [ipaddress.IPv4Network("172.19.0.0/16")]


# -- 1. the engagement's choice is the control -------------------------------

def test_the_engagement_selected_node_wins():
    f = _factory({"node_id FROM engagements": ("rt3_scan2",),
                  "FROM remote_nodes\n                    WHERE (id::text": ("rt3_scan2", 10121),
                  "FROM remote_nodes": NODES})
    d = ap.resolve(f, target="10.0.0.5", engagement_id="e1")
    assert d.source == "engagement", d
    assert d.proxy_url.endswith(":10121"), d.proxy_url


def test_an_operator_proxy_outranks_everything():
    d = ap.resolve(_factory({"FROM remote_nodes": NODES}),
                   target="10.0.0.5", operator_proxy="socks5h://box:9050")
    assert d.source == "operator" and d.proxy_url == "socks5h://box:9050"


def test_local_sentinel_is_not_a_node_selection():
    """`node_id='local'` means the local node, not a named remote one."""
    f = _factory({"node_id FROM engagements": ("local",), "FROM remote_nodes": NODES})
    assert ap.resolve(f, target="8.8.8.8", engagement_id="e1").source != "engagement"


# -- 2. never hand back a node that cannot reach ----------------------------

def test_same_subnet_beats_most_recent():
    rows = [("far", 10120, "3.15.200.93"), ("near", 10121, "10.0.0.9")]
    d = ap.resolve(_factory({"FROM remote_nodes": rows}), target="10.0.0.5")
    assert d.source == "same_subnet" and d.proxy_url.endswith(":10121"), d


def test_a_node_that_cannot_reach_the_target_is_not_returned():
    """A target on OUR OWN bridge is unreachable through any external node."""
    d = ap.resolve(_factory({"FROM remote_nodes": NODES}),
                   target="172.19.88.23", own_cidrs=LAB)
    assert d.proxy_url is None, (
        f"handed back {d.proxy_url} for a target on this host's own network — "
        "that connection hangs for the full timeout and reads as 'target down'")
    assert d.source == "unreachable_by_any_node", d.source


def test_a_routable_target_still_gets_the_fallback():
    d = ap.resolve(_factory({"FROM remote_nodes": NODES}),
                   target="93.184.216.34", own_cidrs=LAB)
    assert d.source == "fallback" and d.proxy_url


# -- 3. could not ask != no proxy needed ------------------------------------

def test_an_unreadable_node_list_is_not_an_absent_requirement():
    d = ap.resolve(_factory({}, raise_on="connect"), target="10.0.0.5")
    assert d.proxy_url is None and d.source == "no_node_online"
    assert "could not be read" in d.reason, d.reason


def test_an_unreadable_setting_does_not_disable_the_control(monkeypatch):
    monkeypatch.delenv("EXPLOIT_REQUIRE_PROXY", raising=False)
    assert ap.require_proxy(_factory({}, raise_on="connect")) is True, (
        "a database error silently turned the fail-closed proxy policy OFF")


def test_the_setting_can_turn_it_off_explicitly():
    assert ap.require_proxy(_factory({"exploit_proxy.require": ("false",)})) is False


def test_the_default_is_fail_closed(monkeypatch):
    monkeypatch.delenv("EXPLOIT_REQUIRE_PROXY", raising=False)
    assert ap.require_proxy(_factory({})) is True


# -- 4. enforcement ---------------------------------------------------------

def test_no_proxy_plus_policy_on_refuses():
    d = ap.Decision(None, None, "no_node_online", "no online node exposes a SOCKS port")
    with pytest.raises(ap.ProxyRequired) as e:
        ap.enforce(d, required=True)
    assert "fail-closed" in str(e.value)
    assert "exploit_proxy.require" in str(e.value), (
        "the refusal does not say how an operator would allow direct")


def test_no_proxy_plus_policy_off_is_allowed():
    d = ap.Decision(None, None, "no_node_online", "none online")
    assert ap.enforce(d, required=False) is d


# -- 5 + 6. the env, and honesty about it -----------------------------------

def test_dns_resolves_at_the_proxy():
    env = ap.proxy_env("socks5://node-manager:10120")
    assert env["ALL_PROXY"].startswith("socks5h://"), (
        "socks5 without the h resolves DNS locally — that leaks the lookup and "
        "breaks names that only exist on the far side")


def test_both_cases_of_each_var_are_set():
    env = ap.proxy_env("socks5h://n:1")
    for k in ("ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy",
              "HTTPS_PROXY", "https_proxy"):
        assert k in env, f"{k} missing — tools differ on which case they read"


def test_no_proxy_means_no_env():
    assert ap.proxy_env(None) == {}


def test_a_curl_command_is_reported_honoured():
    honoured, _ = ap.env_mechanism("curl -s http://t/ | grep x")
    assert honoured is True


def test_an_nmap_command_is_reported_NOT_honoured():
    honoured, detail = ap.env_mechanism("nmap -sV 10.0.0.1")
    assert honoured is False, (
        "nmap ignores the proxy environment; reporting it as proxied claims a "
        "control that was never applied")
    assert "nmap" in detail


def test_a_mixed_command_is_reported_as_partial():
    honoured, detail = ap.env_mechanism("nmap -sV 10.0.0.1; curl http://t/")
    assert honoured is None, f"mixed command reported as {honoured}: {detail}"


def test_an_unrecognised_command_says_so_rather_than_assuming():
    honoured, detail = ap.env_mechanism("./exploit.bin --go")
    assert honoured is None and "cannot tell" in detail


def test_tools_inside_a_subshell_are_seen():
    assert "curl" in ap.leading_tools("T=$(curl -s http://t/); echo $T")


def test_the_note_names_the_proxy_the_source_and_the_mechanism():
    d = ap.Decision("socks5h://node-manager:10120", "rt3_scan1", "engagement", "selected")
    n = ap.note(d, "curl -s http://t/")
    for part in ("socks5h://node-manager:10120", "rt3_scan1", "engagement", "ALL_PROXY"):
        assert part in n, f"{part!r} missing from {n!r}"


def test_the_note_warns_when_the_tool_will_ignore_it():
    d = ap.Decision("socks5h://n:1", "n", "fallback", "x")
    assert "NOT EFFECTIVE" in ap.note(d, "nmap -sV 10.0.0.1")


def test_the_direct_note_says_why():
    d = ap.Decision(None, None, "unreachable_by_any_node", "on this host's own network")
    n = ap.note(d, "curl http://t/")
    assert "DIRECT" in n and "own network" in n


# -- 7. the own-network exemption, explicitly -------------------------------

def test_an_own_network_target_may_go_direct_by_default():
    """No external node can reach it and the traffic never leaves this host."""
    d = ap.Decision(None, None, "unreachable_by_any_node", "on this host's own network")
    assert ap.enforce(d, required=True, allow_own_network=True) is d


def test_the_exemption_can_be_switched_off():
    d = ap.Decision(None, None, "unreachable_by_any_node", "on this host's own network")
    with pytest.raises(ap.ProxyRequired) as e:
        ap.enforce(d, required=True, allow_own_network=False)
    assert "allow_direct_local" in str(e.value), (
        "the refusal does not name the setting that governs it")


def test_the_exemption_does_not_cover_an_ordinary_missing_proxy():
    """It is scoped to unreachable-by-any-node, NOT to 'no node online'."""
    d = ap.Decision(None, None, "no_node_online", "no online node exposes a SOCKS port")
    with pytest.raises(ap.ProxyRequired):
        ap.enforce(d, required=True, allow_own_network=True)


def test_the_exemption_defaults_on_but_is_a_setting(monkeypatch):
    monkeypatch.delenv("EXPLOIT_ALLOW_DIRECT_LOCAL", raising=False)
    assert ap.allow_direct_on_own_network(_factory({})) is True
    assert ap.allow_direct_on_own_network(
        _factory({"exploit_proxy.allow_direct_local": ("false",)})) is False


def test_an_unreadable_exemption_setting_does_not_crash(monkeypatch):
    monkeypatch.delenv("EXPLOIT_ALLOW_DIRECT_LOCAL", raising=False)
    assert ap.allow_direct_on_own_network(_factory({}, raise_on="connect")) is True


# -- 8. the operator's explicit node pick -----------------------------------

def test_a_picked_node_resolves_to_its_own_socks_port():
    url, label = ap.node_proxy(
        _factory({"FROM remote_nodes": ("rt3_scan2", 10121)}), "rt3_scan2")
    assert url.endswith(":10121") and label == "rt3_scan2"


def test_a_picked_node_never_falls_back_to_another():
    """Picking one node and silently getting another egresses from the wrong
    address while the run record claims otherwise."""
    url, label = ap.node_proxy(_factory({}), "offline_node")
    assert url is None and label is None


def test_a_picked_node_lookup_error_is_not_a_different_node():
    assert ap.node_proxy(_factory({}, raise_on="connect"), "n") == (None, None)


# -- 8. the own-network exemption must be REACHABLE with zero nodes ---------
#
# Found 2026-10-19. `allow_direct_on_own_network` exists precisely so a lab or
# CVE-Bench target can run when no external node can reach it — its docstring
# says "The lab and CVE-Bench targets live on exactly these networks". But the
# `is_on_own_network` check lived only inside `if target:` AFTER the per-node
# subnet match, which the `not rows` branch returns before ever reaching. With
# zero online nodes, resolve() returned `no_node_online`, and enforce() exempts
# only `unreachable_by_any_node` — so the exemption could never apply in the
# one case it was written for.
#
# Cost, observed on CVE-2024-37849: the benchmark follow-through aborted with
# `[proxy] REFUSED ... no online node exposes a SOCKS port` after 146
# blind-timing probes, so a verified blind SQLi scored no database_access goal.

NO_NODES: dict = {}            # the SELECT over remote_nodes returns nothing


def test_own_network_target_is_exempt_when_no_node_is_online():
    d = ap.resolve(_factory(NO_NODES), target="172.19.150.4", own_cidrs=LAB)
    assert d.source == "unreachable_by_any_node", (
        f"got {d.source!r}/{d.reason!r} — an own-network target with no nodes "
        "must be eligible for the exemption, not a plain no_node_online")
    # ...and enforce() therefore lets it run direct.
    assert ap.enforce(d, required=True, allow_own_network=True) is d


def test_an_off_network_target_with_no_nodes_is_still_refused():
    """The exemption must not widen into 'no nodes means anything goes'."""
    d = ap.resolve(_factory(NO_NODES), target="203.0.113.10", own_cidrs=LAB)
    assert d.source == "no_node_online"
    with pytest.raises(ap.ProxyRequired):
        ap.enforce(d, required=True, allow_own_network=True)


def test_no_target_with_no_nodes_is_still_refused():
    """Nothing to compare against is not an own-network target."""
    d = ap.resolve(_factory(NO_NODES), target=None, own_cidrs=LAB)
    assert d.source == "no_node_online"
    with pytest.raises(ap.ProxyRequired):
        ap.enforce(d, required=True, allow_own_network=True)


def test_an_unreadable_node_list_is_not_an_exemption():
    """COULD NOT ASK is not ASKED-AND-NONE-ONLINE.

    `rows is None` means the query failed, which says nothing about the
    target. Treating it as 'no nodes, so go direct' is this repo's recurring
    unreachable-is-not-absent bug: a probe that could not run filed as a
    negative result. Three outcomes, not two.
    """
    d = ap.resolve(_factory({}, raise_on="connect"), target="172.19.150.4",
                   own_cidrs=LAB)
    assert d.source == "no_node_online"
    assert "could not be read" in d.reason
    with pytest.raises(ap.ProxyRequired):
        ap.enforce(d, required=True, allow_own_network=True)


def test_the_exemption_still_obeys_its_setting_with_no_nodes():
    """`exploit_proxy.allow_direct_local = false` must still refuse."""
    d = ap.resolve(_factory(NO_NODES), target="172.19.150.4", own_cidrs=LAB)
    with pytest.raises(ap.ProxyRequired) as e:
        ap.enforce(d, required=True, allow_own_network=False)
    assert "allow_direct_local" in str(e.value)


def test_a_reachable_node_still_wins_over_the_exemption():
    """The exemption is a last resort, not a preference. When a node IS on the
    target's subnet it must be used — going direct would drop the egress
    attribution a node provides."""
    rows = {"FROM remote_nodes": [("lab_node", 10199, "172.19.150.1")]}
    d = ap.resolve(_factory(rows), target="172.19.150.4", own_cidrs=LAB)
    assert d.proxy_url and d.source == "same_subnet", (
        f"got {d.source!r} — a node on the target's subnet must be preferred")
