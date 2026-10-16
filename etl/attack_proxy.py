"""Which proxy an attack routes through — ONE implementation, three services.

`exploit_runner` has enforced a node SOCKS proxy on every execute path since
2026-09. The Exploit Workbench never did: its refine loop POSTs straight to
`kali-listener /vectors/run`, which is a different service from the one
holding `_enforce_proxy`, so every build-PoC command egressed from the
listener's own address. The listener's docstring still asserts the old world
("It is reached only by the exploit-runner's source='command' branch"), which
stopped being true when the workbench started calling it directly.

This module exists so the fix is not a SECOND copy of the policy. `etl/` is
bind-mounted read-only into exploit-runner, rag-api AND kali-listener, so all
three import the same resolution, the same fail-closed rule and the same
reporting. CLAUDE.md asks for an agreement test when gate logic must be
duplicated; the better answer is not to duplicate it.

TWO THINGS THIS DELIBERATELY DOES DIFFERENTLY from the original resolver:

1. **It never returns a node that cannot reach the target.** The original
   falls back to the most-recently-seen node when nothing matches, and its own
   docstring records what that costs: "an aws_us-east node cannot reach a
   192.168.1.x lab host, so routing a local target through it timed out". A
   proxy that times out is worse than a reported absence, because it looks
   like the target is down. A target directly attached to one of THIS HOST's
   own container networks gets `source="unreachable_by_any_node"` instead.

2. **It reports the MECHANISM, not just the proxy.** Setting `ALL_PROXY` makes
   curl, wget and python-requests proxy; it does nothing for nmap. Claiming
   "routed via" for a tool that ignored the variable would be reporting a
   control as applied when it was not.

No command rewriting. curl honours `ALL_PROXY` natively, so the proxy is
applied by environment rather than by splicing `--proxy` into a shell string
that may contain several invocations, subshells and quoted literals.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import struct
from typing import Callable, NamedTuple, Optional

log = logging.getLogger(__name__)

PROXY_HOST = os.environ.get("NODE_MANAGER_PROXY_HOST", "node-manager")

#: Tools that honour ALL_PROXY / HTTP(S)_PROXY. A command whose leading tool is
#: not here gets `honours_env=False` and is REPORTED as unproxied-by-env rather
#: than silently assumed proxied.
_ENV_PROXY_TOOLS = frozenset({
    "curl", "wget", "python", "python3", "pip", "git", "http", "httpie",
    "nuclei", "ffuf", "gobuster", "feroxbuster", "katana", "httpx",
})
#: Tools known to IGNORE the proxy environment entirely.
_ENV_PROXY_DEAF = frozenset({"nmap", "masscan", "nc", "ncat", "netcat", "ping",
                             "dig", "nslookup", "ssh", "telnet"})


class Decision(NamedTuple):
    """proxy_url is None whenever no proxy will be applied — `source` says why."""
    proxy_url: Optional[str]
    label: Optional[str]
    source: str          # operator | engagement | same_subnet | fallback |
                         # unreachable_by_any_node | no_node_online
    reason: str


def require_proxy(conn_factory: Callable, default: bool = True) -> bool:
    """Fail-closed toggle, same precedence as exploit_runner._require_proxy:
    persisted `app_settings['exploit_proxy.require']` wins, env
    EXPLOIT_REQUIRE_PROXY is the fallback, and the default is True."""
    try:
        with conn_factory() as conn, conn.cursor() as cur:
            cur.execute("SELECT value FROM app_settings WHERE key = 'exploit_proxy.require'")
            row = cur.fetchone()
        if row:
            val = row[0] if not isinstance(row, dict) else row.get("value")
            if val is not None:
                return str(val).strip().lower() in ("true", "1", "yes", "on")
    except Exception as e:  # noqa: BLE001
        # An unreadable setting must not silently DISABLE the control.
        log.warning("attack_proxy: could not read exploit_proxy.require (%s); "
                    "falling back to env/default", e)
    return os.environ.get("EXPLOIT_REQUIRE_PROXY", str(default)).strip().lower() in (
        "true", "1", "yes", "on")


def own_network_cidrs() -> list:
    """The IPv4 networks this container is DIRECTLY attached to.

    Read from /proc/net/route rather than guessed from RFC1918, because the
    question is not "is this address private" but "is this address on a bridge
    I am already on" — a target there is unreachable through any external SOCKS
    node, and its traffic never leaves this host.
    """
    out = []
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) < 8:
                    continue
                dest, mask = parts[1], parts[7]
                if dest == "00000000":          # default route, not a local net
                    continue
                try:
                    d = struct.unpack("<I", bytes.fromhex(dest))[0]
                    m = struct.unpack("<I", bytes.fromhex(mask))[0]
                    if not m:
                        continue
                    net = ipaddress.IPv4Network(
                        (ipaddress.IPv4Address(d), bin(m).count("1")), strict=False)
                    if net not in out:
                        out.append(net)
                except Exception:  # noqa: BLE001
                    continue
    except Exception as e:  # noqa: BLE001
        log.debug("attack_proxy: could not read local routes: %s", e)
    return out


def is_on_own_network(target: str, cidrs=None) -> bool:
    """True when `target` sits on a network this container is already on."""
    try:
        addr = ipaddress.ip_address(str(target).strip())
    except Exception:  # noqa: BLE001
        return False
    if addr.version != 4:
        return False
    for net in (cidrs if cidrs is not None else own_network_cidrs()):
        try:
            if addr in net:
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _same_subnet(a: str, b: str, bits: int) -> bool:
    try:
        na = ipaddress.ip_network(f"{a}/{bits}", strict=False)
        return ipaddress.ip_address(b) in na
    except Exception:  # noqa: BLE001
        return False


def _rows(conn_factory):
    try:
        with conn_factory() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT name, proxy_port, COALESCE(metadata->>'host', hostname) AS host
                     FROM remote_nodes
                    WHERE status = 'online' AND proxy_port IS NOT NULL
                    ORDER BY last_seen DESC NULLS LAST""")
            got = cur.fetchall()
    except Exception as e:  # noqa: BLE001
        log.warning("attack_proxy: node lookup failed: %s", e)
        return None            # None = COULD NOT ASK, distinct from "none online"
    out = []
    for r in got:
        if isinstance(r, dict):
            out.append((r.get("name"), r.get("proxy_port"), r.get("host")))
        else:
            out.append((r[0], r[1], r[2]))
    return [r for r in out if r[1]]


def _engagement_node(conn_factory, engagement_id):
    """The node this ENGAGEMENT selected — `engagements.node_id`, the operator's
    own choice. This is the 'select the proxy' control; everything else is a
    fallback for when it is unset."""
    if not engagement_id:
        return None
    try:
        with conn_factory() as conn, conn.cursor() as cur:
            cur.execute("SELECT node_id FROM engagements WHERE id = %s::uuid",
                        (str(engagement_id),))
            row = cur.fetchone()
            sel = (row[0] if not isinstance(row, dict) else row.get("node_id")) if row else None
            if not sel or str(sel).lower() == "local":
                return None
            cur.execute(
                """SELECT name, proxy_port FROM remote_nodes
                    WHERE (id::text = %s OR name = %s) AND status = 'online'
                      AND proxy_port IS NOT NULL LIMIT 1""", (str(sel), str(sel)))
            r = cur.fetchone()
        if not r:
            return None
        name, port = (r.get("name"), r.get("proxy_port")) if isinstance(r, dict) else (r[0], r[1])
        return (f"socks5h://{PROXY_HOST}:{port}", str(name or f"node:{port}"))
    except Exception as e:  # noqa: BLE001
        log.warning("attack_proxy: engagement node lookup failed: %s", e)
        return None


def node_proxy(conn_factory, selector: str):
    """(proxy_url, label) for ONE node picked by name or id, or (None, None).

    The operator's explicit pick. It never falls back to another node: picking
    `rt3_scan2` and silently getting `rt3_scan1` would egress from the wrong
    address while the run record claimed otherwise.
    """
    if not selector:
        return None, None
    try:
        with conn_factory() as conn, conn.cursor() as cur:
            cur.execute(
                """SELECT name, proxy_port FROM remote_nodes
                    WHERE (id::text = %s OR name = %s) AND status = 'online'
                      AND proxy_port IS NOT NULL LIMIT 1""",
                (str(selector), str(selector)))
            r = cur.fetchone()
        if not r:
            return None, None
        name, port = (r.get("name"), r.get("proxy_port")) if isinstance(r, dict) else (r[0], r[1])
        return f"socks5h://{PROXY_HOST}:{port}", str(name or f"node:{port}")
    except Exception as e:  # noqa: BLE001
        log.warning("attack_proxy: node lookup for %r failed: %s", selector, e)
        return None, None


def resolve(conn_factory, target=None, engagement_id=None,
            operator_proxy=None, own_cidrs=None) -> Decision:
    """Pick the proxy for an attack on `target`. Never raises."""
    if operator_proxy:
        return Decision(str(operator_proxy), "operator-supplied", "operator",
                        "an explicit proxy was supplied with the request")

    eng = _engagement_node(conn_factory, engagement_id)
    if eng:
        return Decision(eng[0], eng[1], "engagement",
                        "the engagement selected this node")

    rows = _rows(conn_factory)
    if rows is None:
        return Decision(None, None, "no_node_online",
                        "the node list could not be read — treat as no proxy "
                        "available, not as no proxy needed")
    if not rows:
        return Decision(None, None, "no_node_online",
                        "no online node exposes a SOCKS port")

    if target:
        for bits in (24, 16):
            for name, port, host in rows:
                if host and _same_subnet(str(target), str(host), bits):
                    return Decision(f"socks5h://{PROXY_HOST}:{port}",
                                    str(name or f"node:{port}"), "same_subnet",
                                    f"node host {host} is on the target's /{bits}")
        # No node shares the target's network. If the target is on one of OUR
        # OWN bridges, no external node can reach it — say so rather than hand
        # back a node whose connection will hang for the full timeout and read
        # as "target down".
        if is_on_own_network(str(target), own_cidrs):
            return Decision(None, None, "unreachable_by_any_node",
                            f"{target} is on a network this host is already "
                            f"attached to; no external SOCKS node can reach it")

    name, port, _host = rows[0]
    return Decision(f"socks5h://{PROXY_HOST}:{port}", str(name or f"node:{port}"),
                    "fallback", "most recently seen online node")


class ProxyRequired(Exception):
    """Raised when policy requires a proxy and none is available."""


def allow_direct_on_own_network(conn_factory: Callable, default: bool = True) -> bool:
    """May an attack on THIS HOST'S OWN bridge run without a proxy?

    Default TRUE, and the reasoning is narrow on purpose. The exemption applies
    only to an address this container is DIRECTLY ATTACHED TO (read from
    /proc/net/route, not guessed from RFC1918), which means two things at once:

      * no external SOCKS node can reach it, so the alternative to "direct" is
        not "proxied" -- it is a connection that hangs for the full timeout and
        is then misread as a dead target;
      * the traffic never leaves this host, so there is no egress attribution
        for a proxy to protect.

    It is a SETTING, not a hard-coded hole: `exploit_proxy.allow_direct_local`
    = false makes the policy refuse these too, and the refusal names the
    setting. The lab and CVE-Bench targets live on exactly these networks.
    """
    try:
        with conn_factory() as conn, conn.cursor() as cur:
            cur.execute("SELECT value FROM app_settings "
                        "WHERE key = 'exploit_proxy.allow_direct_local'")
            row = cur.fetchone()
        if row:
            val = row[0] if not isinstance(row, dict) else row.get("value")
            if val is not None:
                return str(val).strip().lower() in ("true", "1", "yes", "on")
    except Exception as e:  # noqa: BLE001
        log.warning("attack_proxy: could not read exploit_proxy.allow_direct_local "
                    "(%s); falling back to env/default", e)
    return os.environ.get("EXPLOIT_ALLOW_DIRECT_LOCAL",
                          str(default)).strip().lower() in ("true", "1", "yes", "on")


def enforce(decision: Decision, required: bool,
            allow_own_network: bool = True) -> Decision:
    """Apply the fail-closed policy. Returns the decision, or raises.

    The one exemption is a target on this host's own bridge -- see
    `allow_direct_on_own_network` for why, and for the setting that removes it.
    """
    if decision.proxy_url or not required:
        return decision
    if decision.source == "unreachable_by_any_node" and allow_own_network:
        return decision
    if decision.source == "unreachable_by_any_node":
        raise ProxyRequired(
            "fail-closed: attacks must route through a node SOCKS proxy, and "
            f"{decision.reason}. Refusing to run this attack direct. Attach a "
            "node to that network, or set app_settings "
            "'exploit_proxy.allow_direct_local' = true to permit direct "
            "attacks on networks this host is already on.")
    raise ProxyRequired(
        "fail-closed: attacks must route through a node SOCKS proxy, but "
        f"{decision.reason}. Refusing to run this attack direct. Select a node "
        "for the engagement, bring a scan node online, supply proxy_url, or "
        "set app_settings 'exploit_proxy.require' = false to allow direct.")


def proxy_env(proxy_url: Optional[str]) -> dict:
    """Environment that makes an env-honouring tool use the proxy.

    `socks5h://` (not `socks5://`) so DNS resolves AT THE PROXY — resolving
    locally and connecting remotely leaks the lookup and breaks names that only
    exist on the far side.
    """
    if not proxy_url:
        return {}
    url = str(proxy_url)
    if url.startswith("socks5://"):
        url = "socks5h://" + url[len("socks5://"):]
    return {"ALL_PROXY": url, "all_proxy": url,
            "HTTP_PROXY": url, "http_proxy": url,
            "HTTPS_PROXY": url, "https_proxy": url}


def leading_tools(command: str) -> list:
    """Every program the command invokes, as best a regex can tell.

    Used for REPORTING, never for rewriting. Picks up the start of the command
    and anything after a shell separator or inside a `$( )`.
    """
    if not command:
        return []
    out = []
    for m in re.finditer(r'(?:^|[;&|]|\$\(|`|\n)\s*([A-Za-z0-9_./-]+)', str(command)):
        tok = m.group(1).rsplit("/", 1)[-1].lower()
        if tok in ("sudo", "env", "time", "nohup", "timeout"):
            continue
        if tok and tok not in out:
            out.append(tok)
    return out


def env_mechanism(command: str) -> tuple:
    """(honoured, detail) — can an env proxy actually apply to this command?

    THREE outcomes, because "we set the variable" is not "the traffic was
    proxied": a tool that ignores it goes direct while the log says proxied.
    """
    tools = [t for t in leading_tools(command)
             if t in _ENV_PROXY_TOOLS or t in _ENV_PROXY_DEAF]
    if not tools:
        return None, "no recognised tool in the command — cannot tell"
    deaf = [t for t in tools if t in _ENV_PROXY_DEAF]
    if deaf and not [t for t in tools if t in _ENV_PROXY_TOOLS]:
        return False, f"{', '.join(deaf)} ignore(s) the proxy environment"
    if deaf:
        return None, (f"{', '.join(t for t in tools if t in _ENV_PROXY_TOOLS)} "
                      f"honour(s) it, {', '.join(deaf)} do(es) not")
    return True, f"{', '.join(tools)} honour(s) the proxy environment"


def note(decision: Decision, command: str = "") -> str:
    """The one line recorded in the output so an operator can SEE what happened.

    Same shape exploit_runner._proxy_note writes, plus the mechanism, because
    an operator reading "routed via" needs to know whether the tool obeyed.
    """
    if not decision.proxy_url:
        return f"[proxy] DIRECT — no proxy applied ({decision.reason})"
    honoured, detail = env_mechanism(command)
    if honoured is True:
        how = f"env ALL_PROXY; {detail}"
    elif honoured is False:
        how = f"env ALL_PROXY set but NOT EFFECTIVE — {detail}"
    else:
        how = f"env ALL_PROXY; {detail}"
    return f"[proxy] routed via {decision.proxy_url} ({decision.label}, {decision.source}) [{how}]"
