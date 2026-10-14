"""A proxied nmap must resolve names through the proxy's resolver, not its own.

proxychains hooks the libc resolver through LD_PRELOAD. nmap's built-in
parallel resolver sends DNS itself and is therefore NOT intercepted, so every
name waits out a timeout before nmap falls back. Measured on this stack, the
same two hostnames through the same SOCKS5 proxy:

    default resolver    13.12s
    --system-dns         0.12s

A 762-host scope spent over an hour resolving before probing a single port. The
job sat at **zero output with 0.09 seconds of CPU consumed** — indistinguishable
from a hung scanner, and two separate runs were abandoned before anyone measured
it. (The first diagnosis, NSE scripts, was wrong: removing them changed nothing.)

`--system-dns` routes resolution through the libc path proxychains intercepts
(`proxy_dns` in the generated config), so names resolve at the exit node — where
a proxied scan wants them resolved anyway, rather than from the scanner's own
address.

Static (`ast`): no nmap, no network.

Sabotage check: drop `--system-dns` from the proxychains command and
`test_proxied_nmap_uses_the_system_resolver` fails.

    pytest tests/test_proxied_nmap_dns.py -q
"""

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
NMAP_API = REPO / "nmap_scanner" / "nmap-api.py"


def _proxychains_commands() -> list:
    """Every list literal that builds a proxychains4 invocation."""
    if not NMAP_API.exists():
        pytest.skip(f"{NMAP_API} not found")
    tree = ast.parse(NMAP_API.read_text(encoding="utf-8"))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.List):
            continue
        consts = [e.value for e in node.elts
                  if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        if consts and consts[0].startswith("proxychains"):
            out.append((node.lineno, consts))
    return out


def test_proxied_nmap_uses_the_system_resolver():
    cmds = _proxychains_commands()
    assert cmds, (
        "no proxychains4 command found in nmap-api.py — has the proxied path "
        "moved? This guard is now blind.")
    for lineno, consts in cmds:
        assert "nmap" in consts, f"line {lineno}: not an nmap invocation"
        assert "--system-dns" in consts, (
            f"line {lineno}: proxied nmap runs without --system-dns. Its own "
            "resolver is not intercepted by proxychains, so every hostname "
            "waits out a timeout and a large scope stalls before probing "
            "anything.")


def test_proxied_nmap_is_a_connect_scan():
    """A SYN scan cannot traverse SOCKS; -sT is what makes the proxy work."""
    for lineno, consts in _proxychains_commands():
        assert "-sT" in consts, (
            f"line {lineno}: proxied nmap is not a TCP connect scan — raw "
            "SYN packets cannot traverse a SOCKS proxy")
        assert "-Pn" in consts, (
            f"line {lineno}: proxied nmap lacks -Pn — host-discovery pings "
            "cannot traverse SOCKS, so every host is marked down and nothing "
            "is scanned")
