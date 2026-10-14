"""The Assets list must count ports across the IP, not the hostname's own row.

A port scan reports an IP, so its results land on whichever asset row the
ingest resolved to — frequently an IP-keyed row with a NULL hostname. Counting
only the hostname's own row reports 0 for a host whose address is plainly
listening.

Observed 2026-10-14 on `blog.examplecorp.com`:

    asset rows on 23.185.0.4
      (none)                      open=2     <- the port scan landed here
      examplecorpinstitute.com      open=2
      csr.examplecorp.com           open=2
      blog.examplecorp.com          open=0     <- what the list showed

Ports genuinely ARE per-IP: a vhost on a listening address is reachable on
those ports with a Host header. It is the same reasoning the scope classifier
uses, and it is why the asset DETAIL Ports tab was already correct — it queries
`/ports/open?ip=...`, which matches every row on the address. Only the list
column read the hostname's own row.

The sentinels must stay excluded from the self-join, or every unresolved asset
inherits every other unresolved asset's ports — they all share 0.0.0.0.

Static (`ast`). No DB.

Sabotage check: drop the `a2.ip = a.ip` join and
`test_list_counts_ports_across_the_ip` fails; drop the sentinel exclusion and
`test_sentinels_are_excluded` fails.

    pytest tests/test_asset_port_counts.py -q
"""

import ast
import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"


def _assets_port_sql() -> str:
    """The list query that computes open_ports_count."""
    if not API.exists():
        pytest.skip(f"{API} not found")
    tree = ast.parse(API.read_text(encoding="utf-8"))
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "get_assets"), None)
    assert fn, "get_assets not found — the handler was renamed and this guard is blind"
    for node in ast.walk(fn):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and "open_ports_count" in node.value:
            return " ".join(node.value.split())
        if isinstance(node, ast.JoinedStr):
            parts = [v.value for v in node.values
                     if isinstance(v, ast.Constant) and isinstance(v.value, str)]
            joined = "".join(parts)
            if "open_ports_count" in joined:
                return " ".join(joined.split())
    pytest.fail("no open_ports_count query found in get_assets")


def test_list_counts_ports_across_the_ip():
    sql = _assets_port_sql()
    assert re.search(r"\ba2\.ip\s*=\s*a\.ip\b", sql), (
        "the Assets list counts ports on the hostname's own asset row only, so "
        "a host whose IP is listening reports 0 — blog.examplecorp.com showed 0 "
        "while its address carried 2 open ports")


def test_sentinels_are_excluded():
    sql = _assets_port_sql()
    assert re.search(r"host\(a\.ip\)\s+NOT\s+IN", sql, re.I), (
        "the IP self-join does not exclude 0.0.0.0/::, so every unresolved "
        "asset inherits every other unresolved asset's ports")


def test_still_counts_only_open_ports():
    """Widening the join must not start counting closed ports."""
    sql = _assets_port_sql()
    assert "is_open" in sql, (
        "the port count no longer filters on is_open — closed ports would be "
        "reported as open surface")
