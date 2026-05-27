import pytest
from utils.followup_engine import PortCtx, choose_actions, DEFAULT_RULES
from utils.followup_plugins import get as get_plugin


def test_rule_matching_http_nonstandard():
    ctx = PortCtx(host="127.0.0.1", port=8080, proto="tcp", service="http", product="gunicorn", version="20")
    acts = choose_actions(ctx, rules=DEFAULT_RULES)
    names = [a.plugin for a in acts]
    assert "http_title" in names


def test_rule_matching_tls_service():
    ctx = PortCtx(host="127.0.0.1", port=4443, proto="tcp", service="ssl", product=None, version=None)
    acts = choose_actions(ctx, rules=DEFAULT_RULES)
    assert any(a.plugin == "tls_cert" for a in acts)


def test_rule_matching_ssh_banner():
    ctx = PortCtx(host="127.0.0.1", port=2222, proto="tcp", banner="SSH-2.0-OpenSSH_9.0")
    acts = choose_actions(ctx, rules=DEFAULT_RULES)
    assert any(a.plugin == "ssh_algos" for a in acts)


@pytest.mark.asyncio
async def test_plugin_contracts_exist():
    http = get_plugin("http_title")
    tls = get_plugin("tls_cert")
    ssh = get_plugin("ssh_algos")
    assert http and tls and ssh
    # Non-routable port should still return findings list (error handled inside)
    res1 = await http("127.0.0.1", 9, "tcp", {})
    res2 = await tls("127.0.0.1", 9, "tcp", {})
    res3 = await ssh("127.0.0.1", 9, "tcp", {})
    for r in (res1, res2, res3):
        assert "findings" in r and isinstance(r["findings"], list)
