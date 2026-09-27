"""_wrap_remote must cover the protocols whose tools are already allow-listed
(ssh, smb, mysql, postgres) and feed the held password to sudo for elevation —
while a protocol with no safe runner still returns None (queues nothing).

Runtime tests of langgraph_engine._wrap_remote. The secret stays a `{password}`
placeholder resolved at dispatch, never stored. Skips cleanly where the autogen
deps are absent.
"""
import importlib
import sys
from pathlib import Path

import pytest

AGENTS = Path(__file__).parent.parent / "autogen_agents"


@pytest.fixture()
def lge():
    sys.path.insert(0, str(AGENTS))
    try:
        return importlib.import_module("langgraph_engine")
    except Exception as e:
        pytest.skip(f"langgraph_engine not importable: {e}")


def test_unsupported_protocol_returns_none(lge):
    # A protocol with no safe runner queues nothing rather than something broken.
    assert lge._wrap_remote("rdp", "10.0.0.1", 3389, "whoami") is None
    assert lge._wrap_remote("vnc", "10.0.0.1", 5900, "id") is None
    assert lge._wrap_remote("", "10.0.0.1", None, "id") is None


def test_ssh_non_sudo_closes_stdin(lge):
    w = lge._wrap_remote("ssh", "10.0.0.1", 22, "id")
    assert w and "sshpass" in w and "ssh " in w
    assert "{password}" in w and "{username}" in w   # resolved at dispatch
    assert w.strip().endswith("< /dev/null")          # prompts fail fast


def test_ssh_sudo_feeds_password_and_keeps_stdin(lge):
    w = lge._wrap_remote("ssh", "10.0.0.1", 22, "sudo -n -l")
    assert "sudo -S" in w                    # reads password from stdin
    assert "-n" not in w.split("sudo -S")[1].split("'")[0]  # the -n was dropped
    assert "printf" in w and "{password}" in w            # password piped to stdin
    assert "< /dev/null" not in w            # stdin carries the password now


def test_smb_uses_netexec_exec(lge):
    w = lge._wrap_remote("smb", "10.0.0.1", 445, "whoami")
    assert w.startswith("netexec smb 10.0.0.1") and "-x 'whoami'" in w
    assert "{username}" in w and "{password}" in w


def test_mysql_uses_dash_e(lge):
    w = lge._wrap_remote("mysql", "10.0.0.1", 3306, "SHOW DATABASES;")
    assert w.startswith("mysql -h 10.0.0.1") and "-e 'SHOW DATABASES;'" in w
    assert "-p'{password}'" in w             # no space after -p


def test_postgres_uses_psql_c(lge):
    for proto in ("postgresql", "postgres"):
        w = lge._wrap_remote(proto, "10.0.0.1", 5432, "SELECT 1;")
        assert "psql -h 10.0.0.1" in w and "-tAc 'SELECT 1;'" in w
        assert "PGPASSWORD='{password}'" in w


def test_command_single_quotes_are_escaped(lge):
    # A quote in the step must not break out of the single-quoted remote command.
    w = lge._wrap_remote("ssh", "10.0.0.1", 22, "echo 'hi'")
    assert "'\\''" in w
