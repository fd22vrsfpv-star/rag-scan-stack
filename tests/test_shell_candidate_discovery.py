"""A port whose service or banner is a shell/backdoor MUST be offered as a
bind-shell candidate. Metasploitable's root shell is on 1524, service
'bindshell', banner 'root@metasploitable:/#' — an IDENTIFIED service, so the
old "unidentified only" filter dropped the one port that was a real shell.

Run: pytest tests/test_shell_candidate_discovery.py -v

SABOTAGE PROOF: make _looks_like_shell always return False and
test_bindshell_service_is_a_candidate / test_root_prompt_banner fail.
"""
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

pe = pytest.importorskip("etl.post_enumeration", reason="etl.post_enumeration not importable")


def test_bindshell_service_is_a_candidate():
    assert pe._looks_like_shell("bindshell", "")
    assert pe._looks_like_shell("ingreslock", "")
    assert pe._looks_like_shell("rootshell", "")


def test_root_prompt_banner_is_a_candidate():
    assert pe._looks_like_shell("unknown-svc", "root@metasploitable:/#")
    assert pe._looks_like_shell("", "uid=0(root) gid=0(root)")
    assert pe._looks_like_shell("", "www-data@host:/var/www$ ")


def test_ordinary_services_are_not_candidates():
    assert not pe._looks_like_shell("http", "Apache/2.2.8")
    assert not pe._looks_like_shell("ssh", "OpenSSH 4.7p1")
    assert not pe._looks_like_shell("mysql", "5.0.51a")
    assert not pe._looks_like_shell("", "")
