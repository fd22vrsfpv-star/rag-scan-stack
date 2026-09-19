"""The deepen/enumeration scope gate must resolve IP<->hostname aliases.

WHY: post_enumeration's deepen_web_finding/analyse resolve a finding to its
ASSET IP and scope-gate that IP, but the scope is defined by hostname/URL. Like
the exploit gate (enforce_target_scope), these must pass load_host_aliases to
check_dispatch, or a web finding on demo.testfire.net (65.61.137.117) is refused
"out of scope" and no deepen/sqlmap follow-up is ever queued.

SABOTAGE PROOF: drop the aliases= from any check_dispatch in post_enumeration
and this fails.
"""
import os, re, pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC = os.path.join(REPO, "etl", "post_enumeration.py")

def test_all_check_dispatch_calls_pass_aliases():
    if not os.path.exists(SRC): pytest.skip("post_enumeration.py missing")
    s = open(SRC, encoding="utf-8").read()
    calls = re.findall(r"check_dispatch\([^\n]*", s)
    assert calls, "no check_dispatch calls found — matcher broken?"
    bad = [c for c in calls if "aliases=" not in c]
    assert not bad, ("check_dispatch without alias resolution (IP target refused "
                     "against a hostname scope):\n  " + "\n  ".join(bad))
    assert "load_host_aliases" in s, "must import load_host_aliases"
