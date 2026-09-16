"""Invalid-module auto-correct: decode MSF's bytes keys, then map near-misses.

Regression for the bug that made the Metasploit invalid_module auto-correct a
no-op: `module.search` returns msgpack rows with BINARY (bytes) keys — b'type',
b'fullname' — even under raw=False, so `search_modules`' `m.get("type") ==
"exploit"` filter matched nothing and dropped every result. `_search_correct_module`
then always came back empty and no invalid_module failure was ever corrected.

Also covers the DB-free listing fallback `_closest_module_by_tokens`, which maps a
mistyped leaf ('php_cgi_argument_injection') onto the real module
('multi/http/php_cgi_arg_injection') while returning None for a genuinely absent
module ('drb_remote_codeexec', 'metasploitable_root_shell_1524') — so a phantom
module is not "corrected" into a confident wrong guess.

    pytest tests/test_msf_module_autocorrect.py

Sabotage check: drop the `_decode_msf` call in search_modules and
test_search_modules_decodes_and_filters fails (returns []). Loosen the first-token
gate in _closest_module_by_tokens and test_closest_rejects_absent_modules fails.
"""
import sys
import asyncio
import pathlib

import pytest

RUNNER = pathlib.Path(__file__).resolve().parent.parent / "exploit_runner"
sys.path.insert(0, str(RUNNER))
mc = pytest.importorskip("msf_client")   # imports msgpack + httpx


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---- _decode_msf (pure) -----------------------------------------------------

def test_decode_msf_bytes_keys_and_values():
    row = {b"type": "exploit", b"fullname": b"exploit/unix/misc/distcc_exec",
           b"rank": b"excellent", "name": "DistCC"}
    out = mc._decode_msf([row])
    assert isinstance(out, list) and len(out) == 1
    m = out[0]
    # keys are now str, so .get(...) actually resolves
    assert m.get("type") == "exploit"
    assert m.get("fullname") == "exploit/unix/misc/distcc_exec"
    assert m.get("rank") == "excellent"


def test_decode_msf_leaves_non_bytes_untouched():
    assert mc._decode_msf({"a": 1, "b": [2, "3"]}) == {"a": 1, "b": [2, "3"]}


# ---- search_modules decode + filter (fake _call, no network) ----------------

class _FakeClient(mc.MsfRpcClient):
    def __init__(self, search_rows=None, roster=None):
        # bypass real __init__ networking config
        self.token = "t"
        self._search_rows = search_rows or []
        self._roster = roster or []

    async def _call(self, method, *args):
        if method == "module.search":
            return self._search_rows
        if method == "module.exploits":
            return {"modules": self._roster}
        return {}


def test_search_modules_decodes_and_filters():
    # Exactly the shape MSF returns: bytes keys, mixed bytes/str values.
    rows = [
        {b"type": "exploit", b"name": "Samba usermap",
         b"fullname": b"exploit/multi/samba/usermap_script", b"rank": b"excellent"},
        {b"type": "auxiliary", b"name": "scanner",
         b"fullname": b"auxiliary/scanner/x"},   # must be filtered out
    ]
    c = _FakeClient(search_rows=rows)
    got = _run(c.search_modules("usermap_script", module_type="exploit"))
    # Before the decode fix this was [] (every row missed the str-key filter).
    assert len(got) == 1, f"decode/filter dropped rows: {got}"
    assert got[0]["fullname"] == "exploit/multi/samba/usermap_script"


def test_list_module_names_decodes_and_caches():
    c = _FakeClient(roster=[b"multi/http/php_cgi_arg_injection", "unix/misc/distcc_exec"])
    names = _run(c.list_module_names("exploit"))
    assert "multi/http/php_cgi_arg_injection" in names   # bytes decoded
    assert "unix/misc/distcc_exec" in names
    assert c._module_name_cache["exploit"] is names       # cached


# ---- _closest_module_by_tokens (needs exploit_runner import) ----------------

er = pytest.importorskip("exploit_runner")

_ROSTER = [
    "multi/http/php_cgi_arg_injection",
    "multi/samba/usermap_script",
    "unix/misc/distcc_exec",
    "multi/kubernetes/exec",
    "linux/local/some_root_shell_thing",
]


class _RosterClient:
    async def list_module_names(self, module_type="exploit"):
        return list(_ROSTER)


def test_closest_maps_near_miss():
    got = _run(er._closest_module_by_tokens(_RosterClient(),
              "php_cgi_argument_injection", "exploit/php_cgi_argument_injection"))
    assert got == "exploit/multi/http/php_cgi_arg_injection"


def test_closest_rejects_absent_modules():
    # First token matches nothing loaded -> no confident wrong guess.
    assert _run(er._closest_module_by_tokens(_RosterClient(),
               "drb_remote_codeexec", "exploit/drb_remote_codeexec")) is None
    # 'exec' must NOT match inside 'codeexec' (the earlier false positive), and
    # a synthetic id must not latch onto '..._root_shell_...' via 2 shared tokens
    # because its first token ('metasploitable') is loaded by nobody.
    assert _run(er._closest_module_by_tokens(_RosterClient(),
               "metasploitable_root_shell_1524",
               "exploit/metasploitable_root_shell_1524")) is None
