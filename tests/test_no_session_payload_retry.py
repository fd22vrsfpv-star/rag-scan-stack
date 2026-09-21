"""A no_session auto-correct must not re-run the payload that just failed.

Run on demand:

    pytest tests/test_no_session_payload_retry.py -v

WHY THIS EXISTS
---------------
`_next_correction` handles "no session established" by changing the payload
connect_style. Behind a proxy with no reachable callback host it now FORCES
`bind` (flipping to reverse would aim a callback at an unroutable container
LHOST — the dangerous half of the bug, already fixed).

But `_pick_payload` is DETERMINISTIC: same compatible list, same style, same
payload. So forcing the style the run already used re-picked the SAME payload and
the "correction" was a verbatim re-run — one more identical dispatch at the
target, recorded as an auto-correct that tried something. The payload that failed
is now carried forward in `payload_config["exclude_payloads"]` and dropped from
the candidate pool, so the retry takes the next-best candidate.

What must NOT change, and is asserted here too:
  * `auto` still prefers a REVERSE callback; bind stays the fallback
    (etl/bind_payload_policy).
  * among binds, interpreter reliability still decides (bind_perl beats bind_awk,
    verified live on metasploitable) and netcat is still the last resort.
  * a bind payload still requires MANUAL approval.

SABOTAGE PROOF (performed)
--------------------------
Make `_pick_payload` select from `compatible` instead of the exclusion-filtered
`pool`, and test_retry_picks_a_different_payload +
test_pick_payload_skips_the_failed_payload fail ("retry re-picked the payload
that just failed"). Delete the `exclude_payloads` block from the no_session
branch of `_next_correction` and test_no_session_retry_records_the_dead_payload
+ test_retry_picks_a_different_payload fail. Restored after each.

FIXTURE PROVENANCE
------------------
COMPATIBLE is a realistic reproduction of the compatible-payload set Metasploit
returns for a cmd-exec unix module (the usermap_script / distcc_exec family used
against the lab metasploitable) — the payload NAMES are real Metasploit modules;
the list was reproduced here, not captured live in this session. FAILURE_OUTPUT
is the exploit-runner's own failure text, assembled exactly as
execute_msf_module builds it (proxy note, `Command:` line from _msf_command_str,
job id, "No session established").
"""
import asyncio
import os
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "exploit_runner"))

er = pytest.importorskip("exploit_runner", reason="exploit_runner deps not installed")

COMPATIBLE = [
    "cmd/unix/bind_awk",
    "cmd/unix/bind_busybox_telnetd",
    "cmd/unix/bind_netcat",
    "cmd/unix/bind_nodejs",
    "cmd/unix/bind_perl",
    "cmd/unix/bind_r",
    "cmd/unix/bind_ruby",
    "cmd/unix/bind_zsh",
    "cmd/unix/generic",
    "cmd/unix/reverse",
    "cmd/unix/reverse_awk",
    "cmd/unix/reverse_perl",
]

FAILURE_OUTPUT = (
    "[proxy] routed via socks5://172.18.0.40:10001 (node lab-node)\n"
    "Command: use exploit/multi/samba/usermap_script; set RHOSTS 172.18.0.32; "
    "set RPORT 139; set PAYLOAD cmd/unix/bind_perl; set LPORT 4444; "
    "set Proxies socks5:172.18.0.40:10001; run\n"
    "Job started: 7\n"
    "No session established (a bind payload needs the target port reachable; "
    "a reverse payload needs a reachable callback host)."
)


class _FakeMsf:
    """msf.compatible_payloads only — that is all _build_exploit_options uses."""
    def __init__(self, payloads):
        self._p = payloads

    async def compatible_payloads(self, module):
        return list(self._p)


def _req(**kw):
    base = dict(module_type="exploit", module_name="exploit/multi/samba/usermap_script",
                options={"RHOSTS": "172.18.0.32", "RPORT": 139},
                proxy_url="socks5://172.18.0.40:10001")
    base.update(kw)
    return er.MsfExecuteRequest(**base)


# ── the selector honours the exclusion ───────────────────────────────────────

def test_pick_payload_skips_the_failed_payload():
    first, style = er._pick_payload(COMPATIBLE, "bind", "")
    assert style == "bind" and first == "cmd/unix/bind_perl", first

    second, style2 = er._pick_payload(COMPATIBLE, "bind", "", [first])
    assert style2 == "bind", (second, style2)
    assert second != first, "retry re-picked the payload that just failed"
    assert second in COMPATIBLE and "bind" in second, second


def test_exclusion_does_not_reorder_the_survivors():
    """Dropping a candidate must not disturb the live-verified ordering."""
    # perl gone -> the next reliable interpreter, NOT awk-because-alphabetical
    # and NOT netcat (last resort while anything else remains).
    p = er._pick_payload(COMPATIBLE, "bind", "", ["cmd/unix/bind_perl"])[0]
    assert "netcat" not in p and "awk" not in p, p
    # netcat is still used when it is all that is left
    p2 = er._pick_payload(["cmd/unix/bind_netcat", "cmd/unix/bind_perl"], "bind", "",
                          ["cmd/unix/bind_perl"])[0]
    assert p2 == "cmd/unix/bind_netcat", p2
    # and a callback is still preferred under auto, exclusion or not
    _, s = er._pick_payload(COMPATIBLE, "auto", "", ["cmd/unix/bind_perl"])
    assert s == "reverse", s


def test_excluding_every_candidate_falls_back_to_the_module_default():
    """Never return the failed payload just because nothing else is left."""
    p, s = er._pick_payload(["cmd/unix/bind_perl"], "bind", "", ["cmd/unix/bind_perl"])
    assert (p, s) == (None, None), (p, s)
    # an explicit custom payload that already failed is re-selected, not reused
    p2, _ = er._pick_payload(COMPATIBLE, "bind", "cmd/unix/bind_perl", ["cmd/unix/bind_perl"])
    assert p2 != "cmd/unix/bind_perl", p2


# ── the correction carries the dead payload forward ──────────────────────────

def test_no_session_retry_records_the_dead_payload(monkeypatch):
    monkeypatch.setattr(er, "LLM_DIAGNOSE", False)
    new_req, cls = asyncio.run(er._next_correction(
        _req(), FAILURE_OUTPUT, "cmd/unix/bind_perl"))
    assert cls == "no_session" and new_req is not None
    pc = new_req.payload_config or {}
    # the already-fixed half: proxied + no callback host -> bind, never reverse
    assert pc.get("connect_style") == "bind", pc
    assert "cmd/unix/bind_perl" in (pc.get("exclude_payloads") or []), pc


def test_the_dead_payload_is_recovered_from_the_output(monkeypatch):
    """A caller that passes no payload still gets a non-identical retry: the
    runner's own `Command:` line names it."""
    monkeypatch.setattr(er, "LLM_DIAGNOSE", False)
    assert er._payload_from_output(FAILURE_OUTPUT) == "cmd/unix/bind_perl"
    assert er._payload_from_output("") == ""
    new_req, _ = asyncio.run(er._next_correction(_req(), FAILURE_OUTPUT))
    assert "cmd/unix/bind_perl" in ((new_req.payload_config or {}).get("exclude_payloads") or [])


def test_exclusions_accumulate_without_duplicates(monkeypatch):
    monkeypatch.setattr(er, "LLM_DIAGNOSE", False)
    r = _req(payload_config={"connect_style": "bind",
                             "exclude_payloads": ["cmd/unix/bind_awk"]})
    new_req, _ = asyncio.run(er._next_correction(r, FAILURE_OUTPUT, "cmd/unix/bind_perl"))
    assert (new_req.payload_config or {}).get("exclude_payloads") == [
        "cmd/unix/bind_awk", "cmd/unix/bind_perl"]
    again, _ = asyncio.run(er._next_correction(
        _req(payload_config={"exclude_payloads": ["cmd/unix/bind_perl"]}),
        FAILURE_OUTPUT, "cmd/unix/bind_perl"))
    assert (again.payload_config or {}).get("exclude_payloads") == ["cmd/unix/bind_perl"]


# ── the guard proper: the retry is a different run ───────────────────────────

def test_retry_picks_a_different_payload(monkeypatch):
    """First dispatch -> retry, end to end through the real option builder.

    This is the whole point: before the fix both runs produced the identical
    PAYLOAD, so the auto-correct spent a dispatch re-proving the same failure.
    """
    monkeypatch.setattr(er, "LLM_DIAGNOSE", False)
    msf = _FakeMsf(COMPATIBLE)

    # Run 1: auto with no callback host (a NAT'd/proxied dispatcher) -> bind.
    cfg1 = er.MsfPayloadConfig()
    opts1, _p1, style1 = asyncio.run(
        er._build_exploit_options(msf, "exploit/multi/samba/usermap_script",
                                  "172.18.0.32", 139, cfg1))
    assert style1 == "bind" and "LHOST" not in opts1, opts1
    first = opts1["PAYLOAD"]

    # The correction the runner would compute from that failure.
    new_req, cls = asyncio.run(er._next_correction(_req(), FAILURE_OUTPUT, first))
    assert cls == "no_session" and new_req is not None
    pc = new_req.payload_config or {}

    # Run 2: the retry's config, built the same way.
    cfg2 = er.MsfPayloadConfig(connect_style=pc.get("connect_style", "auto"),
                               exclude_payloads=list(pc.get("exclude_payloads") or []))
    opts2, _p2, style2 = asyncio.run(
        er._build_exploit_options(msf, "exploit/multi/samba/usermap_script",
                                  "172.18.0.32", 139, cfg2))
    assert style2 == "bind", (opts2, style2)
    assert opts2["PAYLOAD"] != first, (
        f"retry re-picked {first} — the correction is a no-op re-run")
    assert "LHOST" not in opts2, (
        "a proxied retry must not aim a callback at an unroutable LHOST")


def test_the_retried_bind_still_needs_manual_approval(monkeypatch):
    """Changing WHICH bind payload must not weaken the approval rule."""
    monkeypatch.setattr(er, "LLM_DIAGNOSE", False)
    from etl.bind_payload_policy import bind_is_likely, is_bind_payload
    new_req, _ = asyncio.run(er._next_correction(_req(), FAILURE_OUTPUT, "cmd/unix/bind_perl"))
    pc = new_req.payload_config or {}
    assert bind_is_likely(pc), pc
    nxt = er._pick_payload(COMPATIBLE, pc["connect_style"], "",
                           pc.get("exclude_payloads"))[0]
    assert is_bind_payload(payload=nxt, style="bind"), nxt


def test_a_resolved_proxy_reaches_the_correction_path():
    """The bind-forcing must see a proxy the RUNNER resolved, not only one the
    caller supplied.

    `_next_correction` decides `proxied` from request.proxy_url /
    request.options["Proxies"]. But execute_msf_module builds
    `options = dict(request.options)` — a COPY — so `options.setdefault("Proxies", ...)`
    never reaches the request. On the normal path (the operator supplies no proxy
    and _enforce_proxy picks the engagement/node proxy) `proxied` was therefore
    False, and the no_session correction flipped to a reverse payload aimed at an
    unroutable LHOST: exactly the failure this auto-correct exists to prevent.

    So the runner must write the resolved proxy back onto the request.
    """
    import ast as _ast
    src = open(os.path.join(REPO, "exploit_runner", "exploit_runner.py"),
               encoding="utf-8").read()
    fn = None
    for n in _ast.walk(_ast.parse(src)):
        if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef)) and n.name == "execute_msf_module":
            fn = _ast.get_source_segment(src, n)
            break
    assert fn, "execute_msf_module not found"
    # Asked structurally: an assignment of the resolved proxy onto the request,
    # not a spelling of it.
    assigns = [n for n in _ast.walk(_ast.parse(fn.lstrip()))
               if isinstance(n, _ast.Assign)
               and any(isinstance(t, _ast.Attribute) and t.attr == "proxy_url"
                       for t in n.targets)
               and isinstance(n.value, _ast.Name) and n.value.id == "eff_proxy"]
    assert assigns, (
        "execute_msf_module does not record the RESOLVED proxy on the request, so "
        "_next_correction cannot tell a proxied dispatch from an unproxied one and "
        "will flip a no_session retry to an unreachable reverse callback")
