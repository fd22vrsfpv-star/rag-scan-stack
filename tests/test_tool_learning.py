"""Tool selection is learned from the error text, not written down.

Run on demand:

    pytest tests/test_tool_learning.py -v

WHY THIS EXISTS
---------------
`cred_checker` decided its fallback with a typed rule::

    if "kex error" in hydra_output or "no match for method" in hydra_output:
        fall back to nmap

The rule was right and the shape of it was the bug. It existed because a human
read one message from one tool on one protocol once, so every other tool/error
pair got nothing: the platform kept re-running something that could not work,
found nothing, and reported "nothing found" — indistinguishable from "there was
nothing to find". Against Metasploitable that cost 7 of 10 discoverable
credentials.

`etl/tool_learning.py` replaces it with an observation loop: signature the raw
error text, record the attempt, and pair a failure against whatever ran next on
the same target. What worked becomes a rule; what never works stops being tried.

THE TESTS SPLIT IN TWO
----------------------
  * Pure-function tests run anywhere — they pin the signature's stability and
    the invariant that a learned rule can only reorder tools the caller offered.
  * Store-backed tests need Postgres and SKIP cleanly without it.

SABOTAGE PROOF
--------------
  * Put "kex" back into `_DIAGNOSTIC_MARKERS` and
    `test_signature_knows_no_protocol_vocabulary` fails.
  * Restore the `if mode == "kex_mismatch"` decision branch in cred_checker and
    `test_cred_checker_does_not_branch_on_a_named_failure` fails.
  * Make `next_tool` return a tool outside `remaining` and
    `test_a_rule_can_only_reorder_what_was_offered` fails.
  * Delete the `_learn_from_execution` call from `db_update_tool_execution` and
    `test_every_command_feeds_the_learner` fails — commands other than
    credential checks would stop teaching the platform anything.
"""
import ast
import os
import re
import sys
import uuid

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

MODULE = os.path.join(REPO, "etl", "tool_learning.py")
CRED = os.path.join(REPO, "nmap_scanner", "cred_checker.py")
LISTENER = os.path.join(REPO, "kali_listener", "listener_service.py")
DDL = os.path.join(REPO, "db_init", "ensure_all_tables.sql")

tl = pytest.importorskip("etl.tool_learning", reason="etl/tool_learning.py not importable")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _func(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


def _strip_docstrings(src):
    """Prose that quotes the old rule is not the old rule.

    Three guards in this repo have been fooled by matching a comment instead of
    code, so every source assertion below runs over stripped source.
    """
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                             ast.Module)) and ast.get_docstring(node):
            node.body = node.body[1:] or [ast.Pass()]
    return ast.unparse(ast.fix_missing_locations(tree))


# Real hydra output, captured from the Metasploitable run that found 0 of the 3
# SSH credentials that were actually there.
HYDRA_KEX = """[DATA] attacking ssh://192.168.1.150:22/
[ERROR] could not connect to ssh://192.168.1.150:22 - kex error : no match for \
method kex algos: server [diffie-hellman-group1-sha1,diffie-hellman-group14-sha1], \
client [curve25519-sha256,ecdh-sha2-nistp256]
[ERROR] all children were disconnected. Now trying 1 tasks."""

HYDRA_REFUSED = "[ERROR] could not connect to telnet://172.18.0.32:23 - Connection refused"


# ── The signature ──────────────────────────────────────────────────────────

def test_the_same_failure_signs_the_same_on_any_host():
    """A rule learned on one target has to apply on the next one, or it learns
    a host, not a failure."""
    a, _ = tl.error_signature(HYDRA_KEX)
    b, _ = tl.error_signature(
        HYDRA_KEX.replace("192.168.1.150", "10.9.8.7").replace(":22", ":2222"))
    assert a and a == b, "signature moved with the address; every host would re-learn"


def test_different_failures_sign_differently():
    kex, _ = tl.error_signature(HYDRA_KEX)
    refused, _ = tl.error_signature(HYDRA_REFUSED)
    assert kex != refused, (
        "two unrelated failures share a signature — a rule learned for one "
        "would fire for the other")


def test_signature_knows_no_protocol_vocabulary():
    """The markers must stay generic English for 'this did not work'.

    A protocol term here re-creates the hardcoded rule this module removes: the
    point is that a service nobody anticipated still gets a working fallback.
    """
    banned = ("kex", "ssh", "ftp", "telnet", "vnc", "mysql", "postgres", "smb",
              "http", "rdp", "hydra", "nmap", "algo", "cipher")
    for marker in tl._DIAGNOSTIC_MARKERS:
        for b in banned:
            assert b not in marker, (
                f"_DIAGNOSTIC_MARKERS contains {marker!r}, which names {b!r} — "
                "that is a typed rule wearing a learner's clothes")


def test_a_silent_tool_still_gets_a_signature():
    """No 'error' keyword anywhere, but it still fails the same way twice.

    An empty signature would collapse every silent failure into one bucket and
    teach a rule that fires for all of them.
    """
    sig, phrase = tl.error_signature("job aborted after 3 retries\nnothing to do")
    assert sig and phrase


def test_nothing_at_all_gets_no_signature():
    """Empty output taught us nothing. Saying so beats inventing a bucket."""
    assert tl.error_signature("") == (None, None)
    assert tl.error_signature("   \n\n ") == (None, None)


def test_credentials_never_reach_the_stored_phrase():
    """The phrase is shown to operators and exported; tools echo the pair they
    just tried on the same line as the error."""
    line = tl.normalise_line("[ERROR] login: msfadmin password: msfadmin failed")
    assert "msfadmin" not in line, f"a credential survived into the phrase: {line}"
    assert "<redacted>" in line


def test_failure_is_detected_from_any_of_three_signals():
    """A tool that exits 0 while printing a fatal error is common enough that
    trusting the exit code alone would miss most of what there is to learn."""
    assert tl.execution_failed(status="failed")
    assert tl.execution_failed(status="timeout")
    assert tl.execution_failed(exit_code=2)
    assert tl.execution_failed(error="Segmentation fault")
    assert not tl.execution_failed(status="completed", exit_code=0, output="ok")


# ── The invariant: selection is not authorisation ──────────────────────────

def test_a_rule_can_only_reorder_what_was_offered():
    """next_tool is bounded by `remaining`, so a learned rule can never add a
    tool the caller did not authorise for that engagement."""
    src = _strip_docstrings(_read(MODULE))
    fn = _func(src, "next_tool")
    assert "remaining = [t for t in remaining if t != failed_tool]" in fn
    assert re.search(r"rules_for_signature\(\s*failed_tool,\s*signature,\s*remaining",
                     fn), "the lookup is no longer restricted to the caller's candidates"


def test_next_tool_returns_only_candidates_it_was_given():
    tool, reason, _ = tl.next_tool("hydra", "deadbeef", ["only_this_one"],
                                   service="nothing-learned-here")
    assert tool in ("only_this_one", None), tool
    assert reason in ("only_candidate", "learned", "exploration", "unavailable",
                      "learned_dead_end", "exhausted")


def test_no_remaining_candidates_means_no_tool():
    assert tl.next_tool("hydra", "deadbeef", [])[0] is None


def test_an_unreachable_store_is_not_a_clean_miss():
    """'Could not look' and 'looked, found nothing' are different answers, and
    this codebase has shipped the bug of conflating them repeatedly."""
    tool, reason, rule_id = tl.next_tool(
        "hydra", "deadbeef", ["nmap"], service="x", store_available=False)
    assert (tool, reason, rule_id) == ("nmap", "unavailable", None)


# ── cred_checker no longer decides from a named failure ────────────────────

def test_cred_checker_does_not_branch_on_a_named_failure():
    """The selection function must contain no protocol-specific decision.

    `kex_mismatch` survives as a LABEL — the audit panel says "couldn't even
    handshake" instead of "wrong password", and the UI reads the flag. What it
    must never do again is choose a tool: a service the labeller has never heard
    of has to get a working fallback anyway, and that is the whole point.
    """
    src = _strip_docstrings(_read(CRED))
    assert "should_fallback" not in src, (
        "the hardcoded hydra→nmap fallback decision is back; every service the "
        "labeller does not recognise loses its fallback again")

    fn = _func(src, "check_default_credentials")
    for line in fn.splitlines():
        if "kex" in line.lower():
            assert "audit" in line, (
                f"the selection function branches on a protocol-specific label: "
                f"{line.strip()!r}")

    # One comparison survives, in the per-attempt labeller that sets the audit
    # flag the UI reads. A second one means a decision site has grown back, so
    # this is a ratchet: the count may go down, never up.
    comparisons = re.findall(r'==\s*["\']kex_mismatch["\']', src)
    assert len(comparisons) <= 1, (
        f"{len(comparisons)} comparisons against a named failure mode — a typed "
        "rule has grown back somewhere. Only the labeller may name one.")


def test_cred_checker_asks_the_learner_which_tool_is_next():
    fn = _func(_strip_docstrings(_read(CRED)), "check_default_credentials")
    assert "learn.next_tool(" in fn, "the fallback is no longer learned"
    assert "learn.preferred_order(" in fn, (
        "the candidate order is no longer learned, so a tool known to fail on "
        "this service is still tried first every time")
    assert "learn.observe_sequence(" in fn, "the run teaches the platform nothing"


def test_cred_checker_still_works_without_the_learner():
    """etl/ unmounted is a valid deployment. Selection is not authorisation, so
    degrading here is safe — but it must degrade, not raise."""
    src = _strip_docstrings(_read(CRED))
    assert "def _tool_learning" in src
    fn = _func(src, "check_default_credentials")
    assert re.search(r"if\s+learn\b", fn) or "if learn:" in fn, (
        "every learner call must be guarded; an unmounted etl/ would abort the "
        "credential check instead of falling back to the declared order")


def test_adding_a_method_needs_no_per_service_branch():
    """The registry is the integration point. A new tool is offered, tried, and
    learned from without a line of routing logic."""
    src = _strip_docstrings(_read(CRED))
    assert re.search(r"^CRED_METHODS\s*=\s*\{", src, re.M)
    assert re.search(r"^DEFAULT_METHOD_ORDER\s*=", src, re.M)


def test_the_audit_says_whether_a_rule_or_a_guess_chose_the_tool():
    """An operator reading the audit must be able to tell the two apart."""
    fn = _func(_strip_docstrings(_read(CRED)), "check_default_credentials")
    assert "chosen_because" in fn
    assert "learning_available" in fn, (
        "the audit no longer distinguishes 'no rule matched' from 'could not "
        "consult the store'")


# ── Every command, not just credential checks ──────────────────────────────

def test_every_command_feeds_the_learner():
    """db_update_tool_execution is the chokepoint every tool the platform runs
    passes through. The hook lives there so a command that errors anywhere
    post-analysis teaches the platform something."""
    src = _strip_docstrings(_read(LISTENER))
    fn = _func(src, "db_update_tool_execution")
    assert "_learn_from_execution(" in fn, (
        "tool executions no longer feed the learner — only credential checks "
        "would learn, which is the narrow fix this replaced")
    hook = _func(src, "_learn_from_execution")
    assert "observe_execution(" in hook
    assert "tool_learning" in hook


def test_the_hook_cannot_fail_a_command_that_already_ran():
    hook = _func(_strip_docstrings(_read(LISTENER)), "_learn_from_execution")
    assert hook.count("except") >= 2, (
        "a learning store that is down would fail a tool run that completed")


def test_the_general_entry_points_exist():
    for name in ("observe_execution", "suggest_alternatives",
                 "learn_from_tool_executions", "execution_failed"):
        assert hasattr(tl, name), f"{name} is gone; the general path is broken"


# ── Schema ─────────────────────────────────────────────────────────────────

def test_tables_are_declared_in_the_installer():
    ddl = _read(DDL)
    for table in ("public.tool_attempts", "public.tool_selection_learned"):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in ddl, (
            f"{table} is not in db_init/ensure_all_tables.sql — a clean install "
            "would have no learning store and every lookup would report "
            "'unavailable' forever")


def test_the_unique_index_constrains_every_row():
    """A nullable column in a unique index permits unlimited duplicates: in
    Postgres a NULL makes rows non-equal. This repo has shipped that bug."""
    ddl = _read(DDL)
    block = ddl[ddl.index("CREATE TABLE IF NOT EXISTS public.tool_selection_learned"):]
    block = block[:block.index("CREATE UNIQUE INDEX IF NOT EXISTS ux_tool_selection_learned_rule")]
    for col in ("phase", "service", "failed_tool", "failure_signature",
                "preferred_tool"):
        assert re.search(rf"^\s+{col}\s+text\s+NOT NULL", block, re.M), (
            f"{col} is in the unique index but is nullable — duplicates get in")


def test_on_conflict_repeats_the_index_expression_exactly():
    """An ON CONFLICT that does not match the index raises 'no unique or
    exclusion constraint matching' on every insert."""
    src = _read(MODULE)
    assert re.search(
        r"ON CONFLICT \(phase, service, failed_tool,\s*\n?\s*failure_signature, "
        r"preferred_tool\)", src)


# ── Store-backed: the loop actually closes ─────────────────────────────────

@pytest.fixture(scope="module")
def store():
    if not tl.available():
        pytest.skip("learning store unreachable (no database here)")
    svc = f"__pytest_{uuid.uuid4().hex[:8]}"
    yield svc
    try:
        import psycopg2
        with psycopg2.connect(tl.DB_DSN) as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM public.tool_selection_learned WHERE service=%s", (svc,))
            cur.execute("DELETE FROM public.tool_attempts WHERE service=%s", (svc,))
    except Exception:
        pass


def test_a_failure_followed_by_a_success_becomes_a_rule(store):
    sig, phrase = tl.error_signature(HYDRA_KEX)
    assert tl.next_tool("hydra", sig, ["nmap", "medusa"], service=store)[1] != "learned", \
        "a rule exists before anything was observed"

    learned = tl.observe_sequence(
        [{"tool": "hydra", "success": False, "signature": sig, "phrase": phrase},
         {"tool": "nmap", "success": True}],
        service=store, emit=False)
    assert learned and learned[0]["status"] == "active", learned

    tool, reason, rule_id = tl.next_tool("hydra", sig, ["nmap", "medusa"], service=store)
    assert (tool, reason) == ("nmap", "learned"), (tool, reason)
    assert rule_id


def test_a_corroborated_rule_reorders_the_candidates(store):
    """The payoff: the dead round-trip through the losing tool stops happening."""
    sig, phrase = tl.error_signature(HYDRA_KEX)
    seq = [{"tool": "hydra", "success": False, "signature": sig, "phrase": phrase},
           {"tool": "nmap", "success": True}]
    for _ in range(tl.PROMOTE_AFTER_SUPPORT + 1):
        tl.observe_sequence(seq, service=store, emit=False)
    order, notes = tl.preferred_order(["hydra", "nmap"], service=store)
    assert order == ["nmap", "hydra"], order
    assert notes and "learned from" in notes[0]


def test_a_fallback_that_never_helps_stops_being_offered(store):
    """Learning only which tool WORKS would leave every useless fallback
    running forever."""
    sig, phrase = tl.error_signature(HYDRA_REFUSED)
    seq = [{"tool": "hydra", "success": False, "signature": sig, "phrase": phrase},
           {"tool": "nmap", "success": False, "signature": sig, "phrase": phrase}]
    for _ in range(tl.SUPPRESS_AFTER + 1):
        tl.observe_sequence(seq, service=store, emit=False)
    assert tl.next_tool("hydra", sig, ["nmap"], service=store) == (
        None, "learned_dead_end", None)


def test_an_operator_rejection_is_not_overturned_by_new_evidence(store):
    import psycopg2
    sig, phrase = tl.error_signature("[FATAL] handshake aborted by peer")
    tl.observe_sequence(
        [{"tool": "hydra", "success": False, "signature": sig, "phrase": phrase},
         {"tool": "nmap", "success": True}], service=store, emit=False)
    with psycopg2.connect(tl.DB_DSN) as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE public.tool_selection_learned SET status='rejected',
               reviewed_by='pytest' WHERE service=%s AND failure_signature=%s""",
            (store, sig))
    tl.observe_sequence(
        [{"tool": "hydra", "success": False, "signature": sig, "phrase": phrase},
         {"tool": "nmap", "success": True}], service=store, emit=False)
    rows = [r for r in tl.rules(service=store) if r["failure_signature"] == sig]
    assert rows and rows[0]["status"] == "rejected", rows
    assert tl.next_tool("hydra", sig, ["nmap"], service=store)[1] != "learned"


def test_observe_execution_learns_across_separate_commands(store):
    """The general path: two unrelated runners reporting one command each, with
    no sequence handed over, still produce the rule."""
    target = f"198.51.100.{uuid.uuid4().int % 200 + 1}"
    a = tl.observe_execution("nuclei", service=store, target=target, port=443,
                             status="failed", exit_code=1,
                             error="connection reset by peer", emit=False)
    assert a["recorded"] and a["failed"] and a["signature"]
    b = tl.observe_execution("curl", service=store, target=target, port=443,
                             status="completed", exit_code=0, output="HTTP/1.1 200",
                             result_count=1, emit=False)
    assert b["recorded"] and not b["failed"]
    assert any(r["failed_tool"] == "nuclei" and r["preferred_tool"] == "curl"
               and r["status"] == "active" for r in b["learned"]), b["learned"]

    advice = tl.suggest_alternatives("nuclei", error="connection reset by peer",
                                     service=store)
    assert advice["available"]
    assert [s["tool"] for s in advice["suggestions"]] == ["curl"], advice
