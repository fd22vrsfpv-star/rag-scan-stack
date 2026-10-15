"""A fact must carry where it came from, be proven, and then be USED.

Three defects, measured, that this covers:

1. CONFIDENCE CARRIED NO INFORMATION. `confirmed_facts.confidence` held 0.9 on
   all 72 rows — confirmed, unverified and REFUTED alike. It was the default
   argument of `_record_confirmation` and not one of its 13 call sites passed
   it. A value read from the grading harness's own eval.yml scored exactly the
   same as one the model invented.

2. TTL WAS WRITTEN AND NEVER ENFORCED. Every one of those 72 rows was past its
   TTL while every reader treated them as live. A `session_valid` fact expires
   in 900s; substituting an hour-old session id into a command produces a 401
   the refine loop then spends iterations "fixing".

3. A PROVEN FACT WAS IGNORED. On CVE-2024-4443 the gather manifest recorded
   `input_field = listingfields (via llm_fallback)` — the correct vulnerable
   parameter, named in the advisory. It appears 22 times in that run's trace
   and in ZERO of the 26 dispatched commands, every one of which attacked
   `?dosrch=1&q=&wpbdp_view=search`. Scoring the fact higher would not have
   changed one of them; something has to check the command.

The provenance scale is the contract: `harness_declared` (1.0) is the only tier
that reaches certainty, because it is the file the score is computed from.
Everything else is evidence of varying quality, and a REFUTED fact is 0.0
whatever its pedigree.

Sabotage check: make `confidence_for` ignore status and
`test_refuted_is_zero_whatever_the_source` fails; drop the TTL clause from the
substitution reader and `test_substitution_reader_enforces_ttl` fails; delete
the fact gate from the refine loop and `test_fact_gate_is_wired_before_dispatch`
fails.

    pytest tests/test_fact_provenance.py -q
"""

import ast
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
sys.path.insert(0, str(REPO / "app" / "rag-api"))

fact_provenance = pytest.importorskip("fact_provenance")
fact_probes = pytest.importorskip("fact_probes")

from fact_provenance import (CONFIRMED, PROVENANCE, REFUTED,  # noqa: E402
                             UNVERIFIED, confidence_for, effective_status,
                             is_stale, label)
from fact_probes import (enforce_facts, command_uses_fact,  # noqa: E402
                         run_probes)


class _R:
    def __init__(self, status_code, text=""):
        self.status_code, self.text = status_code, text


# ── 1. the confidence scale ───────────────────────────────────────────────────

def test_only_the_harness_reaches_certainty():
    """It is the file the score is computed from; nothing else can match it."""
    assert PROVENANCE["harness_declared"] == 1.0
    others = {k: v for k, v in PROVENANCE.items() if k != "harness_declared"}
    assert all(v < 1.0 for v in others.values()), (
        f"a non-harness source claims certainty: "
        f"{[k for k, v in others.items() if v >= 1.0]}")


def test_a_guess_scores_far_below_an_observation():
    assert (confidence_for("model_inferred", CONFIRMED)
            < confidence_for("probe_confirmed", CONFIRMED))
    assert confidence_for("model_inferred", UNVERIFIED) < 0.2, (
        "an unchecked model guess is not worth 0.2 — it was 0.9 before this")


def test_refuted_is_zero_whatever_the_source():
    """A disproof outranks a pedigree."""
    for src in PROVENANCE:
        assert confidence_for(src, REFUTED) == 0.0, (
            f"{src} keeps confidence {confidence_for(src, REFUTED)} after being "
            "refuted — the old code scored a refuted fact 0.9, identically to a "
            "confirmed one")


def test_an_unverified_claim_is_worth_half_its_source():
    """A perfect source still only yields a claim until something checks it."""
    for src, base in PROVENANCE.items():
        assert confidence_for(src, UNVERIFIED) == pytest.approx(base * 0.5, abs=1e-3)
    assert confidence_for("harness_declared", UNVERIFIED) == 0.5, (
        "even the harness's own declaration is only a claim until a probe "
        "confirms this installation matches it")


def test_an_unknown_source_scores_lowest():
    assert confidence_for("something_new", CONFIRMED) == PROVENANCE["unknown"], (
        "an unrecognised source must fall to `unknown`, not to a default that "
        "flatters it — an unattributed fact is the one most likely to be a "
        "guess that lost its label")


# ── 2. staleness ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("ttl,age,expected", [
    (900, 3600, True),     # session expired an hour ago
    (900, 60, False),
    (0, 10 ** 9, False),   # ttl 0 == never stale
    (None, 100, False),
    (900, -5, False),      # unmeasurable age is NOT expiry
    ("bad", 100, False),
])
def test_is_stale(ttl, age, expected):
    assert is_stale(ttl, age) is expected


def test_a_stale_confirmation_reads_as_a_claim():
    assert effective_status(CONFIRMED, 900, 3600) == UNVERIFIED
    assert confidence_for("probe_confirmed", CONFIRMED, stale=True) < \
        confidence_for("probe_confirmed", CONFIRMED)


def test_a_refutation_never_goes_stale():
    """Re-promoting it would hand the loop back a dead end it had ruled out."""
    assert effective_status(REFUTED, 1, 10 ** 9) == REFUTED


def test_label_says_proven_or_claimed():
    assert label("harness_declared", CONFIRMED).startswith("PROVEN")
    assert label("model_inferred", UNVERIFIED).startswith("CLAIMED")
    assert "STALE" in label("probe_confirmed", CONFIRMED, stale=True)
    assert label("probe_confirmed", REFUTED).startswith("REFUTED")


# ── 3. the probes: three outcomes, never two ──────────────────────────────────

FACTS = {"endpoint": "/business-directory", "method": "GET,POST",
         "input_field": "listingfields"}


def test_a_reflected_parameter_is_confirmed():
    def http(m, url, **kw):
        return _R(200, "...pf0prb...") if "listingfields=pf0prb" in url else _R(200, "")
    r = run_probes(http, "http://t:9090", FACTS)["input_field"]
    assert r.status == CONFIRMED and r.value == "listingfields"
    assert "listingfields" in r.evidence


def test_a_blind_parameter_is_never_refuted():
    """THE case that matters: blind injection looks exactly like a wrong param."""
    r = run_probes(lambda m, u, **k: _R(200, "same body"), "http://t:9090", FACTS)
    assert r["input_field"].status == UNVERIFIED, (
        "a parameter that neither reflects nor changes the response was "
        "REFUTED — that discards every blind injection point there is")
    assert "inconclusive" in r["input_field"].evidence


def test_a_404_endpoint_is_refuted():
    r = run_probes(lambda m, u, **k: _R(404, ""), "http://t:9090", FACTS)
    assert r["endpoint_exists"].status == REFUTED


def test_a_protected_endpoint_is_confirmed_not_refuted():
    """401/403 proves the path exists. A 403 on the right path beats 200 on the wrong one."""
    for code in (401, 403, 500):
        r = run_probes(lambda m, u, **k: _R(code, ""), "http://t:9090", FACTS)
        assert r["endpoint_exists"].status == CONFIRMED, code


def test_a_probe_that_could_not_run_is_not_a_refutation():
    def boom(m, url, **kw):
        raise TimeoutError("timed out")
    r = run_probes(boom, "http://t:9090", FACTS)
    assert r["endpoint_exists"].status == UNVERIFIED, (
        "a timeout was recorded as a disproof — this repo's most expensive "
        "recurring bug, now inside the fact layer")
    assert r["target_reachable"].status == REFUTED, (
        "no HTTP response at all IS evidence the target is unreachable")


def test_a_missing_input_says_which_one():
    r = run_probes(lambda m, u, **k: _R(200, ""), "http://t:9090", {"endpoint": "/x"})
    assert r["input_field"].status == UNVERIFIED
    assert "input_field" in r["input_field"].evidence


def test_could_not_run_and_inconclusive_are_distinguishable():
    """Both are UNVERIFIED; they send an operator to different fixes."""
    ran = run_probes(lambda m, u, **k: _R(200, "same"), "http://t:9090", FACTS)["input_field"]
    didnt = run_probes(lambda m, u, **k: _R(200, ""), "http://t:9090", {"endpoint": "/x"})["input_field"]
    assert "did not run" in didnt.evidence
    assert "did not run" not in ran.evidence and "inconclusive" in ran.evidence


def test_405_refutes_a_method():
    r = run_probes(lambda m, u, **k: _R(405, ""), "http://t:9090", FACTS)
    assert r["method_allowed"].status == REFUTED


# ── 4. enforcement: the proven fact must be USED ──────────────────────────────

REAL_FAILING_COMMAND = (
    "curl -s 'http://172.19.18.126:9090/business-directory/"
    "?dosrch=1&q=&wpbdp_view=search'")


def test_the_command_that_actually_ran_26_times_is_refused():
    refusal = enforce_facts(REAL_FAILING_COMMAND, {"input_field": "listingfields"})
    assert refusal, (
        "the exact command dispatched 26 times on CVE-2024-4443 — which never "
        "touched the vulnerable parameter — passes the gate")
    assert "listingfields" in refusal


def test_a_command_using_the_proven_fact_is_allowed():
    cmd = ("curl -s \"http://t:9090/business-directory/"
           "?listingfields[1]=1 AND SLEEP(5)\"")
    assert enforce_facts(cmd, {"input_field": "listingfields"}) is None


@pytest.mark.parametrize("spelling", [
    "listingfields", "LISTINGFIELDS", "listingfields%5B1%5D", "listingfields[1]"])
def test_encoding_variants_count_as_using_the_fact(spelling):
    """Percent-encoding is not a change — the same rule the axis gate learned."""
    assert command_uses_fact("curl 'http://t/x?%s=1'" % spelling, "listingfields")


def test_nothing_to_enforce_allows_everything():
    """The gate must be inert when no fact reaches the bar."""
    assert enforce_facts(REAL_FAILING_COMMAND, {}) is None
    assert enforce_facts(REAL_FAILING_COMMAND, None) is None
    assert enforce_facts("", {"input_field": "x"}) is None
    assert enforce_facts(REAL_FAILING_COMMAND, {"input_field": ""}) is None


# ── 5. the wiring in api.py ───────────────────────────────────────────────────

def _api_src() -> str:
    if not API.exists():
        pytest.skip("api.py not found")
    return API.read_text(encoding="utf-8")


def _func(name):
    for n in ast.walk(ast.parse(_api_src())):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    pytest.fail(f"{name} not defined in api.py")


def test_the_writer_derives_confidence_from_provenance():
    fn = _func("_record_confirmation")
    args = {a.arg for a in fn.args.args}
    assert "source" in args, (
        "_record_confirmation takes no `source`, so confidence cannot be "
        "derived and every fact scores the same again")
    src = ast.get_source_segment(_api_src(), fn) or ""
    assert "confidence_for" in src, "confidence is not derived from provenance"
    # the old constant default must be gone
    default = next((d for a, d in zip(fn.args.args[-len(fn.args.defaults):],
                                      fn.args.defaults) if a.arg == "confidence"), None)
    assert isinstance(default, ast.Constant) and default.value is None, (
        "confidence still has a hardcoded numeric default — that default is "
        "exactly why all 72 ledger rows held 0.9")


def test_substitution_reader_enforces_ttl():
    """These values go straight into the dispatched command."""
    src = _api_src()
    i = src.find("FROM confirmed_facts WHERE target=%s ")
    assert i > 0, "the substitution reader is gone"
    window = src[i:i + 500]
    assert "ttl_seconds" in window and "last_checked_at" in window, (
        "the reader that substitutes fact values into commands does not check "
        "the TTL — an expired session id gets injected and the loop spends "
        "iterations fixing the 401 it causes")


def test_required_facts_only_accepts_proven_high_confidence():
    """The gate may only insist on facts that are proven, fresh and strong.

    Checked against the query's own SQL literal, by the columns it constrains
    rather than by the exact predicate text — the spelling of
    `status = 'confirmed'` is not the invariant, filtering on status is.
    """
    import re as _re
    fn = _func("_required_facts_for")
    sql = " ".join(" ".join(n.value.split()) for n in ast.walk(fn)
                   if isinstance(n, ast.Constant) and isinstance(n.value, str)
                   and "confirmed_facts" in n.value)
    assert sql, "_required_facts_for has no query against confirmed_facts"
    # Only the WHERE clause counts. Searching the whole statement matched
    # `confidence` in the SELECT list, so deleting the `AND confidence >= %s`
    # filter left this test passing — a guard that cannot fail.
    where = _re.split(r"\bWHERE\b", sql, maxsplit=1, flags=_re.I)
    assert len(where) == 2, "the query has no WHERE clause at all"
    where = _re.split(r"\bORDER\s+BY\b", where[1], maxsplit=1, flags=_re.I)[0]
    constrained = set(_re.findall(
        r"\b(status|confidence|ttl_seconds|last_checked_at)\b", where))
    for col, why in (
            ("status", "unproven facts could be insisted on"),
            ("confidence", "a low-confidence guess could be insisted on"),
            ("ttl_seconds", "a stale fact could be insisted on")):
        assert col in constrained, f"{col} is not constrained — {why}"
    assert "confirmed" in where, (
        "the status filter does not name the confirmed state, so an "
        "`unverified` or `refuted` fact could be enforced on the command")


def test_fact_gate_is_wired_before_dispatch():
    """Imported AND called — checked structurally.

    A substring search for "enforce_facts" is satisfied by the alias
    `_enforce_facts`, so deleting the import while leaving the call site
    passed a text check. Both halves are asserted on the AST instead.
    """
    fn = _func("_run_refine_poc")
    imported = {
        alias.asname or alias.name
        for n in ast.walk(fn) if isinstance(n, ast.ImportFrom)
        and n.module == "fact_probes"
        for alias in n.names if alias.name == "enforce_facts"}
    assert imported, (
        "the refine loop does not import enforce_facts from fact_probes — a "
        "proven fact can be ignored by every dispatched command, which is the "
        "CVE-2024-4443 failure this whole layer exists to stop")
    called = {n.func.id for n in ast.walk(fn)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert imported & called, (
        f"enforce_facts is imported as {sorted(imported)} but never called")
    names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
    assert "_required_facts" in names


def test_the_fact_gate_fails_open():
    """A quality check, unlike the scope gate, which fails closed."""
    fn = _func("_run_refine_poc")
    src = ast.get_source_segment(_api_src(), fn) or ""
    assert "refine_fact_gate_opened" in src, (
        "the fact gate has no fail-open path — an unreadable ledger or a "
        "stubborn model would stall the build entirely")
    assert "_REFINE_FACT_REJECT_MAX" in src, "the re-asks are unbounded"


# ── 6. the two flaws found on the first live run (2026-10-15) ─────────────────

def test_degenerate_values_are_not_enforceable():
    """`endpoint_exists = '/'` was armed on a real run.

    Every URL contains "/", so enforcing it can never refuse anything. It is
    not harmful, but it pads the armed set and makes the gate look like it
    checks more than it does — a guard that cannot fail, mistaken for coverage.
    """
    from fact_probes import is_enforceable_value
    for junk in ("/", "//", ".", "-", "", None, "  ", "/ /", "id", "a1",
                 "http", "index.php"):
        assert not is_enforceable_value(junk), f"{junk!r} was armed"
    for real in ("listingfields", "/business-directory", "10084",
                 "wpbdp_view", "/admin1"):
        assert is_enforceable_value(real), f"{real!r} was dropped"


def test_required_facts_filters_degenerate_values():
    """Imported AND called — the import line alone satisfies a text search.

    Checked on the AST: reverting the call site to `if val:` while leaving the
    import in place passed a substring check, which is the same trap that let
    a deleted `enforce_facts` import through earlier.
    """
    fn = _func("_required_facts_for")
    imported = {a.asname or a.name
                for n in ast.walk(fn) if isinstance(n, ast.ImportFrom)
                and n.module == "fact_probes"
                for a in n.names if a.name == "is_enforceable_value"}
    assert imported, (
        "_required_facts_for does not import the enforceability filter")
    called = {n.func.id for n in ast.walk(fn)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert imported & called, (
        f"the filter is imported as {sorted(imported)} but never called — "
        "_required_facts_for still arms every confirmed value, including ones "
        "like '/' that cannot refuse anything")


def test_the_first_command_is_checked_before_dispatch():
    """The gate used to see only REFINE-produced commands.

    On CVE-2024-22120 that meant iterations 1-2 reached the target before the
    gate first looked, at iteration 3.
    """
    fn = _func("_run_refine_poc")
    src = ast.get_source_segment(_api_src(), fn) or ""
    assert "_fact_block" in src, (
        "there is no pre-dispatch fact check, so the command synth wrote is "
        "dispatched without ever being checked against the proven facts")
    assert "fact_predispatch_refused" in src, "the refusal is not traced"
    # It must take the NON-dispatching branch. The dispatch path is the `else`
    # of the syntax-check test, so the fact block has to join its condition.
    assert "if _fact_block or not _syn_ok:" in src, (
        "the fact block does not join the non-dispatch branch — setting a "
        "variable without diverting control flow lets the command dispatch "
        "anyway, which is the bug this test exists to catch")


def test_a_fact_block_does_not_count_as_a_syntax_failure():
    """`_consecutive_syntax_fails` drives the MODEL FALLBACK swap.

    "The command ignores a proven fact" is no evidence that this model cannot
    write shell. Counting it would swap the model out for an unrelated reason.
    """
    fn = _func("_run_refine_poc")
    src = ast.get_source_segment(_api_src(), fn) or ""
    i = src.find("_consecutive_syntax_fails += 1")
    assert i > 0, "the syntax-fail counter is gone"
    guard = src[max(0, i - 220):i]
    assert "if not _fact_block" in guard, (
        "a fact block still increments _consecutive_syntax_fails, so enough "
        "of them silently swap the model out mid-build")


def test_the_predispatch_check_is_bounded_and_fails_open():
    fn = _func("_run_refine_poc")
    src = ast.get_source_segment(_api_src(), fn) or ""
    assert "_REFINE_FACT_REJECT_MAX" in src
    assert "fact_predispatch_opened" in src, (
        "the pre-dispatch check never gives up — a model that will not use the "
        "fact would spin until the loop-pass cap instead of dispatching")
