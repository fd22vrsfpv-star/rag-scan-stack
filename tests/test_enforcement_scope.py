"""A value used to REFUSE must carry the context it was proven in.

WHY THIS GUARD EXISTS
---------------------
Five instances of one defect were found and fixed separately over 2026-10-22/23,
each costing a run to diagnose:

  1. strategist grounding read a ZAP string from a stage that had not run yet,
     so the grounded set was {"/", ""} and every endpoint was "ungrounded";
  2. the fact challenge read the literal "unknown" as a product NAME;
  3. plan-verify probed `?param=canary` where the plan said POST-with-a-body,
     so a dispatcher endpoint could not pass by ANY parameter;
  4. the proven-fact gate enforced `input_field='roles'` — proven against
     /wp-json/wp/v2/users — on a command targeting /wp-admin/admin-ajax.php,
     refusing the one command carrying the advisory's real parameters;
  5. `known_dead` pools error signatures across every CVE and host, counting
     the harness's own pre-dispatch refusals among them.

Same shape every time: evidence established in one context, enforced in
another. This file makes the sixth a test failure instead of an investigation.

WHAT IT ENFORCES
----------------
* the primitives in `etl/enforcement_scope.py` behave as documented, including
  the fail-open cases that keep an existing gate from silently emptying;
* every refusal site in the build-poc pipeline is CLASSIFIED. A new one fails
  by name until it is declared self-contained, scoped, or debt;
* a site declared SCOPED actually consults the primitive.

`SCOPE_DEBT` ratchets: shrink it, never grow it without a stated reason.

    pytest tests/test_enforcement_scope.py
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _ast_assert import calls, call_kwarg, defines, call_order  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
API = ROOT / "app" / "rag-api" / "api.py"
GRAPH = ROOT / "app" / "rag-api" / "build_poc_graph.py"
sys.path.insert(0, str(ROOT))

es = pytest.importorskip("etl.enforcement_scope")


# ── the primitives ──────────────────────────────────────────────────────────

def test_a_scope_survives_a_round_trip():
    ref = es.tag("gather_manifest:input_field (via plan_verify)", "/wp-admin/admin-ajax.php")
    assert es.scope_of(ref) == "/wp-admin/admin-ajax.php"


@pytest.mark.parametrize("unnamed", ["unknown", "", None, "n/a", "-", "  ", "none"])
def test_an_unnamed_scope_is_never_invented(unnamed):
    """A filled field is not a context. Tagging with a placeholder would create
    a scope that later refuses real facts."""
    ref = es.tag("provenance", unnamed)
    assert ref == "provenance"
    assert es.scope_of(ref) is None


def test_a_legacy_ref_is_unscoped_not_global():
    assert es.scope_of("gather_manifest:input_field (via plan_verify)") is None


def test_a_known_mismatch_is_the_only_refusal():
    assert es.may_enforce("/a", "/a") is True
    assert es.may_enforce("/a", "/b") is False


@pytest.mark.parametrize("missing", [None, "", "unknown"])
def test_an_unknown_scope_fails_open(missing):
    """SABOTAGE GUARD. Dropping every unscoped fact would empty an existing
    gate with nobody noticing — this defect inverted."""
    assert es.may_enforce(missing, "/wp-admin/admin-ajax.php") is True
    assert es.may_enforce("/wp-admin/admin-ajax.php", missing) is True


def test_the_current_run_beats_a_stored_value():
    """The real CVE-2023-37999 collision."""
    assert es.prefer_current({"input_field": "roles"},
                             {"input_field": "reg_role"})["input_field"] == "reg_role"


def test_an_empty_current_run_changes_nothing():
    stored = {"input_field": "roles", "endpoint_exists": "/x"}
    assert es.prefer_current(stored, {}) == stored
    assert es.prefer_current(stored, {"input_field": ""}) == stored


def test_this_is_not_an_authorization_boundary():
    """CLAUDE.md: the scope GATE fails closed; these are quality checks and
    fail open. Confusing the two would turn a quality check into permission."""
    doc = (es.__doc__ or "") + (es.may_enforce.__doc__ or "")
    assert "scope_gate" in doc and "fail" in doc.lower()


# ── the registry: every refusal site is classified ──────────────────────────

# Refuses on evidence from THIS run or THIS command — nothing stored, so there
# is no foreign context to carry.
SELF_CONTAINED = {
    "drift_blocked_verification":     "compares the command's family against this run's origin_family",
    "llm_refusal_refused":            "the model declined; the refusal IS the evidence",
    "proxy_refused":                  "host-level routing; the host is the context",
    "refine_axis_rejected":           "compares against this run's own prior commands",
    "refine_identical_rejected":      "duplicate of this run's previous command",
    "refine_identical_rejected_drift": "as above, on the drift path",
    "shell_syntax_refused":           "the command does not parse; self-evident",
    "timing_assertion_drift_blocked": "this run's assertion vs this run's command",
    "class_gate_blocked":             "vuln class of this build vs this command",
    "synth_plan_rejected":            "this run's synthesised plan",
    "run_refine_skipped_blocked":     "upstream gate already decided; no stored fact read",
    "graded_identity_refused":        ("this run's command vs this run's benchmark goal; "
                                       "no stored fact is read"),
}

# Refuses on STORED evidence and must consult enforcement_scope.
SCOPED = {
    "fact_predispatch_refused": "_required_facts_for",
    "refine_fact_rejected":     "_required_facts_for",
}

# Known violations. RATCHETS — shrink it; do not grow it without a reason.
SCOPE_DEBT = {
    "known_dead_signature":
        "_signature_known_dead pools build_poc_error_memory by `signature` alone — "
        "the table carries cve/ip/port and the query uses none of them — and the "
        "pool includes signatures the harness generated (a pre-dispatch refusal "
        "is recorded like any iteration). See Docs/OPEN_ITEMS.md.",
}

_REFUSAL_WORD = re.compile(r"(refused|rejected|blocked|denied)")


def _traced_refusal_phases():
    """Every phase name the pipeline traces that announces a refusal."""
    found = set()
    for path in (API, GRAPH):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
            if getattr(call.func, "id", "") != "_poc_trace":
                continue
            for arg in call.args[1:2]:
                if (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                        and _REFUSAL_WORD.search(arg.value)):
                    found.add(arg.value)
    return found


def test_every_refusal_site_is_classified():
    """A new way to refuse must be declared before it ships. Whoever adds one
    decides whether it reads stored evidence — that is not inferable later."""
    known = set(SELF_CONTAINED) | set(SCOPED) | set(SCOPE_DEBT)
    found = _traced_refusal_phases()
    undeclared = found - known
    assert not undeclared, (
        "undeclared refusal site(s): %s\n"
        "Classify each in tests/test_enforcement_scope.py — SELF_CONTAINED if it "
        "refuses on this run's own evidence, SCOPED if it reads a stored fact "
        "(then it must consult etl/enforcement_scope), or SCOPE_DEBT with a reason."
        % sorted(undeclared))


def test_the_registry_does_not_rot():
    """A classified site that no longer exists is a stale claim about the code."""
    found = _traced_refusal_phases()
    classified = set(SELF_CONTAINED) | set(SCOPED)
    gone = {p for p in classified if p not in found}
    assert not gone, f"classified but no longer traced: {sorted(gone)} — delete the entry"


@pytest.mark.parametrize("phase,source_fn", sorted(SCOPED.items()))
def test_a_scoped_site_consults_the_primitive(phase, source_fn):
    """The refusal reads its facts from `source_fn`, which must apply scope."""
    txt = API.read_text(encoding="utf-8")
    fn = next((n for n in ast.walk(ast.parse(txt))
               if isinstance(n, ast.FunctionDef) and n.name == source_fn), None)
    assert fn is not None, f"{source_fn} is gone — {phase} now reads facts from somewhere unchecked"
    src = ast.get_source_segment(txt, fn) or ""
    assert calls(src, "may_enforce"), f"{source_fn} does not scope its facts ({phase})"
    assert calls(src, "prefer_current"), f"{source_fn} lets a stored fact beat this run ({phase})"


def test_debt_entries_carry_a_reason():
    for name, reason in SCOPE_DEBT.items():
        assert len(reason) > 60, f"{name}: a debt entry without a real reason is a TODO"
