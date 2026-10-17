"""A war story in a prompt must not become a payload.

Observed live on 2026-10-16/17, two separate mechanisms putting another
product's identifiers into a real dispatched command:

1. `enforce_facts()`'s refusal message carried a CONCRETE parameter name from
   a DIFFERENT CVE as the anecdote justifying the rule. The model read it as a
   parameter to use and put it in the command; the next run then read that
   command back as "discovered knowledge" for the host. The explanation for a
   guard became an input to the exploit.

2. `_FRAMEWORK_FINGERPRINTS` matched by bare substring, so the 5-character
   needle "Spage" matched inside `resultsPage` / `fieldsPage` in bundled JS
   and a Jira host was fingerprinted as "LyLme Spage" — a product it has
   nothing to do with. That name then led the run's reasoning all the way to
   its failure analysis, which described the wrong product entirely.

Both are the same shape as `rce` matching inside "resou(rce)key" and `BLIND`
inside "blindly": an identifier matched where it was never meant to.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=.:tests python -m pytest tests/test_prompt_contamination.py -v'
"""
from __future__ import annotations

import ast
import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
API = REPO / "app" / "rag-api" / "api.py"
SRC = API.read_text(encoding="utf-8")
TREE = ast.parse(SRC)

_spec = importlib.util.spec_from_file_location(
    "fact_probes_contam", REPO / "app" / "rag-api" / "fact_probes.py")
fp = importlib.util.module_from_spec(_spec)
sys.modules["fact_probes_contam"] = fp
_spec.loader.exec_module(fp)


def _const(name):
    for n in ast.walk(TREE):
        if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == name for t in n.targets):
            return ast.literal_eval(n.value)
    pytest.fail("%s not found" % name)


# ── 1. the refusal message ─────────────────────────────────────────────────

@pytest.mark.unit
class TestRefusalMessage:
    def test_it_names_only_the_facts_it_was_given(self):
        """Any identifier in the message is a candidate the model may copy."""
        msg = fp.enforce_facts("curl -s http://h/x", {"input_field": "realparam"})
        assert msg, "a command missing its proven fact must be refused"
        backticked = set(re.findall(r"`([^`]+)`", msg))
        assert backticked <= {"realparam"}, (
            "the refusal names identifiers that are not this run's facts: %s"
            % sorted(backticked - {"realparam"}))

    def test_it_carries_no_cve_id(self):
        """A CVE id in the message invites the model to reason about THAT CVE."""
        msg = fp.enforce_facts("curl -s http://h/x", {"input_field": "realparam"})
        assert not re.search(r"CVE-\d{4}-\d{4,}", msg), (
            "a different CVE's id is in the refusal text: %s" % msg)

    def test_the_lesson_itself_survives(self):
        """Removing the anecdote must not remove the reason — the model still
        needs to know WHY the command was refused."""
        msg = fp.enforce_facts("curl -s http://h/x", {"input_field": "realparam"})
        assert "proven fact" in msg
        assert "realparam" in msg

    def test_a_command_that_uses_the_fact_is_not_refused(self):
        assert fp.enforce_facts("curl -s 'http://h/x?realparam=1'",
                                {"input_field": "realparam"}) is None

    def test_no_prompt_builder_hardcodes_a_foreign_parameter(self):
        """The whole class: a concrete identifier inside a STRING that reaches
        the model. Comments and docstrings are fine — they are not sent."""
        offenders = []
        for mod in (REPO / "app" / "rag-api" / "fact_probes.py", API):
            tree = ast.parse(mod.read_text(encoding="utf-8"))
            docstrings = set()
            for n in ast.walk(tree):
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef, ast.Module)):
                    d = ast.get_docstring(n, clean=False)
                    if d:
                        docstrings.add(d)
            for n in ast.walk(tree):
                if not isinstance(n, ast.Constant) or not isinstance(n.value, str):
                    continue
                if n.value in docstrings:
                    continue
                if "listingfields" in n.value:
                    offenders.append("%s:%s" % (mod.name, n.lineno))
        assert not offenders, (
            "a real parameter from another CVE is in a runtime string: %s"
            % offenders)


# ── 2. the framework fingerprint ───────────────────────────────────────────

@pytest.mark.unit
class TestFrameworkFingerprints:
    SAMPLE_JS = ("var resultsPage=1,optionsPage=2,fieldsPage=3,detailsPage=4;"
                 "AJS.contextPath();JIRA.Dashboard.init();")

    @staticmethod
    def _bounded(needle, hay):
        """The matcher's own rule: alphanumeric lookarounds, not \\b.

        Several needles start or end with punctuation ("/administrator/"), and
        \\b there demands a word character OUTSIDE the needle, which silently
        kills the match. The first version of this fix did exactly that.
        """
        return re.search(r"(?<![A-Za-z0-9])" + re.escape(needle)
                         + r"(?![A-Za-z0-9])", hay, re.I)

    def test_no_needle_matches_inside_an_unrelated_identifier(self):
        """`Spage` inside `resultsPage` fingerprinted a Jira host as LyLme
        Spage, and the failure analysis then described that product."""
        bad = [n for n, _, _ in _const("_FRAMEWORK_FINGERPRINTS")
               if self._bounded(n, self.SAMPLE_JS)]
        assert not bad, "needles matching a plain JS sample: %s" % bad

    def test_the_matcher_is_word_anchored(self):
        """A bare `in body.lower()` is the bug; the boundary is the fix."""
        fn = next((n for n in ast.walk(TREE)
                   if isinstance(n, ast.FunctionDef) and "_FRAMEWORK_FINGERPRINTS"
                   in ast.unparse(n)), None)
        assert fn is not None
        src = ast.unparse(fn)
        # Structural: find the `if` that tests the needle and assert it is a
        # bounded regex search, not a bare `in`. A quoted code fragment here
        # would die on a reformat (tests/test_guard_style.py ratchets on it).
        loop = next((n for n in ast.walk(fn) if isinstance(n, ast.For)
                     and "_FRAMEWORK_FINGERPRINTS" in ast.unparse(n.iter)), None)
        assert loop is not None, "no loop over the fingerprint table"
        tests = [ast.unparse(n.test) for n in ast.walk(loop) if isinstance(n, ast.If)]
        bare = [t for t in tests
                if ".lower() in " in t and "search" not in t]
        assert not bare, (
            "the fingerprint match is an unanchored substring again: %s" % bare)
        assert any("A-Za-z0-9" in t for t in tests), (
            "no boundary guard in the fingerprint match")

    def test_the_generic_alias_is_gone(self):
        names = {n for n, _, _ in _const("_FRAMEWORK_FINGERPRINTS")}
        assert "Spage" not in names

    def test_short_generic_needles_are_still_declared_deliberately(self):
        """Short needles are allowed — they just must not match mid-word.
        This records which ones are short so a new one is a conscious choice."""
        short = sorted(n for n, _, _ in _const("_FRAMEWORK_FINGERPRINTS")
                       if len(n) <= 8 and re.fullmatch(r"[A-Za-z0-9]+", n))
        assert short == ["Directus", "Drupal", "Grafana", "Jenkins", "Kibana"], (
            "the short-needle set changed: %s" % short)

    def test_real_fingerprints_still_match(self):
        """The boundary must not break the matches that were working."""
        for needle, name, _ in _const("_FRAMEWORK_FINGERPRINTS"):
            body = "<html><!-- powered by %s --></html>" % needle
            assert self._bounded(needle, body), name
