"""`priority` on a scope rule is an EVALUATION ORDER and lower runs first.

Measured 2026-10-12: a rule authored at priority 60 — chosen specifically to
"beat" an existing rule at 50 — silently never fired. Every target kept
resolving through the broader rule. The same rule re-created at 10 matched
immediately. Both seeded rules sit at 50, so nothing in the existing data
reveals the direction; the only way to discover it was to fail.

The direction is NOT changed here, deliberately. Live rules encode the current
semantics on purpose (a narrow `retired` rule at 19, `no_services` at 20/21,
broad seeds at 50), so flipping to descending would invert live classification
for every target. The fix is to make the order impossible to misread at the
point of authoring.

    docker run --rm -v /opt/rag-scan-stack:/repo -w /repo python:3.12-slim \
      sh -c 'pip install -q pytest && PYTHONPATH=.:tests \
      python -m pytest tests/test_scope_rule_priority.py -v'
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CLASSIFIER = REPO / "app" / "rag-api" / "scope_classifier.py"
API = REPO / "app" / "rag-api" / "api.py"
UI = REPO / "dashboard" / "frontend" / "src" / "pages" / "ScopeIntelligence.tsx"


def _func(path, name):
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    pytest.fail(f"{name} not found in {Path(path).name}")


class TestTheDirectionIsStillAscending:
    """If someone flips this, every live rule's relative order inverts."""

    def test_the_sort_is_ascending(self):
        fn = _func(CLASSIFIER, "load_rules")
        sorts = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                 and getattr(n.func, "id", None) == "sorted"]
        assert sorts, "load_rules no longer sorts the merged rules"
        for s in sorts:
            assert not any(kw.arg == "reverse" and getattr(kw.value, "value", False)
                           for kw in s.keywords), (
                "the rule sort became descending — every live rule's relative "
                "order just inverted (retired=19 and no_services=20/21 were "
                "placed low ON PURPOSE to run before the broad seeds at 50)")

    def test_first_match_wins(self):
        """Ordering only decides anything because evaluation stops at the
        first hit; without that, priority would be decorative."""
        fn = _func(CLASSIFIER, "_check_rules")
        returns_in_loop = [
            r for loop in ast.walk(fn) if isinstance(loop, (ast.For, ast.While))
            for r in ast.walk(loop) if isinstance(r, ast.Return)]
        assert returns_in_loop, (
            "_check_rules no longer returns from inside its loop, so it no "
            "longer stops at the first match and `priority` decides nothing")


class TestAnAuthorIsToldTheDirection:
    def test_the_create_endpoint_reports_evaluation_order(self):
        fn = _func(API, "create_classification_rule")
        src = ast.get_source_segment(API.read_text(encoding="utf-8"), fn) or ""
        assert "evaluation_order" in src, (
            "the create response must state the direction; the column name "
            "alone says the opposite of what happens")

    def test_it_warns_when_a_rule_lands_behind_others(self):
        """The actual mistake: authoring at 60 to beat 50."""
        fn = _func(API, "create_classification_rule")
        # Structural, NOT a substring over the source: the docstring also
        # contains the word "warning", so a text check passes even with the
        # code deleted — a false pass this guard's own sabotage run exposed.
        assigned = set()
        for n in ast.walk(fn):
            if isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant):
                assigned.add(n.slice.value)
            if isinstance(n, ast.Dict):
                assigned |= {k.value for k in n.keys
                             if isinstance(k, ast.Constant) and isinstance(k.value, str)}
        assert "warning" in assigned, (
            "the response must carry a `warning` key; a rule created behind "
            "broader ones can never fire for anything they match")
        assert "rules_evaluated_before_this_one" in assigned, (
            "the author must be shown WHICH rules pre-empt theirs, not just "
            "told that some do")
        # and the warning must be conditional on there actually being any
        conds = [n for n in ast.walk(fn) if isinstance(n, ast.If)
                 and isinstance(n.test, ast.Name) and n.test.id == "earlier"]
        assert conds, (
            "the warning must be gated on `earlier` being non-empty, or every "
            "rule — including a correctly-placed first one — is warned about")

    def test_the_warning_is_advisory_not_a_refusal(self):
        """An operator may legitimately want a catch-all last. Refusing a
        valid rule is worse than explaining it."""
        fn = _func(API, "create_classification_rule")
        raises = [n for n in ast.walk(fn) if isinstance(n, ast.Raise)]
        # the only refusals should be the missing-field checks
        for r in raises:
            seg = ast.dump(r)
            assert "Missing field" in seg, (
                "creating a low-precedence rule must not be refused; it is a "
                "legitimate choice and the response already explains it")

    def test_the_ui_states_the_direction(self):
        """Nothing rendered priority at all, so the direction was invisible
        exactly where rules are authored."""
        src = UI.read_text(encoding="utf-8")
        assert "lower number runs first" in src, (
            "the rule panel must state the direction in words")
        assert "r.priority" in src, (
            "the rule panel must show each rule's priority, or the order is "
            "still unobservable")
