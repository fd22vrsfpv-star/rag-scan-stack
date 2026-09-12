"""Docs/OPEN_ITEMS.md stays actionable, or it stops being worth reading.

Run on demand:

    pytest tests/test_open_items.py -v

WHY THIS EXISTS
---------------
A register of known problems has one failure mode and it is always the same: it
fills with entries nobody can act on and nobody can close, and then nobody reads
it. At that point it is worse than having no file, because its existence implies
the problems are tracked.

CLAUDE.md already says it: "A rule with no enforcing test is a suggestion, and
suggestions do not survive contact with a large change." The same applies to a
list of findings.

So every item must carry the four things that make it actionable by someone who
was not there when it was found:

  Found:       when, so an item can be seen to have gone stale
  Evidence:    what was OBSERVED — a count, a query result, quoted output
  Where:       the file or component, so the reader does not have to search
  Done when:   the closing condition; an item that cannot be closed is a
               complaint, not a finding
  Enforced by: a test that fails while the item is open, or the literal
               `not enforced` — which is an honest and common answer

And a named test must actually exist, because a fake enforcement claim is worse
than admitting there is none.

SABOTAGE PROOF
--------------
Drop any one of the required fields from an item and
`test_every_item_is_actionable` names it. Point an `Enforced by:` at a test file
that does not exist and `test_named_enforcement_exists` fails. Leave a
struck-through or DONE-marked item in the file and
`test_resolved_items_are_deleted_not_annotated` fails.
"""
import os
import re

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
DOC = os.path.join(REPO, "Docs", "OPEN_ITEMS.md")

REQUIRED = ("Found:", "Evidence:", "Where:", "Done when:", "Enforced by:")


def _text():
    if not os.path.exists(DOC):
        pytest.skip("Docs/OPEN_ITEMS.md not present")
    with open(DOC, encoding="utf-8") as fh:
        return fh.read()


def _items():
    """(title, body) per `### ` heading, ignoring the preamble and `## ` groups."""
    text = _text()
    parts = re.split(r"^### ", text, flags=re.M)[1:]
    out = []
    for part in parts:
        title, _, body = part.partition("\n")
        out.append((title.strip(), body))
    return out


def test_the_register_has_items():
    """An empty register and a missing register are different claims. If every
    item really is closed, delete the file rather than leaving a shell."""
    items = _items()
    assert items, (
        "Docs/OPEN_ITEMS.md has no items. Delete the file if nothing is open — "
        "an empty register still implies findings are being tracked")


def test_every_item_is_actionable():
    missing = {}
    for title, body in _items():
        absent = [f for f in REQUIRED if f"**{f}**" not in body]
        if absent:
            missing[title] = absent
    assert not missing, (
        f"items missing required fields: {missing}\n"
        "Someone who was not there when this was found has to be able to act on "
        "it. Without Evidence it cannot be believed; without 'Done when' it "
        "cannot be closed.")


def test_evidence_is_an_observation_not_an_opinion():
    """Evidence has to contain something checkable — a number, a path, a
    quotation. 'X looks wrong' is not something a reader can verify or close."""
    vague = []
    for title, body in _items():
        m = re.search(r"\*\*Evidence:\*\*(.*?)(?=\n\*\*|\Z)", body, re.S)
        ev = (m.group(1) if m else "").strip()
        if len(ev) < 40 or not re.search(r"\d|`|/|\.py|\"", ev):
            vague.append(title)
    assert not vague, (
        f"these items state no checkable observation: {vague}\n"
        "Evidence is a count, a query result, a path or quoted output.")


def test_named_enforcement_exists():
    """A fake enforcement claim is worse than admitting there is none."""
    broken = {}
    for title, body in _items():
        m = re.search(r"\*\*Enforced by:\*\*(.*?)(?=\n\*\*|\n##|\Z)", body, re.S)
        claim = (m.group(1) if m else "").strip()
        if not claim:
            broken[title] = "no claim at all"
            continue
        if claim.lower().startswith("not enforced"):
            continue
        for test_file in re.findall(r"`?(tests/[\w/]+\.py)", claim):
            if not os.path.exists(os.path.join(REPO, test_file)):
                broken[title] = f"names {test_file}, which does not exist"
        if "tests/" not in claim:
            broken[title] = f"claims enforcement but names no test: {claim!r}"
    assert not broken, (
        f"dishonest or empty enforcement claims: {broken}\n"
        "Either name a test that fails while the item is open, or write "
        "'not enforced' — that is a real answer and a common one.")


def test_resolved_items_are_deleted_not_annotated():
    """A register of things that are already fine is one nobody reads. Git
    history is where closed items live."""
    text = _text()
    # Only the item bodies — the preamble explains this rule and says the words.
    body = text[text.index("---"):] if "---" in text else text
    for marker in ("~~", "[DONE]", "**DONE**", "RESOLVED:", "✅"):
        assert marker not in body, (
            f"{marker!r} appears in Docs/OPEN_ITEMS.md — a resolved item is "
            "deleted, not annotated. Git history keeps the record.")


def test_claude_md_points_at_the_register():
    """A convention nobody is told about is not a convention."""
    path = os.path.join(REPO, "CLAUDE.md")
    if not os.path.exists(path):
        pytest.skip("CLAUDE.md not present")
    with open(path, encoding="utf-8") as fh:
        claude = fh.read()
    assert "Docs/OPEN_ITEMS.md" in claude, (
        "CLAUDE.md does not mention the register, so nothing directs a finding "
        "into it and it will go stale")
