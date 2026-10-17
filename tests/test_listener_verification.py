"""Who gets an out-of-band listener, and why it stopped being decided by prose.

`_needs_listener_verification` chose by scanning a guidance string for
keywords (SSRF, BLIND, OOB, XXE, LOG4, DNS, OUTBOUND, COMMAND INJECTION).
Measured against the class table, it disagreed on three classes, and every
disagreement was driven by WORDING rather than by the vulnerability:

    class            keyword scan   table
    deserialization  False          True   <- no listener for a class very
                                              often proven by a callback
    nosql-injection  True           False  <- flipped the moment its guidance
                                              gained "Blind variants use
                                              `$where` with a sleep"
    sqli             True           False  <- its guidance mentions "blind"

Two more: the scan was unanchored, so "the app is blindly trusting input"
matched BLIND; and a bare `cmdi` returned False while the prose "command
injection" returned True — the alias problem, in the one class list that never
got the table.

Editing a prompt string must not decide whether infrastructure is provisioned.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest pyyaml && \
      PYTHONPATH=.:tests python -m pytest tests/test_listener_verification.py -v'
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from etl import vuln_classes as vc  # noqa: E402

API = REPO / "app" / "rag-api" / "api.py"
SRC = API.read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _func(name):
    for n in ast.walk(TREE):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def _predicate():
    """Exec the real predicate with the class shims bound to the real table."""
    ns = {"re": re,
          "_vc_canonical": vc.canonical,
          "_vc_resolve": vc.resolve,
          "_vc_proof_kinds": vc.proof_kinds}
    hint = next(n for n in TREE.body if isinstance(n, ast.Assign)
                and any(getattr(t, "id", "") == "_OOB_HINT_PATTERN" for t in n.targets))
    fn = _func("_needs_listener_verification")
    assert fn is not None, "_needs_listener_verification missing"
    exec(compile(ast.Module([hint, fn], []), "<api>", "exec"), ns)
    return ns["_needs_listener_verification"]


NEEDS = _predicate()


# ── the three disagreements ────────────────────────────────────────────────

@pytest.mark.unit
class TestTheDisagreements:
    def test_deserialization_gets_a_listener(self):
        """The costly miss: no keyword appears in its guidance, so a class
        routinely proven by an outbound callback got no listener hint."""
        assert NEEDS("", vuln_class="deserialization") is True

    def test_prose_no_longer_decides_for_nosql(self):
        """Its guidance says "Blind variants use `$where` with a sleep". That
        sentence used to switch listener provisioning on."""
        guidance = "Blind variants use `$where` with a sleep."
        assert NEEDS(guidance, vuln_class="nosql-injection") is False

    def test_a_bare_class_name_works_as_well_as_prose(self):
        """`cmdi` returned False while "command injection" returned True."""
        assert NEEDS("cmdi") is True
        assert NEEDS("command injection") is True
        assert NEEDS("", vuln_class="cmdi") is True

    def test_blindly_does_not_match_blind(self):
        """Unanchored substrings: the same defect as `rce` inside
        "resou(rce)key"."""
        assert NEEDS("the app is blindly trusting input") is False
        assert NEEDS("a blind SQLi was reported") is True   # real word, real hint


# ── the table decides ──────────────────────────────────────────────────────

@pytest.mark.unit
class TestTableDrivesIt:
    def test_it_matches_the_proof_kinds_for_every_class(self):
        """The predicate is a projection: provable-out-of-band, per class."""
        for name in vc.names():
            if name == "unknown":
                continue
            expect = "oob" in vc.proof_kinds(name)
            assert NEEDS("", vuln_class=name) is expect, name

    def test_provable_oob_is_not_the_same_as_needs_a_sink(self):
        """`needs_oob_sink` means REQUIRED; this predicate only offers the
        pattern. sqli can be proven out-of-band and does not require a sink."""
        assert vc.needs_oob_sink("sqli") is False
        assert NEEDS("", vuln_class="sqli") is True
        assert vc.needs_oob_sink("cmdi") is True
        assert NEEDS("", vuln_class="cmdi") is True

    def test_a_file_read_gets_no_listener(self):
        for name in ("path-traversal", "lfi", "idor", "open-redirect"):
            assert NEEDS("", vuln_class=name) is False, name

    def test_a_misconfiguration_gets_no_listener(self):
        for name in ("webdav-put", "directory-listing", "default-credentials"):
            assert NEEDS("", vuln_class=name) is False, name

    def test_jndi_gets_one_because_its_only_proof_is_out_of_band(self):
        assert vc.proof_kinds("jndi-injection") == ["oob"]
        assert NEEDS("", vuln_class="jndi-injection") is True
        assert NEEDS("a log4shell candidate") is True


# ── resolution order ───────────────────────────────────────────────────────

@pytest.mark.unit
class TestOrder:
    def test_an_explicit_class_beats_the_text(self):
        """The guidance blob is full of words; the class is the fact."""
        assert NEEDS("blind blind blind out-of-band", vuln_class="lfi") is False

    def test_a_class_marker_in_the_text_is_read(self):
        assert NEEDS("PRIMARY: class=cmdi endpoint=/x param=q") is True
        assert NEEDS("PRIMARY: class=lfi endpoint=/x param=q") is False

    def test_a_class_named_in_free_text_is_read(self):
        assert NEEDS("the advisory describes server-side request forgery") is True
        assert NEEDS("the advisory describes a path traversal") is False

    def test_free_text_with_no_class_falls_back_to_mechanism_words(self):
        assert NEEDS("the check is blind, there is no response") is True
        assert NEEDS("an out-of-band callback is required") is True
        assert NEEDS("the response contains the value") is False

    def test_empty_input_is_false(self):
        for bad in ("", None, 0):
            assert NEEDS(bad) is False, bad


# ── wiring ─────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestWiring:
    def test_the_class_is_passed_at_every_call_site(self):
        """Without it the predicate falls back to scanning prose, which is the
        behaviour this change exists to remove."""
        fn = _func("_synthesize_cve_poc")
        assert fn is not None
        calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                 and getattr(n.func, "id", "") == "_needs_listener_verification"]
        assert calls, "the synth path no longer consults the predicate"
        for c in calls:
            assert any(k.arg == "vuln_class" for k in c.keywords), (
                "a call site does not pass vuln_class")

    def test_the_class_is_derived_from_the_cve_not_the_guidance(self):
        src = ast.unparse(_func("_synthesize_cve_poc"))
        assert "_vuln_class_from_cve" in src

    def test_the_pattern_is_not_compiled_at_module_scope(self):
        """api.py has no module-level `re` — every function does
        `import re as _re`. A module-level `re.compile` raises NameError at
        import, which is how this shipped broken for one suite run."""
        names = {t.id for n in TREE.body if isinstance(n, ast.Assign)
                 for t in n.targets if isinstance(t, ast.Name)}
        assert "_OOB_HINT_PATTERN" in names
        assert "_OOB_HINT_RE" not in names, (
            "the pattern is compiled at module scope again; api.py has no "
            "module-level `re`, so that is a NameError at import")

    def test_the_old_keyword_class_list_is_gone(self):
        assert "_BLIND_CLASSES" not in SRC, (
            "the class names are answered by the table now; keeping them in a "
            "keyword list is the duplication the eleven sets were")
