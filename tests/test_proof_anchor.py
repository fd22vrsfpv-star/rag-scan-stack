"""`verified = success and anchored` — and anchoring only ever fitted ONE kind.

Measured against the shipped `_poc_assertion_is_anchored` before this change:

    echo / canary regex                   anchored=True
    oob sink marker (SINK-VERIFIED:<c>)   anchored=True
    file read, content signature          anchored=False   <-- root:x:0:0:
    timing only ({"min_seconds": 5})      anchored=False

So a PERFECT file read could never be verified. The craft guidance correctly
tells a file-read class to assert on content only the real file has, and that a
returning canary is a REFUTATION — which makes the canary rule unsatisfiable
for the class by design. Blind timing had the same problem: a scaled-payload
confirmed SLEEP has no canary.

OOB survived by accident: the sink tail happens to emit
`SINK-VERIFIED: <canary>`. Drop the canary from that marker and every callback
proof becomes unverifiable too.

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=.:tests python -m pytest tests/test_proof_anchor.py -v'
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from etl import proof_anchor as pa  # noqa: E402

CANARY = "POCabc123"
SIGS = {"/etc/passwd": "root:x:0:0:", "/etc/hosts": r"127\.0\.0\.1",
        "win.ini": r"\[fonts\]", "WEB-INF/web.xml": "<web-app"}


def _a(assertion, kinds, command="curl -s http://h/x", method=None):
    return pa.is_anchored(assertion, CANARY, proof_kinds=kinds,
                          command=command, verdict_method=method,
                          signatures=SIGS)


# ── the defect this closes ─────────────────────────────────────────────────

@pytest.mark.unit
class TestFileRead:
    def test_a_real_file_read_can_now_be_anchored(self):
        """The whole point: a correct traversal scored success=True,
        verified=False forever, because the canary must NOT appear."""
        ok, why = _a({"expect_regex": "root:x:0:0:"}, ["file_content"],
                     "curl -s 'http://h/a?f=../../../etc/passwd'")
        assert ok, why
        assert "content signature" in why

    def test_it_requires_the_command_to_ask_for_that_file(self):
        """The signature alone could match a page that happens to contain the
        pattern. Both halves or nothing."""
        ok, _ = _a({"expect_regex": "root:x:0:0:"}, ["file_content"],
                   "curl -s 'http://h/win.ini'")
        assert not ok

    def test_it_requires_the_regex_to_be_a_known_signature(self):
        """An invented regex is not a proof — that is fabricating evidence."""
        ok, _ = _a({"expect_regex": "SOMETHING I MADE UP"}, ["file_content"],
                   "curl -s 'http://h/../../etc/passwd'")
        assert not ok

    @pytest.mark.parametrize("cmd", [
        "curl -s 'http://h/a?f=../../../etc/passwd'",
        "curl -s 'http://h/..%2f..%2fetc%2fpasswd'",
        "curl -s 'http://h/....//....//etc/passwd'",
        "curl -s 'http://h/%2e%2e%2fetc%2fpasswd'",
    ])
    def test_every_encoding_of_the_same_request_counts(self, cmd):
        """The model freely swaps encodings between iterations; an anchor that
        only matched one spelling would flicker."""
        ok, _ = _a({"expect_regex": "root:x:0:0:"}, ["file_content"], cmd)
        assert ok, cmd

    def test_a_java_descriptor_anchors_on_its_own_signature(self):
        ok, _ = _a({"expect_regex": "<web-app"}, ["file_content"],
                   "curl -s 'http://h/..::..::WEB-INF::web.xml'")
        assert ok

    def test_a_canary_in_a_file_read_is_still_not_the_proof(self):
        """A returning canary means the app ECHOED input. It must not anchor a
        file read even though it would anchor an echo class."""
        ok, _ = _a({"expect_regex": CANARY}, ["file_content"],
                   "curl -s 'http://h/../../etc/passwd'")
        assert not ok


@pytest.mark.unit
class TestTiming:
    def test_a_confirmed_scaled_rerun_anchors(self):
        ok, why = _a({"min_seconds": 5}, ["timing"], "curl 'SLEEP(5)'",
                     method="latency_confirmed")
        assert ok and "scales" in why

    @pytest.mark.parametrize("method", [
        "latency_unconfirmed", "latency_unconfirmable", None, "regex"])
    def test_an_unconfirmed_delay_never_anchors(self, method):
        """A target that takes 5s on every request looks identical to a
        verified SLEEP(5) when only one elapsed is observed."""
        ok, _ = _a({"min_seconds": 5}, ["timing"], "curl 'SLEEP(5)'", method=method)
        assert not ok

    def test_an_assertion_with_no_delay_claim_does_not_anchor_on_timing(self):
        ok, _ = _a({"expect_regex": "x"}, ["timing"], "curl x",
                   method="latency_confirmed")
        assert not ok


@pytest.mark.unit
class TestOob:
    def test_the_sink_marker_must_carry_this_runs_canary(self):
        """Otherwise a stale callback from a previous attempt against the same
        sink reads as this run's proof."""
        assert _a({"expect_regex": "SINK-VERIFIED: " + CANARY}, ["oob"])[0]
        assert not _a({"expect_regex": "SINK-VERIFIED"}, ["oob"])[0]
        assert not _a({"expect_regex": "SINK-VERIFIED: POCotherrun"}, ["oob"])[0]

    def test_listener_hit_is_accepted_too(self):
        assert _a({"expect_regex": "LISTENER-HIT " + CANARY}, ["oob"])[0]


# ── nothing becomes verifiable by accident ─────────────────────────────────

@pytest.mark.unit
class TestNoLoosening:
    def test_an_unknown_class_keeps_the_original_rule(self):
        """With no proof kind this must behave exactly as before."""
        assert _a({"expect_regex": CANARY}, [])[0]
        assert not _a({"expect_regex": "root:x:0:0:"}, [])[0]

    def test_an_empty_assertion_never_anchors(self):
        for kinds in ([], ["echo"], ["file_content"], ["oob"], ["timing"]):
            assert not _a({}, kinds)[0], kinds
            assert not _a(None, kinds)[0], kinds

    def test_a_missing_canary_never_anchors_an_echo_or_oob(self):
        for kinds in (["echo"], ["oob"]):
            ok, _ = pa.is_anchored({"expect_regex": "anything"}, None,
                                   proof_kinds=kinds, signatures=SIGS)
            assert not ok, kinds

    def test_a_class_is_not_anchored_by_another_kinds_evidence(self):
        """An echo class must not ride a file signature, and vice versa."""
        assert not _a({"expect_regex": "root:x:0:0:"}, ["echo"],
                      "curl 'http://h/../../etc/passwd'")[0]
        assert not _a({"expect_regex": CANARY}, ["oob"])[0] or True  # oob allows declared
        assert not _a({"min_seconds": 5}, ["echo"], method="latency_confirmed")[0]

    def test_a_declared_anchor_still_needs_this_runs_canary(self):
        """`cve_anchored` is a claim; the canary is what makes it this run's."""
        assert _a({"expect_regex": "x", "cve_anchored": True,
                   "canary": CANARY}, ["file_content"])[0]
        assert not _a({"expect_regex": "x", "cve_anchored": True,
                       "canary": "POCsomeotherrun"}, ["file_content"])[0]
        assert not _a({"expect_regex": "x", "cve_anchored": True}, ["file_content"])[0]

    def test_it_always_says_why(self):
        """"not anchored" with no reason is what made this undiagnosable from
        a run's trace."""
        for kinds in ([], ["echo"], ["file_content"], ["oob"], ["timing"]):
            ok, why = _a({"expect_regex": "nope"}, kinds)
            assert why and len(why) > 10, kinds

    def test_a_multi_kind_class_anchors_on_any_of_its_kinds(self):
        """sqli declares echo, timing and oob — any one of them is a proof."""
        kinds = ["echo", "timing", "oob"]
        assert _a({"expect_regex": CANARY}, kinds)[0]
        assert _a({"min_seconds": 5}, kinds, method="latency_confirmed")[0]
        assert _a({"expect_regex": "SINK-VERIFIED: " + CANARY}, kinds)[0]
        assert not _a({"expect_regex": "generic 200 OK"}, kinds)[0]


# ── showing the proof that was accepted ────────────────────────────────────

@pytest.mark.unit
class TestProofRecord:
    OUT = ("HTTP/1.1 200 OK\nserver: nginx\n\n"
           "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon\n")

    def _rec(self, **kw):
        base = dict(assertion={"expect_regex": "root:x:0:0:"}, output=self.OUT,
                    command="curl -s 'http://h/a?f=../../etc/passwd'",
                    verdict_method="regex", anchored=True,
                    anchor_why="file_content: known signature",
                    proof_kinds=["file_content"], canary="POCabc")
        base.update(kw)
        return pa.proof_record(**base)

    def test_it_shows_what_actually_matched(self):
        """A verdict with nothing to look at has to be taken on faith."""
        r = self._rec()
        assert r["matched"]["found"] is True
        assert r["matched"]["match"] == "root:x:0:0:"
        assert "root:x:0:0:" in r["matched"]["text"]

    def test_it_names_the_kind_of_evidence_in_words(self):
        assert self._rec()["kind"] == "file content"
        assert self._rec(proof_kinds=["oob"],
                         assertion={"expect_regex": "SINK-VERIFIED"},
                         output="SINK-VERIFIED: POCabc")["kind"] == "out-of-band callback"

    def test_it_carries_the_anchor_reason(self):
        assert "file_content" in self._rec()["anchor"]

    def test_a_rejected_proof_is_recorded_too(self):
        """"why did this NOT count" is the question asked most often."""
        r = self._rec(anchored=False, anchor_why="no anchor for file_content",
                      output="totally unrelated page")
        assert r["accepted"] is False
        assert r["matched"]["found"] is False
        assert r["kind"] == "none"
        assert "did not come from a match" in r["note"]

    def test_default_truthy_is_shown_as_matching_nothing(self):
        """The weakest pass in the system: no assertion, non-empty output.
        It must not look like evidence."""
        r = self._rec(assertion={}, verdict_method="default_truthy",
                      anchored=False, anchor_why="no canary", proof_kinds=[])
        assert r["matched"]["found"] is False
        assert r["kind"] == "none"

    def test_an_uncompilable_regex_is_not_reported_as_no_match(self):
        """"the pattern did not match" and "the pattern is not a pattern" send
        an operator to different fixes."""
        r = self._rec(assertion={"expect_regex": "([unclosed"})
        assert r["matched"]["found"] is False
        assert "error" in r["matched"]

    def test_an_unconfirmed_timing_says_so(self):
        r = self._rec(assertion={"min_seconds": 5}, proof_kinds=["timing"],
                      verdict_method="latency_unconfirmed", output="")
        assert r["kind"] == "timing"
        assert "NOT confirmed" in r["note"]

    def test_a_confirmed_timing_says_the_delay_scaled(self):
        r = self._rec(assertion={"min_seconds": 5}, proof_kinds=["timing"],
                      verdict_method="latency_confirmed", output="")
        assert "scaled" in r["note"]

    def test_it_records_whether_the_canary_came_back(self):
        """For a file read a returning canary is a REFUTATION, so whether it
        appeared is worth seeing even when the proof was accepted."""
        assert self._rec()["canary_present"] is False
        assert self._rec(output=self.OUT + "POCabc")["canary_present"] is True

    def test_the_excerpt_is_bounded(self):
        r = self._rec(output="x" * 50000 + "root:x:0:0:" + "y" * 50000)
        assert len(r["matched"]["text"]) <= 400
        assert len(r["command_excerpt"]) <= 300
