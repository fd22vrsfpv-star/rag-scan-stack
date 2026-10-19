"""Negative controls: a probe that cannot fail is not a probe.

Before this, `probe_endpoint_exists` confirmed on any status that was not
404/410. The live ledger for one build showed what that buys:

    confirmed 0.9  GET accepted on .../s/{resourceKey}/_/download/resources/…
    confirmed 0.9  GET accepted on .../../../../WEB-INF/…
    confirmed 0.9  parameter 'command' changed the status (200 -> 404)
    confirmed 0.9  OPTIONS accepted on …/bamboo/browse

Four "facts", all wrong, all 0.9. The first is a TEMPLATE, not a path. The
third is a command-injection parameter on a path-traversal CVE. None of them
had been compared against a control, so none of them could have come back
negative.

Every probe now re-runs its own test with a value it KNOWS is wrong, and
reports `indistinguishable` when the target answers the same way. That is a
flavour of UNVERIFIED — it is not a refutation, because the fact may still be
true; it is a statement that this probe did not test it.

Run standalone:

    docker run --rm -v /opt/rag-scan-stack:/work:ro -w /work \
      python:3.12-slim sh -c 'pip install -q pytest && \
      PYTHONPATH=. python -m pytest tests/test_fact_probe_controls.py -v'
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_mod_path = Path(__file__).parent.parent / "app" / "rag-api" / "fact_probes.py"
_spec = importlib.util.spec_from_file_location("fact_probes", _mod_path)
fact_probes = importlib.util.module_from_spec(_spec)
sys.modules["fact_probes"] = fact_probes
_spec.loader.exec_module(fact_probes)

CONFIRMED = fact_probes.CONFIRMED
REFUTED = fact_probes.REFUTED
UNVERIFIED = fact_probes.UNVERIFIED

BASE = "https://t.example.com:443"


class Resp:
    def __init__(self, status, text=""):
        self.status_code = status
        self.text = text


class Stub:
    """Records every request so a test can assert what was (not) sent."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def __call__(self, method, url, **kw):
        self.calls.append((method, url))
        r = self.handler(method, url)
        if isinstance(r, Exception):
            raise r
        return r

    @property
    def urls(self):
        return [u for _, u in self.calls]


def _indistinguishable(res):
    return res.status == UNVERIFIED and "control matched" in res.evidence


# ── helpers ────────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestHelpers:
    def test_control_token_is_deterministic_and_name_safe(self):
        a = fact_probes.control_token("/download/resources")
        b = fact_probes.control_token("/download/resources")
        assert a == b, "a random control makes two runs incomparable"
        assert a != fact_probes.control_token("/other")
        assert a[0].isalpha(), "some frameworks reject a name starting with a digit"
        assert a.isalnum()

    def test_control_path_keeps_the_route_and_the_query(self):
        nonce = "zdeadbeef"
        out = fact_probes.control_path("/s/abc/_/download/resources/x?a=1", nonce)
        assert out.startswith("/s/abc/_/download/resources/"), (
            "the control must exercise the same handler and middleware")
        assert out.endswith("?a=1")
        assert "/x?" not in out and nonce in out

    def test_control_path_handles_a_bare_root(self):
        assert fact_probes.control_path("/", "zz") == "/zz"
        assert fact_probes.control_path("", "zz") == "/zz"

    def test_placeholder_detection(self):
        for bad in ("/s/{resourceKey}/_/download", "/api/<id>/edit",
                    "/download/.../file", "/s/%7Bkey%7D/x"):
            assert fact_probes.has_placeholder(bad), bad
        for ok in ("/download/resources/x", "/api/12/edit", "", None):
            assert not fact_probes.has_placeholder(ok), ok


# ── endpoint_exists ────────────────────────────────────────────────────────

@pytest.mark.unit
class TestEndpointExists:
    def test_soft_404_app_is_indistinguishable_not_confirmed(self):
        """The headline case: an app that answers every unknown route."""
        http = Stub(lambda m, u: Resp(200, "<html>generic page</html>"))
        res = fact_probes.probe_endpoint_exists(http, BASE, "/download/resources/x")
        assert _indistinguishable(res), res.evidence
        assert res.status != CONFIRMED
        assert len(http.calls) == 2, "the claim and its control"

    def test_control_404_confirms(self):
        def h(m, u):
            return Resp(404, "nope") if "z" == u.rsplit("/", 1)[-1][:1] else Resp(200, "real content here")
        http = Stub(h)
        res = fact_probes.probe_endpoint_exists(http, BASE, "/download/resources/x")
        assert res.status == CONFIRMED, res.evidence
        assert "control" in res.evidence

    def test_a_403_on_a_real_path_still_confirms(self):
        """A 403 on the right path beats a 200 on the wrong one — as long as
        the control does NOT also get a 403."""
        http = Stub(lambda m, u: Resp(404, "") if "/z" in u else Resp(403, "forbidden"))
        res = fact_probes.probe_endpoint_exists(http, BASE, "/admin/panel")
        assert res.status == CONFIRMED, res.evidence

    def test_404_refutes_without_spending_a_control_request(self):
        http = Stub(lambda m, u: Resp(404, ""))
        res = fact_probes.probe_endpoint_exists(http, BASE, "/nope")
        assert res.status == REFUTED
        assert len(http.calls) == 1, "a refuted claim needs no control"

    def test_a_template_is_never_probed(self):
        http = Stub(lambda m, u: Resp(200, "x"))
        res = fact_probes.probe_endpoint_exists(
            http, BASE, "/s/{resourceKey}/_/download/resources/a:b")
        assert res.status == UNVERIFIED
        assert "placeholder" in res.evidence
        assert http.calls == [], "do not spend a request asking about a brace"

    def test_control_failure_still_confirms_but_says_so(self):
        def h(m, u):
            return RuntimeError("boom") if "/z" in u else Resp(200, "content")
        res = fact_probes.probe_endpoint_exists(Stub(h), BASE, "/real/path")
        assert res.status == CONFIRMED
        assert "control unavailable" in res.evidence, (
            "a fact confirmed without a control is worth less and the ledger "
            "must be able to tell the difference")

    def test_size_difference_confirms_even_on_equal_status(self):
        def h(m, u):
            return Resp(200, "tiny") if "/z" in u else Resp(200, "x" * 5000)
        res = fact_probes.probe_endpoint_exists(Stub(h), BASE, "/real/path")
        assert res.status == CONFIRMED, res.evidence


# ── input_field ────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestInputField:
    def test_status_flip_on_any_unknown_param_is_indistinguishable(self):
        """The real `parameter 'command' changed the status (200 -> 404)` row."""
        def h(m, u):
            return Resp(404, "unknown parameter") if "=" in u else Resp(200, "home")
        res = fact_probes.probe_input_field(Stub(h), BASE, "/", "command")
        assert _indistinguishable(res), res.evidence

    def test_status_flip_only_for_the_real_field_confirms(self):
        def h(m, u):
            if "listingfields=" in u:
                return Resp(500, "error")
            return Resp(200, "home")
        res = fact_probes.probe_input_field(Stub(h), BASE, "/dir", "listingfields")
        assert res.status == CONFIRMED, res.evidence
        assert res.value == "listingfields"

    def test_reflection_of_any_value_is_indistinguishable(self):
        http = Stub(lambda m, u: Resp(200, "you asked for pf0prb"))
        res = fact_probes.probe_input_field(http, BASE, "/search", "q")
        assert _indistinguishable(res), res.evidence

    def test_reflection_only_for_the_real_field_confirms(self):
        def h(m, u):
            return Resp(200, "echo pf0prb") if "q=" in u else Resp(200, "echo")
        res = fact_probes.probe_input_field(Stub(h), BASE, "/search", "q")
        assert res.status == CONFIRMED, res.evidence

    def test_size_change_for_any_param_is_indistinguishable(self):
        def h(m, u):
            return Resp(200, "x" * 9000) if "=" in u else Resp(200, "x" * 100)
        res = fact_probes.probe_input_field(Stub(h), BASE, "/list", "sort")
        assert _indistinguishable(res), res.evidence

    def test_no_signal_is_inconclusive_not_refuted(self):
        http = Stub(lambda m, u: Resp(200, "same page every time"))
        res = fact_probes.probe_input_field(http, BASE, "/x", "blindparam")
        assert res.status == UNVERIFIED
        assert "inconclusive" in res.evidence
        assert res.status != REFUTED, "a blind injection point looks exactly like this"

    def test_a_template_field_is_never_probed(self):
        http = Stub(lambda m, u: Resp(200, "x"))
        res = fact_probes.probe_input_field(http, BASE, "/x", "{param}")
        assert res.status == UNVERIFIED and "placeholder" in res.evidence
        assert http.calls == []

    def test_transport_failure_is_unverified_not_refuted(self):
        res = fact_probes.probe_input_field(
            Stub(lambda m, u: TimeoutError("t")), BASE, "/x", "q")
        assert res.status == UNVERIFIED and "did not run" in res.evidence


# ── method_allowed ─────────────────────────────────────────────────────────

@pytest.mark.unit
class TestMethodAllowed:
    def test_server_that_accepts_an_invented_verb_is_indistinguishable(self):
        http = Stub(lambda m, u: Resp(200, "ok"))
        res = fact_probes.probe_method_allowed(http, BASE, "/browse", "OPTIONS")
        assert _indistinguishable(res), res.evidence
        assert len(http.calls) == 2

    def test_405_refutes_without_a_control(self):
        http = Stub(lambda m, u: Resp(405, ""))
        res = fact_probes.probe_method_allowed(http, BASE, "/x", "POST")
        assert res.status == REFUTED
        assert len(http.calls) == 1

    def test_enforced_methods_confirm(self):
        def h(m, u):
            return Resp(200, "ok") if m == "POST" else Resp(501, "")
        res = fact_probes.probe_method_allowed(Stub(h), BASE, "/x", "POST")
        assert res.status == CONFIRMED, res.evidence

    def test_the_control_verb_is_not_a_real_method(self):
        http = Stub(lambda m, u: Resp(200, "ok"))
        fact_probes.probe_method_allowed(http, BASE, "/x", "GET")
        verbs = {m for m, _ in http.calls}
        invented = verbs - {"GET"}
        assert invented, "no control verb was sent"
        for v in invented:
            assert v not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD",
                             "OPTIONS", "TRACE", "CONNECT"), (
                "the control must be a verb nothing can route")


# ── contract ───────────────────────────────────────────────────────────────

@pytest.mark.unit
class TestContract:
    def test_every_probe_returns_one_of_exactly_three_statuses(self):
        http = Stub(lambda m, u: Resp(200, "generic"))
        results = fact_probes.run_probes(
            http, BASE, {"endpoint": "/x", "input_field": "q", "method": "GET"})
        assert set(results) == set(fact_probes.PROBES)
        for claim, res in results.items():
            assert res.status in (CONFIRMED, REFUTED, UNVERIFIED), claim

    def test_run_probes_still_records_a_missing_input_rather_than_skipping(self):
        res = fact_probes.run_probes(Stub(lambda m, u: Resp(200, "")), BASE, {})
        assert res["endpoint_exists"].status == UNVERIFIED
        assert "missing input" in res["endpoint_exists"].evidence

    def test_a_generic_app_confirms_nothing_but_reachability(self):
        """End to end: the whole point. A target that answers everything the
        same way must yield exactly one confirmed fact — that it is up."""
        http = Stub(lambda m, u: Resp(200, "<html>one page fits all</html>"))
        res = fact_probes.run_probes(
            http, BASE, {"endpoint": "/download/x", "input_field": "command",
                         "method": "OPTIONS"})
        confirmed = {k for k, v in res.items() if v.status == CONFIRMED}
        assert confirmed == {"target_reachable"}, (
            "a soft-404 app confirmed %s — the controls are not biting" % confirmed)
