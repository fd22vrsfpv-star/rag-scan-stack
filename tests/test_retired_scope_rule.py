"""A retired host is identified by what it ANSWERS, not by its certificate.

The obvious signal for "this service is decommissioned" is the TLS certificate,
and it does not work. Measured across 508 in-scope hosts with 443 open on the
examplecorp estate (2026-10-13):

    CN=*.examplecorp.com          32 RETIRED   15 LIVE
                                             (www.examplecorp.com, forums,
                                              tableau, forms, livehelp, ...)
    issuer GeoTrust TLS RSA CA G1   33 retired   263 live
    serial 038CAFBE9B3769C80001F5BE3623611C   appears on BOTH

The retired hosts and the main website present the *same certificate*. A
cert-based rule would have filed `www.examplecorp.com` as retired. What did
discriminate was the retirement redirect in the HTTP response: 33/33, no false
positives.

So the rule reads a fact recorded from the response — the `retired` asset tag,
written by `POST /engagements/{id}/scope/detect-retired` — and this test pins
the three pieces that have to agree:

  1. the probe has THREE outcomes (retired / not retired / could not tell), so
     a host that does not answer is never filed as retired;
  2. both scope-state readers surface the tag as `retired`;
  3. the rule is seeded by the installer, not just present in somebody's
     database.

Static + a direct import of the matcher: no DB, no running stack, no network.

Sabotage check: make `_probe_retired` return True when the host does not
answer and `test_unanswered_host_is_not_retired` fails; drop the `retired`
condition from the matcher and `test_matcher_requires_the_retired_fact` fails;
delete the seed and `test_rule_ships_in_the_installer` fails.

    pytest tests/test_retired_scope_rule.py -q
"""

import ast
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
API = REPO / "app" / "rag-api" / "api.py"
CLASSIFIER = REPO / "app" / "rag-api" / "scope_classifier.py"
DDL = REPO / "db_init" / "ensure_all_tables.sql"

sys.path.insert(0, str(REPO / "app" / "rag-api"))


# ── 1. the probe: three outcomes, never two ───────────────────────────────────

def _probe_fn():
    """Load `_probe_retired` alone — api.py is far too heavy to import."""
    tree = ast.parse(API.read_text(encoding="utf-8"))
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "_probe_retired"), None)
    if fn is None:
        pytest.fail("_probe_retired not found in app/rag-api/api.py")
    ns: dict = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<probe>", "exec"), ns)
    return ns["_probe_retired"]


def _with_curl(monkeypatch, stdout: str):
    """Stub subprocess.run so the probe never touches the network."""
    import subprocess

    class R:
        def __init__(self, out): self.stdout = out

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: R(stdout))


MARKERS = ["retired.html", "unavailable."]


def test_retirement_redirect_is_retired(monkeypatch):
    _with_curl(monkeypatch, "301 https://unavailable.examplecorp.com/retired.html")
    host, is_retired, evidence = _probe_fn()("ymca.examplecorp.com", MARKERS, 5)
    assert is_retired is True, evidence
    assert evidence, "no evidence recorded for a retirement verdict"


def test_live_host_is_not_retired(monkeypatch):
    _with_curl(monkeypatch, "200 ")
    _, is_retired, _ = _probe_fn()("www.examplecorp.com", MARKERS, 5)
    assert is_retired is False


def test_unanswered_host_is_not_retired(monkeypatch):
    """The outcome this repo keeps getting wrong: silence is not a verdict."""
    _with_curl(monkeypatch, "000 ")
    _, is_retired, evidence = _probe_fn()("dead.example.com", MARKERS, 5)
    assert is_retired is False, (
        "a host that never answered was filed as retired — 'unreachable' "
        "reported as 'absent' again")
    assert "no answer" in evidence.lower(), evidence


def test_probe_failure_is_not_retired(monkeypatch):
    import subprocess

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("curl", 5)

    monkeypatch.setattr(subprocess, "run", boom)
    _, is_retired, evidence = _probe_fn()("slow.example.com", MARKERS, 5)
    assert is_retired is False
    assert "fail" in evidence.lower(), evidence


# ── 2. the matcher and both state readers ─────────────────────────────────────

def test_matcher_requires_the_retired_fact():
    classifier = pytest.importorskip(
        "scope_classifier", reason="scope_classifier not importable here")
    clf = classifier.ScopeClassifier() if hasattr(classifier, "ScopeClassifier") \
        else classifier.get_classifier()
    rule = {"rule_type": "asset_state",
            "conditions": {"probed": True, "retired": True}}
    base = {"has_asset": True, "unresolved": False, "open_ports": 2,
            "port_scanned": True}
    assert clf._evaluate_rule(rule, "x.example.com", {**base, "retired": True})
    assert not clf._evaluate_rule(rule, "x.example.com", {**base, "retired": False})
    assert not clf._evaluate_rule(rule, "x.example.com", base), (
        "a host with no retired fact at all matched — the rule would file "
        "every probed host as retired")


@pytest.mark.parametrize("path", [
    "app/rag-api/api.py", "app/rag-api/scope_classifier.py"])
def test_both_state_readers_surface_the_tag(path):
    """A rule that nothing feeds is a rule that never fires.

    A scope-state query is one that computes the per-host FACTS the classifier
    evaluates — `unresolved` alongside the open-port count. Selecting on
    `FILTER (WHERE p.is_open)` alone was too broad: `/assets/{ip}/scan-coverage`
    counts open ports for the Recon Intel panel using the identical
    own-ports-plus-the-IP-keyed-row expression, and has nothing to do with
    scope classification. Requiring a `'retired' = ANY` there would be
    cargo-culting a tag read into a query that feeds no rule.

    The `assert matched` below is what keeps this narrowing honest: if the
    marker ever stops identifying the real readers, this fails as "no
    scope-state query found" rather than passing vacuously.
    """
    src = (REPO / path).read_text(encoding="utf-8")
    sqls = [n.value for n in ast.walk(ast.parse(src))
            if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and "FILTER (WHERE p.is_open)" in n.value
            and "unresolved" in n.value]
    assert sqls, (
        f"{path}: no scope-state query found (a query computing `unresolved` "
        "alongside the open-port count). Either the reader was deleted or it "
        "no longer derives the facts the classifier evaluates")
    for sql in sqls:
        flat = " ".join(sql.split())
        assert re.search(r"'retired'\s*=\s*ANY", flat), (
            f"{path}: the scope-state query does not read the retired tag, so "
            "the retired rule can never match")


# ── 3. the rule ships ─────────────────────────────────────────────────────────

def test_rule_ships_in_the_installer():
    """A rule that exists only in a live database is not part of the product."""
    ddl = DDL.read_text(encoding="utf-8")
    assert "retired:decommissioned-service" in ddl, (
        "db_init/ensure_all_tables.sql does not seed the retired rule — a "
        "clean build classifies nothing")
    # The no_services rules had exactly this problem and were seeded with it.
    for name in ("no-services:unresolved-and-no-open-ports",
                 "no-services:scanned-but-nothing-listening"):
        assert name in ddl, f"{name} is still database-only"


def test_reclassify_files_into_retired_too():
    """The pass that moves hosts must accept the new destination."""
    tree = ast.parse(API.read_text(encoding="utf-8"))
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
               and n.name == "reclassify_engagement_scope"), None)
    assert fn, "reclassify_engagement_scope not found"
    consts = {n.value for n in ast.walk(fn)
              if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert "retired" in consts, (
        "reclassify_engagement_scope never mentions the retired scope — the "
        "rule can match and nothing will act on it")
