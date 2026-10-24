"""A privilege escalation has to know WHO is on the target first.

THE DEFECT (CVE-2023-37999, six builds, 2026-10-22/23)
------------------------------------------------------
Operator, 2026-10-23: "if it is a privilege escalation shouldn't we find what
users are present first" / "if we have that type we need a recon loop to find
the ids".

Every build invented an account — `POCz563d7ad88a_12345` — and tried to raise
THAT to administrator. CVE-Bench grades goal 7 against the account it names
(`username`), so a randomly named admin scores zero however well the exploit
works. Nothing had established which accounts existed, what ids they held, or
whether the graded one was even present. (It was not: the challenge's db.sql
seeds only `admin`, which is why the goal text says "Create the account first
if it does not exist.")

The platform could already enumerate users — `_enumerate_access_inventory` is
WordPress-aware and returns {object_type: [{id, name}]} — but it is reachable
only as a deep-recon step AND only with a session, so a build whose gather
SUCCEEDS can never run it. The enumeration that would have answered the
question was structurally out of reach of the builds that needed it.

THE FIX, AS DATA
----------------
  knowledge/vuln_classes.yaml   privilege-escalation declares identity_required
  knowledge/gap_tools.yaml      user_enum_rest / _author_scan / _generic
                                declare `gaps: [identity, ...]`
  api.py                        a class that requires identity gets an
                                `identity` manifest item; missing blocks
                                gather, which routes to deep recon, which
                                picks those tools.

No branching logic decides which tool runs — adding another identity source is
a YAML entry (CLAUDE.md: "New knowledge should take effect by being loaded and
embedded, not by editing branching logic").

    pytest tests/test_identity_recon.py
"""
from __future__ import annotations

import ast
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import _ast_assert  # noqa: E402
from _ast_assert import calls, call_kwarg, call_order  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[1]
API = ROOT / "app" / "rag-api" / "api.py"
sys.path.insert(0, str(ROOT))
yaml = pytest.importorskip("yaml")


def _classes():
    doc = yaml.safe_load((ROOT / "knowledge" / "vuln_classes.yaml").read_text(encoding="utf-8"))
    return doc.get("classes") if isinstance(doc, dict) else doc


def _gap_tools():
    doc = yaml.safe_load((ROOT / "knowledge" / "gap_tools.yaml").read_text(encoding="utf-8"))
    return doc["tools"]


def _src():
    return API.read_text(encoding="utf-8")


def _fn(name):
    txt = _src()
    node = next((n for n in ast.walk(ast.parse(txt))
                 if isinstance(n, ast.FunctionDef) and n.name == name), None)
    assert node is not None, f"{name} is gone from api.py"
    return ast.get_source_segment(txt, node) or ""


# ── the class declares the need, in YAML ────────────────────────────────────

def test_privilege_escalation_requires_an_identity():
    pe = next((c for c in _classes() if c.get("name") == "privilege-escalation"), None)
    assert pe is not None
    assert pe.get("identity_required") is True, (
        "the class whose premise is 'this principal ends up over-privileged' "
        "must declare that it needs to know which principals exist")


def test_classes_that_do_not_need_it_are_unchanged():
    """SABOTAGE GUARD. Requiring identity everywhere would add a recon pass to
    every build — an SQLi does not need a user list to inject."""
    for name in ("sqli", "lfi", "xxe", "ssti"):
        c = next((x for x in _classes() if x.get("name") == name), None)
        if c is None:
            continue
        assert not c.get("identity_required"), f"{name} should not require identity"


def test_the_accessor_reads_the_declaration():
    vc = pytest.importorskip("etl.vuln_classes")
    vc.load(str(ROOT / "knowledge" / "vuln_classes.yaml"), force=True)
    assert vc.needs_identity("privilege-escalation") is True
    assert vc.needs_identity("privesc") is True, "aliases must resolve"
    assert vc.needs_identity("sqli") is False


# ── the tools that answer it, in YAML ───────────────────────────────────────

def test_a_tool_answers_the_identity_gap():
    answering = [t for t in _gap_tools() if "identity" in (t.get("gaps") or [])]
    assert answering, (
        "identity is declared a gap and nothing can answer it — the manifest "
        "would block gather with no tool to unblock it")


def test_every_identity_tool_is_read_only():
    """SABOTAGE GUARD. `safe: false` is never auto-run, so an unsafe identity
    tool would silently never fire — and enumerating users must not write."""
    for t in _gap_tools():
        if "identity" in (t.get("gaps") or []):
            assert t.get("safe") is True, f"{t['id']} must be read-only to auto-run"


def test_the_identity_tools_are_unauthenticated():
    """The step must work on a build that never gets a session — that is
    exactly the case where the old access_inventory path was unreachable."""
    for t in _gap_tools():
        if "identity" in (t.get("gaps") or []):
            cmd = t.get("command") or ""
            assert "cookie" not in cmd.lower() and "-u " not in cmd, (
                f"{t['id']} appears to need credentials")


def test_a_wordpress_target_has_a_rest_route_tool():
    rest = next((t for t in _gap_tools() if t.get("id") == "user_enum_rest"), None)
    assert rest is not None
    assert "/wp-json/wp/v2/users" in rest["command"]
    assert "wordpress" in [i.lower() for i in (rest.get("indicators") or [])]


def test_there_is_a_fallback_when_the_rest_route_is_blocked():
    ids = {t["id"] for t in _gap_tools() if "identity" in (t.get("gaps") or [])}
    assert len(ids) >= 2, f"one identity source is a single point of failure: {ids}"


# ── the wiring ──────────────────────────────────────────────────────────────

def test_the_manifest_requires_identity_for_such_a_class():
    """`identity` must join the REQUIRED set, and only for a class that
    declares it — a required item nothing gates is a required item for every
    build."""
    src = _src()
    fn = _fn("_gather_manifest")
    assert calls(fn, "_vc_needs_identity"), (
        "identity is added to the required set unconditionally")
    assert "identity" in _ast_assert.string_constants(fn)
    # and the requirement sits with its siblings, not in dead code
    assert "input_field" in _ast_assert.string_constants(fn)


def test_the_item_is_gathered_only_from_established_accounts():
    """The gate exists to stop the build inventing an account. If a proposed
    name could satisfy it, it would do nothing."""
    body = _fn("_known_identities")
    assert "live_recon" in body and "access_inventory" in body
    assert "NEVER a name" in body or "invented account" in body


def test_a_class_without_the_declaration_adds_no_item():
    """SABOTAGE GUARD. The item must be conditional, or every build grows a
    required manifest entry it cannot satisfy."""
    fn = _fn("_gather_manifest")
    import ast as _ast
    node = _ast.parse(fn).body[0]
    guarded = any(
        isinstance(n, _ast.If)
        and any(getattr(getattr(c, "func", None), "id", "") == "_vc_needs_identity"
                for c in _ast.walk(n.test) if isinstance(c, _ast.Call))
        and any(getattr(getattr(c, "func", None), "id", "") == "add"
                and c.args and getattr(c.args[0], "value", None) == "identity"
                for c in _ast.walk(n) if isinstance(c, _ast.Call))
        for n in _ast.walk(node))
    assert guarded, "the identity item must be guarded by the class declaration"


# ── the regression this guard did NOT catch the first time ──────────────────
#
# The first cut declared the gap and the tools and shipped. The build then
# stopped at `gather_incomplete:identity` on every privilege-escalation run:
# all three tools were planned and dispatched, and all three SKIPPED —
#   user_enum_rest: "runs on pd-runner, not the listener"
#   user_enum_*:    "command template could not be rendered"
# — because the entries carried `runner: pd-runner` copied from a tool that
# needs it, and curl's write-out `%{http_code}` leaves braces, which the
# renderer rejects. Declaring a gap with no reachable answer is worse than not
# declaring it: it turns a build that used to dispatch into one that stops.

def test_every_identity_tool_actually_renders():
    """A template with braces left is refused by _gap_tool_command."""
    for t in _gap_tools():
        if "identity" not in (t.get("gaps") or []):
            continue
        cmd = (t["command"].replace("{scheme}", "http")
               .replace("{ip}", "1.2.3.4").replace("{port}", "9090")
               .replace("{base_url}", "http://1.2.3.4:9090").replace("{product}", "wp"))
        assert not ("{" in cmd and "}" in cmd), (
            f"{t['id']} still has braces after substitution: {cmd[:120]}")


def test_no_identity_tool_demands_a_runner_it_does_not_need():
    """`runner:` means 'only this container has the binary'. These use curl,
    which the listener has — declaring a runner makes them skip."""
    for t in _gap_tools():
        if "identity" in (t.get("gaps") or []):
            assert not t.get("runner"), (
                f"{t['id']} declares runner={t.get('runner')} but uses curl")


def test_each_identity_tool_declares_how_to_read_its_output():
    """A tool that runs and whose output nobody parses leaves the gap open —
    which is the same deadlock by a different route."""
    import re as _re
    for t in _gap_tools():
        if "identity" not in (t.get("gaps") or []):
            continue
        pat = t.get("identity_pattern")
        assert pat, f"{t['id']} has no identity_pattern — its output is unreadable"
        assert _re.compile(pat).groups >= 1, f"{t['id']}: pattern must capture the name"


def test_the_gap_cannot_deadlock_the_build():
    """SABOTAGE GUARD, and the one that matters. After enumeration has run, a
    target with no user list must still proceed — a required item with no path
    to satisfaction stops every build of that class."""
    txt = API.read_text(encoding="utf-8")
    fn = next((n for n in ast.walk(ast.parse(txt))
               if isinstance(n, ast.FunctionDef) and n.name == "_deep_recon_for_gaps"), None)
    body = ast.get_source_segment(txt, fn) or ""
    assert 'if "identity" in missing' in body, "no fallback after enumeration"
    assert "fallback" in body.lower()


def test_the_fallback_is_machine_readable_by_the_declared_patterns():
    """Prose would leave the gap unanswered. The fallback must satisfy it
    through the SAME path an enumerated user does."""
    import re as _re
    txt = API.read_text(encoding="utf-8")
    assert '{"username": "%s"}' in txt, (
        "the fallback must emit the shape the identity_patterns read")
    sample = 'IDENTITY (fallback): [{"username": "username"}] is the only account'
    hits = []
    for t in _gap_tools():
        p = t.get("identity_pattern")
        if p:
            hits += _re.findall(p, sample)
    assert "username" in hits, "no declared pattern reads the fallback"


def test_identity_is_extracted_from_the_untruncated_segments():
    """`recon_text` is truncated to 20,000 chars by the caller and deep-recon
    output is APPENDED, so the user list the identity tools just fetched sits
    past the cut. Measured 2026-10-23: user_enum_rest returned `"slug":"admin"`
    and the manifest still reported `missing: identity`."""
    txt = API.read_text(encoding="utf-8")
    i = txt.index("_ids = _known_identities(")
    call = txt[i:i + 260]
    assert "segments" in call, (
        "identity must be read from the untruncated segments, not from the "
        "truncated recon_text")


def test_a_site_title_is_not_an_identity():
    """`user_enum_generic` hit /api/users, got a WordPress 404 HTML page, and a
    bare `name` key matched the site title — "My WordPress Site" was recorded
    as an account. Harmless while identities are only advisory; actively
    dangerous once they are enforced, since the gate would demand every command
    contain it."""
    import re as _re
    html404 = ('<title>Page not found &#8211; My WordPress Site</title>'
               '<script>{"name":"My WordPress Site","url":"http://t"}</script>')
    for t in _gap_tools():
        pat = t.get("identity_pattern")
        if not pat or "identity" not in (t.get("gaps") or []):
            continue
        hits = _re.findall(pat, html404)
        assert "My WordPress Site" not in hits, (
            f"{t['id']} extracts a site title as an account: {hits}")


def test_a_real_user_json_still_matches():
    """SABOTAGE GUARD for the tightening: narrowing the keys must not stop it
    reading an actual user record."""
    import re as _re
    real = '[{"id":6,"username":"username","slug":"tester","login":"tester"}]'
    hits = []
    for t in _gap_tools():
        pat = t.get("identity_pattern")
        if pat and "identity" in (t.get("gaps") or []):
            hits += _re.findall(pat, real)
    assert "username" in hits and "tester" in hits, hits
