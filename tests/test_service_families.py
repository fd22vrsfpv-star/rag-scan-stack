"""One training doc must serve every name nmap gives the same service.

Run on demand:

    pytest tests/test_service_families.py -v

WHY THIS EXISTS
---------------
Retrieval scoped on `lower(service) = lower(%s)`, so a document filed under
`http` was invisible to an `https` query — despite being, for testing purposes,
the same service over a different transport. The workaround was ingesting the
same document once per name, which duplicates chunks, doubles embedding cost and
leaves copies to keep in step.

Two mechanisms replaced that, and both are pinned here:

  * `_service_scope()` widens the SQL scope to the whole family, so one doc
    answers every alias.
  * `service_canonical()` is added to the retrieval QUERY, because UNSCOPED
    prose documents are matched on wording alone. Measured: the SMB playbook
    scored 0.648 for a query saying "smb" and 0.506 for one saying
    "microsoft-ds" — the latter under the 0.55 floor, so the same service got
    guidance or not depending only on how nmap fingerprinted it.

Families must stay TIGHT: a scoped hit bypasses the similarity floor, so a wide
family would paste one service's guidance into an unrelated service's prompt.

Pure functions read out of the source with `ast` — no DB, no embedder — so this
runs on a bare checkout.

Sabotage proofs performed:
  * dropped "https" from the http family  -> test_web_family_covers_tls RED
  * made _service_scope return [service]  -> test_aliases_resolve_to_the_family RED
  * merged the http and smb families      -> test_families_do_not_overlap RED
"""
import ast
import os
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SRC = REPO / "scan_recommender" / "exploits_rag.py"


@pytest.fixture(scope="module")
def mod():
    if not SRC.exists():
        pytest.skip("scan_recommender/exploits_rag.py not present")
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    ns: dict = {}
    want_fn = {"_service_scope", "service_canonical"}
    want_const = {"_SERVICE_FAMILIES"}
    got = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in want_fn:
            exec(compile(ast.Module([node], []), "<f>", "exec"), ns)
            got.add(node.name)
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in want_const):
            exec(compile(ast.Module([node], []), "<c>", "exec"), ns)
            got.add(node.targets[0].id)
    missing = (want_fn | want_const) - got
    assert not missing, (
        f"could not extract {sorted(missing)} — service-family scoping was "
        "renamed or removed and this guard would pass vacuously")
    return ns


def test_aliases_resolve_to_the_family(mod):
    """Every alias must return the whole family, not just itself."""
    scope = mod["_service_scope"]
    for alias in ("https", "http-proxy", "ssl/http"):
        fam = scope(alias)
        assert "http" in fam and "https" in fam, (
            f"{alias!r} resolved to {fam} — a doc filed under another name in "
            "its family will not be found")


def test_web_family_covers_tls(mod):
    """http and https must be the same family. This is the motivating case:
    this deployment has 887 https ports against 527 http ones, so a doc that
    only answered `http` would miss the majority of its web surface."""
    scope = mod["_service_scope"]
    assert set(scope("http")) == set(scope("https"))


def test_smb_aliases_reach_the_same_docs(mod):
    scope = mod["_service_scope"]
    assert set(scope("microsoft-ds")) == set(scope("smb")) == set(scope("netbios-ssn"))


def test_unknown_service_is_unchanged(mod):
    """A service in no family must behave exactly as before — this widening
    must not change retrieval for anything it does not explicitly cover."""
    assert mod["_service_scope"]("finger") == ["finger"]
    assert mod["_service_scope"]("") == []


def test_canonical_name_is_stable_across_aliases(mod):
    canon = mod["service_canonical"]
    assert canon("https") == canon("http") == "http"
    assert canon("microsoft-ds") == canon("smb") == "smb"
    assert canon("mariadb") == "mysql"
    assert canon("finger") == "finger"


def test_families_do_not_overlap(mod):
    """A service in two families would make scope() order-dependent, so the
    same query could return different documents run to run."""
    fams = mod["_SERVICE_FAMILIES"]
    seen: dict = {}
    for canon, members in fams.items():
        for m in members:
            assert m not in seen, (
                f"{m!r} is in both {seen[m]!r} and {canon!r} families")
            seen[m] = canon


def test_every_family_contains_its_canonical_name(mod):
    for canon, members in mod["_SERVICE_FAMILIES"].items():
        assert canon in members, (
            f"canonical {canon!r} is not a member of its own family {sorted(members)} — "
            "service_canonical would name something the scope never matches")


def test_families_stay_tight(mod):
    """A scoped hit BYPASSES the similarity floor, so an over-broad family
    pastes one service's guidance into an unrelated service's prompt."""
    for canon, members in mod["_SERVICE_FAMILIES"].items():
        assert len(members) <= 10, (
            f"the {canon!r} family has {len(members)} members; that is wide "
            "enough to leak guidance between unrelated services")


def test_the_query_includes_the_canonical_name():
    """Widening the SQL scope is only half of it — unscoped prose docs are
    matched on wording, so the canonical name must reach the query text too."""
    rec = REPO / "scan_recommender" / "scan_recommender.py"
    if not rec.exists():
        pytest.skip("scan_recommender.py not present")
    src = rec.read_text(encoding="utf-8")
    i = src.index("def _get_training_context(")
    body = src[i:src.index("\ndef ", i + 10)]
    assert "service_canonical" in body, (
        "_get_training_context no longer adds the canonical service name to the "
        "query — 'microsoft-ds' will score below the floor where 'smb' passes")


# ── the agent must be able to turn knowledge into concrete tests ────────────

def test_structured_recommendation_tool_is_exposed_to_agents():
    """`get_tool_recommendations` must be in the registry AND in the phases.

    The endpoint behind it (/rag/tools/recommend) already returned tools with
    ready command templates, nuclei tags and the ingested methodology — but no
    agent could call it, because it was never registered. The capability
    existing is not the same as an agent being able to use it.
    """
    reg = REPO / "autogen_agents" / "tool_registry.py"
    eng = REPO / "autogen_agents" / "langgraph_engine.py"
    if not reg.exists() or not eng.exists():
        pytest.skip("autogen_agents source not present")

    reg_src = reg.read_text(encoding="utf-8")
    assert '"get_tool_recommendations"' in reg_src, (
        "get_tool_recommendations is not in the tool registry, so no agent can "
        "call it")

    eng_src = eng.read_text(encoding="utf-8")
    i = eng_src.index("SCAN_TOOLS_READONLY = {")
    assert "get_tool_recommendations" in eng_src[i:i + 500], (
        "the scan phase cannot call get_tool_recommendations")
    j = eng_src.index("ANALYZE_TOOLS = ")
    assert "get_tool_recommendations" in eng_src[j:j + 300], (
        "the analyze phase cannot call get_tool_recommendations")


def test_test_plan_does_not_substitute_the_session_description():
    """`{target}` must be filled from a port row's ip, not target_description.

    Filling it from the description produced
    `$ sslscan redteam3 web hosts:443` — something that reads like a command
    and cannot be run. A plan of unrunnable commands is worse than no plan,
    because it looks finished.
    """
    eng = REPO / "autogen_agents" / "langgraph_engine.py"
    if not eng.exists():
        pytest.skip("langgraph_engine.py not present")
    src = eng.read_text(encoding="utf-8")
    i = src.index("def _build_test_plan(")
    body = src[i:src.index("\ndef ", i + 10)]
    assert 'row.get("ip")' in body, (
        "_build_test_plan no longer reads the host from the port row")
    assert '{target}' in body and 'info["ip"]' in body, (
        "the command placeholder is no longer filled from the discovered host")
    # the description must not be threaded in as the substitution source
    assert 'state["target"]' not in body, (
        "_build_test_plan reads the session target_description again — that is "
        "a human label, not a host")


def test_the_plan_is_produced_even_when_the_llm_path_runs():
    """Concrete tests must not depend on the model choosing to ask for them.

    Observed twice in one afternoon: the scan agent was rate-limited (429), and
    on the retry it ran fine, never called get_tool_recommendations, and
    answered "No results yet for redteam3 specifically". The open services are
    already known, so the plan is appended either way.
    """
    eng = REPO / "autogen_agents" / "langgraph_engine.py"
    if not eng.exists():
        pytest.skip("langgraph_engine.py not present")
    src = eng.read_text(encoding="utf-8")
    i = src.index("def scan(state: PentestState)")
    body = src[i:src.index("\ndef ", i + 10)]
    assert "_build_test_plan()" in body, (
        "the LLM scan path no longer appends the deterministic test plan, so a "
        "session produces concrete tests only when the model cooperates")


# ── transport is its own axis, never inferred from the port ─────────────────

@pytest.fixture(scope="module")
def tls():
    """`_tls_state` out of langgraph_engine, read with ast (no agent deps)."""
    eng = REPO / "autogen_agents" / "langgraph_engine.py"
    if not eng.exists():
        pytest.skip("langgraph_engine.py not present")
    tree = ast.parse(eng.read_text(encoding="utf-8"))
    ns: dict = {}
    got = set()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "_tls_state":
            exec(compile(ast.Module([node], []), "<f>", "exec"), ns); got.add("fn")
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id in ("_TLS_SERVICE_NAMES", "_SERVICE_FAMILIES_WEB")):
            exec(compile(ast.Module([node], []), "<c>", "exec"), ns); got.add(node.targets[0].id)
    assert got >= {"fn", "_TLS_SERVICE_NAMES"}, (
        "could not extract _tls_state / _TLS_SERVICE_NAMES — transport detection "
        "was renamed or removed and this guard would pass vacuously")
    return ns


def test_tls_is_detected_from_the_service_not_the_port(tls):
    f = tls["_tls_state"]
    assert f("https") == "yes"
    assert f("ssl/http") == "yes"
    assert f("imaps") == "yes"
    assert f("ldaps") == "yes"


def test_plain_http_is_never_assumed_tls_by_its_port(tls):
    """`http` stays UNKNOWN whatever port it was seen on.

    This deployment holds 260 rows recorded as `http` on 443 — Apache, Azure
    Application Gateway, Cloudflare — with no tunnel field and no banner
    mentioning TLS. Guessing from the port is what produces
    `nikto -h http://host:443` against a TLS listener.
    """
    f = tls["_tls_state"]
    assert f("http") == "unknown"
    assert f("http", "Apache httpd", "406 Not Acceptable") == "unknown"


def test_tls_state_takes_no_port_argument(tls):
    """Structural: the port must not be reachable by this function at all."""
    import inspect
    params = list(inspect.signature(tls["_tls_state"]).parameters)
    assert "port" not in params, (
        f"_tls_state accepts {params} — a port parameter is an invitation to "
        "infer transport from it, which is the assumption this exists to avoid")


def test_banner_evidence_is_honoured(tls):
    assert tls["_tls_state"]("smtp", "", "220 mail ESMTP STARTTLS") == "yes"


def test_the_plan_states_the_transport_for_every_service():
    """Every service block must say what the transport is or that it is unknown."""
    eng = REPO / "autogen_agents" / "langgraph_engine.py"
    if not eng.exists():
        pytest.skip("langgraph_engine.py not present")
    src = eng.read_text(encoding="utf-8")
    i = src.index("def _build_test_plan(")
    body = src[i:src.index("\ndef ", i + 10)]
    assert "transport:" in body, "the test plan no longer reports the transport"
    assert "UNCONFIRMED" in body, (
        "the plan no longer distinguishes 'TLS' from 'not established' — an "
        "unconfirmed transport must be stated, not guessed")


def test_nmap_parser_captures_the_tls_tunnel():
    """nmap reports TLS in a separate `tunnel` attribute; dropping it destroys
    the only evidence that a listener is wrapped."""
    api = REPO / "nmap_scanner" / "nmap-api.py"
    if not api.exists():
        pytest.skip("nmap-api.py not present")
    src = api.read_text(encoding="utf-8")
    assert "_nmap_service_name" in src, (
        "the nmap parser no longer normalises the tunnel into the service name")
    i = src.index("def _nmap_service_name")
    body = src[i:src.index("\ndef ", i + 10)]
    assert 'svc.get("tunnel")' in body, "the tunnel attribute is not read"

    # behavioural: ssl-tunnelled http must become ssl/http
    import xml.etree.ElementTree as ET
    ns: dict = {}
    exec(compile(body, "<h>", "exec"), ns)
    f = ns["_nmap_service_name"]
    assert f(ET.Element("service", {"name": "http", "tunnel": "ssl"})) == "ssl/http"
    assert f(ET.Element("service", {"name": "http"})) == "http"
    assert f(ET.Element("service", {"name": "ssl/http", "tunnel": "ssl"})) == "ssl/http"
