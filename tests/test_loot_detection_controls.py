"""Guard: the loot-detection controls, end to end, on synthetic pentest loot.

Feeds a captured post-access enumeration dump (tests/fixtures/
pentest_loot_enumeration.txt — AWS/Azure/SSH/DB/document loot, all synthetic)
through the REAL extractor -> fact -> rule chain and asserts each control fires:

  extractors   cloud keys (AWS + Azure), DB URLs, tokens, private keys,
               known_hosts peers, sensitive documents
  rules        private-key-found, known-host-discovered

This is the control test the suite lacked: every extractor was unit-tested
against its own regex, but nothing proved that a realistic loot dump produces
the facts the rules are written against. Three real gaps were found writing it
(no Azure extractors at all; the SAS pattern missed the XML-escaped '&amp;sig='
form that web.config actually stores; no extractor for document loot).

Runs standalone; needs only pyyaml.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "etl"))
sys.path.insert(0, str(ROOT))

pytest.importorskip("yaml")
try:
    import post_enumeration as pe
except Exception as exc:  # pragma: no cover
    pytest.skip(f"post_enumeration unavailable: {exc}", allow_module_level=True)

from conftest import LAB_TARGET, DOC_PEERS  # noqa: E402


def _facts(loot_output):
    return pe.facts_from(None, output=loot_output, target=LAB_TARGET, service="ssh")


def _kinds(facts, fact_type):
    return {f.get("kind") for f in facts if f.get("fact") == fact_type}


# ── extractor controls ───────────────────────────────────────────────────────

def test_aws_key_pair_is_extracted(loot_output):
    kinds = _kinds(_facts(loot_output), "secret")
    assert {"aws_access_key", "aws_secret_key"} <= kinds, (
        "an AWS credentials file in loot must yield BOTH halves of the pair; "
        f"got {sorted(kinds)}")


@pytest.mark.parametrize("kind", [
    "azure_storage_key",        # AccountKey=<88 b64>== — full storage control
    "azure_connection_string",  # account + key together, directly usable
    "azure_client_secret",      # service-principal secret
    "azure_sas_token",          # delegated storage access
])
def test_azure_secret_is_extracted(loot_output, kind):
    """Azure was entirely uncovered while AWS was — an Azure key in a looted
    azure.json / web.config produced no fact at all."""
    assert kind in _kinds(_facts(loot_output), "secret"), (
        f"{kind} not extracted from realistic Azure loot")


def test_sas_survives_xml_escaping(loot_output):
    """A SAS in a web.config is stored as '&amp;sig=', not '&sig=' — the raw
    form silently missed every config-embedded SAS."""
    assert "&amp;sig=" in loot_output, "fixture must use the realistic XML form"
    assert "azure_sas_token" in _kinds(_facts(loot_output), "secret")


def test_db_urls_and_tokens_are_extracted(loot_output):
    kinds = _kinds(_facts(loot_output), "secret")
    assert "db_url" in kinds and "github_token" in kinds


def test_private_key_and_documents_are_extracted(loot_output):
    facts = _facts(loot_output)
    file_kinds = _kinds(facts, "file")
    assert "private_key" in file_kinds
    assert "sensitive_document" in file_kinds, (
        "password spreadsheets / runbooks / DB dumps are loot on their name alone")
    docs = {f.get("path") for f in facts
            if f.get("fact") == "file" and f.get("kind") == "sensitive_document"}
    assert any(str(d).endswith(".xlsx") for d in docs)
    assert any(str(d).endswith(".sql") for d in docs)


def test_ssh_peers_become_host_leads(loot_output):
    """known_hosts / ssh config name hosts this account already reaches. They are
    LEADS — recorded so the scope gate can decide, never auto-trusted."""
    leads = {f.get("target") for f in _facts(loot_output)
             if f.get("fact") == "host" and f.get("source") == "known_hosts"}
    assert set(DOC_PEERS) <= leads, f"missing SSH peer leads; got {sorted(leads)}"


# ── rule controls (facts must reach the rules written against them) ──────────

def test_rules_fire_on_the_loot(loot_output):
    facts = _facts(loot_output)
    rules = pe.load_rules()
    fired = {r["id"] for f in facts for r in rules if pe._matches(r, f)}
    assert "private-key-found" in fired, "a private key must drive the SSH followup"
    assert "known-host-discovered" in fired, "a known_hosts peer must drive a lead scan"


# ── the fixture itself must stay synthetic ───────────────────────────────────

def test_fixture_is_non_functional(loot_output):
    """Documentation-example values and reserved ranges only — a fixture must
    never carry something that could authenticate or name a routable host."""
    assert "AKIAIOSFODNN7EXAMPLE" in loot_output, "use AWS's published example key"
    for peer in DOC_PEERS:
        assert peer.startswith(("192.0.2.", "198.51.100.", "203.0.113.")), \
            "peers must be RFC 5737 documentation ranges"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
