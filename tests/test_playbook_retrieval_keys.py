"""Playbook-phase documents carry retrieval KEYS, and only honest ones.

`rag_documents` has first-class `vuln_class` / `cve` / `service` columns so a
reader can FILTER rather than hope similarity lands. The 76 playbook_phase
documents carried none of them: every playbook was reachable only by
similarity. `_playbook_keys` fills that in — narrowly, because a wrong key is
worse than none. A document filed under a class it does not describe is
retrieved by a build that asked for that class, and nothing downstream can see
the key was a guess.

The three derivations this pins:

  * service nests from the playbook title ("SSH Penetration Testing
    Methodology" -> every phase is ssh), and is read from the phase heading
    first when the heading names one.
  * a class is a CLAIM and does not nest: the title of
    `code_injection.yaml` resolves to `rce` through the `code-injection`
    alias, and must NOT be stamped on its DLL/shellcode/APC phases.
  * in a service methodology a class word belongs to a PRODUCT name:
    "Microsoft SQL Server (Port 1433)" resolves to `sqli` on the bare `sql`
    alias and must stay unclassified.

    pytest tests/test_playbook_retrieval_keys.py
"""
import glob
import importlib
import os
import sys

import pytest

yaml = pytest.importorskip("yaml")
pytest.importorskip("httpx")
pytest.importorskip("psycopg2")

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLAYBOOKS = os.path.join(REPO, "knowledge", "playbooks")

if REPO not in sys.path:
    sys.path.insert(0, REPO)
os.environ.setdefault("KNOWLEDGE_DIR", os.path.join(REPO, "knowledge"))

L = importlib.import_module("etl.load_knowledge_documents")


def _render_all():
    """Every playbook phase document, as (metadata, title) pairs."""
    out = []
    for path in sorted(glob.glob(os.path.join(PLAYBOOKS, "*.yaml"))):
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        stem = os.path.basename(path)[: -len(".yaml")]
        for doc in L._render_playbook(data, stem):
            assert len(doc) == 3, f"{stem}: playbook doc carries no metadata"
            out.append((doc[2], doc[0]))
    assert out, "no playbook documents rendered — fixtures missing?"
    return out


def _by_phase(docs, playbook_fragment, phase_fragment):
    hits = [m for m, _ in docs
            if playbook_fragment.lower() in str(m.get("playbook", "")).lower()
            and phase_fragment.lower() in str(m.get("phase", "")).lower()]
    assert len(hits) == 1, (
        f"expected exactly one {playbook_fragment!r}/{phase_fragment!r} phase,"
        f" got {len(hits)}")
    return hits[0]


# --------------------------------------------------------------- derivation --

def test_service_is_read_from_the_phase_heading():
    """A heading that names a service or a port keys the document on it."""
    docs = _render_all()
    expected = {
        ("Database", "MySQL"): "mysql",
        ("Database", "PostgreSQL"): "postgresql",
        # No word here is a catalogue name; port_hints 1433 is what resolves.
        ("Database", "Microsoft SQL Server"): "mssql",
        ("Database", "MongoDB"): "mongodb",
        ("Database", "Redis"): "redis",
        ("Network Services", "FTP"): "ftp",
        ("Network Services", "SNMP"): "snmp",
        # Names 2049 AND 111; 111 is rpc in port_hints. The NAME must win.
        ("Network Services", "NFS"): "nfs",
        ("Lateral Movement", "SMB Relay"): "smb",
        ("Lateral Movement", "SSH Tunneling"): "ssh",
    }
    for (pb, phase), svc in expected.items():
        assert _by_phase(docs, pb, phase).get("service") == svc, \
            f"{pb}/{phase} should key on {svc}"


def test_service_scope_nests_from_the_playbook_title():
    """Phases with no service in their own heading inherit the book's."""
    docs = _render_all()
    for m, _ in docs:
        if str(m.get("playbook", "")).lower().startswith("ssh "):
            assert m.get("service") == "ssh", m.get("phase")
        if str(m.get("playbook", "")).lower().startswith("smb/"):
            assert m.get("service") == "smb", m.get("phase")
    # The generic headings are the ones that would be missed without the
    # fallback, so name one explicitly.
    assert _by_phase(docs, "SSH", "Post-Exploitation").get("service") == "ssh"


def test_every_service_key_is_in_the_catalogue():
    """No key may be invented: the column's value comes from service_tools."""
    names = L._service_catalogue()["names"]
    ports = set(L._service_catalogue()["ports"].values())
    assert names, "service catalogue did not load — this test proves nothing"
    for m, title in _render_all():
        for svc in (m.get("services") or []):
            assert svc in names or svc in ports, f"{title}: unknown service {svc}"


def test_whole_tokens_only_never_substrings():
    """`finger` must not match `Fingerprinting`, `ssh` not `sshd-config`."""
    assert L._services_named("Technology Fingerprinting") == []
    assert L._services_named("Initial Reconnaissance") == []
    assert L._services_named("FTP (Port 21)") == ["ftp"]


def test_a_port_only_answers_when_no_name_does():
    assert L._services_named("NFS (Port 2049/111)") == ["nfs"]
    assert L._services_named("Microsoft SQL Server (Port 1433)") == ["mssql"]


def test_several_services_stay_out_of_the_column():
    """The column takes ONE value; picking the first misreports the rest."""
    data = {"title": "Mixed", "phases": [{"name": "redis and mongodb",
                                          "steps": [{"title": "look"}]}]}
    docs = L._render_playbook(data, "mixed")
    assert len(docs) == 1
    meta = docs[0][2]
    assert meta.get("services") == ["mongodb", "redis"]
    assert meta.get("service") is None


# ------------------------------------------------------------ the two traps --

def test_a_product_name_is_not_a_vulnerability_claim():
    """`Microsoft SQL Server` resolves to sqli on the bare `sql` alias."""
    vc = importlib.import_module("etl.vuln_classes")
    assert vc.resolve("Microsoft SQL Server (Port 1433)")["class"] == "sqli", \
        "premise gone: the alias no longer matches, so this guard is idle"
    docs = _render_all()
    assert _by_phase(docs, "Database", "Microsoft SQL Server") \
        .get("vuln_class") is None


def test_a_title_is_not_a_claim_about_every_phase():
    """`code-injection` is an rce alias; its phases are process injection."""
    vc = importlib.import_module("etl.vuln_classes")
    assert vc.resolve("Code Injection & Process Injection Techniques")[
        "class"] == "rce", "premise gone: this guard is idle"
    for m, title in _render_all():
        if "code injection" in str(m.get("playbook", "")).lower():
            assert m.get("vuln_class") is None, title


def test_a_phase_heading_that_names_a_class_does_key_on_it():
    """The rule is narrow, not dead: a real claim still resolves."""
    data = {"title": "Synthetic", "phases": [
        {"name": "SQL Injection", "steps": [{"title": "probe"}]},
        {"name": "Local File Inclusion", "steps": [{"title": "probe"}]},
    ]}
    classes = [d[2].get("vuln_class") for d in L._render_playbook(data, "syn")]
    assert classes == ["sqli", "lfi"]


def test_step_classes_never_become_the_phase_class():
    """`vuln_classes` describes the STEPS; it must not reach the column."""
    docs = _render_all()
    listed = [(m, t) for m, t in docs if m.get("vuln_classes")]
    assert listed, "no phase names a class in its steps — fixtures changed?"
    for m, title in listed:
        assert m.get("vuln_class") is None, title
    manual = _by_phase(docs, "Web Application", "Manual Testing")
    assert set(manual["vuln_classes"]) >= {"sqli", "xss", "xxe"}
    assert manual.get("vuln_class") is None


# ------------------------------------------------- three outcomes, not two --

def test_an_unreadable_catalogue_resolves_nothing_and_says_so(monkeypatch, caplog):
    """"could not derive" is not "does not apply" — fail closed and log it."""
    monkeypatch.setattr(L, "_SERVICE_CATALOGUE", {})
    monkeypatch.setattr(L, "KNOWLEDGE_DIR", os.path.join(REPO, "no-such-dir"))
    with caplog.at_level("WARNING"):
        assert L._services_named("FTP (Port 21)") == []
    assert any(r.levelname == "WARNING" for r in caplog.records), \
        "an underivable key must be visible in the log, not silent"
    monkeypatch.setattr(L, "_SERVICE_CATALOGUE", {})


# --------------------------------------------------------------- the ratchet --

SERVICE_KEYED_FLOOR = 34


def test_coverage_does_not_regress():
    """How many of the playbook phases are filterable at all. Ratchets up."""
    docs = _render_all()
    keyed = [m for m, _ in docs if m.get("service") or m.get("vuln_class")]
    assert len(keyed) >= SERVICE_KEYED_FLOOR, (
        f"{len(keyed)} of {len(docs)} playbook phases carry a retrieval key,"
        f" floor is {SERVICE_KEYED_FLOOR}")
