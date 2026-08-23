"""Two parsers that had never stored a single row.

Run on demand:

    pytest tests/test_dead_parsers.py -v

WHY THIS EXISTS
---------------
`etl/parse_subdomain_takeover.py` wrote EIGHT columns `recon_findings` does not
have (scan_id, domain, subdomain, title, description, evidence_data,
discovered_at, metadata). `etl/parse_pacu.py` wrote THREE that
`credential_findings` does not have (target, finding_type, data). Every insert
raised `UndefinedColumn` inside a `try/except` that counted it as one error among
many, so both features looked implemented, reported "0 findings" and nobody
noticed.

They were the 11 entries in SQL_DEBT. Neither was a rename — each needed a
decision about where the data belongs:

  * takeover findings -> recon_findings, with the tool-specific fields in the
    `data` jsonb, `finding_type='subdomain_takeover'` and the subdomain as
    `target`.
  * pacu AWS keys -> credential_vault, NOT credential_findings. That table's
    `ip`, `port` and `username` are all NOT NULL and an AWS access key has no
    host or port; credential_vault is built for this and even carries a
    `cloud_metadata` jsonb.

These tests execute the parsers against the live database, because the defect
was invisible to every static check: the modules imported, `ast.parse` passed,
and the containers were healthy.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))


def _in_container(script):
    """Run a snippet inside rag-api, which has DB_DSN and the etl mount."""
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "python3", "-c", script],
                             capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


@pytest.fixture(scope="module")
def rag_api():
    if _in_container("print('ok')") is None:
        pytest.skip("rag-api container not reachable")
    return True


# ── source-level guards (always run) ────────────────────────────────────────

@pytest.mark.unit
def test_takeover_parser_targets_the_real_columns():
    src = open(os.path.join(REPO, "etl", "parse_subdomain_takeover.py"),
               encoding="utf-8").read()
    assert "INSERT INTO recon_findings" in src
    for gone in ("scan_id,", "evidence_data", "discovered_at,", "subdomain,"):
        assert gone not in src.split("INSERT INTO recon_findings")[1][:400], \
            f"{gone!r} is back in the takeover insert; recon_findings has no such column"
    assert "finding_type" in src and "subdomain_takeover" in src


@pytest.mark.unit
def test_takeover_keeps_volatile_ids_out_of_the_fingerprinted_payload():
    """trg_recon_findings_dedup hashes source|finding_type|target|data.

    A per-scan id inside `data` would fork the fingerprint on every run and
    defeat the dedup entirely, which is why scan_id is excluded and the payload
    is serialised with sort_keys.
    """
    src = open(os.path.join(REPO, "etl", "parse_subdomain_takeover.py"),
               encoding="utf-8").read()
    payload = src.split("json.dumps({", 1)[1].split("}", 1)[0]
    assert "scan_id" not in payload, "scan_id is back in the fingerprinted payload"
    assert "sort_keys=True" in src, \
        "unsorted json makes the fingerprint depend on key order"


@pytest.mark.unit
def test_pacu_writes_to_credential_vault_not_credential_findings():
    src = open(os.path.join(REPO, "etl", "parse_pacu.py"), encoding="utf-8").read()
    assert "INSERT INTO credential_vault" in src
    assert "INSERT INTO credential_findings" not in src, (
        "pacu is writing to credential_findings again — its ip, port and "
        "username are NOT NULL and an AWS access key has none of them")


@pytest.mark.unit
def test_pacu_upsert_repeats_the_partial_index_predicate():
    """ux_credvault_source_entity is PARTIAL.

    ON CONFLICT must repeat `WHERE source_entity_id IS NOT NULL` or Postgres
    refuses with "no unique or exclusion constraint matching the ON CONFLICT
    specification" — the same failure that once made asset ingestion report
    "23 records seen, 23 errors, 0 ports".
    """
    src = open(os.path.join(REPO, "etl", "parse_pacu.py"), encoding="utf-8").read()
    assert "ON CONFLICT (source, source_entity_id)" in src
    assert "WHERE source_entity_id IS NOT NULL" in src


@pytest.mark.unit
def test_pacu_identity_is_deterministic():
    """Dedup needs a stable identity; uuid4 per import would duplicate forever.

    The access key id IS the credential's identity, so a uuid5 of it is the
    natural key.
    """
    src = open(os.path.join(REPO, "etl", "parse_pacu.py"), encoding="utf-8").read()
    assert "uuid.uuid5(" in src, "source_entity_id is not deterministic"
    assert "aws-access-key" in src


# ── executed against the live database ──────────────────────────────────────

def test_takeover_parser_actually_stores_and_dedupes(rag_api):
    out = _in_container(r"""
import sys, os, psycopg2
sys.path.insert(0, '/app')
from etl.parse_subdomain_takeover import insert_subdomain_takeover_findings
conn = psycopg2.connect(os.environ['DB_DSN'])
f = {'source': 'subzy-test', 'scan_id': 'scan-1',
     'subdomain': 'dead-parser-probe.example.test',
     'title': 'AWS S3 Bucket Subdomain Takeover',
     'description': 'CNAME to unclaimed bucket', 'severity': 'high',
     'confidence': 'high', 'service_provider': 's3', 'evidence': 'NoSuchBucket',
     'risk_score': 8.0, 'remediation': 'claim it', 'references': ['https://x']}
n1 = insert_subdomain_takeover_findings([f], conn)
# a second identical run must merge, not duplicate
f2 = dict(f); f2['scan_id'] = 'scan-2'
insert_subdomain_takeover_findings([f2], conn)
cur = conn.cursor()
cur.execute("SELECT count(*), max(finding_type), max(severity) FROM recon_findings "
            "WHERE target = 'dead-parser-probe.example.test'")
rows, ftype, sev = cur.fetchone()
cur.execute("DELETE FROM recon_findings WHERE target = 'dead-parser-probe.example.test'")
conn.commit()
print(f"{n1}|{rows}|{ftype}|{sev}")
""")
    assert out, "probe failed to run"
    inserted, rows, ftype, sev = out.strip().splitlines()[-1].split("|")
    assert int(inserted) == 1, f"parser inserted {inserted}, not 1"
    assert int(rows) == 1, (
        f"{rows} rows after two runs — a differing scan_id forked the fingerprint")
    assert ftype == "subdomain_takeover"
    assert sev == "high", "severity was lost"


def test_pacu_parser_actually_stores_and_dedupes(rag_api):
    out = _in_container(r"""
import sys, os, json, tempfile, psycopg2
sys.path.insert(0, '/app')
from etl.parse_pacu import parse_pacu
doc = {'account_id': '123456789012', 'credentials': [
  {'access_key_id': 'AKIAIOSFODNN7EXAMPLE',
   'secret_access_key': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
   'user_name': 'dead-parser-probe-user'},
  {'AccessKeyId': 'ASIAI44QH8DHBEXAMPLE', 'SessionToken': 'FQoGZXIvYXdzEXAMPLE',
   'user_name': 'dead-parser-probe-role'}]}
with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as fh:
    json.dump(doc, fh); path = fh.name
s1 = parse_pacu(path, profile='test')
parse_pacu(path, profile='test')          # re-import must update, not duplicate
conn = psycopg2.connect(os.environ['DB_DSN']); cur = conn.cursor()
cur.execute("SELECT count(*) FROM credential_vault WHERE username LIKE 'dead-parser-probe%'")
rows = cur.fetchone()[0]
cur.execute("SELECT string_agg(DISTINCT credential_type, ',' ORDER BY credential_type) "
            "FROM credential_vault WHERE username LIKE 'dead-parser-probe%'")
types = cur.fetchone()[0]
cur.execute("SELECT count(*) FROM credential_vault WHERE username LIKE 'dead-parser-probe%' "
            "AND cloud_metadata->>'account_id' = '123456789012'")
with_acct = cur.fetchone()[0]
cur.execute("DELETE FROM credential_vault WHERE username LIKE 'dead-parser-probe%'")
conn.commit(); os.unlink(path)
print(f"{s1['credentials_inserted']}|{s1['errors']}|{rows}|{types}|{with_acct}")
""")
    assert out, "probe failed to run"
    ins, errs, rows, types, with_acct = out.strip().splitlines()[-1].split("|")
    assert int(errs) == 0, (
        f"{errs} error(s) — the whole point is that every insert used to raise")
    assert int(ins) == 2, f"inserted {ins}, not 2"
    assert int(rows) == 2, f"{rows} rows after re-import — the upsert is not deduping"
    assert types == "aws_access_key,aws_sts", (
        f"credential_type not discriminated: {types}")
    assert int(with_acct) == 2, "account_id did not reach cloud_metadata"


def test_pacu_records_the_plaintext_storage_caution(rag_api):
    """Credential material is stored in the clear by operator choice; the caution
    belongs at the point of storage, not only in a document."""
    src = open(os.path.join(REPO, "etl", "parse_pacu.py"), encoding="utf-8").read()
    assert "CAUTION" in src and "unencrypted" in src
