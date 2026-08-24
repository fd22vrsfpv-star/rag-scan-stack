"""Discovered accounts, and whether a password is known for each.

Run on demand:

    pytest tests/test_identity_credential_state.py -v

WHY THIS EXISTS
---------------
enum4linux and enum4linux-ng enumerated 35 accounts on 192.168.1.150 through an
SMB null session, and the only durable record was raw tool text. The vault held
FOUR names — every one of them an account a password had already been found for.
So "which accounts have we not tried yet?" could not be answered without
re-parsing tool output.

Two design decisions are pinned here.

**`status='unknown'`, not 'active'.** `identities.status` is an ACCOUNT-state
field — its CHECK allows exactly active/disabled/unknown/deleted — and
enumeration proves the account EXISTS, not that it can be used. A working login
is what proves 'active'. A re-import must never downgrade a proven account.

**"Has a password" is DERIVED, never stored.** `v_identity_credential_state`
joins the vault and the verified findings. A stored flag goes stale the moment a
password is cracked, and a stale flag would send the operator to re-attack an
account already owned — or skip one still open.
"""
import os
import subprocess
import sys

import pytest

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
for path in (REPO, os.path.join(REPO, "app", "rag-api")):
    if path not in sys.path:
        sys.path.insert(0, path)


def _psql(sql):
    try:
        out = subprocess.run(
            ["docker", "exec", "rag-postgres", "psql", "-U", "app", "-d", "scans",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def _curl(method, path, timeout=300):
    cmd = (f'curl -sk --max-time {timeout} -H "x-api-key: $API_KEY" '
           f'-X {method} "https://127.0.0.1:8000{path}"')
    try:
        out = subprocess.run(["docker", "exec", "rag-api", "sh", "-c", cmd],
                             capture_output=True, text=True, timeout=timeout + 30)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


@pytest.fixture(scope="module")
def db():
    if _psql("SELECT 1") != "1":
        pytest.skip("rag-postgres not reachable")
    if _psql("SELECT count(*) FROM pg_views WHERE "
             "viewname='v_identity_credential_state'") == "0":
        pytest.skip("v_identity_credential_state not installed")
    return True


# ── the username filter that was wrong ──────────────────────────────────────

@pytest.mark.unit
def test_user_is_a_real_username():
    """`user` was rejected as implausible because it reads like a column header.

    It is a real local account on this target WITH A VERIFIED PASSWORD already in
    the vault, so the filter dropped a known-good name from the identity list and
    from every generated wordlist. A word that can be a header is not thereby an
    impossible account name.
    """
    tw = pytest.importorskip("target_wordlists")
    assert tw._plausible_username("user") is True, \
        "'user' is rejected again — it is a real account with a known password"
    for also_real in ("admin", "guest", "root", "operator", "service", "test"):
        assert tw._plausible_username(also_real) is True, also_real


@pytest.mark.unit
def test_header_cells_are_still_rejected():
    """The filter must not be widened into uselessness."""
    tw = pytest.importorskip("target_wordlists")
    for header in ("username", "Permissions", "Sharename", "Remark", "null",
                   "n/a", "", "  "):
        assert tw._plausible_username(header) is False, header


# ── the account-state column ────────────────────────────────────────────────

def test_status_allows_exactly_four_values(db):
    """The design constraint. `status` cannot express credential knowledge, which
    is why that lives in a view instead."""
    got = _psql("SELECT pg_get_constraintdef(oid) FROM pg_constraint "
                "WHERE conrelid='identities'::regclass AND contype='c' "
                "AND conname LIKE '%status%'")
    assert got, "no status CHECK on identities"
    for value in ("active", "disabled", "unknown", "deleted"):
        assert value in got, f"{value} missing from the status constraint"


def test_enumerated_accounts_are_unknown_not_active(db):
    """Enumeration proves existence, not usability."""
    got = _psql("SELECT count(*) FROM identities "
                "WHERE 'discovery:enumerated' = ANY(tags) AND status = 'active' "
                "AND display_name NOT IN (SELECT username FROM credential_findings)")
    if got is None:
        pytest.skip("query failed")
    assert int(got) == 0, (
        f"{got} enumerated account(s) marked 'active' without a credential — "
        "enumeration does not prove an account is usable")


def test_a_proven_account_is_never_downgraded(db):
    """Re-importing must keep the stronger value. msfadmin and user were both
    already 'active' from a working login AND appear in the enumerated list."""
    got = _psql("SELECT count(*) FROM v_identity_credential_state "
                "WHERE credential_state = 'password_verified' AND status <> 'active'")
    if got is None:
        pytest.skip("query failed")
    assert int(got) == 0, \
        f"{got} verified account(s) downgraded out of 'active' by a re-import"


# ── derived, not stored ─────────────────────────────────────────────────────

def test_has_credential_is_not_a_stored_column(db):
    """A stored flag goes stale the moment a password is cracked."""
    got = _psql("SELECT count(*) FROM information_schema.columns "
                "WHERE table_name='identities' AND column_name IN "
                "('has_credential','has_password','credential_state')")
    assert got is not None and int(got) == 0, (
        "a credential flag was added to the identities TABLE; it must stay "
        "derived in v_identity_credential_state")


def test_the_view_classifies_every_identity(db):
    """No identity may fall outside the three states."""
    total = _psql("SELECT count(*) FROM identities")
    classified = _psql("SELECT count(*) FROM v_identity_credential_state "
                       "WHERE credential_state IN "
                       "('username_only','password_stored','password_verified')")
    assert total and classified
    assert int(total) == int(classified), \
        f"{total} identities but {classified} classified"


def test_the_spray_list_is_not_empty(db):
    """`username_only` is the actual deliverable: enumerated, no password yet."""
    got = _psql("SELECT count(*) FROM v_identity_credential_state "
                "WHERE credential_state = 'username_only'")
    assert got is not None
    assert int(got) >= 20, (
        f"only {got} username_only accounts — the 35 enumerated names have not "
        "been imported")


def test_verified_accounts_are_excluded_from_the_spray_list(db):
    """An account we already own must not appear as a target."""
    got = _psql("SELECT count(*) FROM v_identity_credential_state "
                "WHERE credential_state = 'username_only' AND has_credential")
    assert got is not None and int(got) == 0, \
        "an account with a credential is listed as username_only"


# ── the endpoints ───────────────────────────────────────────────────────────

def test_import_endpoint_is_dry_by_default(db):
    import json
    body = _curl("POST", "/identities/import-enumerated")
    if not body:
        pytest.skip("rag-api not reachable")
    d = json.loads(body)
    assert d.get("ok") is True, d
    assert d["dry_run"] is True
    assert d["inserted"] == 0 and d["updated"] == 0, "a dry run wrote rows"
    assert d["found"] > 0, "no enumerated usernames found at all"


def test_import_is_idempotent(db):
    import json
    before = _psql("SELECT count(*) FROM identities")
    d = json.loads(_curl("POST", "/identities/import-enumerated?dry_run=false"))
    after = _psql("SELECT count(*) FROM identities")
    assert d["inserted"] == 0, f"re-import inserted {d['inserted']} duplicates"
    assert int(after) == int(before), f"identities grew {before} -> {after}"


def test_credential_state_endpoint_filters_the_spray_list(db):
    import json
    body = _curl("GET", "/identities/credential-state?state=username_only")
    if not body:
        pytest.skip("rag-api not reachable")
    d = json.loads(body)
    assert d.get("ok") is True, d
    assert d["returned"] > 0, "the spray list came back empty"
    for row in d["identities"]:
        assert row["credential_state"] == "username_only", row
        assert row["has_credential"] is False, row
    assert "counts_by_state" in d


def test_the_wordlist_builder_reads_the_durable_source(db):
    """`extracted` re-derives names from raw output, which works only while that
    output is still stored. `identities` is what survives pruning."""
    import json
    body = _curl("POST", "/wordlists/build-target?target=192.168.1.150&port=21&service=ftp")
    if not body:
        pytest.skip("rag-api not reachable")
    d = json.loads(body)
    assert d["harvested"].get("identities", 0) > 20, (
        f"the builder harvested {d['harvested'].get('identities')} identities — "
        "the durable source is not wired in")
    assert "user" in d["users"], \
        "'user' is missing from the generated list again"
