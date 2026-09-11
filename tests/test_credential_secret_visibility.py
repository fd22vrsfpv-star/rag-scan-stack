"""A harvested credential must reach the operator, not just the database.

Run on demand:

    pytest tests/test_credential_secret_visibility.py -v

WHY THIS EXISTS
---------------
Assets → Credentials listed accounts with no secret and no way to see one. The
`credential_findings.secret_value` column existed the whole time, and the bug was
in THREE places at once — each of which alone would have hidden the value:

  1. **The writer.** `POST /credentials` built a `metadata` dict containing the
     secret and left `secret_value` out of its INSERT column list entirely, so
     the column was NULL on every row it created.
  2. **The reader.** `GET /assets/{ip}/credentials` — the drill-down the panel
     actually calls — did not SELECT `secret_value`, while the global
     `GET /credentials` list did. So even a populated column would not have
     reached this panel.
  3. **The UI.** `AssetBrowser.tsx` rendered username, protocol, type, source and
     timestamps, and had no markup for the secret at all.

Not a cosmetic bug: `etl/credential_bridge.py` SELECTs `cf.secret_value`, so
every post-ex harvested credential was invisible to the credential bridge too.
Measured live: **9 of 9 rows from `source='postex_enum'`** had the column NULL
and the material only in `metadata->>'secret_value'`.

WHY THE SECRET IS RETURNED IN PLAINTEXT
---------------------------------------
Deliberate, and the same reasoning the global list endpoint already carried: the
operator's next step is to authenticate with it, and a credential they cannot
read is a credential they cannot use. Both endpoints are authenticated. The UI
masks it behind a reveal toggle so it does not land in a screenshot by accident,
but the value is there to be copied.

ONE COPY, NOT TWO
-----------------
The backfill lifts the secret out of `metadata` and REMOVES the key, so it is not
stored in two places. A secret duplicated is one more copy to leak and two places
to keep in sync.

SABOTAGE PROOF
--------------
Remove `secret_value` from the INSERT column list in `create_credential` and
`test_writer_populates_the_column` fails. Remove it from the
`/assets/{ip}/credentials` SELECT and `test_per_asset_endpoint_returns_it` fails.
Delete the `<SecretValue` usage from AssetBrowser.tsx and `test_ui_renders_it`
fails — all three without needing the stack.
"""
import ast
import os
import re

import pytest

from _container import container_exec

REPO = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))
API = os.path.join(REPO, "app", "rag-api", "api.py")
SCHEMA = os.path.join(REPO, "db_init", "ensure_all_tables.sql")
UI = os.path.join(REPO, "dashboard", "frontend", "src", "pages", "AssetBrowser.tsx")
CLIENT = os.path.join(REPO, "dashboard", "frontend", "src", "api", "assets.ts")


def _read(path):
    if not os.path.exists(path):
        pytest.skip(f"{path} not present")
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _func_source(src, name):
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    return ""


# ── 1. The writer ──────────────────────────────────────────────────────────

def test_writer_populates_the_column(api_src=None):
    src = api_src or _read(API)
    fn = _func_source(src, "create_credential")
    assert fn, "create_credential() is gone"
    insert = fn[fn.index("INSERT INTO credential_findings"):]
    cols = insert[insert.index("("):insert.index(")")]
    assert "secret_value" in cols, (
        "secret_value is not in the INSERT column list — the column will be NULL "
        "on every credential this endpoint creates, and the credential bridge "
        "(which SELECTs cf.secret_value) will never see it")


def test_writer_does_not_also_stuff_it_into_metadata():
    """One copy. A secret in two places is two places to leak it from."""
    fn = _func_source(_read(API), "create_credential")
    assert 'metadata["secret_value"]' not in fn, (
        "the secret is being written to metadata as well as the column")


# ── 2. The reader ──────────────────────────────────────────────────────────

def test_per_asset_endpoint_returns_it():
    """The drill-down panel calls THIS endpoint, not the global list."""
    fn = _func_source(_read(API), "get_asset_credentials")
    assert fn, "get_asset_credentials() is gone"
    assert "secret_value" in fn, (
        "GET /assets/{ip}/credentials does not select secret_value, so the "
        "Assets > Credentials panel gets an account with no secret")


def test_global_list_endpoint_still_returns_it():
    """It always did; this keeps the two read paths from drifting apart again."""
    src = _read(API)
    i = src.index("FROM credential_findings\n            {where}")
    assert "secret_value" in src[i - 600:i], (
        "the global credentials list stopped returning secret_value")


# ── 3. The UI ──────────────────────────────────────────────────────────────

def test_ui_renders_it():
    src = _read(UI)
    assert "function SecretValue(" in src, "the SecretValue component is gone"
    assert "<SecretValue" in src, "SecretValue is defined but never rendered"


def test_ui_masks_by_default():
    """This panel is on screen during screen-shares and report writing."""
    src = _read(UI)
    comp = src[src.index("function SecretValue("):]
    comp = comp[:comp.index("\nfunction ")]
    assert "useState(false)" in comp, (
        "the secret is no longer hidden by default — key material would render "
        "into any screenshot of this page")
    assert "Reveal" in comp and "Copy" in comp, (
        "the reveal and copy controls are gone; a masked value with no way to "
        "read or copy it is worse than not showing it")


def test_ui_falls_back_to_metadata_for_legacy_rows():
    """An install that has not run the backfill still has the value in metadata."""
    src = _read(UI)
    assert "metadata?.secret_value" in src, (
        "the metadata fallback is gone; rows written before the writer was fixed "
        "would silently show 'not captured'")


def test_client_type_declares_it():
    src = _read(CLIENT)
    assert re.search(r"secret_value:\s*string \| null", src), (
        "CredentialFinding.secret_value is missing from the type")


# ── 4. The backfill ────────────────────────────────────────────────────────

def test_schema_backfills_and_removes_the_duplicate():
    src = _read(SCHEMA)
    assert "UPDATE public.credential_findings" in src, (
        "the secret_value backfill is gone; historical rows stay invisible")
    assert "metadata - 'secret_value'" in src, (
        "the backfill no longer removes the metadata copy, leaving the secret "
        "stored in two places")


# ── Live ───────────────────────────────────────────────────────────────────

_LIVE = r"""
import json, os, urllib3, requests, psycopg2
urllib3.disable_warnings()
H = {"x-api-key": os.environ.get("API_KEY", "changeme")}
c = psycopg2.connect(os.environ["DB_DSN"]); c.autocommit = True
cur = c.cursor()
res = {}
IP = "192.0.2.61"           # RFC 5737 TEST-NET-1, never a live host
SECRET = "pytest-secret-value-do-not-use"
try:
    # Round-trip through the real endpoint, not a hand-written INSERT.
    r = requests.post("https://localhost:8000/credentials",
                      params={"ip": IP, "port": 22, "protocol": "ssh",
                              "username": "pytest-cred", "secret_value": SECRET,
                              "secret_type": "password", "source": "pytest"},
                      headers=H, verify=False, timeout=30)
    res["create_status"] = r.status_code

    cur.execute("SELECT secret_value, metadata ? 'secret_value' "
                "FROM credential_findings WHERE host(ip)::text=%s", (IP,))
    row = cur.fetchone()
    res["column_matches"] = bool(row) and row[0] == SECRET
    res["also_in_metadata"] = bool(row) and row[1]

    g = requests.get(f"https://localhost:8000/assets/{IP}/credentials",
                     headers=H, verify=False, timeout=30)
    res["get_status"] = g.status_code
    creds = g.json().get("credentials", []) if g.ok else []
    res["endpoint_returns_secret"] = any(x.get("secret_value") == SECRET for x in creds)
finally:
    cur.execute("DELETE FROM credential_findings WHERE host(ip)::text=%s", (IP,))
    cur.execute("DELETE FROM credential_findings WHERE source='pytest'")
print(json.dumps(res))
"""


@pytest.fixture(scope="module")
def live():
    out = container_exec(_LIVE, timeout=180)
    if out is None:
        pytest.skip("rag-api container unreachable")
    if out.startswith("__ERR__"):
        pytest.fail(f"credential round-trip failed: {out}")
    import json
    return json.loads(out.strip().splitlines()[-1])


def test_round_trip_stores_the_secret_in_the_column(live):
    assert live["create_status"] < 400, f"POST /credentials -> {live['create_status']}"
    assert live["column_matches"] is True, (
        "the secret did not land in the secret_value column")


def test_round_trip_does_not_duplicate_into_metadata(live):
    assert live["also_in_metadata"] is False, (
        "the secret is stored in metadata as well as the column")


def test_round_trip_is_readable_through_the_panel_endpoint(live):
    assert live["get_status"] == 200
    assert live["endpoint_returns_secret"] is True, (
        "GET /assets/{ip}/credentials did not return the secret the operator "
        "needs in order to use the credential")
