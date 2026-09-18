"""A successful httpx fingerprint asserts the port is OPEN, overriding a prior
closed/filtered result (common when a network scan is proxy-routed and can't
reach the host while the web scan went direct — the reason demo.testfire.net's
80/443 were is_open=false despite serving HTTP)."""
import os, re
import pytest
REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def test_parse_httpx_upserts_open():
    src = open(os.path.join(REPO, "etl", "parse_httpx.py"), encoding="utf-8").read()
    assert "ON CONFLICT (asset_id, proto, port) DO UPDATE SET" in src
    m = re.search(r"ON CONFLICT \(asset_id, proto, port\) DO UPDATE SET[\s\S]{0,160}", src)
    assert m and "is_open = true" in m.group(0), "httpx must assert is_open=true on conflict"

def test_live_upsert_flips_closed_to_open():
    psycopg2 = pytest.importorskip("psycopg2")
    dsn = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")
    try:
        c = psycopg2.connect(dsn, connect_timeout=5)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"DB unreachable: {type(e).__name__}")
    try:
        cur = c.cursor()
        cur.execute("SELECT to_regclass('public.assets'), to_regclass('public.ports')")
        if not all(cur.fetchone()):
            pytest.skip("schema not present")
        cur.execute("BEGIN")
        cur.execute("INSERT INTO assets (id, ip) VALUES (gen_random_uuid(),'203.0.113.200'::inet) RETURNING id")
        aid = cur.fetchone()[0]
        # a prior scan recorded the port CLOSED
        cur.execute("INSERT INTO ports (id, asset_id, proto, port, service, is_open) "
                    "VALUES (gen_random_uuid(),%s,'tcp',443,'https',false)", (aid,))
        # httpx's upsert asserts open
        cur.execute("""INSERT INTO ports (id, asset_id, proto, port, service, product, is_open)
                       VALUES (gen_random_uuid(), %s, 'tcp', 443, 'https', 'Apache-Coyote/1.1', true)
                       ON CONFLICT (asset_id, proto, port) DO UPDATE SET
                         is_open = true, service = EXCLUDED.service,
                         product = COALESCE(EXCLUDED.product, ports.product), last_seen = now()""", (aid,))
        cur.execute("SELECT is_open, product FROM ports WHERE asset_id=%s AND port=443", (aid,))
        row = cur.fetchone()
        assert row[0] is True and row[1] == 'Apache-Coyote/1.1'
    finally:
        c.rollback(); c.close()
