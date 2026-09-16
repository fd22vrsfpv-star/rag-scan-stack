"""Held access is mirrored into the findings model with a severity.

A root shell was recorded in obtained_access but never became a finding, so the
findings-driven severity view and reports showed zero criticals while we held
root. `etl.access._sync_access_findings` closes that: a live root shell becomes a
CRITICAL vuln, a service credential a HIGH/MEDIUM one, and the finding resolves
when the access goes dead.

Sets up an asset + obtained_access rows directly (no target traffic — this
exercises the DB->findings mirror, not probing) and asserts the finding. Skips
cleanly without a DB or the etl package.

    DB_DSN=... pytest tests/test_access_finding_bridge.py
"""
import os
import uuid

import pytest

psycopg2 = pytest.importorskip("psycopg2")
access = pytest.importorskip("etl.access")

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")


def _conn():
    try:
        c = psycopg2.connect(DB_DSN, connect_timeout=5)
        c.autocommit = True
        return c
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"DB unreachable: {type(e).__name__}")


@pytest.fixture
def target_with_access():
    conn = _conn()
    cur = conn.cursor()
    ip = f"203.0.113.{uuid.uuid4().int % 250 + 1}"      # TEST-NET-3
    aid = None
    try:
        cur.execute("INSERT INTO public.assets (ip) VALUES (%s::inet) RETURNING id", (ip,))
        aid = cur.fetchone()[0]
        cur.execute("INSERT INTO public.ports (asset_id, proto, port, service) "
                    "VALUES (%s,'tcp',1524,'bindshell')", (aid,))
        # A LIVE root bind shell — the highest-impact access there is.
        cur.execute(
            """INSERT INTO public.obtained_access
                 (target, port, kind, handle, transport, whoami, uid, is_root,
                  probes, probes_ok, score, status)
               VALUES (%s,1524,'bind_shell',%s,'raw','root',0,true,3,3,100,'live')""",
            (ip, f"root@{ip}:1524"))
        yield {"ip": ip, "aid": aid}
    finally:
        try:
            cur.execute("DELETE FROM public.vulns WHERE asset_id = %s", (aid,))
            cur.execute("DELETE FROM public.obtained_access WHERE target = %s", (ip,))
            cur.execute("DELETE FROM public.assets WHERE id = %s", (aid,))
        except Exception:
            pass
        cur.close(); conn.close()


def _finding(ip):
    conn = _conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT severity, title, workflow_status FROM public.vulns "
            "WHERE metadata->>'source' = 'access_bridge' "
            "  AND fingerprint = md5('access|' || %s || '|bind_shell|root@' || %s || ':1524')",
            (ip, ip))
        return cur.fetchone()
    finally:
        conn.close()


def test_live_root_shell_becomes_a_critical_finding(target_with_access):
    ip = target_with_access["ip"]
    conn = _conn()
    cur = conn.cursor()
    n = access._sync_access_findings(cur, ip, None)
    cur.close(); conn.close()
    assert n >= 1, "no access findings synced"

    f = _finding(ip)
    assert f is not None, "root shell did not become a finding"
    assert f[0] == "critical", f"root shell severity should be critical, got {f[0]}"
    assert "ROOT" in f[1].upper()
    assert f[2] != "resolved"


def test_dead_access_resolves_the_finding(target_with_access):
    ip = target_with_access["ip"]
    conn = _conn()
    cur = conn.cursor()
    access._sync_access_findings(cur, ip, None)      # create it
    conn.commit()
    # Access goes dead; re-sync must resolve, not leave a phantom critical.
    cur.execute("UPDATE public.obtained_access SET status = 'dead' WHERE target = %s", (ip,))
    conn.commit()
    access._sync_access_findings(cur, ip, None)
    conn.commit()
    cur.close(); conn.close()

    f = _finding(ip)
    assert f is not None
    assert f[2] == "resolved", f"dead access finding should be resolved, got {f[2]}"


def test_severity_mapping():
    # Unit: no DB. Root -> critical, shell -> high, ssh cred -> high, other -> medium.
    sev, _ = access._access_severity_title({"kind": "bind_shell", "is_root": True, "target": "t"})
    assert sev == "critical"
    sev, _ = access._access_severity_title({"kind": "bind_shell", "is_root": False, "target": "t"})
    assert sev == "high"
    sev, _ = access._access_severity_title({"kind": "ssh_credential", "target": "t", "whoami": "u"})
    assert sev == "high"
    sev, _ = access._access_severity_title({"kind": "credential", "transport": "postgres", "target": "t"})
    assert sev == "medium"
