"""What to try on a port the default bind-shell probe could not reach.

WHY THIS EXISTS
---------------
The access probe opens a TCP socket and sends `id`; that only speaks to a raw
bind shell. Every other service — an FTP with a backdoor that needs a trigger,
an rsh with its own wire protocol, an RPC program behind rpcbind, a web server —
comes back "dead" to that probe even when there is a real way in. The way in is
just not the default one. Enumeration then stalls on the default and the
non-default option nobody surfaced.

This reads the DEAD access on a target, joins each dead port to what nmap
identified it as, and looks up the non-default method for that service in
`knowledge/service_access_methods.yaml`. It answers "this port is dead to the
probe — is there a path in, and what is it?" with data an operator can act on.

It is advice, not action. It runs nothing and opens nothing; it says what WOULD
work, the same contract as tool_options.yaml. Whether a method actually works
here stays measured elsewhere.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

log = logging.getLogger("dead_port_advisor")

_REPO_YAML = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "knowledge", "service_access_methods.yaml")
METHODS_YAML = os.environ.get("SERVICE_ACCESS_METHODS_YAML",
                              "/knowledge/service_access_methods.yaml")


def _connect():
    import psycopg2
    return psycopg2.connect(
        os.environ.get("DB_DSN") or os.environ.get("DATABASE_URL")
        or "postgresql://app:app@rag-postgres:5432/scans", connect_timeout=5)


def load_methods() -> List[Dict[str, Any]]:
    """The method catalogue, or empty if unreadable. Empty is the safe
    direction and it is logged: no methods means no advice, never wrong advice."""
    for candidate in (METHODS_YAML, _REPO_YAML):
        if not candidate or not os.path.exists(candidate):
            continue
        try:
            import yaml
            with open(candidate, encoding="utf-8") as fh:
                return (yaml.safe_load(fh) or {}).get("methods") or []
        except Exception as e:  # noqa: BLE001
            log.warning("service access methods %s unreadable: %s", candidate, e)
            return []
    log.warning("no service access methods found (looked in %s, %s)",
                METHODS_YAML, _REPO_YAML)
    return []


def match_method(methods: List[Dict[str, Any]], *, service: str = "",
                 product: str = "", version: str = "") -> Optional[Dict[str, Any]]:
    """Best method for a (service, product, version). Most specific wins:
    a product+version match beats a product match beats a service-only match, so
    a generic 'http' entry never shadows a precise 'vsftpd 2.3.4' one."""
    service = (service or "").strip().lower()
    product = (product or "").strip().lower()
    version = (version or "").strip()
    best, best_score = None, -1
    for m in methods:
        score = 0
        msvc = (m.get("service") or "").strip().lower()
        mprod = (m.get("product") or "").strip().lower()
        mver = m.get("version") or ""
        if msvc:
            if msvc != service:
                continue
            score += 1
        if mprod:
            if mprod not in product:
                continue
            score += 2
        if mver:
            if not (product or version) or not re.search(mver, version or product):
                continue
            score += 4
        if not (msvc or mprod):
            continue  # an entry that matches nothing specific is ignored
        if score > best_score:
            best, best_score = m, score
    return best


def advise(target: str, *, persist: bool = True) -> List[Dict[str, Any]]:
    """Advice for every DEAD non-ssh access on this target.

    A dead ssh_credential is a wrong password, not a service needing a different
    method, so only bind_shell / listener rows are advised. Each is joined to the
    port's identified service and matched against the catalogue. Ports with no
    matching method are still returned (method=None) — "we don't have a
    non-default method for this" is an honest, actionable answer, not silence.
    """
    methods = load_methods()
    out: List[Dict[str, Any]] = []
    conn = None
    try:
        conn = _connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT oa.port, oa.last_error,
                       COALESCE(p.service,''), COALESCE(p.product,''),
                       COALESCE(p.version,'')
                  FROM public.obtained_access oa
                  LEFT JOIN public.assets a ON host(a.ip) = oa.target
                  LEFT JOIN public.ports p
                         ON p.asset_id = a.id AND p.port = oa.port
                            AND LOWER(COALESCE(p.proto,'tcp')) = 'tcp'
                 WHERE oa.target = %s AND oa.status = 'dead'
                   AND oa.kind IN ('bind_shell', 'listener_callback')
                 ORDER BY oa.port
                """, (target,))
            rows = cur.fetchall()
        for port, last_error, service, product, version in rows:
            m = match_method(methods, service=service, product=product,
                             version=version)
            out.append({
                "target": target, "port": port,
                "service": service or None, "product": product or None,
                "version": version or None,
                "probe_error": (last_error or "").strip() or None,
                "method_id": (m or {}).get("id"),
                "method": (m or {}).get("method"),
                "summary": (m or {}).get("summary"),
                "steps": list((m or {}).get("steps") or []),
                "tool": (m or {}).get("tool"),
                "opens": (m or {}).get("opens"),
                "caution": (m or {}).get("caution"),
            })
        if persist and out:
            _persist(conn, out)
    except Exception as e:  # noqa: BLE001
        log.warning("dead-port advice failed for %s: %s", target, e)
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
    return out


def _persist(conn, advice: List[Dict[str, Any]]) -> None:
    """Upsert one row per (target, port). Best-effort — advice is a convenience
    surface, and a persistence failure must never break the caller that asked
    for it. A separate try so a missing table on an un-migrated DB is survivable.
    """
    try:
        with conn, conn.cursor() as cur:
            for a in advice:
                cur.execute(
                    """
                    INSERT INTO public.port_access_advice
                      (target, port, service, product, version, probe_error,
                       method_id, method, summary, steps, tool, opens, caution,
                       first_seen, last_seen)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::text[],%s,%s,%s,
                            now(), now())
                    ON CONFLICT (target, port) DO UPDATE SET
                      service = EXCLUDED.service, product = EXCLUDED.product,
                      version = EXCLUDED.version, probe_error = EXCLUDED.probe_error,
                      method_id = EXCLUDED.method_id, method = EXCLUDED.method,
                      summary = EXCLUDED.summary, steps = EXCLUDED.steps,
                      tool = EXCLUDED.tool, opens = EXCLUDED.opens,
                      caution = EXCLUDED.caution, last_seen = now()
                    """,
                    (a["target"], a["port"], a["service"], a["product"],
                     a["version"], a["probe_error"], a["method_id"], a["method"],
                     a["summary"], a["steps"], a["tool"], a["opens"],
                     a["caution"]))
    except Exception as e:  # noqa: BLE001
        log.warning("dead-port advice persist failed: %s", e)
