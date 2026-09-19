"""Default-credential check on discovered login forms.

When a login form is discovered (content_extractions.login_pages, or a login
web_finding), this STANDARD followup tries a small set of DOCUMENTED default
credentials against it and reports any that work — closing the "default admin
password on the app login" class a link-only crawl never tests. On success it
records the working credential and auto-populates an Auth Profile (the on-ramp to
authenticated scanning).

THE SETTING (knowledge/default_cred_check.yaml::max_auto_attempts, env override
DEFAULT_CRED_MAX_AUTO_ATTEMPTS): if the candidate-pair count is AT OR BELOW it,
the check auto-fires on the safe lane; ABOVE it, the check is queued for operator
APPROVAL instead (a large spray never fires unattended). A hard max_total_attempts
caps the set even when approved — never a full brute force.

Login POSTs run via the listener's /vectors/run (POST-capable, scope-gated,
proxy-enforced) — the same lane the impactful deepen uses; the GET page-fetch runs
on the read-only /tools/execute lane. Lockout-aware: stops early on repeated
anomalies.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, quote

log = logging.getLogger("default_cred_check")

KALI_LISTENER_URL = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")
RAG_API_URL = os.environ.get("RAG_API_URL", "https://localhost:8000")
API_KEY = os.environ.get("API_KEY", "")

_DEFAULTS = {
    "max_auto_attempts": 24,
    "max_total_attempts": 120,
    "app_login": [{"username": "admin", "password": "admin"}],
    "success": {"login_path_markers": ["login", "signin", "logon", "error", "denied", "invalid"]},
    "skip_csrf": True,
    "priority": 26,
    "followup_tag": "default_cred_check",
}


def _kn_path(name: str) -> Optional[str]:
    for p in (f"/knowledge/{name}",
              os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "knowledge", name)):
        if os.path.exists(p):
            return p
    return None


def load_cfg() -> Dict[str, Any]:
    p = _kn_path("default_cred_check.yaml")
    cfg = dict(_DEFAULTS)
    if p:
        try:
            import yaml
            d = (yaml.safe_load(open(p, encoding="utf-8")) or {}).get("default_cred_check") or {}
            cfg.update({k: v for k, v in d.items() if v is not None})
        except Exception as e:  # noqa: BLE001
            log.debug("default_cred_check.yaml load failed: %s", e)
    env = os.environ.get("DEFAULT_CRED_MAX_AUTO_ATTEMPTS")
    if env and env.isdigit():
        cfg["max_auto_attempts"] = int(env)
    return cfg


def _zap_crawl_settings(cur, cfg: Dict[str, Any]) -> Dict[str, int]:
    """Authenticated-crawl tuning, resolved as: ZAP settings (app_settings
    zap.auth_crawl.*) > YAML authenticated_rescan > tuned defaults. These are the
    knobs surfaced in the dashboard's ZAP settings so an operator can widen the
    authenticated crawl (more pages / deeper) to seed ZAP's whole logged-in tree."""
    rc = cfg.get("authenticated_rescan") or {}
    out = {"max_pages": int(rc.get("max_pages", 200)),
           "max_depth": int(rc.get("max_depth", 5)),
           "wait_seconds": int(rc.get("crawl_wait_seconds", 300))}
    keymap = {"max_pages": "zap.auth_crawl.max_pages",
              "max_depth": "zap.auth_crawl.max_depth",
              "wait_seconds": "zap.auth_crawl.wait_seconds"}
    try:
        cur.execute("SELECT key, value FROM app_settings WHERE key = ANY(%s) AND category='config'",
                    (list(keymap.values()),))
        got = {k: v for k, v in cur.fetchall()}
        for k, dbk in keymap.items():
            v = got.get(dbk)
            if v is not None and str(v).strip().isdigit():
                out[k] = int(v)
    except Exception:  # noqa: BLE001
        try:
            cur.connection.rollback()
        except Exception:  # noqa: BLE001
            pass
    out["max_pages"] = max(1, min(out["max_pages"], 1000))
    out["max_depth"] = max(1, min(out["max_depth"], 5))
    out["wait_seconds"] = max(30, min(out["wait_seconds"], 1800))
    # Ajax spider OFF by default (memory-heavy; redundant after the authenticated
    # crawl). Optional via ZAP setting zap.ajax_spider.
    out["ajax_spider"] = 0
    # Active-scan chunking ON by default (batch size 10) so ZAP flushes its message
    # store to disk between batches and peak memory stays bounded regardless of site
    # size. Set zap.active_scan_chunk_size=0 for the whole-tree scan.
    out["active_scan_chunk_size"] = 10
    try:
        cur.execute("""SELECT key, value FROM app_settings
                        WHERE key IN ('zap.ajax_spider','zap.active_scan_chunk_size')
                          AND category='config'""")
        got = {k: v for k, v in cur.fetchall()}
        if str(got.get("zap.ajax_spider", "")).strip().lower() in ("1", "true", "yes", "on"):
            out["ajax_spider"] = 1
        cs = got.get("zap.active_scan_chunk_size")
        if cs is not None and str(cs).strip().lstrip("-").isdigit():
            out["active_scan_chunk_size"] = max(0, min(int(cs), 500))
    except Exception:  # noqa: BLE001
        try:
            cur.connection.rollback()
        except Exception:  # noqa: BLE001
            pass
    return out


def _load_default_credentials() -> Dict[str, Any]:
    p = _kn_path("default_credentials.yaml")
    if not p:
        return {}
    try:
        import yaml
        return yaml.safe_load(open(p, encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return {}


def candidate_pairs(port: Optional[int], cfg: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Documented default (user, pass) pairs: the service-for-the-port + the
    global `common` set + the app_login extras + username_as_password. Deduped and
    hard-capped by max_total_attempts. Small and documented — NOT a brute force."""
    dc = _load_default_credentials()
    users: List[str] = []
    passwords: List[str] = []
    common = dc.get("common") or {}
    users += list(common.get("usernames") or [])
    passwords += list(common.get("passwords") or [])
    # service whose default port list contains this port
    for svc in (dc.get("services") or {}).values():
        if isinstance(svc, dict) and port and port in (svc.get("ports") or []):
            users += list(svc.get("usernames") or [])
            passwords += list(svc.get("passwords") or [])
    users = list(dict.fromkeys(u for u in users if u))
    passwords = list(dict.fromkeys(p for p in passwords))

    pairs: List[Tuple[str, str]] = []
    # explicit app_login pairs first (highest-value, e.g. admin:admin)
    for e in (cfg.get("app_login") or []):
        if isinstance(e, dict) and e.get("username") is not None and e.get("password") is not None:
            pairs.append((str(e["username"]), str(e["password"])))
    if dc.get("username_as_password"):
        pairs += [(u, u) for u in users]
    # then the cross of common/service users x passwords
    for u in users:
        for pw in passwords:
            pairs.append((u, pw))
    # dedupe, drop pairs with shell-hostile chars (defaults never have them), cap
    seen, out = set(), []
    for u, pw in pairs:
        if "'" in u or "'" in pw or "\n" in u or "\n" in pw:
            continue
        k = (u, pw)
        if k in seen:
            continue
        seen.add(k)
        out.append(k)
    return out[: int(cfg.get("max_total_attempts", 120))]


def _research_host_default_creds(cur, host: str, html: str) -> List[Tuple[str, str]]:
    """Web+LLM research of default creds for THIS host's apps, so candidates are
    DISCOVERED, not hardcoded. Research terms: the login page <title> (the app
    fingerprint, e.g. 'Altoro Mutual') + the host's detected_software products
    (tomcat, apache, wordpress...). Calls rag-api /software/default-credentials
    (DuckDuckGo + LLM, proxy-configurable), which also stores the pairs as
    UNVALIDATED accounts. Also folds in any previously-stored researched
    candidates for the host. Best-effort -> [] on any failure."""
    import re as _re
    terms: List[str] = []
    m = _re.search(r"<title[^>]*>(.*?)</title>", html or "", _re.I | _re.S)
    if m:
        t = _re.sub(r"\s+", " ", _re.sub(r"<[^>]+>", "", m.group(1))).strip()
        if 2 <= len(t) <= 60:
            terms.append(t)
    try:
        # detected_software is a VIEW whose `ip` is already text (host(a.ip)::text),
        # so match on ip directly — host(ip) would error and abort the transaction.
        cur.execute("""SELECT DISTINCT product FROM detected_software
                        WHERE ip = %s AND product IS NOT NULL AND product <> '' LIMIT 5""",
                    (host,))
        terms += [r[0] for r in cur.fetchall() if r[0]]
    except Exception:  # noqa: BLE001
        try:
            cur.connection.rollback()
        except Exception:  # noqa: BLE001
            pass
    seen_terms, pairs = set(), []
    import httpx
    for term in terms[:4]:
        tl = term.strip().lower()
        if not tl or tl in seen_terms:
            continue
        seen_terms.add(tl)
        try:
            with httpx.Client(verify=False, timeout=45) as cli:
                r = cli.post(f"{RAG_API_URL.rstrip('/')}/software/default-credentials",
                             json={"product": term}, headers={"x-api-key": API_KEY})
                if r.status_code < 400:
                    for p in (r.json().get("pairs") or []):
                        u, pw = str(p.get("username", "")), str(p.get("password", ""))
                        if u:
                            pairs.append((u, pw))
        except Exception as e:  # noqa: BLE001
            log.debug("default-cred research for %r failed: %s", term, e)
    # previously-stored researched candidates for this host
    try:
        # Reuse creds already discovered for this host: web-researched candidates
        # (unvalidated) AND ones a prior check already validated — both are the
        # best things to try on this login. Validated first.
        cur.execute("""SELECT DISTINCT username, secret_value, valid_cred FROM credential_findings
                        WHERE host(ip)=%s
                          AND source IN ('default_cred_research','default_cred_check')
                          AND username IS NOT NULL AND secret_value IS NOT NULL
                        ORDER BY valid_cred DESC NULLS LAST""", (host,))
        pairs += [(u, pw) for u, pw, _v in cur.fetchall() if u]
    except Exception:  # noqa: BLE001
        try:
            cur.connection.rollback()
        except Exception:  # noqa: BLE001
            pass
    return list(dict.fromkeys(pairs))


def _run_tool(tool: str, command: str, host: str, port: int, *, lane: str,
              timeout: int = 30) -> str:
    """Dispatch via the listener and return stdout. lane='safe' -> /tools/execute
    (read-only GET); lane='vectors' -> /vectors/run (POST-capable, needs key)."""
    import time
    import httpx
    timeout = max(30, int(timeout))  # /tools/execute requires timeout >= 30
    try:
        with httpx.Client(verify=False, timeout=timeout + 10) as cli:
            if lane == "vectors":
                r = cli.post(f"{KALI_LISTENER_URL.rstrip('/')}/vectors/run",
                             json={"command": command, "target": host, "port": port,
                                   "timeout": timeout},
                             headers={"x-api-key": API_KEY})
                if r.status_code >= 400:
                    return f"__REFUSED__ {r.status_code} {r.text[:120]}"
                return r.json().get("output", "") or ""
            r = cli.post(f"{KALI_LISTENER_URL.rstrip('/')}/tools/execute",
                         json={"tool": tool, "command": command, "target": host,
                               "service": "default_cred_check", "port": port,
                               "timeout": timeout})
            if r.status_code >= 400:
                return f"__REFUSED__ {r.status_code} {r.text[:120]}"
            eid = r.json().get("id")
            for _ in range(12):
                time.sleep(2)
                d = cli.get(f"{KALI_LISTENER_URL.rstrip('/')}/tools/executions/{eid}").json()
                if d.get("status") in ("completed", "failed"):
                    return d.get("output") or ""
            return ""
    except Exception as e:  # noqa: BLE001
        return f"__ERROR__ {e}"


def _parse_response(out: str) -> Dict[str, Any]:
    """From a `curl -s -i` dump: status code, Location header, Set-Cookie names."""
    codes = re.findall(r"HTTP/\d(?:\.\d)?\s+(\d{3})", out)
    loc = re.search(r"(?im)^location:\s*(.+?)\s*$", out)
    cookies = re.findall(r"(?im)^set-cookie:\s*([^=]+)=", out)
    return {"status": int(codes[-1]) if codes else None,
            "location": (loc.group(1).strip() if loc else ""),
            "cookies": {c.strip().lower() for c in cookies}}


def _login_command(login_url: str, form: Dict[str, Any], user: str, pw: str) -> str:
    parts = [f"--data-urlencode '{form['user_field']}={user}'",
             f"--data-urlencode '{form['pass_field']}={pw}'"]
    for k, v in (form.get("extras") or {}).items():
        parts.append(f"--data-urlencode '{k}={v}'")
    return f"curl -s -i -m 15 -X POST {' '.join(parts)} '{login_url}'"


def _is_success(resp: Dict[str, Any], baseline: Dict[str, Any], markers: List[str]) -> bool:
    """A working login differs from the known-bad baseline: it redirects somewhere
    that is NOT a login/error page, or sets an auth cookie the baseline did not."""
    loc = (resp.get("location") or "").lower()
    if loc and not any(m in loc for m in markers):
        if loc != (baseline.get("location") or "").lower():
            return True
    new_cookies = resp.get("cookies", set()) - baseline.get("cookies", set())
    if new_cookies:
        return True
    return False


def run_default_cred_check(cur, host: str, login_page_url: str, *,
                           asset_id: Optional[str] = None,
                           engagement_id: Optional[str] = None,
                           scope_rows=None, aliases=None,
                           force: bool = False) -> Dict[str, Any]:
    """Try documented default creds against a discovered login form. Honors the
    max_auto_attempts SETTING: at/below it auto-fires; above it queues for approval
    (unless force=True, the approval path). On success records the credential + a
    High web_finding and auto-populates an Auth Profile. Returns a result dict."""
    from psycopg2.extras import Json
    out: Dict[str, Any] = {"ok": False, "host": host, "login_page": login_page_url}
    cfg = load_cfg()
    pu = urlparse(login_page_url)
    port = pu.port or (443 if pu.scheme == "https" else 80)

    # scope gate (fail-closed)
    if scope_rows is not None:
        try:
            from etl.scope_gate import check_dispatch
        except ImportError:  # pragma: no cover
            from scope_gate import check_dispatch
        refusal = check_dispatch(str(host), scope_rows, command=f"curl {login_page_url}", aliases=aliases)
        if refusal:
            out["reason"] = f"out of scope: {refusal}"
            return out

    # 1) fetch the login page (read-only lane) and parse the form
    html = _run_tool("curl", f"curl -s -m 15 '{login_page_url}'", host, port, lane="safe")
    if html.startswith(("__REFUSED__", "__ERROR__")):
        out["reason"] = f"could not fetch login page: {html[:120]}"
        return out
    try:
        import auth_autopopulate as ap
    except ImportError:  # pragma: no cover
        try:
            from app.rag_api import auth_autopopulate as ap  # type: ignore
        except Exception:
            out["reason"] = "auth_autopopulate unavailable"
            return out
    form = ap.parse_login_form(html)
    if not form:
        out["reason"] = "no login form found on page"
        return out
    if form.get("csrf_field") and cfg.get("skip_csrf", True):
        out.update({"ok": True, "skipped": "csrf",
                    "reason": "login form is CSRF-protected — left for manual review"})
        return out
    login_url = urljoin(login_page_url, form.get("action") or "") or login_page_url

    # 2) candidate set. The SETTING caps how many are submitted UNATTENDED: the
    # auto run tries the top `max_auto_attempts` (highest-value first, so admin:admin
    # is always tried); if none work and the full set is larger, the fuller spray is
    # queued for operator APPROVAL. force=True (the approval path) runs the full set.
    # DISCOVERED candidates first (web+LLM research of this app's default creds —
    # e.g. jsmith:demo1234 for 'Altoro Mutual'), then the static documented set.
    researched = _research_host_default_creds(cur, host, html) if cfg.get("research_defaults", True) else []
    out["researched_candidates"] = len(researched)
    pairs = list(dict.fromkeys(researched + candidate_pairs(port, cfg)))
    out["candidates"] = len(pairs)
    threshold = int(cfg.get("max_auto_attempts", 24))
    run_set = pairs if force else pairs[:threshold]

    # 3) run the bounded spray
    markers = (cfg.get("success") or {}).get("login_path_markers") or []
    base_cmd = _login_command(login_url, form, "zz_baseline_no_such_user", "zz_bad_pw_123")
    baseline = _parse_response(_run_tool("curl", base_cmd, host, port, lane="vectors"))
    found = None
    anomalies = 0
    attempted = 0
    for user, pw in run_set:
        attempted += 1
        resp_raw = _run_tool("curl", _login_command(login_url, form, user, pw), host, port, lane="vectors")
        if resp_raw.startswith("__REFUSED__"):
            out["reason"] = f"login POST refused: {resp_raw[:120]}"
            return out
        if resp_raw.startswith("__ERROR__"):
            anomalies += 1
            if anomalies >= 3:  # lockout / connectivity guard: stop early
                out["reason"] = "stopped after repeated errors (possible lockout/connectivity)"
                break
            continue
        if _is_success(_parse_response(resp_raw), baseline, markers):
            found = {"username": user, "password": pw}
            break
    out["attempted"] = attempted

    if not found:
        # none of the auto set worked; if more candidates exist, queue the fuller
        # spray for approval (never auto-submit more than the setting).
        if not force and len(pairs) > threshold:
            cur.execute(
                """INSERT INTO scan_recommendations
                     (ip, service, scanner, action, script, source, priority,
                      status, engagement_id, extra)
                   VALUES (%s,'http',%s,%s,%s,'default_cred_check',%s,'pending',%s,%s)
                   ON CONFLICT (fingerprint) DO NOTHING RETURNING id::text""",
                (host, cfg.get("followup_tag", "default_cred_check"),
                 f"full default-cred spray ({len(pairs)} pairs) @ {login_url}",
                 f"default-cred check @ {login_url}", int(cfg.get("priority", 26)),
                 engagement_id,
                 Json({"followup": True, "followup_type": "default_cred_check",
                       "login_url": login_url, "candidate_count": len(pairs),
                       "auto_tried": threshold, "requires_approval": True,
                       "reason": f"top {threshold} defaults tried (none worked); full spray ({len(pairs)}) needs approval",
                       "queued_by": "enum:default_cred_check"})))
            row = cur.fetchone()
            out.update({"ok": True, "valid": False, "login_url": login_url,
                        "requires_approval": True, "queued": 1 if row else 0,
                        "recommendation_id": row[0] if row else None,
                        "reason": f"top {threshold} defaults tried; full spray ({len(pairs)}) queued for approval"})
            return out
        out.update({"ok": True, "valid": False, "login_url": login_url})
        return out

    # 4) record the working credential + a High finding, then auto-populate a profile
    out.update({"ok": True, "valid": True, "username": found["username"],
                "login_url": login_url})
    cred_id = None
    try:
        cur.execute(
            """INSERT INTO credential_findings
                 (asset_id, ip, port, protocol, username, secret_value, secret_type,
                  valid_cred, auth_type, severity, source, status, engagement_id, metadata)
               VALUES (%s,%s,%s,'http',%s,%s,'password',true,'form','high',
                       'default_cred_check','valid',%s,%s)
               RETURNING id::text""",
            (asset_id, host, port, found["username"], found["password"],
             engagement_id, Json({"login_url": login_url, "via": "default_cred_check"})))
        r = cur.fetchone()
        cred_id = r[0] if r else None
        # on dedup conflict the insert returns nothing — fetch the existing id
        if not cred_id:
            cur.execute("""SELECT id::text FROM credential_findings
                            WHERE host(ip)=%s AND username=%s AND source='default_cred_check'
                            ORDER BY created_at DESC LIMIT 1""", (host, found["username"]))
            rr = cur.fetchone()
            cred_id = rr[0] if rr else None
        out["credential_id"] = cred_id
    except Exception as e:  # noqa: BLE001
        log.warning("record credential failed: %s", e)
    try:
        cur.execute(
            """INSERT INTO web_findings
                 (asset_id, url, source, issue_type, name, severity, param, evidence,
                  method, engagement_id)
               VALUES (%s,%s,'default_cred_check','default-credentials',
                       'Default Credentials Accepted','high',%s,%s,'POST',%s)
               ON CONFLICT DO NOTHING""",
            (asset_id, login_url, form.get("user_field"),
             f"login accepted default credentials ({found['username']}:****)", engagement_id))
    except Exception as e:  # noqa: BLE001
        log.debug("record web_finding failed: %s", e)

    # Commit first: the profile upsert + authenticated scan run in SEPARATE
    # service transactions and must see the credential we just wrote.
    try:
        cur.connection.commit()
    except Exception as e:  # noqa: BLE001
        log.debug("pre-profile commit failed: %s", e)

    # Build the Auth Profile keyed by the HOSTNAME the scan targets (the resolver
    # matches on the scan URL's host, not the credential's IP), referencing the
    # credential by id. Set an auth indicator so ZAP can verify the session.
    try:
        import auth_autopopulate as _ap
    except Exception:  # noqa: BLE001
        _ap = ap
    login_data = _ap.build_login_data(form)
    scan_host = urlparse(login_url).hostname or host
    scheme = urlparse(login_url).scheme or "http"
    logged_in_regex = ((cfg.get("success") or {}).get("logged_in_regex")
                       or r"(?i)(sign ?off|log ?off|log ?out|sign ?out|logout|my account)")
    profile_body = {"host": scan_host, "engagement_id": engagement_id,
                    "login_url": login_url, "login_data": login_data,
                    # username is not secret and ZAP form-auth needs it; the SECRET
                    # stays referenced by credential_id (resolved at scan time).
                    "username": found["username"],
                    "credential_id": cred_id, "csrf_field": form.get("csrf_field"),
                    "auth_type": "form", "logged_in_regex": logged_in_regex,
                    # login_url is the form ACTION; the browser login needs the form
                    # PAGE (may differ, e.g. /login.jsp -> POST /doLogin).
                    "session": {"login_page": login_page_url},
                    "enabled": True}
    import httpx
    pw_url = os.environ.get("PLAYWRIGHT_URL") or os.environ.get("PLAYWRIGHT_SCANNER_URL") \
        or "https://playwright-scanner:8014"
    try:
        with httpx.Client(verify=False, timeout=30) as cli:
            pr = cli.post(f"{pw_url.rstrip('/')}/web-auth", json=profile_body)
            out["auth_profile"] = ({"ok": True, "host": scan_host, "login_url": login_url,
                                    "login_data": login_data, "credential_id": cred_id}
                                   if pr.status_code < 400 else
                                   {"error": pr.status_code, "detail": pr.text[:160]})
    except Exception as e:  # noqa: BLE001
        out["auth_profile"] = {"error": str(e)[:160]}

    # Gap 2 — trigger an AUTHENTICATED scan. Playwright WALKS the logged-in app
    # first (a real browser login, crawling through the ZAP proxy so ZAP's site
    # tree is seeded with the authenticated /bank/* pages), THEN ZAP scans that
    # seeded tree. Both calls carry engagement_id in the BODY (the X-Engagement-Id
    # header contextvar is reset before the async scan/crawl runs).
    if isinstance(out.get("auth_profile"), dict) and out["auth_profile"].get("ok"):
        import time
        rc = cfg.get("authenticated_rescan") or {}
        zc = _zap_crawl_settings(cur, cfg)   # ZAP settings (app_settings) > YAML > defaults
        out["auth_crawl_settings"] = zc
        base = f"{scheme}://{scan_host}/"
        hdr = {"X-Engagement-Id": str(engagement_id or "")}
        try:
            with httpx.Client(verify=False, timeout=40) as cli:
                # 1) authenticated Playwright crawl — walk the logged-in app, seed ZAP.
                if rc.get("crawl_first", True):
                    cr = cli.post(f"{pw_url.rstrip('/')}/crawl",
                                  json={"url": base, "engagement_id": engagement_id,
                                        "max_pages": zc["max_pages"], "max_depth": zc["max_depth"],
                                        "use_zap_proxy": True},
                                  headers=hdr)
                    cj = cr.json().get("job_id") if cr.status_code < 400 else None
                    out["authenticated_crawl"] = {"dispatched": cr.status_code < 400, "job_id": cj}
                    deadline = time.time() + zc["wait_seconds"]
                    while cj and time.time() < deadline:
                        time.sleep(6)
                        try:
                            j = cli.get(f"{pw_url.rstrip('/')}/crawl/{cj}").json()
                            if str(j.get("status", "")).lower() in ("completed", "failed", "blocked", "done"):
                                out["authenticated_crawl"].update(
                                    {"status": j.get("status"),
                                     "pages_visited": j.get("pages_visited"),
                                     "authenticated": j.get("authenticated")})
                                break
                        except Exception:  # noqa: BLE001
                            pass
                # 2) THEN ZAP the authenticated-seeded tree.
                sr = cli.post(f"{pw_url.rstrip('/')}/scan",
                              json={"url": base, "engagement_id": engagement_id,
                                    "zap_spider": bool(rc.get("zap_spider", True)),
                                    "zap_active_scan": bool(rc.get("zap_active_scan", True)),
                                    "zap_ajax_spider": bool(zc.get("ajax_spider", 0)),
                                    "zap_active_scan_chunk_size": int(zc.get("active_scan_chunk_size", 10))},
                              headers=hdr)
                body = sr.json() if sr.status_code < 400 else {}
                out["authenticated_scan"] = {
                    "dispatched": sr.status_code < 400,
                    "status": sr.status_code,
                    "job_id": body.get("scan_id") or body.get("job_id") or body.get("id"),
                    "detail": (None if sr.status_code < 400 else sr.text[:160])}
        except Exception as e:  # noqa: BLE001
            out["authenticated_scan"] = {"dispatched": False, "error": str(e)[:160]}
    return out
