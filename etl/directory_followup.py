"""Directory-discovery enumeration followup.

When the crawl/scan discovers a directory (a listing, or a crawled folder URL such
as `/my documents/JohnSmith/Bank Site Documents/`), this runs a STANDARD followup:
a gobuster content scan of that directory using a docs/backup wordlist ENRICHED
with site-harvested words ("cewl data") — the words a target actually uses name
its leaked backups and documents, and a generic list misses them. This is how a
VAPT finds the exposed document a link-only crawl walks past.

Word sources merged into the followup wordlist (see knowledge/directory_followups.yaml):
  1. repo docs/backup names (/wordlists/docs-backup.txt)
  2. site-harvested corpus (app/rag-api/wordlist_generator, from content_extractions)
  3. live cewl spidered from the site, WHEN cewl is installed (best-effort, cached
     per host; cewl runs in the kali container and prints to stdout, which rag-api
     captures and writes to the shared /wordlists — kali's /wordlists is read-only).

Execution: auto-fire on the SAFE lane (kali-listener /tools/execute, itself scope-
and concurrency-gated; it ingests gobuster output). The queued row is TAGGED as a
follow-up (scanner='dir_followup', extra.followup=true) for visibility.
Scope-gated before dispatch (defence in depth) and fail-closed.
"""
from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

log = logging.getLogger("directory_followup")

WORDLIST_DIR = os.environ.get("WORDLIST_DIR", "/wordlists")
KALI_LISTENER_URL = os.environ.get("KALI_LISTENER_URL", "https://kali-listener:8019")
_DEFAULT_CFG = {
    "extensions": ["txt", "pdf", "doc", "docx", "xls", "xlsx", "csv", "bak",
                   "old", "zip", "tar", "gz", "sql", "conf", "config", "log",
                   "json", "xml", "bak", "backup"],
    "gobuster": {"threads": 10, "timeout_seconds": 600, "status_codes_blacklist": "404"},
    "priority": 24,
    "followup_tag": "dir_followup",
    "cewl": {"depth": 2, "min_word_length": 4},
}


def load_cfg() -> Dict[str, Any]:
    """Read knowledge/directory_followups.yaml (bind-mounted). Fail-safe to defaults."""
    for path in ("/knowledge/directory_followups.yaml",
                 os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "knowledge", "directory_followups.yaml")):
        if not os.path.exists(path):
            continue
        try:
            import yaml
            d = (yaml.safe_load(open(path, encoding="utf-8")) or {}).get("directory_followup") or {}
            cfg = dict(_DEFAULT_CFG)
            cfg.update({k: v for k, v in d.items() if v is not None})
            # normalise cewl params from wordlist_sources
            for s in (d.get("wordlist_sources") or []):
                if isinstance(s, dict) and isinstance(s.get("cewl_live"), dict):
                    cfg["cewl"] = {"depth": s["cewl_live"].get("depth", 2),
                                   "min_word_length": s["cewl_live"].get("min_word_length", 4)}
            return cfg
        except Exception as e:  # noqa: BLE001
            log.debug("directory_followups.yaml load failed: %s", e)
            return dict(_DEFAULT_CFG)
    return dict(_DEFAULT_CFG)


def _hostsafe(host: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", host or "unknown")


def _repo_docs_backup_words() -> List[str]:
    path = os.path.join(WORDLIST_DIR, "docs-backup.txt")
    if not os.path.exists(path):
        return []
    try:
        return [w.strip() for w in open(path, encoding="utf-8", errors="ignore") if w.strip()]
    except Exception:  # noqa: BLE001
        return []


def _site_corpus_words(asset_id: Optional[str]) -> List[str]:
    """Site-harvested directory/file candidate words from the platform's own
    generator (content_extractions). Best-effort — degrades to [] if the module
    or data is unavailable (e.g. running outside rag-api)."""
    if not asset_id:
        return []
    try:
        try:
            from wordlist_generator import generate_wordlist  # rag-api context
        except ImportError:
            from app.rag_api.wordlist_generator import generate_wordlist  # type: ignore
        res = generate_wordlist(asset_id=asset_id, list_type="directories",
                                enable_mutations=False)
        p = res.get("path")
        if p and os.path.exists(p):
            return [w.strip() for w in open(p, encoding="utf-8", errors="ignore") if w.strip()]
    except Exception as e:  # noqa: BLE001
        log.debug("site corpus wordlist unavailable: %s", e)
    return []


def _cewl_cache_path(host: str) -> str:
    return os.path.join(WORDLIST_DIR, f"cewl_live_{_hostsafe(host)}.txt")


def _live_cewl_words(host: str, base_url: str, cfg: Dict[str, Any]) -> List[str]:
    """Live cewl words, WHEN cewl is installed. Cached per host in the shared
    /wordlists (kali's copy is read-only, so rag-api captures cewl stdout and
    writes the cache here). Best-effort: any failure (cewl absent, timeout) -> []."""
    cache = _cewl_cache_path(host)
    if os.path.exists(cache):
        try:
            return [w.strip() for w in open(cache, encoding="utf-8", errors="ignore") if w.strip()]
        except Exception:  # noqa: BLE001
            return []
    depth = int(cfg.get("cewl", {}).get("depth", 2))
    minlen = int(cfg.get("cewl", {}).get("min_word_length", 4))
    cmd = f"cewl -d {depth} -m {minlen} {base_url}"
    try:
        import httpx
        import time
        with httpx.Client(verify=False, timeout=30) as cli:
            r = cli.post(f"{KALI_LISTENER_URL.rstrip('/')}/tools/execute",
                         json={"tool": "cewl", "command": cmd, "target": host,
                               "service": "dir_followup", "port": 80, "timeout": 120})
            if r.status_code >= 400:
                log.debug("cewl dispatch refused (%s): %s", r.status_code, r.text[:120])
                return []
            eid = r.json().get("id")
            out = ""
            for _ in range(40):  # up to ~120s
                time.sleep(3)
                s = cli.get(f"{KALI_LISTENER_URL.rstrip('/')}/tools/executions/{eid}")
                d = s.json()
                if d.get("status") in ("completed", "failed"):
                    out = d.get("output") or ""
                    break
        words = [w.strip() for w in out.splitlines()
                 if w.strip() and not w.startswith(("CeWL", "http", "["))]
        if words:
            try:
                with open(cache, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(dict.fromkeys(words)) + "\n")
            except Exception:  # noqa: BLE001
                pass
        return words
    except Exception as e:  # noqa: BLE001
        log.debug("live cewl unavailable: %s", e)
        return []


def _probe_directory_status(host: str, dir_url: str, timeout: int = 30) -> Optional[int]:
    """Best-effort HTTP status of a candidate directory via the SAFE lane (a HEAD
    request; scope-gated at the listener). Returns the status code, or None if it
    could not be determined. Used to SKIP phantom directories — a path that 404s
    for everything, e.g. a relative-path-confusion crawl artifact like testfire's
    `/my documents/JohnSmith/Bank Site Documents/` — before spending cewl+gobuster
    on it. `curl -sI` (no %{...}) avoids the listener's unresolved-placeholder
    guard."""
    try:
        import re
        import time
        import httpx
        cmd = f"curl -s -I -m 15 {dir_url}"
        port = urlparse(dir_url).port or (443 if dir_url.startswith("https") else 80)
        with httpx.Client(verify=False, timeout=timeout) as cli:
            r = cli.post(f"{KALI_LISTENER_URL.rstrip('/')}/tools/execute",
                         json={"tool": "curl", "command": cmd, "target": host,
                               "service": "dir_followup_probe", "port": port,
                               "timeout": 30})
            if r.status_code >= 400:
                return None
            eid = r.json().get("id")
            for _ in range(10):  # up to ~30s
                time.sleep(3)
                d = cli.get(f"{KALI_LISTENER_URL.rstrip('/')}/tools/executions/{eid}").json()
                if d.get("status") in ("completed", "failed"):
                    out = d.get("output") or ""
                    codes = re.findall(r"HTTP/\d(?:\.\d)?\s+(\d{3})", out)
                    return int(codes[-1]) if codes else None
        return None
    except Exception as e:  # noqa: BLE001
        log.debug("dir existence probe failed for %s: %s", dir_url, e)
        return None


def build_merged_wordlist(host: str, asset_id: Optional[str], base_url: str,
                          cfg: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Merge docs/backup + site corpus + (best-effort) live cewl into ONE deduped
    wordlist under the shared /wordlists, and return its path (kali reads it for
    gobuster). Returns None if there are no words at all."""
    cfg = cfg or load_cfg()
    words: List[str] = []
    words += _repo_docs_backup_words()
    words += _site_corpus_words(asset_id)
    words += _live_cewl_words(host, base_url, cfg)
    words = [w for w in (x.strip() for x in words) if w and len(w) <= 128]
    words = list(dict.fromkeys(words))  # dedupe, preserve order
    if not words:
        return None
    os.makedirs(WORDLIST_DIR, exist_ok=True)
    path = os.path.join(WORDLIST_DIR, f"dirfollowup_{_hostsafe(host)}.txt")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(words) + "\n")
    except Exception as e:  # noqa: BLE001
        log.warning("could not write merged wordlist %s: %s", path, e)
        return None
    return path


def _resolve_session_cookie(cur, host: str, engagement_id: Optional[str] = None) -> Optional[str]:
    """The authenticated session cookie for `host`, from the Auth Profile
    (web_auth_configs.session.cookies) that the crawl persisted — so gobuster can
    brute-force the LOGGED-IN surface. Returns "name=value; ..." or None. Prefers
    the engagement's profile, else a global one. Never raises."""
    try:
        cur.execute(
            """SELECT session FROM web_auth_configs
                WHERE enabled AND host = %s
                  AND (engagement_id IS NULL
                       OR (%s::uuid IS NOT NULL AND engagement_id = %s::uuid))
                ORDER BY (engagement_id IS NOT NULL) DESC LIMIT 1""",
            (host, engagement_id, engagement_id))
        r = cur.fetchone()
    except Exception:  # noqa: BLE001
        try:
            cur.connection.rollback()
        except Exception:  # noqa: BLE001
            pass
        return None
    if not r or not r[0]:
        return None
    session = r[0]
    if isinstance(session, str):
        try:
            session = json.loads(session or "{}")
        except Exception:  # noqa: BLE001
            return None
    cookies = (session or {}).get("cookies") or []
    pairs = [f"{c.get('name')}={c.get('value')}" for c in cookies
             if isinstance(c, dict) and c.get("name")]
    return "; ".join(pairs) if pairs else None


def _gobuster_command(dir_url: str, wordlist_path: str, cfg: Dict[str, Any],
                      cookie: Optional[str] = None) -> str:
    exts = ",".join(str(e) for e in (cfg.get("extensions") or []))
    g = cfg.get("gobuster", {})
    threads = int(g.get("threads", 10))
    blk = g.get("status_codes_blacklist", "404")
    u = dir_url if dir_url.endswith("/") else dir_url + "/"
    # Authenticated brute-force: gobuster dir -c sends the session cookie, so the
    # scan runs as the logged-in user (mirrors ffuf's -H). Static snapshot — fine
    # for a bounded followup; no re-auth on expiry (that is ZAP's job).
    auth = f' -c "{cookie}"' if cookie else ""
    return (f"gobuster dir -u {u} -w {wordlist_path} -x {exts} -t {threads} "
            f"-q -k -b {blk} --no-error{auth}")


_CD_CFG = None


def _content_discovery_cfg() -> Dict[str, Any]:
    """Load knowledge/content_discovery.yaml once (tool templates + default +
    custom-attack recipes). Data-driven: edit the YAML to add tools/recipes."""
    global _CD_CFG
    if _CD_CFG is not None:
        return _CD_CFG
    cfg = {}
    for path in ("/knowledge/content_discovery.yaml",
                 os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                              "knowledge", "content_discovery.yaml")):
        if os.path.exists(path):
            try:
                import yaml
                cfg = yaml.safe_load(open(path, encoding="utf-8")) or {}
            except Exception:  # noqa: BLE001
                cfg = {}
            break
    _CD_CFG = cfg
    return cfg


def _select_content_tool(cur) -> str:
    """Which content-discovery tool to run: the operator setting
    (content_discovery.tool) if it names a known tool, else the YAML default
    (gobuster). One of the 3 — never all three."""
    cd = _content_discovery_cfg().get("content_discovery") or {}
    tools = cd.get("tools") or {}
    default = cd.get("default_tool", "gobuster")
    try:
        cur.execute("SELECT value FROM app_settings WHERE key=%s AND category='config'",
                    (cd.get("setting_key", "content_discovery.tool"),))
        r = cur.fetchone()
        sel = (r[0].strip().lower() if r and r[0] else "")
        if sel in tools:
            return sel
    except Exception:  # noqa: BLE001
        try:
            cur.connection.rollback()
        except Exception:  # noqa: BLE001
            pass
    return default if default in tools else "gobuster"


def _build_content_command(tool: str, dir_url: str, wordlist: str,
                           cfg: Dict[str, Any], cookie: Optional[str] = None) -> str:
    """Build the selected tool's command from its YAML template, injecting the
    authenticated session cookie. Falls back to the gobuster builder."""
    cd = _content_discovery_cfg().get("content_discovery") or {}
    spec = (cd.get("tools") or {}).get(tool)
    if not spec or not spec.get("template"):
        return _gobuster_command(dir_url, wordlist, cfg, cookie=cookie)
    exts = ",".join(str(e) for e in (cfg.get("extensions") or []))
    g = cfg.get("gobuster", {})
    threads = int(g.get("threads", 10))
    blk = g.get("status_codes_blacklist", "404")
    u = dir_url if dir_url.endswith("/") else dir_url + "/"
    cookie_flag = ""
    if cookie and spec.get("cookie_flag"):
        cookie_flag = str(spec["cookie_flag"]).format(cookie=cookie)
    return str(spec["template"]).format(
        url=u, wordlist=wordlist, exts=exts, threads=threads,
        blacklist=blk, cookie_flag=cookie_flag)


def queue_directory_followup(cur, host: str, dir_url: str, *,
                             asset_id: Optional[str] = None,
                             engagement_id: Optional[str] = None,
                             base_url: Optional[str] = None,
                             scope_rows=None, aliases=None,
                             dispatch: bool = True) -> Dict[str, Any]:
    """Standard followup for a discovered directory: build the cewl-enriched
    docs/backup wordlist, record a scan_recommendation TAGGED as a follow-up
    (scanner='dir_followup', extra.followup=true), and — auto-fire — dispatch a
    SAFE-lane gobuster to kali-listener /tools/execute (scope- and concurrency-
    gated there; it ingests the results). Scope-gated here first (fail-closed).
    Returns {ok, queued, dispatched, command, wordlist, recommendation_id, reason?}.
    """
    out: Dict[str, Any] = {"ok": False, "queued": 0, "dispatched": False}
    cfg = load_cfg()
    if not base_url:
        pu = urlparse(dir_url)
        base_url = f"{pu.scheme or 'http'}://{pu.netloc}" if pu.netloc else f"http://{host}"

    # Existence check: skip a phantom directory (404 for everything — a
    # relative-path-confusion crawl artifact) before spending cewl+gobuster on it.
    # Fail-OPEN: only a definitive 404 skips; an undeterminable status proceeds so
    # a transient probe error never suppresses a real followup.
    if cfg.get("verify_exists", True):
        status = _probe_directory_status(host, dir_url)
        out["dir_status"] = status
        if status == 404:
            out.update({"ok": True, "queued": 0, "skipped": True,
                        "reason": "directory does not exist (HTTP 404)"})
            return out

    wordlist = build_merged_wordlist(host, asset_id, base_url, cfg)
    if not wordlist:
        out["reason"] = "no wordlist words available"
        return out
    # Authenticated brute-force when the crawl has persisted a session cookie for
    # this host into the Auth Profile (mirrors ffuf's -H). Falls back to anonymous.
    _cookie = _resolve_session_cookie(cur, host, engagement_id)
    _tool = _select_content_tool(cur)
    command = _build_content_command(_tool, dir_url, wordlist, cfg, cookie=_cookie)

    # Scope gate (fail-closed) before anything leaves.
    if scope_rows is not None:
        try:
            from etl.scope_gate import check_dispatch
        except ImportError:  # pragma: no cover
            from scope_gate import check_dispatch
        refusal = check_dispatch(str(host), scope_rows, command=command, aliases=aliases)
        if refusal:
            out["reason"] = f"out of scope: {refusal}"
            return out

    from psycopg2.extras import Json
    tag = cfg.get("followup_tag", "dir_followup")
    cur.execute(
        """INSERT INTO scan_recommendations
             (ip, service, scanner, action, script, source, priority,
              status, engagement_id, extra)
           VALUES (%s,'http',%s,%s,%s,'directory_followup',%s,'pending',%s,%s)
           ON CONFLICT (fingerprint) DO NOTHING RETURNING id::text""",
        (host, tag, command, command, int(cfg.get("priority", 24)),
         engagement_id,
         Json({"followup": True, "followup_type": "directory_enumeration",
               "directory": dir_url, "wordlist": wordlist, "base_url": base_url,
               "queued_by": "enum:dir_followup"})))
    row = cur.fetchone()
    rec_id = row[0] if row else None
    if rec_id:
        out["queued"] = 1
        out["recommendation_id"] = rec_id
    out.update({"ok": True, "command": command, "wordlist": wordlist})

    if dispatch:
        try:
            import httpx
            with httpx.Client(verify=False, timeout=20) as cli:
                r = cli.post(f"{KALI_LISTENER_URL.rstrip('/')}/tools/execute",
                             json={"tool": _tool, "command": command,
                                   "target": host, "service": tag,
                                   "port": urlparse(base_url).port or (443 if base_url.startswith("https") else 80),
                                   "timeout": int(cfg.get("gobuster", {}).get("timeout_seconds", 600))})
                out["dispatched"] = r.status_code < 400
                if r.status_code >= 400:
                    out["dispatch_status"] = r.status_code
                    out["dispatch_detail"] = r.text[:160]
                else:
                    out["execution_id"] = r.json().get("id")
        except Exception as e:  # noqa: BLE001
            log.warning("directory followup dispatch failed: %s", e)
            out["dispatch_error"] = str(e)[:160]
    return out
