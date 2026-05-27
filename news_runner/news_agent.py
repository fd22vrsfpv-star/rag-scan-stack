"""
News Intelligence Agent — pulls 16 security feeds, dedupes by CVE/topic,
LLM-enriches with structured flags, optionally runs asset-match + GitHub PoC
search on KEV/RCE items, and exposes everything to the operator triage UI.

Lives in the dedicated news-runner container so feed scraping + LLM enrichment
can't take down the rag-api process. Communicates with rag-api over HTTP only
for webhook emission; everything else is direct DB access.

Status pipeline on news_items.status:
    new → reviewed → follow_up → applies → research → future
    (deleted is the soft-delete tombstone)
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Iterable

import psycopg2
import requests
from psycopg2.extras import Json, RealDictCursor

log = logging.getLogger("news_agent")
log.setLevel(logging.INFO)

DB_DSN = os.environ.get("DB_DSN", "postgresql://app:app@rag-postgres:5432/scans")

# LLM — mirror cloud_triage_agent's resolution chain.
OLLAMA_BASE = (
    os.environ.get("OLLAMA_BASE_URL")
    or os.environ.get("OLLAMA_URL")
    or "http://host.docker.internal:11434"
).rstrip("/")
LLM_MODEL = os.environ.get(
    "NEWS_AGENT_MODEL",
    os.environ.get("OLLAMA_MODEL", os.environ.get("LLM_MODEL", "gemma4:31b")),
)
LLM_TIMEOUT_S = int(os.environ.get("NEWS_AGENT_TIMEOUT_S", "240"))

# Scheduler knobs.
NEWS_AUTO_FETCH = os.environ.get("NEWS_AUTO_FETCH", "1") not in ("0", "false", "False", "")
NEWS_FETCH_INTERVAL_HOURS = int(os.environ.get("NEWS_FETCH_INTERVAL_HOURS", "24"))
NEWS_FETCH_HOUR_LOCAL = int(os.environ.get("NEWS_FETCH_HOUR_LOCAL", "6"))

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
USER_AGENT = (
    "Mozilla/5.0 (compatible; rag-scan-stack-news/1.0; +https://github.com/raptordoug/rag_scan_stack)"
)

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _connect():
    return psycopg2.connect(DB_DSN)


def _normalize_title(title: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace — for fingerprinting."""
    if not title:
        return ""
    s = re.sub(r"[^\w\s]", " ", title.lower())
    return " ".join(s.split())[:200]


def _fingerprint(primary_cve: Optional[str], normalized_title: str) -> str:
    """Stable hash so re-ingest of the same story collapses to one news_items row."""
    key = (primary_cve or "").upper().strip() + "|" + normalized_title
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


def _extract_cves(*texts: str) -> list:
    found = set()
    for t in texts:
        if not t:
            continue
        for m in CVE_RE.finditer(t):
            found.add(m.group(0).upper())
    # Sort so primary_cve selection is deterministic
    return sorted(found)


RAG_API_URL = os.environ.get("RAG_API_URL", "https://rag-api:8000").rstrip("/")
RAG_API_KEY = os.environ.get("API_KEY", "changeme")
GITHUB_PAT = os.environ.get("GITHUB_PAT", "")

# Tracks GitHub rate-limit window across calls in this process.
_github_rate = {"remaining": 30, "reset": 0}


def _emit_webhook(event_type: str, source: str, data: dict) -> None:
    """Fire-and-forget webhook — POST to rag-api which owns the webhook
    dispatcher. Errors are swallowed so feed-fetch doesn't break on them."""
    try:
        requests.post(
            f"{RAG_API_URL}/webhooks/emit",
            headers={"x-api-key": RAG_API_KEY, "Content-Type": "application/json"},
            json={"event_type": event_type, "source": source, "data": data},
            timeout=5, verify=False,
        )
    except Exception as e:
        log.debug("emit_webhook failed (%s): %s", event_type, e)


def _github_exploit_search(product: str, version: str, cve_ids: Optional[list] = None) -> list:
    """Search GitHub for PoC/exploit repos matching product+version or CVE IDs.

    Inlined from the original rag-api helper so news-runner has no compile-time
    dependency on app/rag-api/. Same shape: returns list of dicts
    {repo, url, stars, updated, description, language, topics}. Rate-limit
    aware — backs off on 403/429."""
    cve_ids = cve_ids or []
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_PAT:
        headers["Authorization"] = f"Bearer {GITHUB_PAT}"

    if _github_rate["remaining"] < 3 and time.time() < _github_rate["reset"]:
        return []

    queries = []
    if product:
        queries.append(f"{product} {version} exploit".strip())
        queries.append(f"{product} {version} PoC".strip())
    for cve in (cve_ids or [])[:5]:
        queries.append(f"{cve} exploit OR PoC")

    repos: dict = {}
    for q in queries:
        try:
            resp = requests.get(
                "https://api.github.com/search/repositories",
                params={"q": q, "sort": "stars", "per_page": 10},
                headers=headers, timeout=10,
            )
            _github_rate["remaining"] = int(resp.headers.get("X-RateLimit-Remaining", 30))
            _github_rate["reset"] = int(resp.headers.get("X-RateLimit-Reset", 0))
            if resp.status_code == 200:
                for item in resp.json().get("items", []):
                    url = item.get("html_url", "")
                    if url and url not in repos:
                        repos[url] = {
                            "repo": item.get("full_name", ""),
                            "url": url,
                            "stars": item.get("stargazers_count", 0),
                            "updated": item.get("updated_at", ""),
                            "description": (item.get("description") or "")[:200],
                            "language": item.get("language"),
                            "topics": item.get("topics", []),
                        }
            elif resp.status_code in (403, 429):
                log.warning("[news] github rate limited (%d), stopping", resp.status_code)
                break
        except Exception as e:
            log.debug("[news] github search error for %r: %s", q, e)
    return sorted(repos.values(), key=lambda r: r.get("stars", 0), reverse=True)[:20]


# ---------------------------------------------------------------------------
# Feed fetching
# ---------------------------------------------------------------------------

def _fetch_feed(url: str, parser: str) -> list:
    """Pull articles from one source. Returns a list of normalized dicts:
        {title, link, published, raw_excerpt}
    All dicts share a stable shape so the downstream upserter is parser-agnostic."""
    import feedparser  # local import — keeps the module importable even if pip step is pending
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=20, verify=True)
        if resp.status_code >= 400:
            raise RuntimeError(f"http {resp.status_code}")
        feed = feedparser.parse(resp.content)
    except Exception:
        # feedparser can also pull URLs directly; fall back to that path.
        feed = feedparser.parse(url)

    articles = []
    for entry in feed.entries[:50]:
        title = (entry.get("title") or "").strip()
        link = (entry.get("link") or "").strip()
        if not title or not link:
            continue
        # Try summary, then content
        excerpt = entry.get("summary") or ""
        if not excerpt and entry.get("content"):
            try:
                excerpt = entry["content"][0].get("value", "")
            except Exception:
                excerpt = ""
        # Strip basic HTML tags from excerpt for cleaner CVE extraction & display
        excerpt = re.sub(r"<[^>]+>", " ", excerpt)
        excerpt = re.sub(r"\s+", " ", excerpt).strip()[:2000]

        published = ""
        for k in ("published", "updated", "created"):
            if entry.get(k):
                published = entry[k]
                break
        articles.append({
            "title": title,
            "link": link,
            "published": published,
            "raw_excerpt": excerpt,
        })
    return articles


def fetch_all_sources(run_id: Optional[str] = None,
                     enabled_only: bool = True,
                     source_id: Optional[str] = None) -> dict:
    """Walk every enabled source, normalize articles, dedupe-and-upsert into
    news_items, then enrich. Returns aggregate counters."""
    stats = {"sources_fetched": 0, "articles_seen": 0, "items_new": 0,
             "items_updated": 0, "items_enriched": 0, "per_source": []}
    new_item_ids: list[str] = []

    with _connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            q = "SELECT id, name, url, parser FROM news_sources WHERE 1=1"
            params: list = []
            if enabled_only:
                q += " AND enabled = true"
            if source_id:
                q += " AND id = %s::uuid"
                params.append(source_id)
            q += " ORDER BY name"
            cur.execute(q, params)
            sources = cur.fetchall()

        for src in sources:
            src_stats = {"id": str(src["id"]), "name": src["name"],
                         "articles": 0, "new": 0, "updated": 0, "error": None}
            try:
                articles = _fetch_feed(src["url"], src["parser"])
                src_stats["articles"] = len(articles)
                stats["articles_seen"] += len(articles)
                stats["sources_fetched"] += 1

                with conn.cursor() as cur:
                    cur.execute(
                        """UPDATE news_sources
                              SET last_fetched_at = now(), last_status = 'ok', last_error = NULL
                            WHERE id = %s""",
                        (src["id"],),
                    )
                    conn.commit()

                # Upsert each article into news_items.
                for art in articles:
                    iid, was_new = _dedupe_and_upsert(conn, art, src["name"])
                    if was_new:
                        src_stats["new"] += 1
                        stats["items_new"] += 1
                        new_item_ids.append(iid)
                    else:
                        src_stats["updated"] += 1
                        stats["items_updated"] += 1
            except Exception as e:
                log.warning("[news] source %r failed: %s", src["name"], e)
                src_stats["error"] = str(e)
                with conn.cursor() as cur:
                    cur.execute(
                        """UPDATE news_sources
                              SET last_fetched_at = now(),
                                  last_status = 'error',
                                  last_error = %s
                            WHERE id = %s""",
                        (str(e)[:500], src["id"]),
                    )
                    conn.commit()
            stats["per_source"].append(src_stats)
            if run_id:
                _update_run(conn, run_id, stats)

    # Stage 1 — LLM-enrich every freshly-touched item (capped).
    enriched = _enrich_pending(limit=200)
    stats["items_enriched"] = enriched

    # Stage 2 — only on items where stage 1 flagged kev/rce.
    _stage2_for_flagged_items()

    return stats


# ---------------------------------------------------------------------------
# Dedup + upsert
# ---------------------------------------------------------------------------

def _dedupe_and_upsert(conn, article: dict, source_name: str) -> tuple[str, bool]:
    """Insert or update one news_items row. Returns (id, was_new)."""
    cves = _extract_cves(article["title"], article.get("raw_excerpt", ""))
    primary_cve = cves[0] if cves else None
    fp = _fingerprint(primary_cve, _normalize_title(article["title"]))

    article_obj = {
        "source": source_name,
        "title": article["title"],
        "link": article["link"],
        "published": article.get("published") or "",
        "raw_excerpt": (article.get("raw_excerpt") or "")[:1000],
    }

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            """SELECT id, articles, all_cves, last_seen
                 FROM news_items WHERE fingerprint = %s""",
            (fp,),
        )
        row = cur.fetchone()
        if row:
            # Append article if its link isn't already in articles[].
            existing_links = {(a or {}).get("link") for a in (row["articles"] or [])}
            if article["link"] not in existing_links:
                cur.execute(
                    """UPDATE news_items
                          SET articles = articles || %s::jsonb,
                              all_cves = ARRAY(SELECT DISTINCT unnest(all_cves || %s::text[])),
                              last_seen = now()
                        WHERE id = %s""",
                    (Json([article_obj]), cves, row["id"]),
                )
            else:
                cur.execute(
                    "UPDATE news_items SET last_seen = now() WHERE id = %s",
                    (row["id"],),
                )
            conn.commit()
            return str(row["id"]), False

        cur.execute(
            """INSERT INTO news_items
                (fingerprint, title, primary_cve, all_cves, articles)
               VALUES (%s, %s, %s, %s, %s)
               RETURNING id""",
            (fp, article["title"], primary_cve, cves, Json([article_obj])),
        )
        new_id = str(cur.fetchone()["id"])
        conn.commit()
        _emit_webhook("news_item_created", "news_agent",
                      {"id": new_id, "title": article["title"],
                       "primary_cve": primary_cve, "source": source_name})
        return new_id, True


# ---------------------------------------------------------------------------
# CISA KEV cache
# ---------------------------------------------------------------------------

def refresh_cisa_kev() -> dict:
    """Pull the public KEV catalog and upsert into cisa_kev_cache. Idempotent."""
    log.info("[news] refreshing CISA KEV catalog")
    try:
        resp = requests.get(KEV_CATALOG_URL, headers={"User-Agent": USER_AGENT},
                            timeout=30, verify=True)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        log.warning("[news] CISA KEV refresh failed: %s", e)
        return {"ok": False, "error": str(e)}

    items = data.get("vulnerabilities", []) or []
    inserted = 0
    with _connect() as conn, conn.cursor() as cur:
        for v in items:
            try:
                cur.execute(
                    """INSERT INTO cisa_kev_cache
                        (cve_id, date_added, short_description, required_action,
                         known_ransomware, fetched_at)
                       VALUES (%s, %s, %s, %s, %s, now())
                       ON CONFLICT (cve_id) DO UPDATE SET
                          date_added = EXCLUDED.date_added,
                          short_description = EXCLUDED.short_description,
                          required_action = EXCLUDED.required_action,
                          known_ransomware = EXCLUDED.known_ransomware,
                          fetched_at = now()""",
                    (
                        (v.get("cveID") or "").upper(),
                        v.get("dateAdded"),
                        (v.get("shortDescription") or "")[:1000],
                        (v.get("requiredAction") or "")[:1000],
                        str(v.get("knownRansomwareCampaignUse") or "").lower() == "known",
                    ),
                )
                inserted += 1
            except Exception as e:
                log.debug("[news] kev row insert failed: %s", e)
        conn.commit()
    log.info("[news] CISA KEV refresh: %d entries", inserted)
    return {"ok": True, "entries": inserted}


# ---------------------------------------------------------------------------
# LLM enrichment (stage 1)
# ---------------------------------------------------------------------------

_ENRICH_PROMPT = """You are an offensive security analyst working both pentest and red-team
engagements. Below are excerpts from one or more articles covering a single
vulnerability story. Respond with ONLY a JSON object — no prose, no fenced
code-block markers — using these keys:

  "summary": string, 2-3 sentences focused on what a pentester or red-team
              operator needs: what the vuln gets you (RCE / SSRF / auth
              bypass / privesc / lateral move / etc.), prerequisites
              (unauth? authenticated? user click? local?), affected
              product + version range, and whether a public PoC or active
              exploitation is reported. Skip vendor PR / patch advice.
              If the article is commentary or analysis with no actionable
              detail, say so plainly.
  "primary_cve": string, the most relevant CVE-####-#### or "UNKNOWN"
  "rce": true | false | null
  "easily_exploitable": true | false | null
  "malware_exploitable": true | false | null
  "active_internet_breach": true | false | null
  "patch_available": true | false | null

Use null when the article does not explicitly state the property. Do not
guess. "easily_exploitable" means publicly known PoC, low-skill exploit, or
unauthenticated. "active_internet_breach" means the article confirms in-the-wild
exploitation against real targets.

ARTICLES:
{articles_block}
"""


def _call_llm(prompt: str) -> Optional[dict]:
    """Returns the parsed JSON object, or None on any failure."""
    try:
        resp = requests.post(
            f"{OLLAMA_BASE}/api/generate",
            json={"model": LLM_MODEL, "prompt": prompt, "stream": False,
                  "format": "json",
                  "options": {"temperature": 0.2, "num_predict": 1024}},
            timeout=LLM_TIMEOUT_S, verify=False,
        )
        resp.raise_for_status()
        body = resp.json().get("response", "")
        return _extract_json(body)
    except Exception as e:
        log.warning("[news] LLM call failed: %s", e)
        return None


def _extract_json(text: str) -> Optional[dict]:
    """Tolerant JSON extractor — same pattern as cloud_triage_agent."""
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    raw = fence.group(1) if fence else text
    try:
        return json.loads(raw)
    except Exception:
        pass
    start = raw.find("{")
    if start < 0:
        return None
    depth = 0
    for i, ch in enumerate(raw[start:], start=start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(raw[start:i + 1])
                except Exception:
                    return None
    return None


def _coerce_bool_or_null(v):
    if v is True or v is False:
        return v
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in ("true", "yes", "y"):
        return True
    if s in ("false", "no", "n"):
        return False
    if s in ("null", "unknown", "n/a", ""):
        return None
    return None


def _enrich_pending(limit: int = 200, item_ids: Optional[list] = None) -> int:
    """LLM-enrich items where enriched_at IS NULL or last_seen > enriched_at.
    Also flips kev_listed deterministically based on cisa_kev_cache.
    Returns count of items successfully enriched."""
    enriched = 0
    with _connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if item_ids:
                placeholders = ",".join(["%s::uuid"] * len(item_ids))
                cur.execute(
                    f"""SELECT id, title, primary_cve, all_cves, articles
                          FROM news_items
                         WHERE id IN ({placeholders})""",
                    item_ids,
                )
            else:
                cur.execute(
                    """SELECT id, title, primary_cve, all_cves, articles
                         FROM news_items
                        WHERE enriched_at IS NULL OR last_seen > enriched_at
                        ORDER BY last_seen DESC
                        LIMIT %s""",
                    (limit,),
                )
            rows = cur.fetchall()

        for row in rows:
            try:
                articles_block = "\n\n".join(
                    f"- [{(a or {}).get('source','?')}] {(a or {}).get('title','')}\n"
                    f"  {(a or {}).get('raw_excerpt','')[:800]}"
                    for a in (row["articles"] or [])
                )[:8000]
                prompt = _ENRICH_PROMPT.format(articles_block=articles_block)
                obj = _call_llm(prompt)
                if not obj:
                    continue

                # Some local LLMs spit long runs of newlines/whitespace into
                # the summary field. Collapse to a single-line block and cap
                # at 600 chars so the UI row stays bounded.
                raw_summary = obj.get("summary") or ""
                summary = re.sub(r"\s+", " ", raw_summary).strip()[:600]
                pcve = (obj.get("primary_cve") or "").upper().strip()
                if pcve and pcve != "UNKNOWN" and not CVE_RE.match(pcve):
                    pcve = ""  # reject malformed
                rce = _coerce_bool_or_null(obj.get("rce"))
                easy = _coerce_bool_or_null(obj.get("easily_exploitable"))
                mal = _coerce_bool_or_null(obj.get("malware_exploitable"))
                breach = _coerce_bool_or_null(obj.get("active_internet_breach"))
                patch = _coerce_bool_or_null(obj.get("patch_available"))

                # Deterministic KEV flag — any matching CVE in the local cache flips it.
                cves_to_check = list(row["all_cves"] or [])
                if pcve and pcve != "UNKNOWN":
                    cves_to_check.append(pcve)
                kev = None
                if cves_to_check:
                    with conn.cursor() as cur2:
                        cur2.execute(
                            "SELECT 1 FROM cisa_kev_cache WHERE cve_id = ANY(%s) LIMIT 1",
                            (cves_to_check,),
                        )
                        kev = cur2.fetchone() is not None

                with conn.cursor() as cur2:
                    # Only overwrite primary_cve if we don't already have one and the LLM gave us a real CVE.
                    set_pcve = ""
                    args: list = [
                        summary, rce, easy, mal, breach, patch, kev, str(row["id"]),
                    ]
                    if pcve and pcve != "UNKNOWN" and not row["primary_cve"]:
                        set_pcve = ", primary_cve = %s"
                        args = [
                            summary, rce, easy, mal, breach, patch, kev, pcve, str(row["id"]),
                        ]
                    cur2.execute(
                        f"""UPDATE news_items
                              SET summary = COALESCE(NULLIF(%s, ''), summary),
                                  rce = %s,
                                  easily_exploitable = %s,
                                  malware_exploitable = %s,
                                  active_internet_breach = %s,
                                  patch_available = %s,
                                  kev_listed = %s
                                  {set_pcve},
                                  enriched_at = now()
                            WHERE id = %s::uuid""",
                        args,
                    )
                    conn.commit()
                enriched += 1

                if kev:
                    _emit_webhook("news_kev_match", "news_agent",
                                  {"id": str(row["id"]), "title": row["title"],
                                   "primary_cve": pcve or row["primary_cve"]})
            except Exception as e:
                log.warning("[news] enrich failed for %s: %s", row["id"], e)
                conn.rollback()
    return enriched


# ---------------------------------------------------------------------------
# Stage 2 — asset matching + GitHub PoC search
# ---------------------------------------------------------------------------

def _match_assets(conn, item_id: str) -> int:
    """For each CVE on the item, find vulns rows referencing the CVE and pivot
    to assets. Persists hits to news_items.asset_matches. Returns count of hits."""
    hits = []
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT all_cves, primary_cve FROM news_items WHERE id = %s::uuid",
            (item_id,),
        )
        row = cur.fetchone()
        if not row:
            return 0
        cves = list(row["all_cves"] or [])
        if row["primary_cve"] and row["primary_cve"] != "UNKNOWN" and row["primary_cve"] not in cves:
            cves.append(row["primary_cve"])
        if not cves:
            cur.execute(
                """UPDATE news_items SET asset_matched_at = now() WHERE id = %s::uuid""",
                (item_id,),
            )
            conn.commit()
            return 0

        # vulns.cve is a text column carrying the raw CVE id; ANY-match against our list.
        cur.execute(
            """SELECT DISTINCT v.cve, v.severity, a.id AS asset_id, a.ip::text AS ip,
                              a.hostname, a.engagement_id
                 FROM vulns v JOIN assets a ON a.id = v.asset_id
                WHERE v.cve = ANY(%s)
                ORDER BY v.cve""",
            (cves,),
        )
        for r in cur.fetchall():
            hits.append({
                "cve": r["cve"],
                "severity": r["severity"],
                "asset_id": str(r["asset_id"]),
                "ip": r["ip"],
                "hostname": r["hostname"],
                "engagement_id": str(r["engagement_id"]) if r["engagement_id"] else None,
                "match_reason": "vuln.cve",
            })

    with conn.cursor() as cur:
        cur.execute(
            """UPDATE news_items
                  SET asset_matches = %s::jsonb,
                      asset_matched_at = now()
                WHERE id = %s::uuid""",
            (Json(hits), item_id),
        )
        conn.commit()

    if hits:
        _emit_webhook("news_item_asset_match_found", "news_agent",
                      {"id": item_id, "hit_count": len(hits)})
    return len(hits)


def _github_search(conn, item_id: str) -> int:
    """Pull title + CVEs and call the local _github_exploit_search."""
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(
            "SELECT title, primary_cve, all_cves FROM news_items WHERE id = %s::uuid",
            (item_id,),
        )
        row = cur.fetchone()
        if not row:
            return 0

    cves = list(row["all_cves"] or [])
    if row["primary_cve"] and row["primary_cve"] != "UNKNOWN" and row["primary_cve"] not in cves:
        cves.append(row["primary_cve"])
    # Use the title's leading 2-3 words as a "product" hint.
    product_hint = " ".join((row["title"] or "").split()[:3])

    try:
        repos = _github_exploit_search(product_hint, "", cves) or []
    except Exception as e:
        log.warning("[news] github search failed for %s: %s", item_id, e)
        repos = []

    with conn.cursor() as cur:
        cur.execute(
            """UPDATE news_items
                  SET github_links = %s::jsonb,
                      github_searched_at = now()
                WHERE id = %s::uuid""",
            (Json(repos), item_id),
        )
        conn.commit()
    return len(repos)


def _stage2_for_flagged_items() -> int:
    """Auto-run asset-match + github-search on items where stage 1 flagged
    kev_listed=true OR rce=true and stage 2 hasn't run yet (or last_seen has
    advanced past the previous stage 2)."""
    processed = 0
    with _connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """SELECT id FROM news_items
                    WHERE status <> 'deleted'
                      AND (kev_listed = true OR rce = true)
                      AND (asset_matched_at IS NULL OR asset_matched_at < last_seen)
                    ORDER BY last_seen DESC
                    LIMIT 100"""
            )
            ids = [str(r["id"]) for r in cur.fetchall()]
        for iid in ids:
            try:
                _match_assets(conn, iid)
                _github_search(conn, iid)
                processed += 1
            except Exception as e:
                log.warning("[news] stage 2 failed for %s: %s", iid, e)
    return processed


# ---------------------------------------------------------------------------
# Topic deep search
# ---------------------------------------------------------------------------

def deep_search(topic: str, include_deleted: bool = False,
                refresh_llm: bool = False, max_items: int = 50) -> dict:
    """Run expensive enrichment across every item matching `topic`. Returns a
    structured summary; caller is expected to also persist to news_runs."""
    topic_norm = (topic or "").strip()
    if not topic_norm:
        return {"matched_items": 0, "asset_hits_total": 0, "github_repos_total": 0,
                "items": [], "topic": ""}

    with _connect() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            sql = """
                SELECT id, title, primary_cve
                  FROM news_items
                 WHERE (title ILIKE %s OR summary ILIKE %s
                        OR %s = ANY(all_cves) OR primary_cve = %s)
            """
            args: list = [f"%{topic_norm}%", f"%{topic_norm}%",
                          topic_norm.upper(), topic_norm.upper()]
            if not include_deleted:
                sql += " AND status <> 'deleted'"
            sql += " ORDER BY last_seen DESC LIMIT %s"
            args.append(max_items)
            cur.execute(sql, args)
            rows = cur.fetchall()

        if refresh_llm and rows:
            _enrich_pending(limit=max_items, item_ids=[str(r["id"]) for r in rows])

        items_out = []
        asset_hits_total = 0
        github_total = 0
        for row in rows:
            iid = str(row["id"])
            try:
                ah = _match_assets(conn, iid)
                gh = _github_search(conn, iid)
                asset_hits_total += ah
                github_total += gh
                items_out.append({"id": iid, "title": row["title"],
                                  "primary_cve": row["primary_cve"],
                                  "asset_hits": ah, "github_repos": gh})
            except Exception as e:
                log.warning("[news] deep_search item %s failed: %s", iid, e)

    summary = {
        "topic": topic_norm,
        "matched_items": len(items_out),
        "asset_hits_total": asset_hits_total,
        "github_repos_total": github_total,
        "items": items_out,
    }
    _emit_webhook("news_deep_search_completed", "news_agent", summary)
    return summary


# ---------------------------------------------------------------------------
# news_runs lifecycle helpers
# ---------------------------------------------------------------------------

def start_run(triggered_by: str = "manual", topic: Optional[str] = None) -> str:
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """INSERT INTO news_runs (triggered_by, topic, status)
               VALUES (%s, %s, 'running') RETURNING id""",
            (triggered_by, topic),
        )
        run_id = str(cur.fetchone()[0])
        conn.commit()
    return run_id


def _update_run(conn, run_id: str, stats: dict) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """UPDATE news_runs
                  SET sources_fetched = %s,
                      articles_seen   = %s,
                      items_new       = %s,
                      items_updated   = %s,
                      items_enriched  = %s,
                      per_source      = %s::jsonb
                WHERE id = %s::uuid""",
            (stats["sources_fetched"], stats["articles_seen"], stats["items_new"],
             stats["items_updated"], stats["items_enriched"], Json(stats["per_source"]),
             run_id),
        )
        conn.commit()


def finish_run(run_id: str, stats: dict, error: Optional[str] = None) -> None:
    status = "failed" if error else "completed"
    with _connect() as conn, conn.cursor() as cur:
        cur.execute(
            """UPDATE news_runs
                  SET status = %s,
                      completed_at = now(),
                      sources_fetched = %s,
                      articles_seen   = %s,
                      items_new       = %s,
                      items_updated   = %s,
                      items_enriched  = %s,
                      per_source      = %s::jsonb,
                      error           = %s
                WHERE id = %s::uuid""",
            (status, stats.get("sources_fetched", 0), stats.get("articles_seen", 0),
             stats.get("items_new", 0), stats.get("items_updated", 0),
             stats.get("items_enriched", 0), Json(stats.get("per_source", [])),
             (error or "")[:1000] if error else None, run_id),
        )
        conn.commit()


def run_full_cycle(triggered_by: str = "manual", source_id: Optional[str] = None) -> dict:
    """Kick off a complete fetch + dedupe + enrich cycle. Returns {run_id, ...stats}."""
    refresh_cisa_kev()
    run_id = start_run(triggered_by=triggered_by)
    try:
        stats = fetch_all_sources(run_id=run_id, source_id=source_id)
        finish_run(run_id, stats)
        return {"run_id": run_id, **stats}
    except Exception as e:
        log.exception("[news] full cycle failed")
        finish_run(run_id, {}, error=str(e))
        return {"run_id": run_id, "error": str(e)}


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

_scheduler_started = False
_scheduler_lock = threading.Lock()


def _next_fire_time(now: datetime) -> datetime:
    """Next NEWS_FETCH_HOUR_LOCAL hh:00 strictly in the future, separated by
    NEWS_FETCH_INTERVAL_HOURS."""
    target = now.replace(hour=NEWS_FETCH_HOUR_LOCAL, minute=0, second=0, microsecond=0)
    if target <= now:
        target += timedelta(hours=NEWS_FETCH_INTERVAL_HOURS)
    return target


def _scheduler_loop():
    log.info("[news] scheduler thread alive — interval=%dh hour=%d",
             NEWS_FETCH_INTERVAL_HOURS, NEWS_FETCH_HOUR_LOCAL)
    # Catch-up on startup if we've been idle for >= interval.
    try:
        with _connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT MAX(last_fetched_at) FROM news_sources")
            last = cur.fetchone()[0]
        if last is None or (datetime.now(timezone.utc) - last) > timedelta(hours=NEWS_FETCH_INTERVAL_HOURS):
            log.info("[news] startup catch-up — running initial fetch")
            try:
                run_full_cycle(triggered_by="scheduler")
            except Exception as e:
                log.warning("[news] startup catch-up failed: %s", e)
    except Exception as e:
        log.warning("[news] startup probe failed: %s", e)

    while True:
        try:
            now = datetime.now()
            target = _next_fire_time(now)
            sleep_s = max(60.0, (target - now).total_seconds())
            log.info("[news] sleeping %.0fs until %s", sleep_s, target.isoformat())
            time.sleep(sleep_s)
            run_full_cycle(triggered_by="scheduler")
        except Exception as e:
            log.warning("[news] scheduler tick failed: %s", e)
            time.sleep(300)


def start_scheduler() -> None:
    """Idempotent — safe to call multiple times. Disabled when NEWS_AUTO_FETCH=0."""
    global _scheduler_started
    if not NEWS_AUTO_FETCH:
        log.info("[news] auto-fetch disabled via NEWS_AUTO_FETCH=0")
        return
    with _scheduler_lock:
        if _scheduler_started:
            return
        _scheduler_started = True
    t = threading.Thread(target=_scheduler_loop, name="news-scheduler", daemon=True)
    t.start()
