"""Subdomain takeover hunter.

Scans `recon_findings` for hostnames whose CNAME / A-record points at a
de-provisioned cloud resource (dangling pointers to S3, Azure WebApps,
GitHub Pages, Heroku, etc.). Confirms via active HTTP probe + fingerprint
match, then writes a `subdomain_takeover` recon_finding so the operator can
claim the resource as part of the engagement.

Design choices (locked in by operator):
- Active engagements only (`engagements.status='active'`)
- All probes route through the configured proxy (app_settings.config.burp_proxy_url)
- 50 parallel probes max
- Deterministic fingerprint matching only — no LLM dependency
- Idempotent: re-running upserts on (target, detector_id), bumping last_seen
- Webhook events on start / completion / each detection
"""

import asyncio
import datetime as _dt
import hashlib
import json
import logging
import os
import re
from typing import Any, Iterable, Optional

import httpx
import psycopg2
from psycopg2.extras import RealDictCursor, Json

log = logging.getLogger("takeover-hunter")

_FP_PATH = os.path.join(os.path.dirname(__file__), "takeover_fingerprints.json")
_DEFAULT_CONCURRENCY = 50
_DEFAULT_TIMEOUT_S = 6.0
_DEBOUNCE_SECONDS = 600  # 10 min — matches operator-chosen cadence


def _load_fingerprints() -> list[dict]:
    with open(_FP_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    detectors = data.get("detectors") or []
    # Pre-compile regexes once so the inner loop stays cheap.
    for d in detectors:
        d["_body_re"] = re.compile(d["body_regex"], re.IGNORECASE) if d.get("body_regex") else None
    return detectors


def _proxy_url_from_settings(cur) -> Optional[str]:
    """Pull burp_proxy_url from app_settings.config — same source other scans use."""
    try:
        cur.execute("SELECT value FROM app_settings WHERE category='config' AND key='burp_proxy_url' LIMIT 1")
        row = cur.fetchone()
        if row and row.get("value"):
            return row["value"]
    except Exception:
        pass
    # Fall back to env so the agent still works on a dev box without the setting wired.
    return os.environ.get("BURP_PROXY_URL") or os.environ.get("HTTP_PROXY")


def _active_engagement_ids(cur) -> list[str]:
    cur.execute("SELECT id::text AS id FROM engagements WHERE status='active'")
    return [r["id"] for r in cur.fetchall()]


def _candidates_for_engagements(cur, engagement_ids: list[str], detectors: list[dict],
                                limit: int) -> list[dict]:
    """Pull dns_cname / subfinder / dns_a recon_findings whose target hostname or
    cname value matches one of the detector cname_patterns. Returns
    (target, cname_target, finding_id, engagement_id) tuples for verification.

    Engagement scoping: includes findings stamped with one of the active
    engagement_ids OR findings with NULL engagement_id (legacy data) so the
    operator still benefits from existing recon."""
    if not detectors:
        return []
    patterns = []
    for d in detectors:
        for p in d.get("cname_patterns") or []:
            patterns.append(p)
    if not patterns:
        return []
    like_clauses = " OR ".join(["(data::text) ILIKE %s" for _ in patterns])
    args: list[Any] = [f"%{p}%" for p in patterns]
    eng_filter = ""
    if engagement_ids:
        eng_filter = " AND (engagement_id::text = ANY(%s) OR engagement_id IS NULL)"
        args.append(engagement_ids)
    args.append(limit)
    cur.execute(f"""
        SELECT id::text AS id,
               target,
               source,
               finding_type,
               (data::jsonb) AS data,
               engagement_id::text AS engagement_id
        FROM recon_findings
        WHERE source IN ('dnsx','subfinder','dns-enum')
          AND finding_type IN ('dns_cname','subdomain','dns_a','dns_records')
          AND ({like_clauses})
          {eng_filter}
        ORDER BY created_at DESC
        LIMIT %s
    """, args)
    return cur.fetchall() or []


def _detector_for(cname_or_target: str, detectors: list[dict]) -> Optional[dict]:
    s = (cname_or_target or "").lower()
    for d in detectors:
        for p in d.get("cname_patterns") or []:
            if p.lower() in s:
                return d
    return None


def _extract_cname(row: dict) -> str:
    """recon_findings.data shape varies by source. Check common paths."""
    data = row.get("data") or {}
    if isinstance(data, dict):
        for k in ("cname", "cname_target", "value", "answer"):
            v = data.get(k)
            if isinstance(v, str) and v:
                return v
    # Subfinder/dns_a entries don't have a CNAME — fall back to target itself
    # since operators care about the *hostname* status either way.
    return row.get("target") or ""


async def _probe(client: httpx.AsyncClient, hostname: str, detector: dict) -> dict:
    """Returns a dict with probe outcome:
       {ok, claimable, status, body_excerpt, error}.

    Strategy:
    - If detector is nx_only: trust DNS NXDOMAIN. We don't currently re-resolve
      from inside this agent (fingerprint is satisfied if HTTP fails to connect).
    - Else: HTTP GET, check status_code + body_regex.

    Probe is best-effort; transient errors do NOT mark vulnerable to avoid
    false positives during proxy hiccups."""
    url = f"https://{hostname}"
    nx_only = bool(detector.get("nx_only"))
    try:
        resp = await client.get(url, timeout=_DEFAULT_TIMEOUT_S, follow_redirects=False)
    except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError, httpx.TimeoutException) as e:
        # If detector says NX/connect-fail is sufficient, that's our positive signal.
        if nx_only:
            return {"ok": True, "claimable": True, "status": None,
                    "body_excerpt": "", "error": f"{type(e).__name__}: {e}"}
        # HTTP detector but connection failed → inconclusive, not vulnerable.
        return {"ok": False, "claimable": False, "status": None,
                "body_excerpt": "", "error": f"{type(e).__name__}: {e}"}
    except Exception as e:
        return {"ok": False, "claimable": False, "status": None,
                "body_excerpt": "", "error": f"unexpected:{type(e).__name__}: {e}"}

    body = resp.text[:4000]
    status_match = (not detector.get("http_status")) or (resp.status_code in (detector.get("http_status") or []))
    body_re = detector.get("_body_re")
    body_match = bool(body_re and body_re.search(body)) if body_re else (body_re is None)
    claimable = status_match and body_match
    return {"ok": True, "claimable": bool(claimable), "status": resp.status_code,
            "body_excerpt": body[:500], "error": None}


async def _verify_all(candidates: list[dict], detectors: list[dict],
                      proxy_url: Optional[str],
                      concurrency: int) -> list[dict]:
    """Probe every candidate concurrently (bounded). Returns list of
    {candidate, detector, probe} dicts only for confirmed claimable hosts."""
    sem = asyncio.Semaphore(concurrency)
    confirmed: list[dict] = []

    client_kwargs: dict[str, Any] = {
        "verify": False,
        "headers": {"User-Agent": "takeover-hunter/1.0"},
    }
    if proxy_url:
        client_kwargs["proxy"] = proxy_url

    async with httpx.AsyncClient(**client_kwargs) as client:
        async def _one(cand: dict):
            cname = _extract_cname(cand)
            detector = _detector_for(cname, detectors) or _detector_for(cand.get("target") or "", detectors)
            if not detector:
                return
            hostname = cand.get("target") or cname
            if not hostname:
                return
            async with sem:
                outcome = await _probe(client, hostname, detector)
            if outcome.get("claimable"):
                confirmed.append({"candidate": cand, "detector": detector, "probe": outcome})

        await asyncio.gather(*(_one(c) for c in candidates), return_exceptions=False)

    return confirmed


def _fingerprint(target: str, detector_id: str) -> str:
    h = hashlib.sha1(f"{target}|{detector_id}".encode("utf-8")).hexdigest()
    return f"takeover:{h[:16]}"


def _persist(cur, confirmed: list[dict]) -> dict:
    """Insert / upsert subdomain_takeover findings.

    Idempotent on (fingerprint) — second run bumps `last_seen` in data, leaves
    one row per (target, detector_id). Uses ON CONFLICT DO UPDATE keyed on the
    fingerprint stored in `data->>fingerprint` via a unique partial index
    (created lazily here if missing)."""
    if not confirmed:
        return {"inserted": 0, "updated": 0, "errors": []}

    # Lazy create the unique index for idempotency. CREATE INDEX IF NOT EXISTS
    # is safe to call repeatedly and avoids needing a migration.
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS recon_findings_takeover_fp_idx
        ON public.recon_findings ((data->>'fingerprint'))
        WHERE finding_type = 'subdomain_takeover'
    """)

    inserted = 0
    updated = 0
    errors: list[str] = []
    now_iso = _dt.datetime.utcnow().isoformat() + "Z"
    for c in confirmed:
        cand = c["candidate"]; det = c["detector"]; probe = c["probe"]
        target = cand.get("target") or _extract_cname(cand)
        detector_id = det["id"]
        fp = _fingerprint(target, detector_id)
        body = {
            "fingerprint": fp,
            "detector_id": detector_id,
            "claim_hint": det.get("claim_hint"),
            "vulnerable": bool(det.get("vulnerable", True)),
            "cname_target": _extract_cname(cand),
            "http_status": probe.get("status"),
            "body_excerpt": probe.get("body_excerpt"),
            "trigger_finding_id": cand.get("id"),
            "first_seen": now_iso,
            "last_seen": now_iso,
        }
        try:
            cur.execute("""
                INSERT INTO recon_findings
                    (target, source, finding_type, severity, data, engagement_id)
                VALUES (%s, 'takeover_hunter', 'subdomain_takeover', %s, %s::jsonb, %s::uuid)
                ON CONFLICT ((data->>'fingerprint'))
                  WHERE finding_type = 'subdomain_takeover'
                DO UPDATE SET
                    data = recon_findings.data
                            || jsonb_build_object('last_seen', %s, 'http_status', %s)
                RETURNING (xmax = 0) AS inserted
            """, (
                target,
                "high" if det.get("vulnerable") else "medium",
                Json(body),
                cand.get("engagement_id"),
                now_iso,
                probe.get("status"),
            ))
            r = cur.fetchone()
            if r and r.get("inserted"):
                inserted += 1
            else:
                updated += 1
        except Exception as e:
            if len(errors) < 10:
                errors.append(f"{type(e).__name__}: {e}")

    return {"inserted": inserted, "updated": updated, "errors": errors}


# ── Debounce state (module-level; cleared on rag-api restart) ──
_last_run_at: Optional[float] = None


def _is_debounced(now_ts: float) -> bool:
    if _last_run_at is None:
        return False
    return (now_ts - _last_run_at) < _DEBOUNCE_SECONDS


def hunt(cur,
         engagement_ids: Optional[list[str]] = None,
         limit: int = 5000,
         concurrency: int = _DEFAULT_CONCURRENCY,
         force: bool = False,
         dry_run: bool = False) -> dict:
    """Synchronous orchestrator (run in a worker thread / background task).

    `engagement_ids=None` → discover active engagements automatically.
    `force=True` bypasses the 10-minute debounce.
    `dry_run=True` returns candidates + verifications without writing to DB.
    """
    import time
    global _last_run_at
    now_ts = time.time()
    if not force and _is_debounced(now_ts):
        return {"debounced": True, "next_eligible_in_s": int(_DEBOUNCE_SECONDS - (now_ts - _last_run_at))}

    detectors = _load_fingerprints()
    if engagement_ids is None:
        engagement_ids = _active_engagement_ids(cur)

    proxy_url = _proxy_url_from_settings(cur)
    candidates = _candidates_for_engagements(cur, engagement_ids, detectors, limit)
    if not candidates:
        _last_run_at = now_ts
        return {"engagement_ids": engagement_ids, "candidates_examined": 0,
                "confirmed": 0, "inserted": 0, "updated": 0,
                "proxy_used": bool(proxy_url), "dry_run": dry_run}

    # Run the async verifier from a sync caller. We're typically inside a
    # FastAPI background task or worker thread, so a fresh event loop is fine.
    confirmed = asyncio.run(_verify_all(candidates, detectors, proxy_url, concurrency))

    summary: dict[str, Any] = {
        "engagement_ids": engagement_ids,
        "candidates_examined": len(candidates),
        "confirmed": len(confirmed),
        "proxy_used": bool(proxy_url),
        "dry_run": dry_run,
        "by_detector": {},
    }
    for c in confirmed:
        det_id = c["detector"]["id"]
        summary["by_detector"][det_id] = summary["by_detector"].get(det_id, 0) + 1

    if dry_run:
        # Don't bump debounce on dry-run — operator may immediately commit.
        summary["preview"] = [
            {"target": c["candidate"].get("target"),
             "detector_id": c["detector"]["id"],
             "vulnerable": bool(c["detector"].get("vulnerable")),
             "http_status": c["probe"].get("status"),
             "claim_hint": c["detector"].get("claim_hint")}
            for c in confirmed[:50]
        ]
        return summary

    persist_result = _persist(cur, confirmed)
    summary.update(persist_result)
    _last_run_at = now_ts

    # Per-detection webhook so external trackers (Slack, n8n) get individual
    # notifications they can route. Includes everything an operator needs to
    # act without round-tripping back to the dashboard.
    try:
        from webhooks import emit_webhook
        for c in confirmed:
            emit_webhook("subdomain_takeover_detected", "takeover_hunter", {
                "target": c["candidate"].get("target"),
                "detector_id": c["detector"]["id"],
                "vulnerable": bool(c["detector"].get("vulnerable")),
                "claim_hint": c["detector"].get("claim_hint"),
                "engagement_id": c["candidate"].get("engagement_id"),
                "http_status": c["probe"].get("status"),
                "trigger_finding_id": c["candidate"].get("id"),
            })
    except Exception:
        pass

    return summary
