"""
Cloud Triage Agent — LLM-driven re-ordering of cloud_scan_recommendations.

Static priority sort (critical → high → medium → low) ignores attack-chain
dependencies and operator state. This agent re-ranks open recommendations
considering:

  1. Attack-chain order      — identity recon before privesc; enumerate
                                before exploit; passive before active
  2. Credential availability — recs that need creds the operator already
                                has in the vault rank higher
  3. Already-imported sources — recs whose tool has run rank lower (don't
                                re-suggest scans we already have data for)
  4. Tier-0 signal           — Global Admins / dirsync accounts / exposed
                                secrets always float to the top regardless
                                of how easy the rec is to execute

Output:
  - cloud_scan_recommendations.triage_order      (1 = do first)
  - cloud_scan_recommendations.triage_reasoning  (one-line "why this rank")
  - cloud_triage_runs.top_actions  jsonb [{rec_id, title, why}, ...]
  - cloud_triage_runs.summary      text — 2-3 sentence narrative
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Optional

import requests
from psycopg2.extras import Json, RealDictCursor

log = logging.getLogger("cloud_triage_agent")
log.setLevel(logging.INFO)

# Match api.py's pattern: OLLAMA_BASE_URL is the canonical setting, with
# host.docker.internal as the Mac/dev default (Ollama runs on the host, not
# in a sibling container). Linux clusters override via OLLAMA_BASE_URL or
# OLLAMA_URL.
OLLAMA_BASE = (
    os.environ.get("OLLAMA_BASE_URL")
    or os.environ.get("OLLAMA_URL")
    or "http://host.docker.internal:11434"
).rstrip("/")
LLM_MODEL = os.environ.get("CLOUD_TRIAGE_MODEL",
                           os.environ.get("OLLAMA_MODEL",
                                          os.environ.get("LLM_MODEL", "gemma4:31b")))
LLM_TIMEOUT_S = int(os.environ.get("CLOUD_TRIAGE_TIMEOUT_S", "300"))
TOP_ACTIONS = 3

# Recs that haven't been re-triaged in this many seconds are stale; the
# auto-trigger respects this so back-to-back ingests don't spam the LLM.
DEFAULT_DEBOUNCE_S = 60


def _gather_context(cur, engagement_id: Optional[str], provider: Optional[str]) -> dict:
    """Snapshot the operator's current state for prompt grounding.
    Cheap aggregate queries only — no per-row data sent to the LLM."""
    where_provider = "AND provider = %s" if provider else ""
    p_args = [provider] if provider else []

    # Open recommendations
    cur.execute(f"""
        SELECT id, rule_id, rule_name, priority, tool, action,
               command_hint, import_as, trigger_source, trigger_summary,
               provider, account_id, created_at
        FROM cloud_scan_recommendations
        WHERE status = 'open' {where_provider}
        ORDER BY
            CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                          WHEN 'medium' THEN 2 ELSE 3 END,
            created_at DESC
        LIMIT 100
    """, p_args)
    recs = cur.fetchall()

    # Posture: which sources have findings?
    cur.execute("""
        SELECT source, count(*) AS n
        FROM recon_findings
        WHERE source IN ('prowler','scoutsuite','pacu','cloudfox','azurehound','microburst')
        GROUP BY source
    """)
    sources = {r["source"]: r["n"] for r in cur.fetchall()}

    # Tier-0 signals already in the data
    cur.execute("""
        SELECT finding_type, count(*) AS n
        FROM recon_findings
        WHERE finding_type IN (
            'azure_role_global_admin','azure_user_dirsync',
            'azure_secret_exposure','azure_role_app_admin',
            'azure_app_with_secret','azure_domain_federated','azure_ca_disabled')
        GROUP BY finding_type
    """)
    tier0 = {r["finding_type"]: r["n"] for r in cur.fetchall()}

    # Credentials in vault per provider
    cur.execute("""
        SELECT credential_type, count(*) AS n
        FROM credential_vault
        WHERE status NOT IN ('revoked','expired')
        GROUP BY credential_type
    """)
    creds = {r["credential_type"]: r["n"] for r in cur.fetchall()}

    return {
        "open_recs": [dict(r) for r in recs],
        "sources_imported": sources,
        "tier0_signals": tier0,
        "credentials_in_vault": creds,
    }


def _build_prompt(ctx: dict) -> str:
    recs = ctx["open_recs"]
    rec_summary = [
        {
            "id": str(r["id"]),
            "rule_id": r["rule_id"],
            "name": r["rule_name"],
            "priority": r["priority"],
            "tool": r["tool"],
            "action": r["action"],
            "trigger": r.get("trigger_summary") or r.get("trigger_source"),
            "provider": r.get("provider"),
        }
        for r in recs
    ]
    return (
        "You are a senior offensive-security operator triaging cloud security "
        "scan recommendations. You are given the open recommendations, what "
        "data has already been imported, what tier-0 findings are already on "
        "the table, and what credentials are in the vault. Re-rank the "
        "recommendations into the order they should be executed.\n\n"
        "Ranking principles (apply in order):\n"
        "1. ATTACK CHAIN: identity / passive recon BEFORE privesc / active "
        "exploit. Don't suggest exploitation tools before enumeration is done.\n"
        "2. NO REPEATS: a rec whose tool already has lots of findings is "
        "lower priority — we already have the data.\n"
        "3. CRED-READY: a rec that USES credentials we already have in the "
        "vault should rank higher than one that requires fresh creds.\n"
        "4. TIER-0 ALWAYS WINS: any rec tied to an existing Global Admin / "
        "dirsync account / exposed secret / federated domain is a top-3 item "
        "no matter what.\n"
        "5. CONFIRM-BEFORE-PIVOT: prefer recs that confirm/expand existing "
        "tier-0 signals over ones that introduce a new attack vector.\n\n"
        "Return STRICT JSON ONLY (no prose, no fences) with this shape:\n"
        '{\n'
        '  "ranked": [\n'
        '    {"id": "<rec_id>", "order": 1, "why": "one-line reason (<=120 chars)"},\n'
        '    ...one entry per input rec...\n'
        '  ],\n'
        f'  "top_actions": [\n'
        f'    {{"id": "<rec_id>", "title": "<short label>", "why": "<one sentence rationale>"}}\n'
        f'    ... up to {TOP_ACTIONS} entries — the immediate next steps\n'
        '  ],\n'
        '  "summary": "<2-3 sentence narrative of the recommended attack path>"\n'
        "}\n\n"
        "OPEN RECOMMENDATIONS:\n"
        + json.dumps(rec_summary, indent=2, default=str)
        + "\n\nSOURCES ALREADY IMPORTED (with finding counts):\n"
        + json.dumps(ctx["sources_imported"], default=str)
        + "\n\nTIER-0 FINDINGS ALREADY PRESENT:\n"
        + json.dumps(ctx["tier0_signals"], default=str)
        + "\n\nCREDENTIALS IN VAULT (by type):\n"
        + json.dumps(ctx["credentials_in_vault"], default=str)
        + "\n\nReturn the JSON. Nothing else.\n"
    )


def _resolve_model(override: Optional[str] = None) -> str:
    """Pick an available model. Resolution order:
      1. Explicit `override` argument (per-run UI swap).
      2. Settings → LLM Tuning → Cloud Triage Agent (DB-backed via api.get_agent_model).
      3. CLOUD_TRIAGE_MODEL / OLLAMA_MODEL / LLM_MODEL env vars.
      4. Configured default.
    Then verifies the model is actually installed on Ollama; falls back to
    the first non-embedding installed model if not."""
    candidate: Optional[str] = None
    if override:
        candidate = override.strip()
    else:
        try:
            from api import get_agent_model
            candidate = (get_agent_model("cloud_triage_agent") or "").strip()
        except Exception:
            candidate = None
    if not candidate:
        candidate = LLM_MODEL
    try:
        r = requests.get(f"{OLLAMA_BASE}/api/tags", timeout=5, verify=False)
        if r.status_code != 200:
            return candidate
        installed = {m.get("name", "") for m in r.json().get("models", [])}
        if candidate in installed:
            return candidate
        # Fall back: prefer non-embedding chat models
        for name in installed:
            if "embed" in name.lower():
                continue
            log.warning("cloud_triage: model %r not installed, falling back to %r",
                        candidate, name)
            return name
    except Exception as e:
        log.warning("cloud_triage: model discovery failed (%s); using %r",
                    e, candidate)
    return candidate


def _call_llm(prompt: str, model_override: Optional[str] = None) -> tuple[str, dict]:
    model = _resolve_model(model_override)
    t0 = time.time()
    resp = requests.post(
        f"{OLLAMA_BASE}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False,
              "options": {"temperature": 0.2, "num_predict": 4096}},
        timeout=LLM_TIMEOUT_S, verify=False,
    )
    latency_ms = int((time.time() - t0) * 1000)
    resp.raise_for_status()
    data = resp.json()
    return data.get("response", ""), {
        "model": model,
        "latency_ms": latency_ms,
        "prompt_tokens": data.get("prompt_eval_count", 0),
        "completion_tokens": data.get("eval_count", 0),
    }


def _extract_json(text: str) -> Optional[dict]:
    """Tolerant JSON extractor — handles fenced blocks and prefix prose."""
    if not text:
        return None
    # strip ```json ... ``` fences if present
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    raw = fence.group(1) if fence else text
    # try direct parse
    try:
        return json.loads(raw)
    except Exception:
        pass
    # find first { ... } balanced span
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


def triage_recommendations(cur,
                           engagement_id: Optional[str] = None,
                           provider: Optional[str] = None,
                           force: bool = False,
                           model: Optional[str] = None,
                           debounce_s: int = DEFAULT_DEBOUNCE_S) -> dict:
    """Run a triage pass and persist results.

    `model` (optional): override the configured triage model for THIS run only.
    Useful for swapping in a faster model when the default times out, or trying
    a different model without restarting rag-api.

    Returns a dict suitable for the API response (run_id, top_actions, summary,
    ranked_count). Skips work and returns the previous run if the most recent
    triage was within `debounce_s` seconds and `force=False`.
    """
    # When caller pins a specific model for this run, skip the debounce —
    # the cached result probably came from a different model and isn't what
    # they're asking for.
    if model and not force:
        force = True

    # Debounce check
    if not force:
        cur.execute("""
            SELECT id, top_actions, summary, created_at, model,
                   open_recs_count, latency_ms
            FROM cloud_triage_runs
            WHERE created_at > now() - interval '%s seconds'
              AND (engagement_id = %s OR (engagement_id IS NULL AND %s IS NULL))
              AND (provider      = %s OR (provider      IS NULL AND %s IS NULL))
            ORDER BY created_at DESC LIMIT 1
        """, (debounce_s, engagement_id, engagement_id, provider, provider))
        cached = cur.fetchone()
        if cached:
            return {
                "run_id": str(cached["id"]),
                "cached": True,
                "top_actions": cached["top_actions"],
                "summary": cached["summary"],
                "ranked_count": cached["open_recs_count"],
                "model": cached["model"],
                "latency_ms": cached["latency_ms"],
                "created_at": cached["created_at"].isoformat() if cached["created_at"] else None,
            }

    ctx = _gather_context(cur, engagement_id, provider)
    if not ctx["open_recs"]:
        # Nothing to rank — record an empty run so callers don't keep retrying
        cur.execute("""
            INSERT INTO cloud_triage_runs (engagement_id, provider, open_recs_count,
                                            top_actions, summary)
            VALUES (%s, %s, 0, '[]'::jsonb, 'No open recommendations to triage.')
            RETURNING id
        """, (engagement_id, provider))
        run_id = str(cur.fetchone()["id"])
        return {"run_id": run_id, "cached": False,
                "top_actions": [], "summary": "No open recommendations to triage.",
                "ranked_count": 0, "model": None, "latency_ms": 0}

    prompt = _build_prompt(ctx)
    error: Optional[str] = None
    parsed: dict = {}
    meta = {"model": model or LLM_MODEL, "latency_ms": 0,
            "prompt_tokens": 0, "completion_tokens": 0}
    try:
        raw, meta = _call_llm(prompt, model_override=model)
        parsed = _extract_json(raw) or {}
        if not parsed.get("ranked"):
            raise ValueError(f"LLM response missing 'ranked' array (got keys: {list(parsed.keys())})")
    except Exception as e:
        log.exception("cloud triage LLM call failed")
        error = f"{type(e).__name__}: {e}"

    # Persist the run
    ranked = parsed.get("ranked") or []
    top_actions = (parsed.get("top_actions") or [])[:TOP_ACTIONS]
    summary = parsed.get("summary") or ""

    cur.execute("""
        INSERT INTO cloud_triage_runs
            (engagement_id, provider, open_recs_count, top_actions, summary,
             model, prompt_tokens, completion_tokens, latency_ms, error)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (
        engagement_id, provider, len(ctx["open_recs"]),
        Json(top_actions), summary,
        meta.get("model"), meta.get("prompt_tokens"),
        meta.get("completion_tokens"), meta.get("latency_ms"), error,
    ))
    run_id = str(cur.fetchone()["id"])

    # Apply the rank back onto each rec
    if ranked and not error:
        valid_ids = {str(r["id"]) for r in ctx["open_recs"]}
        for entry in ranked:
            rec_id = str(entry.get("id") or "")
            if rec_id not in valid_ids:
                continue
            try:
                order_n = int(entry.get("order") or 0)
            except (TypeError, ValueError):
                continue
            why = (entry.get("why") or "")[:500]
            try:
                cur.execute("""
                    UPDATE cloud_scan_recommendations
                    SET triage_order = %s, triage_reasoning = %s, triaged_at = now()
                    WHERE id = %s::uuid
                """, (order_n, why, rec_id))
            except Exception as e:
                log.warning("failed to write triage rank for rec %s: %s", rec_id, e)

    return {
        "run_id": run_id,
        "cached": False,
        "top_actions": top_actions,
        "summary": summary,
        "ranked_count": len(ranked),
        "model": meta.get("model"),
        "latency_ms": meta.get("latency_ms"),
        "error": error,
    }


def get_latest_run(cur, engagement_id: Optional[str] = None,
                   provider: Optional[str] = None) -> Optional[dict]:
    """Fetch the most recent triage run for surface in the UI."""
    cur.execute("""
        SELECT id, engagement_id, provider, open_recs_count,
               top_actions, summary, model, latency_ms, error, created_at
        FROM cloud_triage_runs
        WHERE (engagement_id = %s OR (engagement_id IS NULL AND %s IS NULL))
          AND (provider      = %s OR (provider      IS NULL AND %s IS NULL))
        ORDER BY created_at DESC LIMIT 1
    """, (engagement_id, engagement_id, provider, provider))
    row = cur.fetchone()
    if not row:
        return None
    return {
        "run_id": str(row["id"]),
        "engagement_id": str(row["engagement_id"]) if row["engagement_id"] else None,
        "provider": row["provider"],
        "open_recs_count": row["open_recs_count"],
        "top_actions": row["top_actions"],
        "summary": row["summary"],
        "model": row["model"],
        "latency_ms": row["latency_ms"],
        "error": row["error"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }
