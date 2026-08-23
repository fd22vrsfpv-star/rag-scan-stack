"""The consumer for the raw-artifact LLM queue.

WHY THIS EXISTS
---------------
`raw_artifacts` had 274 rows in `llm_status='pending'`, 1 stuck in
`'processing'` and 1 `'done'` — the oldest pending dated 2026-08-18. Every
server-side piece was already built: `/artifacts/claim` (with FOR UPDATE SKIP
LOCKED so two workers take disjoint batches), `/artifacts/{id}/processed`,
`/artifacts/{id}/actions`, `/artifacts/stats`. Nothing ever called claim, so the
queue only ever grew, and api.py's own cleanup warns about exactly that:

    "...they will never age out — run a consumer, or ..."

What the LLM pass is FOR: `artifact_actions.suggest_actions()` already works on
raw text alone, and takes `llm_result` as an optional enrichment. So this is not
load-bearing for follow-up suggestions — it makes them better. That is why it is
opt-in rather than always-on: the operator decides when to spend model time.

TWO THINGS THE QUEUE COULD NOT DO BEFORE
----------------------------------------
* **Recover a claimed row.** `/artifacts/claim` moves rows to 'processing' and
  the docstring says they "can be requeued" — but nothing requeued them, so the
  one row that was claimed and never reported stayed stuck indefinitely.
  `requeue_stale()` fixes that, and it is what makes claiming safe: a worker
  that dies no longer costs an artifact.
* **Stop retrying a poisoned row.** `llm_attempts` was incremented and never
  read. A row that fails deterministically (content the model always chokes on)
  would be re-claimed forever, at the front of the queue, starving everything
  behind it. Past MAX_ATTEMPTS it is marked 'failed' with the reason kept.
"""
import json
import logging
import os
import re
import time
from typing import Any, Dict, Optional

import requests

log = logging.getLogger("artifact_consumer")

OLLAMA_BASE = (os.environ.get("OLLAMA_BASE_URL")
               or os.environ.get("OLLAMA_URL")
               or "http://ollama:11434").rstrip("/")
# Resolution order ends at OLLAMA_MODEL, which .env already sets to a model the
# operator actually has. The previous literal default (copied from a sibling
# module) named "gemma4:26b", which is not installed here — a request for an
# absent model comes back as a retryable failure, so the queue would have looked
# broken rather than misconfigured.
DEFAULT_MODEL = (os.environ.get("ARTIFACT_LLM_MODEL")
                 or os.environ.get("LLM_MODEL")
                 or os.environ.get("OLLAMA_MODEL")
                 or "gemma4:31b")
LLM_TIMEOUT_S = int(os.environ.get("ARTIFACT_LLM_TIMEOUT_S", "120"))

# Past this many failures a row is parked, not retried. Without it a single
# unparseable artifact is re-claimed forever and blocks the queue behind it,
# because claim() orders by created_at.
MAX_ATTEMPTS = int(os.environ.get("ARTIFACT_LLM_MAX_ATTEMPTS", "3"))

# Content sent to the model. Whole tool outputs run to megabytes; the head is
# where the structure is, and an unbounded prompt is how one artifact eats the
# entire batch's time budget.
MAX_CONTENT_CHARS = int(os.environ.get("ARTIFACT_LLM_MAX_CHARS", "12000"))

_PROMPT = """You are summarising one security tool's raw output for a pentester.

Tool: {tool}
Target: {target}{port}
Command: {command}

Return ONLY a JSON object, no prose, with these keys:
  "summary":     one or two sentences on what this output shows
  "findings":    array of short strings — concrete things worth acting on
  "services":    array of short strings — software/versions identified, if any
  "next_steps":  array of short strings — what a tester would do next
  "confidence":  "high" | "medium" | "low"

If the output shows nothing of interest, say so in "summary" and return empty
arrays. Do not invent findings that are not in the text.

--- OUTPUT ---
{content}
--- END ---
"""


def _extract_json(text: str) -> Optional[dict]:
    """Pull the JSON object out of a model reply. Models add prose and fences."""
    if not text:
        return None
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.S)
    if fence:
        try:
            return json.loads(fence.group(1))
        except Exception:
            pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except Exception:
            return None
    return None


def _call_llm(prompt: str, model: str) -> tuple[str, dict]:
    t0 = time.time()
    resp = requests.post(
        f"{OLLAMA_BASE}/api/generate",
        json={"model": model, "prompt": prompt, "stream": False,
              "options": {"temperature": 0.1, "num_predict": 900}},
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


def requeue_stale(cur, older_than_minutes: int = 30) -> int:
    """Return rows stuck in 'processing' to 'pending'. Returns how many.

    A claimed row whose worker died is invisible to both the queue and the
    operator: it is not pending, so nothing retries it, and it is not done, so
    nothing reports it. This is what makes claiming recoverable.
    """
    cur.execute("""
        UPDATE raw_artifacts
           SET llm_status = 'pending'
         WHERE llm_status = 'processing'
           AND COALESCE(llm_processed_at, first_seen)
               < now() - (%s || ' minutes')::interval
        RETURNING id
    """, (int(older_than_minutes),))
    return len(cur.fetchall())


def _claim(cur, limit: int, tool: Optional[str], model: str) -> list:
    """Atomically take a batch. Mirrors /artifacts/claim exactly.

    FOR UPDATE SKIP LOCKED so a second worker takes different rows rather than
    duplicating this one's. Rows already past MAX_ATTEMPTS are excluded here as
    well as parked below, so a poisoned row cannot be re-claimed even if
    something resets its status.
    """
    params: Dict[str, Any] = {"limit": max(1, min(int(limit), 100)),
                              "model": model, "max_attempts": MAX_ATTEMPTS}
    tool_clause = ""
    if tool:
        tool_clause = "AND tool = %(tool)s"
        params["tool"] = tool
    cur.execute(f"""
        UPDATE raw_artifacts SET llm_status = 'processing',
                                 llm_attempts = llm_attempts + 1,
                                 llm_model = COALESCE(%(model)s, llm_model),
                                 llm_processed_at = now()
         WHERE id IN (SELECT id FROM raw_artifacts
                       WHERE llm_status = 'pending' {tool_clause}
                         AND COALESCE(llm_attempts, 0) < %(max_attempts)s
                       ORDER BY first_seen
                       LIMIT %(limit)s FOR UPDATE SKIP LOCKED)
        RETURNING id, tool, command, target, port, service, content,
                  COALESCE(llm_attempts, 0) AS llm_attempts
    """, params)
    return cur.fetchall()


def process_batch(cur, limit: int = 10, tool: Optional[str] = None,
                  model: Optional[str] = None,
                  requeue_stale_minutes: int = 30) -> dict:
    """Claim up to `limit` pending artifacts, run the LLM, record the outcome.

    Each row is committed to a terminal state before the next is attempted, so a
    crash mid-batch loses at most the row in flight — and `requeue_stale` will
    recover even that one.
    """
    chosen = model or DEFAULT_MODEL
    requeued = requeue_stale(cur, requeue_stale_minutes)

    rows = _claim(cur, limit, tool, chosen)
    done = failed = parked = 0
    errors: list = []

    for r in rows:
        aid = str(r["id"])
        content = (r["content"] or "")[:MAX_CONTENT_CHARS]
        prompt = _PROMPT.format(
            tool=r["tool"], target=r["target"] or "unknown",
            port=f":{r['port']}" if r["port"] else "",
            command=(r["command"] or "")[:400], content=content)
        try:
            raw, meta = _call_llm(prompt, chosen)
            parsed = _extract_json(raw)
            if parsed is None:
                raise ValueError("model returned no parsable JSON object")
            parsed["_meta"] = meta
            cur.execute("""
                UPDATE raw_artifacts
                   SET llm_status = 'done', llm_result = %s::jsonb,
                       llm_error = NULL, llm_model = %s, llm_processed_at = now()
                 WHERE id = %s
            """, (json.dumps(parsed), chosen, aid))
            done += 1
        except Exception as e:
            msg = f"{type(e).__name__}: {e}"
            # Park it once it has had its chances, so it stops re-entering the
            # front of the queue. 'failed' is terminal for the claim query.
            terminal = int(r["llm_attempts"] or 0) >= MAX_ATTEMPTS
            cur.execute("""
                UPDATE raw_artifacts
                   SET llm_status = %s, llm_error = %s, llm_processed_at = now()
                 WHERE id = %s
            """, ("failed" if terminal else "pending", msg[:2000], aid))
            if terminal:
                parked += 1
            else:
                failed += 1
            if len(errors) < 10:
                errors.append(f"{aid}: {msg}")
            log.warning("artifact %s LLM pass failed (attempt %s/%s): %s",
                        aid, r["llm_attempts"], MAX_ATTEMPTS, msg)

    return {
        "claimed": len(rows),
        "done": done,
        "retryable_failures": failed,
        "parked": parked,
        "requeued_stale": requeued,
        "model": chosen,
        "errors": errors,
    }


def queue_depth(cur) -> dict:
    """Current queue state, for the endpoint's response and for tests."""
    cur.execute("""
        SELECT COALESCE(llm_status, 'pending') AS status, count(*) AS n
          FROM raw_artifacts GROUP BY 1
    """)
    return {r["status"]: r["n"] for r in cur.fetchall()}
