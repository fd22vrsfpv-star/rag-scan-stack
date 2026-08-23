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

# Above this size an artifact is SKIPPED rather than truncated.
#
# Truncation is fine for a 40 KB nmap run: the head really is where the structure
# is. It is not fine for the 8.0 MB and 7.7 MB katana crawls sitting in this
# queue — summarising their first 12 KB produces a confident statement about
# 0.15% of the file, and nothing downstream can tell that from a summary of the
# whole. A skip with a reason is honest; a sampled summary is not.
MAX_ARTIFACT_BYTES = int(os.environ.get("ARTIFACT_LLM_MAX_BYTES", str(256 * 1024)))

# Tools whose output already has a dedicated parser, so the structured data is in
# the database and an LLM pass re-derives it. Discovered from the FILESYSTEM
# rather than hard-coded: a new etl/parse_<tool>.py should take effect without
# anyone remembering to edit a list here.
_PARSER_DIR = os.environ.get("ETL_PARSER_DIR", "/app/etl")


def tools_with_parsers(parser_dir: str = None) -> set:
    """Tool names that have an etl/parse_<tool>.py.

    Underscores in a filename map to hyphens as well, because the tools are
    named both ways across the stack (`smtp-user-enum` vs `parse_smtp_user_enum`).
    Returns an empty set if the directory is unreadable — callers must treat that
    as "skip nothing", never as "skip everything".
    """
    import glob
    out = set()
    for path in glob.glob(os.path.join(parser_dir or _PARSER_DIR, "parse_*.py")):
        stem = os.path.basename(path)[len("parse_"):-len(".py")]
        if stem:
            out.add(stem)
            out.add(stem.replace("_", "-"))
    return out

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


def _commit(cur) -> None:
    """Commit the cursor's connection, tolerating an autocommit connection.

    The consumer must not hold a transaction open across an LLM call — see the
    note in process_batch. On an autocommit connection there is nothing to
    commit, and psycopg2 raises rather than no-op'ing, so that case is caught.
    """
    conn = getattr(cur, "connection", None)
    if conn is None or getattr(conn, "autocommit", False):
        return
    try:
        conn.commit()
    except Exception as e:                     # pragma: no cover
        log.debug("commit skipped: %s", e)


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
    # COMMIT the claim before any model call.
    #
    # rag-api's pool sets idle_in_transaction_session_timeout=120000 on every
    # connection — a deliberate guard against held connections. A batch of N
    # sequential LLM calls inside one transaction blows straight through it:
    # Postgres logged "FATAL: terminating connection due to idle-in-transaction
    # timeout" at exactly 120s and the whole batch was lost, having already
    # marked its rows 'processing'.
    #
    # Committing here also means the claim survives: if this process dies during
    # a model call, requeue_stale() can recover those rows, which is only true
    # if the 'processing' state was actually written.
    _commit(cur)
    done = failed = parked = 0
    errors: list = []

    oversized = 0
    no_target = 0
    for r in rows:
        aid = str(r["id"])
        raw = r["content"] or ""
        if len(raw) > MAX_ARTIFACT_BYTES:
            cur.execute("""
                UPDATE raw_artifacts
                   SET llm_status = 'skipped', llm_processed_at = now(),
                       llm_error = %s
                 WHERE id = %s
            """, (f"skipped: {len(raw)} bytes exceeds ARTIFACT_LLM_MAX_BYTES="
                  f"{MAX_ARTIFACT_BYTES}. Summarising the first "
                  f"{MAX_CONTENT_CHARS} chars would describe "
                  f"{100.0 * MAX_CONTENT_CHARS / max(1, len(raw)):.2f}% of the "
                  "file as though it were the whole.", aid))
            oversized += 1
            _commit(cur)
            continue
        if not (r["target"] or "").strip():
            # Recorded, not hidden: without a target the overlap check
            # (_already_ran) and scope attribution cannot run on this artifact,
            # so its pass is not equivalent to the others in the batch.
            no_target += 1
        content = raw[:MAX_CONTENT_CHARS]
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
            # Per row, for the same reason: the next model call must not start
            # with an open transaction behind it.
            _commit(cur)
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
            _commit(cur)
            if len(errors) < 10:
                errors.append(f"{aid}: {msg}")
            log.warning("artifact %s LLM pass failed (attempt %s/%s): %s",
                        aid, r["llm_attempts"], MAX_ATTEMPTS, msg)

    return {
        "claimed": len(rows),
        "done": done,
        "retryable_failures": failed,
        "parked": parked,
        "skipped_oversized": oversized,
        "no_target": no_target,
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


def skip_redundant(cur, dry_run: bool = True, limit: int = 5000,
                   parser_dir: str = None) -> dict:
    """Mark pending artifacts SKIPPED when a dedicated parser already read them.

    57% of this queue came from nmap/masscan/nuclei/whatweb/httpx/katana, whose
    structured output is already in `ports`, `vulns` and `web_findings`. An LLM
    pass over them re-derives normalised data, and the rule engine
    (artifact_actions) has already extracted follow-ups from their text without a
    model. So the pass buys little, while 272-pending is a number nobody can act
    on.

    Rows are KEPT, never deleted: /export/burp and /export/har read artifact
    content to build the Burp sitemap and the HAR file, and 'skipped' is
    reversible — /artifacts/{id}/processed accepts it as a status, so a row can be
    put back to 'pending' if the judgement changes.
    """
    parsed = tools_with_parsers(parser_dir)
    if not parsed:
        # "Cannot read the parser directory" must mean skip NOTHING. Treating it
        # as "skip everything" would empty the queue on a bad mount.
        return {"dry_run": dry_run, "parsers_found": 0, "candidates": 0,
                "skipped": 0, "by_tool": {},
                "error": f"no parsers found under {parser_dir or _PARSER_DIR} — "
                         "skipping nothing rather than guessing"}

    cur.execute("""
        SELECT tool, count(*) AS n
          FROM raw_artifacts
         WHERE llm_status = 'pending' AND tool = ANY(%s)
         GROUP BY tool ORDER BY n DESC
    """, (sorted(parsed),))
    by_tool = {r["tool"]: r["n"] for r in cur.fetchall()}
    total = sum(by_tool.values())

    skipped = 0
    if not dry_run and total:
        cur.execute("""
            UPDATE raw_artifacts
               SET llm_status = 'skipped', llm_processed_at = now(),
                   llm_error = 'skipped: ' || tool || ' has a dedicated parser '
                               || '(etl/parse_*.py), so its structured output is '
                               || 'already stored; an LLM pass would re-derive it'
             WHERE llm_status = 'pending' AND tool = ANY(%s)
               AND id IN (SELECT id FROM raw_artifacts
                           WHERE llm_status = 'pending' AND tool = ANY(%s)
                           LIMIT %s)
            RETURNING id
        """, (sorted(parsed), sorted(parsed), int(limit)))
        skipped = len(cur.fetchall())

    return {
        "dry_run": dry_run,
        "parsers_found": len(parsed),
        "candidates": total,
        "skipped": skipped,
        "by_tool": by_tool,
    }
