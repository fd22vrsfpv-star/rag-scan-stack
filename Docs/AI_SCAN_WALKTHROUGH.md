# How an AI-driven scan actually works

A trace of one engagement through the stack: **nmap → ingest → AI scan recommendation → web scan**, with the
exact HTTP calls, parameters, SQL tables, and the RAG retrieval path that feeds the LLM.

Every endpoint, field name and table below was read out of the source at the commit this document was written
against. `file.py:123` references are clickable in most editors. Where a path has more than one leg, or where
behaviour surprised me, it is called out rather than smoothed over.

**Scope of this document:** the default local topology (`docker-compose.yml`), Postgres in `remote_direct`
mode, `AGENT_ENGINE=langgraph`.

---

## 0. The services, and who owns what

| Service | Port | Owns |
|---|---|---|
| `pentest-dashboard` | 3002 (https) | nginx + the BFF (`/api/*`, uvicorn on :8050) and the React UI |
| `rag-api` | 8000 | ingest endpoints, jobs/tasks, health/schema, WSTG knowledge, exports |
| `nmap_scanner` | 8012 | masscan + nmap execution |
| `scan-recommender` | 8013 | `service_prompts`, the **vector store**, embeddings, the recommendation LLM, `/rag/*` |
| `web-scanner` | — | the web pipeline (wafw00f → katana → playwright → gobuster → nikto → nuclei → zap) |
| `playwright-scanner` | — | real-browser crawl, DOM analysis, client-side checks |
| `kali-listener` | — | `/tools/execute` — the one place arbitrary tools actually run |
| `embedder` | 8030 | sentence-transformers embeddings |
| `nuclei-runner`, `pd-runner`, `zap`, … | — | individual tools |

Two rules that explain most of the design:

- **The BFF is a proxy, not a brain.** Almost every `/api/*` route forwards to one upstream service. The
  interesting logic is upstream.
- **`kali-listener` is the only general execution surface.** Everything else runs one specific tool.

---

## 1. Starting an nmap scan

### 1.1 The operator/UI call

```http
POST https://localhost:3002/api/scans/nmap
Content-Type: application/json

{
  "target": "192.168.1.150",
  "ports": "--top-ports 1000",
  "engagement_id": "a7ea4284-4d39-4a6d-a331-cbcd36bb4b72",
  "rate": 1000
}
```

`dashboard/bff/routers/scans.py:1343` — `launch_scan(scan_type, req: ScanRequest)`.

`scan_type` must be a key of `SCAN_ROUTES` (`scans.py:436`), otherwise 400. The nmap-relevant ones:

| `scan_type` | upstream | path |
|---|---|---|
| `nmap` | `nmap_scanner_url` | `/jobs/masscan-then-nmap` |
| `nmap-tcp` | `nmap_scanner_url` | `/jobs/masscan-then-nmap` (with proxy) |
| `full` | `nmap_scanner_url` | `/jobs/full-scan` |
| `masscan` | `nmap_scanner_url` | `/jobs/masscan-only` |
| `udp` | `nmap_scanner_url` | `/jobs/nmap-udp` |

`ScanRequest` (`scans.py:671`) sets `model_config = {"extra": "allow"}`, so a number of nmap options
(`service_detection`, `version_intensity`, `os_detection`, `scripts`, `scan_type_flag`, `timing`,
`script_args`, `extra_args`, `timeout_seconds`) are **not declared fields** — they ride through `extra` and are
read by `_coerce_nmap_opts` (`scans.py:369`). Useful to know when you are wondering why an option "isn't in the
model".

`port_profile` is resolved into `ports` and then explicitly nulled before forwarding
(`scans.py:1362`, `req.port_profile = None  # consumed; never forwarded downstream`).

**Gate order inside the route** (`scans.py:1349`–`1482`):

1. `_enforce_scan_scope` — the authorization gate
2. `_apply_port_profile`
3. `_apply_web_profile`
4. `_check_proxy_required`
5. `_check_scan_limit` → **429** at `scans.py:154`

### 1.2 The scope gate — fail closed

The rules live in one place: `etl/scope_gate.py`. The BFF has an *adapter*, not a copy —
`dashboard/bff/scope_guard.py:3` says so explicitly.

- `is_in_scope(host, scope_rows)` (`scope_gate.py:108`) — *"Fail closed: empty/blank host or empty scope
  returns False."*
- `check_dispatch(target, scope_rows, command, aliases)` (`scope_gate.py:282`) returns a **refusal string or
  `None`**. Notable: it also scans the command line for IPv4 literals, so a tool argument cannot smuggle a
  third-party address past a valid `target` (`scope_gate.py:303`).
- Scope source: `SELECT target, target_type FROM public.scope_targets` (`scope_gate.py:263`).

**An inconsistency worth knowing:** `SCAN_SCOPE_ENFORCE` defaults to `strict` in the BFF
(`scans.py:1303`) but `warn` in the scanner (`nmap_scanner/nmap-api.py:657`). And when the gate cannot be
imported at all, the BFF raises 503 (`scans.py:1288`) while the scanner logs and proceeds
(`nmap-api.py:648-651`). The BFF is the hard edge; the scanner's own check is defence in depth.

### 1.3 What the scanner receives

```http
POST https://nmap_scanner:8012/jobs/masscan-then-nmap
x-api-key: …
x-engagement-id: …

{ "targets": ["192.168.1.150"], "ports": "…", "rate": 1000, "timeout_seconds": null,
  "service_detection": true, "version_intensity": 9, "scripts": "banner,http-title,…" }
```

`nmap_scanner/nmap-api.py:1570`, body model `MasscanBody` (`nmap-api.py:732-757`).

The scope check is deliberately placed in `MasscanBody.validate_inputs()` (`nmap-api.py:775`) rather than in
the route — the in-code comment explains why: *"so no route can add itself later and quietly skip the check."*

Response:

```json
{"ok": true, "job_id": "…", "message": "Scan job started. Use GET /jobs/{job_id} to check status.",
 "status_url": "/jobs/…"}
```

### 1.4 Execution

`_run_masscan_then_nmap_async` (`nmap-api.py:1186`):

1. **masscan** — `masscan --rate {rate} -oJ {out} -p {ports} --wait 30 [-e iface] {targets}`
   (`nmap-api.py:1120`), output under `NMAP_OUT_DIR` (default `/app/nmap_out`, `nmap-api.py:97`).
   *Fallbacks:* non-zero exit **or empty results** → `_run_nmap_fallback` (`nmap-api.py:1167`, `:1174`), which
   retries `-sS` then `-sT`.
2. **ingest masscan** → `POST {rag-api}/ingest/masscan` (multipart `file`).
3. **nmap enrichment** — `app/run_masscan_nmap.py:97`:
   `nmap -Pn -sT -T4 -p {ports} [-sV --version-intensity N] [--script …] -oA {base} {ip}`,
   batched `NMAP_PORT_BATCH` (default 100) ports at a time.
4. Session artifacts written to `scan_results_{job_id[:8]}.json` (`nmap-api.py:1281`).

> **Gotcha:** the enrichment step walks **every open port in the database**, not just this job's targets
> (`run_masscan_nmap.py:37-90`). That is exactly why the scope gate is duplicated there — an unscoped
> enrichment pass would touch hosts the job never named.

> **Gotcha:** `_nmap_scan_opts` is a **module-global** (`nmap-api.py:105`) assigned per request
> (`:1587`). Concurrent jobs share it.

### 1.5 Polling

```http
GET https://localhost:3002/api/scans/{job_id}
```

`scans.py:1943`. If the job is tracked it goes straight to the owning service; otherwise it probes each scanner
in turn (`scans.py:1967`), then falls back to a `tool_executions` DB lookup for Kali runs
(`scans.py:1988`), then 404. Upstream truth is `GET {nmap_scanner}/jobs/{job_id}` (`nmap-api.py:888`);
status ∈ `queued|running|completed|failed|stopped`.

---

## 2. Ingest — where nmap output becomes rows

```http
POST https://rag-api:8000/ingest/nmap
Content-Type: multipart/form-data;  file=@nmap.xml
?job_id=…&target=…
```

`app/rag-api/api.py:2324` → `etl/parse_nmap.py:157`, `parse_nmap(path, profile, job_id, target)`.

**It writes exactly three tables:**

| Table | Key columns | Notes |
|---|---|---|
| `assets` | `id`, `ip`, `hostname`, `last_seen` | `parse_nmap.py:263-274` |
| `ports` | `asset_id`, `proto`, `port`, `service`, `product`, `version`, `banner`, `is_open` | `:368-390`; `version` is written as `version or extrainfo` |
| `vulns` | `asset_id`, `port_id`, `script`, `output`, `severity`, `cve text[]`, `cvss`, `metadata jsonb`, `fingerprint` | `:413-425`, `ON CONFLICT (fingerprint) DO UPDATE` |

`fingerprint` comes from `vuln_fingerprint(ip, port, script, cves)` in `etl/fingerprint.py` — the stable hash
that makes dedup work across runs and tools.

`parse_masscan` (`etl/parse_masscan.py:32`) writes only `assets` and `ports`.

**The reactive loop starts here.** `_emit_ingest_event("nmap", stats)` (`api.py:2335`) →
`_trigger_recommendations_for` (`api.py:2270`) → `_dispatch_recommender_for_ports` (`api.py:2224`), which
calls the recommender for each newly-open port. A **429 stops the whole pass** (`api.py:2258-2265`) — shed,
don't queue.

Only these sources trigger it (`api.py:2161`):
`nmap, masscan, naabu, nessus, nuclei, whatweb, wafw00f, httpx, zap`.

---

## 3. The AI step — scan recommendations

### 3.1 The call

```http
GET https://scan-recommender:8013/next_scan
      ?ip=192.168.1.150&port=80&service=http&banner=Apache/2.4.7&persist=true&use_ollama=false
```

`scan_recommender/scan_recommender.py:2067`. Note these are **query params, not a body**.

| Param | Type | Default |
|---|---|---|
| `ip` | str | required |
| `service` | str? | `None` |
| `banner` | str? | `None` |
| `port` | int? | `None` |
| `use_ollama` | bool | `False` — force the LLM even when the DB already has rows |
| `persist` | bool | `True` |

Admission control wraps the whole handler: `_next_scan_admission()` (`scan_recommender.py:1981`) is a
`BoundedSemaphore(NEXT_SCAN_MAX_CONCURRENCY)` and returns **429 + `Retry-After: 5`** rather than queueing.
`GET /next_scan/capacity` (`:2053`) reports the current limits.

### 3.2 What context it gathers (this is the interesting part)

**(a) Open ports** — `scan_recommender.py:2085`:
```sql
SELECT p.service, p.banner, p.port
  FROM public.ports p JOIN public.assets a ON p.asset_id = a.id
 WHERE host(a.ip) = %s
```

**(b) Detected technology** — `_get_detected_tech` (`:397`):
```sql
SELECT rf.data, rf.source FROM public.recon_findings rf
  JOIN public.assets a ON a.id = rf.asset_id
 WHERE host(a.ip) = %s AND rf.source IN ('httpx','whatweb')
   AND (%s IS NULL OR rf.data->>'port' = %s)
 ORDER BY rf.created_at DESC LIMIT 10
```
Tokens are taken from `data->'tech'` and `data->>'webserver'`.

**(c) Operator guidance** — `service_prompts`, selected by `selector_type` in
`port_service | tech | port | service` (`_build_guidance_block`, `:690`).

**(d) RAG knowledge context** — see §4. `_get_training_context` (`:741`).

**(e) Prior findings, used to SUPPRESS** — `_already_satisfied` (`:1117`) runs three queries against
`vulns`, `credential_findings` and `session_scan_metrics`, so the same NSE script is not recommended twice.

### 3.3 The prompt and the LLM call

`fetch_ollama_recommendations(...)` (`scan_recommender.py:1689`). The prompt is assembled at `:1699-1728`
and ends with the two retrieved blocks — `{guidance}` then `{training}` — and demands a fixed JSON shape:

```json
{"recommendations": [{"scanner": "...", "action": "...", "script": "...", "template": "..."}]}
```

Provider selection is `LLM_BACKEND` (`:1735-1763`), and **the DB wins over the env**:
`common/llm_settings.py:103-109` resolves *DB → env → default*, reading

```sql
SELECT key, value FROM app_settings WHERE key LIKE 'llm.%' AND category = 'config'
```

(`llm_settings.py:71`, 30-second cache). Refreshed per request by the middleware `_llm_settings_mw`
(`scan_recommender.py:1785`). **This is why checking env vars to find the active model misleads you.**

| Backend | Call |
|---|---|
| `azure` | `POST {azure}/…/chat/completions`, `{"model", "messages", "temperature": 0.7, "max_tokens": 2048, "response_format": {"type": "json_object"}}`, header `api-key` |
| `openai` | `POST {OPENAI_API_BASE}/v1/chat/completions`, same shape, `Authorization: Bearer` |
| `anthropic` | `POST https://api.anthropic.com/v1/messages`, `{"model", "max_tokens": 2048, "messages"}`, headers `x-api-key` + `anthropic-version: 2023-06-01` |
| `ollama` (default) | `POST {OLLAMA}/api/generate`, `{"model", "prompt", "stream": true, "format": "json"}` |

**Fallback legs:**
- Ollama is retried **without** `format=json` when the first stream returns empty (`:1409-1417`) — reasoning
  models emit nothing under the JSON constraint. Parsing therefore uses `_extract_json_object` (a
  balanced-brace scan, `:1521`), not `json.loads`.
- If the LLM fails during the hybrid pass, the **rule-based recommendations are kept** (`:2210-2221`).
- `generate_recommendations` degrades DB override → YAML tool KB → three hardcoded rules (`:975-985`).

Every result passes `filter_recommendations()`, which rejects unrunnable tool names and emits the webhook
`scan_recommender_invalid_recs_rejected` (`:2115`).

### 3.4 Persistence

`scan_recommendations` (`db_init/add_missing_tables.sql:65`):

```sql
INSERT INTO public.scan_recommendations
  (asset_id, ip, service, banner, scanner, action, script, template,
   source, model, extra, priority, engagement_id, target_kind, status)
VALUES (…, COALESCE(%s, 50), …)
ON CONFLICT (fingerprint) DO NOTHING
```

- `fingerprint` is a **generated column**: `md5(ip|service|scanner|action|script|template)`
  (`add_missing_tables.sql:87`).
- `priority integer DEFAULT 50` — **lower runs first**.
- `status` ∈ `pending|queued|running|completed|failed|skipped`.
- **There is no `port` column.** Port lives in `extra->>'port'` (`scan_recommender.py:1285`).
- Suppressed recommendations are stored as `status='skipped'` with `extra.skip_reason` — **not dropped**, so
  the UI can show why something is not being run.
- `target_kind='range'` rewrites the identity to the scope CIDR so 18 open ports don't queue 18 masscans
  (`:1305-1315`).

### 3.5 Listing and executing

```http
GET  https://localhost:3002/api/scan-recommendations?status=pending&limit=100
POST https://localhost:3002/api/scan-recommendations/run
     {"ids": ["…"], "use_kali": true, "force": false, "approve_exploits": false}
```

`dashboard/bff/routers/assets.py:589` and `:1202` (`RunRecommendationsRequest`, `:757`).

`approve_exploits` defaults to `False` — a caller that does not know the flag exists cannot auto-exploit.

Dispatch order inside `dispatch_rec` (`assets.py:1437`):

1. **Scope gate first.** Failure → `status="blocked"`, `out_of_scope=True`. **`force` cannot override scope**
   (`assets.py:1447-1466`) — it only overrides the platform's own *suppression*.
2. `target_kind` gate — anything but `service` becomes a manual follow-up (`:1468`).
3. Routing via `SCANNER_URLS` (`:1371`).
4. **Concurrency** — `asyncio.Semaphore(get_max_concurrent())` (`:2352`). The comment records the bug it
   fixes: 50 selected recommendations used to dispatch 50 scans at once.

The Kali leg (`assets.py:2087`):

```http
POST {kali_listener}/tools/execute
{"tool": "sslscan", "command": "sslscan 192.168.1.150:443", "target": "192.168.1.150"}
```

`kali_listener/listener_service.py:2114`, body `ToolExecuteRequest` (`:89`): `tool`, `command`, `target`
required; `port`, `timeout` (30–3600, default 300), `scan_id`, `service` optional.

**Guards, in order** (`listener_service.py:2122-2232`):

1. `enforce_scope(target, command)` → **403**
2. Unresolved `{placeholder}` in the command → **400**
3. `check_candidate_space` + `check_account_lockout` for brute tools → **400** + webhooks
4. Tool name must match `^[a-zA-Z0-9_.-]+$` → 400
5. **Allowlist** `get_allowed_tools()` (`:1057`) → 400
6. Shell metacharacters (`;`, `&&`, `||`, `|`, backtick, `$(`, newline) → 400

> **This is where a missing tool bites.** A tool can pass the scope gate and still be refused at step 5, or
> pass the allowlist and die with `not found`. Both were live defects: `ncrack`, `ffuf` and `feroxbuster` were
> declared in `knowledge/service_tools.yaml` and installed nowhere, and `sslscan` — needed by two
> WSTG-CRYP map entries — was likewise absent. All four are now in `kali_listener/Dockerfile` and the
> allowlist.

---

## 4. The RAG path — what actually reaches the model

This is the part most people want and it is the least obvious. There is **one corpus table**,
`exploit_chunks`, holding ExploitDB entries, playbooks, WSTG guidance, operator training notes and tool
analyses side by side, distinguished by `source_repo` and `doc_kind`.

### 4.1 Embeddings

```http
POST https://embedder:8030/embed
{"texts": ["ssh penetration testing methodology"]}
→ {"embeddings": [[...]], "model": "sentence-transformers/all-MiniLM-L6-v2", "dimensions": 384}
```

`app/embedder/main.py:49`, model from `EMBED_MODEL` (`:15`).

Backend resolution is **separate from chat**: `_resolve_embed_backend()`
(`scan_recommender/exploits_rag.py:68`) picks `azure | embedder | ollama` from `EMBED_BACKEND`. Unlike the
chat backend, **the embedding backend is env-only** — `common/llm_settings.py:44-59` carries no embed key, and
`exploits_rag.py:93-96` says so in a comment.

### 4.2 The corpus and the query

`exploit_chunks` (DDL `exploits_rag.py:226`, plus `service`, `port`, `doc_kind`, `tech` at `:261`):

```sql
SELECT id, edb_id, title, path, chunk, section_header,
       service, port, doc_kind, tech,
       1 - (embedding <=> %s::vector) AS sim
  FROM exploit_chunks
 WHERE <scope clauses>
 ORDER BY embedding <=> %s::vector
 LIMIT %s
```

`exploits_rag.py:1415`, `:1451`. The operator is `<=>` — **cosine distance**.

Retrieval is two-pass (`_retrieve`, `:1384`):

1. **Scoped pass** — `lower(service) = ANY(...)` with family expansion (http/smb/mysql/mssql/ldap/rdp,
   `:1257`), `port = %s`, `lower(tech) = ANY(...)`, `source_repo = ANY(...)`. Rows tagged `match="scoped"`.
2. **Top-up pass** — relaxes service/port/tech, keeps `source_repo`, excludes already-seen ids. Tagged
   `"topup"`. Scoped rows always sort ahead of top-ups (`:1503`).

> **Known mismatch, worth your attention:** the index is
> `ivfflat (embedding vector_l2_ops)` (`exploits_rag.py:279`) while every query orders by `<=>` (cosine).
> **The index cannot serve these queries** — they are sequential scans. Also, the static DDL declares
> `vector(768)` (`db_init/ensure_all_tables.sql:1826`) while the default embedder is 384-d;
> `_reconcile_vector_dim` (`:134`) exists to repair that and deliberately **raises** rather than corrupting
> an already-populated `exploit_chunks`.

### 4.3 Feedback-weighted re-ranking

Retrieval is not pure similarity. `_apply_feedback_ranking` (`exploits_rag.py:1360`):

```python
adj = _FEEDBACK_WEIGHT * math.tanh(net / _FEEDBACK_SCALE)   # 0.08, 3.0
r["ranked_score"] = r["sim"] + adj
```

`net` is the sum of votes for that chunk:

```sql
SELECT chunk_id, SUM(delta)::int AS net FROM (
    SELECT unnest(helpful_chunk_ids)   AS chunk_id,  1 AS delta FROM rag_feedback
    UNION ALL
    SELECT unnest(unhelpful_chunk_ids) AS chunk_id, -1 AS delta FROM rag_feedback
) v GROUP BY chunk_id
```

(`:1316`). Because the candidate pool is over-fetched `_POOL_FACTOR = 4` (`:1450`), feedback can promote a
chunk that similarity ranked 7th into the top 3. Cached 30 s, invalidated immediately on a new rating
(`:3092`).

### 4.4 Retrieval endpoints

| Endpoint | Params | Returns |
|---|---|---|
| `GET /rag/ask` (`exploits_rag.py:1674`) | `q` (required), `top_k` (1–25, default 6) | `{answer, sources, retrieved[], query_log_id, duration_ms, status, indexed_chunks}` |
| `GET /rag/tools/recommend` (`:2564`) | `service`, `port`, `include_msf=true`, `include_nuclei=true`, `include_rag=true`, `top_k` (1–10, default 3) | tool list + `rag_context` |
| `GET /rag/search/enhanced` (`:2376`) | `cve`, `service`, `version`, `port`, `query`, `top_k` (1–50), `min_confidence` (default 0.2), `embed_on_demand` | CSV/CVE matches — **not** vector search by default |
| `GET /rag/service-docs` (`:2980`) | `service`, `port`, `tech`, `limit` | ingested training docs |
| `GET /rag/wstg/{wstg_id}` (`app/rag-api/api.py:7402`) | path id | ingested WSTG guidance |
| `GET /rag/status` (`:1968`) | — | embedder reachability + dimensions |

> **Two API traps.** The BFF exposes `POST /api/rag/ask` but calls the upstream `GET /rag/ask`
> (`dashboard/bff/routers/rag.py:62` vs `exploits_rag.py:1674`) — hitting scan-recommender directly with POST
> returns 405. And `/rag/status` reports the embedding model keyed off `LLM_BACKEND` rather than
> `EMBED_BACKEND` (`:2024-2028`), so it can name the wrong model.

WSTG guidance is *not* vector-searched — it is an ILIKE on title (`app/rag-api/api.py:7338`):

```sql
SELECT chunk FROM public.exploit_chunks
 WHERE doc_kind = 'wstg' AND title ILIKE %s
 ORDER BY chunk_id LIMIT 6
```

### 4.5 Writing into the corpus

| Endpoint | Body |
|---|---|
| `POST /rag/service-docs/ingest` (`:2893`) | `ServiceDocIngest`: `title`, `content`, `service?`, `port?`, `tech?`, `doc_kind="training"` |
| `POST /rag/playbooks/ingest` (`:2684`) | `playbook_dir` (default `/knowledge/playbooks`) |
| `POST /rag/ingest` (`:1642`) | `searchsploit_json`, `exploit_root` |
| `POST /rag/refresh` (`:1819`) | chains `update_json` → `ingest` |
| `POST /kb/seed` (`scan_recommender.py:3823`) | `files?`, `dry_run`, `include_docs` — seeds `knowledge/seed/*.yaml` |
| `POST /rag/feedback` (`:3054`) | `query_log_id`, `rating` (−1…5), `helpful_chunk_ids[]`, `unhelpful_chunk_ids[]`, `comment` |

Ingest is an **atomic replace** keyed on identity — `DELETE … WHERE source_repo=%s AND edb_id=%s` then INSERT
in one transaction (`:2751`), which is what makes re-seeding idempotent instead of duplicating chunks.

### 4.6 How the context reaches the prompt

Two different assemblers:

**`/rag/ask`** (`exploits_rag.py:1731-1769`) builds `[CTX n] title > section / PATH / chunk` blocks and prefixes:

```
You are a cybersecurity assistant. Answer using ONLY the provided context.
If the answer isn't in the context, say you don't know.
```

**Scan recommendations** use `_get_training_context` (`scan_recommender.py:741`):

- query string: `service + canonical + "port N" + tech tokens + "penetration testing methodology"` (`:761`)
- retrieval restricted to `source_repos=[training, knowledge_base]` (`:773`)
- similarity floor `TRAINING_CONTEXT_MIN_SIM` (default **0.55**) applied **only to non-scoped hits** (`:794`)
- rendered as `KNOWLEDGE CONTEXT (ingested methodology for this service/port):` then `- [header] chunk[:600]`

Every `/rag/ask` call is logged to `rag_query_log` (query, embedding, top-k ids and sims, answer, duration) —
which is what makes the feedback loop and the eval harness possible.

### 4.7 What learns, and what does not

Layers 1–2 are live: queries are logged (`rag_query_log`), operators rate answers (`rag_feedback`), and the
re-rank above **does** change retrieval order. Layer 3 exports training datasets (`POST /rag/training/export`)
and layer 4 scores retrieval quality (`POST /rag/eval/run` → `rag_eval_runs`, nDCG/MRR/recall). The GRPO
trainer consumes the exports but is not wired into a scheduled loop — exporting a dataset is not the same as
training on it.

---

## 5. The web scan

### 5.1 Starting it

```http
POST https://localhost:3002/api/scans/pipeline
{"target_url": "http://192.168.1.150/", "max_paths_to_visit": 50}
```

→ `POST {web_scanner}/jobs/pipeline-scan` (`web_scanner/web_scan.py:2799`), body `PipelineReq`
(`web_scan.py:1009`): `target_url` required; `wordlist`, `max_paths_to_visit=50`, and `skip_*` booleans for
gobuster / playwright / zap / nuclei / nikto / katana / wafw00f.

Response includes the stage list:

```json
{"ok": true, "job_id": "…", "status": "queued",
 "stages": ["wafw00f","katana","playwright","gobuster","nikto","nuclei","zap"]}
```

### 5.2 Stage order (from `scan_pipeline.py:209-663`)

| # | Stage | What it contributes |
|---|---|---|
| 0 | **wafw00f** | WAF detection first, so the tester knows before anything is fired |
| 1 | **katana** | JS-aware crawl → URL set |
| 2 | **playwright** | real-browser crawl **through the ZAP proxy** → more URLs, DOM, params |
| 3 | **gobuster** | content discovery |
| 4 | **nikto** | its discovered URIs are merged into the URL list |
| 5 | **nuclei** | `POST {nuclei}/jobs/nuclei-scan` with `severity: "low,medium,high,critical"` |
| 6 | **zap** | last, so it aggregates every URL the earlier stages found; exports XML |
| 7–8 | gowitness, playwright_scan | screenshots + the per-URL security scan |

Refusals are **labelled, not raised**: an out-of-scope pipeline returns
`{"blocked": "out_of_scope", …}` and marks the job `status="blocked"` (`scan_pipeline.py:180-206`), which is
also a first-class value in the `playwright_scans.status` CHECK constraint.

> ZAP's context is set up *before* scanning (`web_scan.py:832-853`) — without an explicit context the active
> scanner silently skips the gobuster/katana URLs, which is a quiet way to get a clean report that means
> nothing.

> **Silent fallback:** if ZAP is not ready, Playwright continues **unproxied** with only a `print` warning
> (`playwright_scanner.py:253-258`). The scan still "succeeds"; ZAP just never sees the traffic.

### 5.3 Where web findings land

| Table | Key columns |
|---|---|
| `web_findings` | `url`, `source`, `issue_type`, `name`, `severity`, `evidence`, `status_code`, `cwe text[]`, `refs jsonb`, `port` (trigger-filled from the URL) |
| `playwright_findings` | `scan_id`, `url`, `finding_type`, `severity`, `title`, `evidence`, `cwe text[]`, `owasp_category`, `dom_element jsonb` |
| `discovered_params` | `url_pattern`, `param_name`, `param_type`, `http_method`, `param_location`, `sample_values text[]`, `occurrence_count` |
| `dom_analysis`, `content_extractions`, `playwright_screenshots`, `zap_sessions` | — |

Two type traps are documented in the code itself (`playwright_scanner.py:534-556`): the column is **`refs`
(jsonb), not `references`** (a reserved word — every ZAP finding from that path used to fail to save), and
`cwe` is `text[]`, so a bare `"CWE-79"` string must be wrapped in a list.

### 5.4 Client-side checks (WSTG-CLNT)

`DOMAnalyzer.get_client_security_signals()` (`playwright_scanner/dom_analyzer.py:38`) runs one
`page.evaluate()` across every `<script>` and returns
`{domSinks, evalUse, insecureWS, postMessageNoOrigin, crossOriginNoSRI}`.

`SecurityChecker.check_client_side()` (`security_checks.py:500`) turns those plus browser storage into
findings:

| finding_type | Severity | WSTG | CWE |
|---|---|---|---|
| `dom-xss-sink` | medium | CLNT-01 | CWE-79 |
| `unsafe-js-exec` | low | CLNT-02 | CWE-95 |
| `insecure-websocket` | medium | CLNT-10 | CWE-319 |
| `postmessage-no-origin` | medium | CLNT-11 | CWE-346 |
| `sensitive-browser-storage` | medium | CLNT-12 | CWE-922 |
| `cross-origin-script-no-sri` | low | CLNT-13 | CWE-353 |

A DOM-XSS sink is only reported when the *same script* also references a URL source
(`location`, `document.URL`, `location.hash`, `location.search`, `name`) — a sink alone is not a finding.

---

## 6. The whole path, end to end

```
operator / agent
      │  POST /api/scans/nmap                     dashboard/bff/routers/scans.py:1343
      ▼
  scope gate  ── refuse ──▶ 403                   etl/scope_gate.py:282  (fail closed)
      │
      ▼  POST /jobs/masscan-then-nmap             nmap_scanner/nmap-api.py:1570
   masscan ──(empty/fail)──▶ nmap -sS/-sT fallback
      │
      ▼  POST /ingest/masscan, /ingest/nmap       app/rag-api/api.py:2523 / :2324
   assets · ports · vulns                         etl/parse_nmap.py
      │
      ▼  _emit_ingest_event  ──429──▶ stop pass   api.py:2270
      │
      ▼  GET /next_scan?ip&port&service           scan_recommender.py:2067
      │      ├── ports + recon_findings + service_prompts
      │      └── RAG: embed → cosine <=> → feedback re-rank   exploits_rag.py:1384
      │             │
      │             ▼  prompt = rules + guidance + KNOWLEDGE CONTEXT
      │             ▼  LLM (backend from app_settings, DB > env)
      ▼
   scan_recommendations  (priority, status, fingerprint)
      │
      ▼  POST /api/scan-recommendations/run       assets.py:1202
   scope gate → target_kind → semaphore
      │
      ▼  POST /tools/execute                      listener_service.py:2114
   6 guards: scope · placeholders · brute-force · name · ALLOWLIST · shell metachars
      │
      ▼  web pipeline: wafw00f → katana → playwright → gobuster → nikto → nuclei → zap
   web_findings · playwright_findings · discovered_params
```

---

## 7. Things to check when it "doesn't work"

| Symptom | Most likely cause |
|---|---|
| Scan refused 403 with no obvious reason | Scope gate fails **closed** — an empty scope refuses everything (`scope_gate.py:113`) |
| Tool dispatched, result `not found` | Tool declared in `service_tools.yaml` but not installed — check `kali_listener/Dockerfile` |
| Tool refused 400 "not allowed" | Installed but missing from `get_allowed_tools()` (`listener_service.py:1057`) |
| Recommendations reference tools you don't have | `knowledge/tool_catalogs.json` is stale — re-run `scripts/refresh-tool-catalogs.sh` after any image rebuild |
| Wrong LLM answering | The active backend is in `app_settings` (DB), **not** the env — `common/llm_settings.py:103` |
| RAG returns nothing | `service_prompts` / corpus never seeded — Maintenance page → Seed knowledge, or `POST /kb/seed` |
| ZAP report suspiciously clean | ZAP wasn't ready and Playwright ran unproxied (`playwright_scanner.py:253`) |
| Recommendations page blank | 429 from `/next_scan` stopped the dispatch pass (`api.py:2258`) |
| A finding never saved | `cwe` is `text[]` and `refs` is `jsonb` — a bare string or dict is rejected |

---

## 8. Try it yourself

```bash
# 1. what the recommender would suggest, with RAG context
curl -sk "https://localhost:8013/rag/tools/recommend?service=http&port=80&top_k=3" | jq

# 2. ask the corpus directly (note: GET here, POST via the BFF)
curl -sk "https://localhost:8013/rag/ask?q=how+do+I+test+for+SSH+weak+ciphers&top_k=5" | jq '.answer, .sources'

# 3. what is actually indexed
curl -sk "https://localhost:8013/rag/status" | jq

# 4. full pipeline against an authorised target
curl -sk -X POST https://localhost:3002/api/scans/pipeline \
  -H 'Content-Type: application/json' \
  -d '{"target_url":"http://TARGET/","max_paths_to_visit":50}' | jq

# 5. follow it
curl -sk "https://localhost:3002/api/scans/JOB_ID" | jq '.status, .progress.stage'
```

Everything above respects the scope gate. If step 4 returns 403, the target is not in
`scope_targets` — which is the system working, not failing.
