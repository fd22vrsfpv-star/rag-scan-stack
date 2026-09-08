# Changelog

## 2026-09-08 — The web scan survives its own ZAP stage

A run of fixes that all trace back to one symptom: the ZAP stage of a pipeline
scan reliably killed ZAP and lost everything it had found.

### ZAP no longer dies, and findings survive if it does
- **Findings are stored as they are found** — after the spiders and every
  `ZAP_DRAIN_INTERVAL` seconds (default 60), via the same `parse_zap_alerts(dedupe=True)`
  ETL the end-of-scan path uses. The first measured run banked **958 findings
  through a ZAP death that had previously cost all of them**.
- **`wappalyzer` (Technology Detection) removed.** Its passive rule took 40–110s
  per message — 327 warnings naming that one rule — and drove ZAP to 11.98 GiB.
  Removing it held the crawl **flat at 2.335 GiB** where it had previously died.
  No coverage cost: INFO-08/09 come from whatweb/httpx evidence.
- **Passive scanning pauses for the active scan** (`ZAP_PSCAN_DURING_ACTIVE_SCAN=false`),
  and `pscan_only_in_scope` now defaults to `true` — ZAP's own default is `false`,
  i.e. it passive-scans third-party resources the target merely links to.
- **The active scanner is bounded**: 8 threads per host (was 64), 5 min per rule
  and 60 min per scan (both were unlimited). The per-rule bound is the general
  one — it stops whichever rule runs away next.
- **The active scan runs as five per-category passes**, using ZAP's own policy
  categories, Client Browser **last** because it launches a real browser. Each
  pass banks its findings first, so a later crash cannot take earlier results.
  `ZAP_ASCAN_SPLIT=false` restores single-pass behaviour.
- **`GET /api/zap/status` reports `pscan_queue`** — the unbounded passive queue
  holds whole HTTP messages, so its depth is what predicts a memory death.

*Result on the same target and profile:* all five passes completed including
Client Browser, **639 findings**, `restarts=0`, peak 7.58 GiB under a 12 GiB
ceiling. Previously: dead at ~5,000 messages with nothing stored.

### A gated scan now actually uses its proxy
`block_local_scans` requires a proxy, but the gate was satisfied by the parameter
merely being **present**. Pydantic defaults to `extra="ignore"`, so a request
model that did not *declare* `proxy` discarded it silently — the gate passed, the
job file recorded the proxy, and the traffic left from the host's own address.
Three of five routes were affected (`pipeline-scan`, `gobuster`, `nikto-scan`).

Also fixed in the shared `proxied_scan()`: it **failed open** (ZAP proxy setup was
wrapped in `except Exception: logger.warning` and scanned on regardless); global
state was never restored; `ALL_PROXY` was routing the scanner's own internal
service calls through the operator's egress node; and `requests` had no SOCKS
support in the image at all.

### Maintenance
- **Knowledge seeding is a background job.** It was never hung — 585 docs at
  ~1.45s each is ~14 minutes inside one HTTP request, behind a 900s timeout, so
  the request was abandoned and the work discarded every time. `POST /kb/seed`
  now returns a `job_id` in 0.04s with a status endpoint and per-doc progress;
  `dry_run` stays inline.
- **Wordlists are checked at boot.** A stale `WORDLIST` cost a full pipeline —
  crawl, render and spider all ran before content discovery failed on a path that
  had been wrong since startup. A gobuster timeout also **keeps the paths already
  found** instead of discarding them, and reports `timed_out` / `complete`.

### Tests
Six new guard modules, all sabotage-proven:
`test_zap_pscan_tuning`, `test_zap_ascan_split`, `test_zap_addon_policy`,
`test_zap_progressive_findings`, `test_scan_proxy_forwarding`,
`test_wordlists_exist`.

Two existing guards were **re-anchored, not weakened**, when `ascan.scan()` moved
into `_run_active_pass` — the drain guard now finds whichever function actually
polls `ascan.status`, and was re-sabotaged in its new location.

*Known:* with docker available to the test runner, ~68 normally-skipped tests
execute and 9 pre-existing failures surface (verified identical on `main`):
`test_export_completeness`, `test_image_freshness`, `test_scan_parameters` (×2),
`test_scope_learn`, `test_target_wordlists` (×4). Not addressed here.

See `Docs/WEB_SCAN_TUNING.md` for the operator reference and
`Docs/CHANGES_MADE.md` for the measurements behind each decision.


## 2026-08-28 — LangGraph is the agent engine; AutoGen retired

### Agent orchestration
- **AutoGen retired.** `pyautogen` removed from `autogen_agents/requirements.txt`;
  nothing imports `autogen`. Deleted `pentest_agents.py` (`PentestTeam`, GroupChat
  + custom speaker selection, 1231 lines), the AutoGen agent factories in
  `agent_config.py` (157 lines), the AutoGen session runner in
  `autogen_service.py` (570 lines), `attempt_session_recovery`, the
  `OpenAIWrapper.create` metrics monkeypatch, and `POST /pentest/{id}/nudge`.
  The service, container and directory keep the `autogen` name for continuity.
- **LangGraph is the only engine.** `AGENT_ENGINE` and the per-request `engine`
  field are kept; `autogen` is now a *recognised-but-retired* value that logs a
  warning and runs LangGraph, so launch presets saved earlier still work.
- **New `tool_registry.py`** — one declarative list of the 49 tools an LLM may
  call (name, LLM-facing description, callable). Replaces three
  hand-maintained copies of the roster.
- **Exploit approval is a native `interrupt()`** — three nodes
  (`exploit_plan` → `exploit_approval` → `exploit_exec`) so nothing runs twice on
  resume. New `GET /pentest/engine`, `GET /pentest/{id}/pending-approval`,
  `POST /pentest/{id}/approve`; new session status `awaiting_approval`.
- **Stall recovery removed, stall detection kept.** Recovery worked by nudging
  `groupchat.messages`; there is no speaker-selection loop in a StateGraph.

### Fixed
- `get_scan_recommendations` returned HTTP 500 for every call: scan-recommender
  embedded via `OLLAMA_HOST` (`ollama:11434`) in a deployment with no ollama
  container. Embeddings now resolve independently of `LLM_BACKEND` via
  `EMBED_BACKEND` (default `auto`), and the pgvector column dimension is
  reconciled on a backend switch instead of failing on the first insert.
- **The embedder served plain HTTP while all four callers used
  `https://embedder:8030`** — every embed call failed with
  `SSLError WRONG_VERSION_NUMBER`. The cert already carried `DNS:embedder`; the
  compose `command:`/certs mount were missing. This is why `scope_decisions`
  held 1151 rows with 0 embeddings.
- `scope_classifier` posted `{"text": …}` and read `["embedding"]`; the
  embedder's contract is `{"texts": […]}` → `{"embeddings": [[…]]}`. The 422 was
  swallowed by a bare `except`.
- **Every `langgraph_*` webhook event was discarded.** `_ALL_EVENT_TYPES` on the
  `event-log` webhook is an allow-list; `/webhooks/emit` returned 200 and
  dropped them, so the Agent Activity timeline showed nothing for any LangGraph
  session.
- LangGraph sessions never set the `scan_tracker` session context, so `/scans`
  was empty and `port_profile`/`web_profile` were silently ignored.
- LLM metrics were fed by an AutoGen-only monkeypatch — replaced with a
  LangChain callback writing the same `llm_request_metrics` rows.
- `auto_run_recommendations` was accepted by the LangGraph engine and ignored.
- Session output collection, scan metadata and `_finalize_session` (flow
  summary, claim validation, KB drain) ran only on the AutoGen path; ported.
- `mcp_tools_bridge.NATIVE_TOOL_NAMES` had drifted: it listed the non-existent
  `start_nikto_scan` and omitted `get_attack_vectors` and
  `start_subdomain_takeover`, so an MCP server could shadow a scope-gated local
  tool body. Derived from the registry now.
- The analyze phase silently truncated at its step budget and returned
  LangGraph's "Sorry, need more steps…" as if it were the analysis.
- scan-recommender startup wasted ~60s per restart waiting for an Ollama host
  that does not resolve.
- `tests/test_extractor_learn.py` had an unclosed triple-quote and **aborted
  collection of the entire suite** — `pytest tests/` had never completed.
- `test_proxy_contracts` false-positived on `/agent-flags/{}/{}`; both actions
  are now checked rather than exempted.

### Database
- New status value `awaiting_approval` on `agent_sessions`.
- LangGraph checkpoint tables (`checkpoints`, `checkpoint_blobs`,
  `checkpoint_writes`, `checkpoint_migrations`) declared in `db_init/` and
  asserted by both health-check scripts and rag-api.

## Unreleased
- Initial extraction of RAG Scan Stack with patched DB schema, nmap -sV, web scanner, nuclei runner.
