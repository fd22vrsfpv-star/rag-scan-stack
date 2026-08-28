# Changelog

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
