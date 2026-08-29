# AutoGen → LangGraph Migration Plan (DRAFT for review — no code yet)

Date: 2026-08-27
Status: **Proposal.** Nothing here is built. Review and approve before any code.

## 0. Why this document exists
The interactive AI agents run on **AutoGen** (`pyautogen==0.2.18`) in the
`autogen-agents` service (port 8015), NOT LangGraph. This plan describes moving
that orchestration to **LangGraph** while preserving every authorization
invariant and the operator-facing session API the dashboard depends on.

The deterministic follow-up pipeline (extractor profiles, rule engine, KB
scan-recommender) is **out of scope and unchanged** — it is not agentic and does
not move.

## 1. Current architecture (what we're migrating)
- **Service:** `autogen_agents/` → container `autogen-agents:8015`. FastAPI.
- **Agents (one `GroupChat`):** Coordinator, Reconnaissance, Scanner, Analyzer,
  Exploit, Reporter, Executor (`UserProxyAgent` that runs tool calls).
  Orchestrated by `GroupChatManager` with LLM **speaker selection**.
- **Tools:** **92** registered functions (`start_subfinder`, `start_nmap_scan`,
  `query_assets`, `get_scan_recommendations`, `start_nuclei_scan`, …) in
  `pentest_agents.py`, bound via `register_function_to_agent`. Also exposed over
  MCP (`mcp_server.py`, `mcp_tools_bridge.py`). The tool bodies call rag-api /
  scanner endpoints — **these already pass the scope gate + concurrency limit.**
- **LLM:** Ollama-compatible (DeepSeek proxy) with Azure fallback
  (`agent_config.py`); per-request metrics via a monkeypatch (`llm_metrics.py`).
- **Session API (BFF proxies `/api/agent-sessions/*` → these):**
  `/pentest` (start), `/pentest/{id}/resume|stop|nudge|delete`,
  `/pentest/{id}` , `/flow-summary`, `/messages`, `/scans`, `/report`,
  `/sessions`, `/pentest/mcp-tools`, `/pentest/watchdog`.
- **Persistence:** `agent_sessions` + `agent_session_messages` (Postgres),
  `parent_session_id` for resumed sessions, status incl. `stalled`.
- **Reliability scaffolding (telling):** `session_watchdog`,
  `attempt_session_recovery`, `/nudge`, dynamic timeouts — much of this exists to
  handle **GroupChat speaker-selection stalls**, a failure mode LangGraph's
  deterministic edges remove.

## 2. Target architecture (LangGraph)
A `StateGraph` per session, one durable graph run per `thread_id = session_id`.

| AutoGen concept | LangGraph equivalent |
|---|---|
| `GroupChat` + `GroupChatManager` | `StateGraph` with a **supervisor** node |
| LLM speaker selection | **Deterministic conditional edges** (phase/state-driven), LLM routing only where genuinely needed |
| Coordinator agent | supervisor node (routes by state: recon done? ports found? findings?) |
| Reconnaissance / Scanner / Analyzer / Exploit / Reporter | one node (or subgraph) each |
| Executor (`UserProxyAgent`) | `ToolNode` (LangGraph prebuilt) |
| 92 `register_function` tools | same Python bodies wrapped as LangGraph `@tool`s (reuse `scan_tools.py` / MCP bridge — **implementations do not change**) |
| `agent_session_messages` (manual) | **PostgresSaver checkpointer** (native, durable) |
| `parent_session_id` resume hack | resume by `thread_id`; checkpointer restores state |
| `UserProxy` human input / `/nudge` | `interrupt()` (human-in-the-loop) + `Command(resume=…)` |
| `session_watchdog` / recovery | mostly unnecessary; keep a wall-clock timeout guard |

**State schema (sketch):**
```
class SessionState(TypedDict):
    session_id: str
    engagement_id: str | None
    phase: Literal['recon','scan','analyze','exploit','report','done']
    messages: Annotated[list, add_messages]
    scan_jobs: list[dict]      # dispatched job ids + status
    findings: list[dict]
    scope: dict                # cached scope for gate checks
    awaiting_human: bool
```

## 3. Invariants that MUST survive (enforced by tests — do not regress)
- **Scope gate (fail-closed):** tool bodies dispatch through the SAME scope-gated
  endpoints. A LangGraph tool node is still "a dispatcher" under CLAUDE.md — it
  must call the existing dispatch path, never a new one. *Guard:*
  `test_dispatch_invariants::test_no_new_ungated_dispatchers` must stay green.
- **`MAX_CONCURRENT_SCANS`:** unchanged (same dispatch bodies).
- **Override ≠ authorization:** a forced out-of-scope call is still refused.
- **Webhooks:** every node action emits an event (`/webhooks/emit`) → Agent
  Activity timeline. Add `agent_engine=langgraph` to payloads for A/B visibility.
- **LLM metrics:** re-instrument via a LangChain callback handler writing the
  same `llm_request_metrics` rows (replaces the AutoGen monkeypatch).
- **Session API shape:** `/messages`, `/flow-summary`, `/report`, `/scans`
  response shapes the frontend renders MUST be preserved (adapter layer).

## 4. Phased rollout (strangler — both engines coexist, flag-selected)
- **Phase 0 — Spike (no user impact).** Add `langgraph` to
  `autogen_agents/requirements.txt` (resolves clean: langgraph 1.2.11,
  langgraph-checkpoint 4.2.0, langchain-core 1.6.1, pydantic 2.13.4 OK). Build a
  throwaway 3-node graph (recon→scan→report) that imports 3–4 existing tool
  bodies. Prove: tools fire, scope gate holds, PostgresSaver checkpoints/resumes.
- **Phase 1 — Engine behind the same API.** Introduce `AGENT_ENGINE` env
  (`autogen` default | `langgraph`). Implement the graph behind the existing
  `/pentest*` routes via an adapter that maps graph state ↔ the current response
  shapes. BFF and frontend unchanged.
- **Phase 2 — Tool parity.** Wrap all 92 tools as LangGraph tools (mechanical;
  reuse bodies + the MCP bridge). Add a parity test: for a fixed scenario, the
  set of dispatched endpoints matches AutoGen's.
- **Phase 3 — One flow at a time.** Cut over read-only **recon** first (lowest
  risk), validate on `redteam3`, then scan/analyze, then exploit (gated) last.
  Native checkpoint resume replaces `parent_session_id`; `interrupt()` replaces
  `/nudge`.
- **Phase 4 — Flip default & retire AutoGen.** Default `AGENT_ENGINE=langgraph`,
  keep AutoGen as fallback one release, then remove `pyautogen` + the
  watchdog/recovery scaffolding once parity holds.

## 5. What we GAIN (why it's worth it)
1. **Removes the speaker-selection stall class** — the watchdog, recovery,
   dynamic-timeout and `/nudge` machinery exist to babysit GroupChat. Deterministic
   edges make most of it unnecessary.
2. **Native durable checkpointing + resume** (PostgresSaver) replaces manual
   message persistence and the `parent_session_id` resume hack.
3. **Clean human-in-the-loop** via `interrupt()` (approve an exploit step, feed a
   credential) instead of UserProxy input modes.
4. **Cheaper, more predictable control flow** — routing is code, not an LLM call
   per turn; LLM used only inside nodes that need reasoning.
5. **Better observability** — typed state + checkpoints per step.

## 6. Risks / cost
- **Tool re-binding (92):** large but mechanical; bodies reused, so low logic risk.
- **LLM metrics re-instrumentation:** must match `llm_request_metrics` columns.
- **Response-shape parity:** `/flow-summary`, `/messages`, `/report` feed the UI;
  needs an adapter + snapshot tests.
- **Human-in-the-loop semantics:** map `/nudge`/resume to `interrupt`/`Command`.
- **Two engines during migration:** more surface area until Phase 4.
- **Effort:** medium–large (multi-week), front-loaded by Phase 0–2; de-risked by
  strangler + tool reuse. No big-bang cutover.

## 7. Explicit non-goals
- Not touching the deterministic follow-up pipeline (extractors/rules/KB).
- Not changing the scope gate, concurrency limits, or webhook contract.
- Not changing the BFF or frontend session API (adapter preserves shapes).

## 8. Decision needed to start
Approve Phase 0 (the spike: add the dep, 3-node graph, prove tools + scope gate +
checkpoint on `redteam3`). It's reversible and touches only the autogen-agents
service. Everything after is gated on the spike's results.

## 9. Phase 0 RESULTS — DONE (2026-08-27) ✅
`autogen_agents/langgraph_spike.py` (standalone, not wired in). Ran in the
autogen-agents container against the live stack. All three proofs PASS:
- **Tools fire:** `scan_tools.query_assets(limit=5)` returned 2535 chars of live
  asset data through the UNCHANGED tool body from a LangGraph node.
- **Scope gate holds:** a node attempting `nmap 203.0.113.99` (TEST-NET-3) was
  REFUSED — "target 203.0.113.99 is not in the configured scope" — via the same
  `enforce_target_scope` the AutoGen tools use. No new ungated path.
- **Checkpoint/resume:** `PostgresSaver` persisted the run (5 checkpoints for the
  thread); the graph interrupted before `report`, then a second
  `invoke(None, cfg)` resumed from the Postgres checkpoint by `thread_id` and
  completed. This is the native replacement for manual message persistence +
  `parent_session_id`.

Install validated clean in the container: langgraph 1.2.11,
langgraph-checkpoint-postgres, psycopg[binary]; added to
`autogen_agents/requirements.txt` for the Phase 1 rebuild. Notes:
- `PostgresSaver.setup()` creates library-managed tables (`checkpoints`,
  `checkpoint_blobs`, `checkpoint_writes`, `checkpoint_migrations`). When
  productionised in Phase 1 these must be added to `db_init/*` + the health check.
- The spike used the ephemeral in-container install; the requirements change takes
  effect on the next autogen-agents rebuild (deferred to Phase 1 to avoid
  disrupting the running agent service).

**Next decision:** approve Phase 1 (introduce `AGENT_ENGINE` flag + the graph
behind the existing `/pentest*` routes via an adapter). Rebuild autogen-agents
then.

## 10. Phase 1 RESULTS — DONE (2026-08-27) ✅
Engine behind the same API, flag-gated, autogen-agents rebuilt (durable).
- **`AGENT_ENGINE` flag** (`autogen` default | `langgraph`): env in
  `docker-compose.yml`; branch at the top of
  `autogen_service.run_pentest_session_sync` delegates to the LangGraph engine.
  Default unchanged → current users see no difference.
- **`langgraph_engine.py`** — deterministic supervisor `StateGraph`
  (recon → scan → analyze → report). Reuses `scan_tools` bodies unchanged
  (scope gate intact); writes to the SAME `agent_sessions`/`agent_messages`
  tables via db_utils; checkpoints to Postgres (thread_id = session_id); emits
  webhooks (`langgraph_session_started/_phase_completed/_completed`, tagged
  `engine=langgraph`).
- **Verified live** (auto_execute=False, in-container end-to-end): session
  active→**completed**; **5 messages** (Coordinator/Reconnaissance/Scanner/
  Analyzer/Reporter) so `/sessions`, `/messages`, `/pentest/{id}` and the UI
  render it identically; real tools fired (query_assets, query_open_ports,
  get_scan_recommendations, query_vulnerabilities — all 200); **6 Postgres
  checkpoints**; webhooks 200. A `get_web_findings` 404 (pre-existing tool-path
  bug) was caught by the defensive `_tool` wrapper without crashing the graph.
- **Durability:** langgraph 1.2.11 + langgraph-checkpoint-postgres +
  psycopg[binary] baked into the autogen-agents image; service healthy on
  default `autogen`.
- **Note (carry to Phase 3):** `PostgresSaver.setup()` (called on each langgraph
  session start, idempotent) auto-creates the checkpoint tables
  (`checkpoints`, `checkpoint_blobs`, `checkpoint_writes`,
  `checkpoint_migrations`). They are library-managed; a fresh install self-heals
  on first langgraph session. Document in db_init when langgraph becomes default.

**Next decision:** Phase 2 — wrap all tools as LangGraph tools + a parity test,
then Phase 3 (cut recon over first) and richer supervisor routing.

## 11. Phase 2 RESULTS — DONE (2026-08-27) ✅
Tool surface parity. (Correction: the AutoGen roster is **49** distinct
`register_for_llm` tools, not the ~92 estimated earlier — that count included
duplicate registrations across agents + non-tool matches.)
- **`autogen_agents/langgraph_tools.py`** — the LangGraph tool surface is
  DERIVED from the AutoGen registrations (parses `register_for_llm(name=...)(fn)`
  in pentest_agents.py and resolves each callable from that module's namespace),
  then wraps them as LangChain `StructuredTool`s. Parity is by construction — the
  two cannot drift. Verified: **49/49** tools resolved, 49 LangChain-wrapped, 0
  unresolved (incl. the mismatched-name ones: `list_pending_exploits` →
  `list_pending_exploits_tool`, `search_msf_modules` → `search_msf_modules_tool`).
- **`tests/test_langgraph_tool_parity.py`** — executable guard. Skips cleanly
  without the autogen deps. **Sabotage-proven:** injecting a parsed-but-
  unresolvable AutoGen tool turns it RED
  (`LangGraph cannot provide these AutoGen tools: ['fake_tool_xyz']`); clean →
  2 passed.
- Tool BODIES unchanged, so scope gate / concurrency / webhooks are identical
  regardless of which engine calls a tool. `langgraph_tools` isn't runtime-
  imported by the engine yet (that's Phase 3), so no rebuild was required; it
  bakes into the image on the next build.

**Next decision:** Phase 3 — bind `LANGGRAPH_TOOLS` to an LLM `ToolNode`, give the
supervisor real routing, and cut the read-only recon flow over first on redteam3
with a dispatched-endpoint comparison vs AutoGen.

## 12. Phase 3 RESULTS — recon cutover DONE (2026-08-27) ✅
The recon phase is now a real LLM agent; the other phases stay deterministic until
their own cutover (scan/analyze/exploit are the remaining increments).
- **`_chat_model()`** targets the SAME active backend AutoGen uses (`get_llm_config`
  → **DeepSeek-V4-Flash via Azure `/openai/v1`**), handling `openai` and `azure`
  api types.
- **Recon node = `create_react_agent`** (LLM ↔ `ToolNode`) over a **read-only**
  subset (10 tools: query_assets/open_ports/vulnerabilities/web_findings/
  search_all_findings/attack_vectors/credential_findings/exploitdb/system_status/
  active_jobs — NO `start_*`). Deterministic fallback if the LLM errors, so a
  session never hard-fails.
- **Proven live on redteam3:** the agent ran a multi-turn tool loop
  (`query_assets`, `query_open_ports`, `search_all_findings`×3, `get_attack_vectors`)
  and produced a genuine recon summary (1,828 assets across AWS/Azure/on-prem, key
  hosts + ports). Fallback also proven: on a `429 RateLimitReached` the session
  completed via deterministic recon with real data.
- **Dependency resolution:** langgraph 1.x → langchain-core 1.x → langchain-openai
  → openai≥3. Relaxed `openai==1.10.0` to `openai>=1.3,<4`; verified AutoGen 0.2.18
  `OpenAIWrapper` builds and its completion API surface is intact on openai 3.5.0
  (the 1.x→3.x change didn't touch AutoGen's path). langgraph pinned `<2` so
  `create_react_agent` stays valid. autogen-agents rebuilt; healthy on default
  `autogen`.
- **Pre-existing bugs surfaced (NOT introduced here, affect AutoGen too):**
  (a) `get_scan_recommendations` → 500: scan-recommender `/rag/ask` calls
  `…/openai/v1/embeddings` which 404s (Azure DeepSeek has no embeddings route) —
  dropped from the recon toolset; (b) DeepSeek-V4-Flash has a low rate limit in
  centralus (429 under sustained testing) — the fallback handles it.
- **Not yet done (carry forward):** a full AutoGen GroupChat *session* was not
  re-run on openai 3.5.0 (rate limits + quota) — verified at import/client level
  only; the supervisor still routes deterministically (recon is the only LLM
  phase); scan/analyze/exploit cutover + `interrupt()`/nudge wiring remain.

**Next decision:** Phase 4 — flip default `AGENT_ENGINE=langgraph` behind a canary,
cut scan/analyze over, wire `interrupt()` for exploit approval, add the langgraph
checkpoint tables to db_init + health check, then retire the AutoGen scaffolding.

## 13. Phase 4 RESULTS — default flipped, scan/analyze cut over, HITL landed (2026-08-28) ✅

### What changed
- **Default engine is now LangGraph.** `DEFAULT_AGENT_ENGINE = "langgraph"` in
  `autogen_service.py`, `AGENT_ENGINE: ${AGENT_ENGINE:-langgraph}` in
  `docker-compose.yml`, `AGENT_ENGINE=langgraph` in `.env` / `.env.example`.
- **AutoGen is the fallback for one release, and the canary is per session.**
  `POST /pentest {"engine": "autogen"}` pins ONE session to either engine with no
  restart and no shared state; the *resolved* engine is persisted in the session
  `configuration`, so a run stays correctly labelled after the default moves (an
  A/B comparison where past runs relabel themselves is worthless). A resumed
  session inherits its parent's engine. `GET /pentest/engine` reports the
  resolved engine plus whether each engine is loadable.
- **scan + analyze are now LLM agents** (same `create_react_agent` pattern as
  recon), each with its own toolset and a deterministic fallback. The
  `auto_execute` contract is enforced by the **toolset, not the prompt**: with it
  off the scan agent is handed no `start_*` tool at all. `SCAN_TOOLS_DISPATCH`
  deliberately excludes credential brute force (`start_brutus`,
  `start_credential_check`) so an unattended session's blast radius is
  enumeration only.
- **Human-in-the-loop exploit approval via native `interrupt()`** (opt-in:
  `enable_exploit_phase`, `LANGGRAPH_EXPLOIT_PHASE`, off by default because a
  session with it on *parks* until a human answers). Three nodes, not one:
  `exploit_plan` (LLM, read-only + `queue_exploit_for_approval`) →
  `exploit_approval` (`interrupt()` only) → `exploit_exec`. The split is
  load-bearing: **a node containing `interrupt()` re-runs from its start on
  resume**, so any side effect in front of the pause would happen twice (a
  duplicate queued exploit, a second LLM bill).
  New routes: `GET /pentest/{id}/pending-approval` (reads the *checkpoint*, so it
  is correct after a restart) and `POST /pentest/{id}/approve`
  (`Command(resume=…)` continues the SAME session — no new row, no
  `parent_session_id`, no replay).
- **New session status `awaiting_approval`** — added to the `agent_sessions`
  CHECK in `db_init/ensure_all_tables.sql`, `create_agent_tables.sql`,
  `setup_alldb.sql` and the runtime self-heal migration in `db_utils.py`. It is
  deliberately NOT `active`: the watchdog only inspects `active`, so a parked
  session is no longer mistaken for a stall and "recovered".
- **Checkpoint tables are now declared**, not runtime magic:
  `db_init/create_langgraph_checkpoint_tables.sql` (+ the same block in
  `ensure_all_tables.sql`), asserted by `scripts/post-install-check.sh`,
  `scripts/ensure_db_schema.sh` and rag-api `health_router.py`. DDL is copied
  verbatim from `langgraph.checkpoint.postgres.base.MIGRATIONS`, and
  `checkpoint_migrations` is left **empty on purpose** — the library reads
  `MAX(v)` to decide what to apply and every migration is idempotent, so empty
  means "re-apply all" (correct). Seeding versions would make it SKIP work.
- **UI**: `awaiting_approval` gets a pulsing purple dot and an "awaiting
  approval" badge, is filed under LIVE sessions (not history — that is how an
  approval sits unnoticed), and gets an approval banner with the candidate,
  Approve & run / Decline, and a link to Pending Exploits. The launch form gained
  an **Engine** selector and an **Exploit phase** checkbox; the session detail
  shows which engine the run used.

### Parity gaps found and closed (these would have broken on the flip)
1. **`scan_tracker.set_session()` was never called.** Every LangGraph session
   therefore had an empty `/scans` view, and `port_profile` / `web_profile` were
   accepted by the API and silently ignored — the operator's port scope simply
   did not apply.
2. **No LLM metrics.** `llm_request_metrics` is fed by a monkeypatch on AutoGen's
   `OpenAIWrapper.create`, which a LangChain client never goes through — so
   flipping the default would have emptied the cost/latency dashboards.
   Replaced with a LangChain callback handler writing the identical row shape.
   *Verified:* 16 rows for one live session with per-agent attribution, tokens,
   latency, tool names, and an `is_error=True` row for a 429.
3. **Every webhook event was being dropped.** `_ALL_EVENT_TYPES` on the
   `event-log` webhook is an **allow-list**, not a catch-all. `/webhooks/emit`
   answered 200 and the events were discarded, so the Agent Activity timeline
   showed nothing for any LangGraph session — Phase 1's "webhooks 200" was true
   and misleading. The nine `langgraph_*` types are now in the list
   (`app/rag-api/webhooks/router.py`, applied on startup so existing installs
   self-heal). *Verified:* 11 events on the timeline for one park+resume run, all
   `status=delivered`, tagged `engine=langgraph`.
4. **The AutoGen fallback could not start a session at all.** Phase 4's premise
   is "AutoGen stays available for one release", so this had to be true rather
   than assumed. It was not: `POST /pentest {"engine":"autogen"}` failed with
   *"Pre-flight check failed: Azure endpoint or API key not configured"*.
   Cause (pre-existing, nothing to do with LangGraph): the active backend moved
   into the dashboard DB, so `get_llm_backend()` answers `azure` from the DB
   while `check_azure_sync()` still reads the raw `AZURE_ENDPOINT` /
   `AZURE_API_KEY` env vars — both **empty** here. The DB config
   (`DeepSeek-V4-Flash` at `https://rt3ai.services.ai.azure.com/openai/v1`) was
   fine, and the LangGraph engine used it happily, which is exactly why nobody
   noticed. Fixed with `check_resolved_llm_sync()`: ping the config the agents
   are actually built from, fall back to the env-var checks only when it
   resolves nothing, and treat a **429 as healthy** (rate-limited means
   reachable and authorised; refusing to start does strictly less than starting
   and letting the session's own retries handle it).
   *Verified:* `LLM check passed (azure): DeepSeek-V4-Flash healthy at
   https://rt3ai.services.ai.azure.com/openai/v1`, then a real AutoGen GroupChat
   session ran to `completed` with 5 messages.
5. **The analyze phase was silently truncated.** `recursion_limit` counts graph
   super-steps and one tool-using turn costs TWO, so the old budget of 14 was
   ~7 tool rounds. Analyze made 10 calls on its first live run and returned
   LangGraph's "Sorry, need more steps to process this request." in place of an
   analysis — which reads like a model refusal. Budgets are now per phase
   (`PHASE_STEP_BUDGET`) and a truncated answer is labelled `[TRUNCATED …]`
   instead of being stored as the phase's conclusion.

### Verified live (observed, quoted)
- `GET /pentest/engine` and the BFF proxy:
  `{"engine":"langgraph","default":"langgraph","env_AGENT_ENGINE":"langgraph",…,"availability":{"langgraph":{"available":true},"autogen":{"available":true}}}`
- **A real LLM session on the new default** (`321ac742…`, exploit phase on,
  `auto_execute=false`): recon ran a 3-call tool loop, analyze a 10-call loop,
  scan fell back on a 429, and exploit planning skipped the gate rather than
  parking on a candidate that was never queued — every fallback behaved as
  designed and the session completed.
- **Park + resume, end to end, across processes.** The graph parked with
  `status=awaiting_approval`, **6 Postgres checkpoints**, the payload in session
  metadata; the *service* process then read that interrupt back through
  `GET /api/agent-sessions/{id}/pending-approval` (written by a different
  process — the durability proof). `approved=true` with no `pending_exploit_id`
  → **400**. Decline → resumed to `completed` with
  `operator exploit decision: approved=False`, and the summary still showed the
  earlier phases' real tool counts, i.e. **nothing was replayed**. Approve with a
  well-formed but non-existent id → reached the real gated body and reported
  `{"ok": false, "error": "Exploit not found"}`, proving the wiring without
  firing an exploit.
- Endpoint status codes: malformed uuid **400**, unknown session **404**,
  not-parked session **409**, live session pending-approval **200**.
- `agent_sessions_status_check` on the live DB now includes
  `'awaiting_approval'` (runtime migration self-healed it).

### Tests
- `tests/test_langgraph_phases.py` — 20 cases. Reads the phase tool-name sets out
  of `langgraph_engine.py` with `ast` instead of importing it, so the guard runs
  on a bare checkout rather than skipping everywhere. Covers: every phase tool
  exists in the AutoGen roster; no read-only phase holds a dispatcher; the scan
  phase excludes brute force; **`execute_approved_exploit` appears in no toolset
  and is called from exactly one function (`exploit_exec`)**; the default engine
  and the compose/.env defaults agree; and the real graph parks, resumes
  approved, resumes declined, never parks with the phase off, and never parks
  with no candidate.
  **Sabotage-proven, all three restored:** `start_nmap_scan` into
  `SCAN_TOOLS_READONLY` → RED; `execute_approved_exploit` into
  `EXPLOIT_PLAN_TOOLS` → RED; `interrupt()` replaced by a plain return → RED.
- Green: `test_dispatch_invariants`, `test_langgraph_tool_parity`,
  `test_proxy_contracts`, `test_route_contracts`, `test_fstring_placeholders`.
- **Fixed a pre-existing red baseline** (failing on HEAD before this work):
  `test_proxy_contracts::test_upstream_paths_exist` flagged
  `/agent-flags/{}/{}` because the action segment was an inline tuple. Named it
  `AGENT_FLAG_ACTIONS` and moved it into `DYNAMIC_SEGMENT_SOURCES`, so both
  actions are now *checked* against declared upstream routes rather than
  exempted. `PROXY_DYNAMIC` stays a one-entry list.

### Still open — as written at the END OF PHASE 4. Superseded; see §14 and below.
- ~~**AutoGen is not yet removed.**~~ Retired in Phase 5 (§14).
- ~~**`get_scan_recommendations` still 500s.**~~ Fixed 2026-08-28: embeddings now
  resolve via `EMBED_BACKEND` independently of `LLM_BACKEND`, and the embedder
  serves TLS. Returns grounded answers with cited playbook sources.
- **DeepSeek-V4-Flash rate-limits (429) in centralus** under sustained use. The
  per-phase fallbacks absorb it, but a session that hits it loses that phase's
  reasoning. A higher-quota deployment or a second backend would fix it.
- ~~A full AutoGen GroupChat session has still not been re-run on openai
  3.5.0~~ — **done in Phase 4.** Session `ab8de451…` ran on `engine=autogen`,
  pre-flight passed, GroupChat produced 5 messages, status `completed`. The
  Phase 3 concern (openai 1.x → 3.x breaking AutoGen) is now closed by an actual
  session, not just an import check.
- Native `interrupt()` now covers exploit approval; `/nudge` and the
  `parent_session_id` resume path are still the mechanism for the AutoGen engine.

## 14. Phase 5 RESULTS — AutoGen RETIRED (2026-08-28) ✅
The migration is complete. `pyautogen` is gone and nothing imports `autogen`.

### Removed
| What | Where | Lines |
|---|---|---|
| `PentestTeam`, GroupChat, custom speaker selection | `pentest_agents.py` (deleted) | 1231 |
| AutoGen session runner (build team → GroupChat → poll `groupchat.messages` → interpret `_termination_reason`) | `autogen_service.py::run_pentest_session_sync` | 570 |
| Agent factories (`create_assistant_agent`, `create_user_proxy_agent`, `register_function_to_agent`, `create_group_chat`, `create_group_chat_manager`) | `agent_config.py` | 157 |
| `_patched_create` / `install_llm_metrics_patch` (monkeypatch on `OpenAIWrapper.create`) | `llm_metrics.py` | 122 |
| `attempt_session_recovery` | `autogen_service.py` | 113 |
| `POST /pentest/{id}/nudge` | `autogen_service.py` | 31 |
| `pyautogen==0.2.18` | `requirements.txt` | — |

`run_pentest_session_sync` survives as a ~15-line delegator so every call site
still works. `SYSTEM_MESSAGES` and every `get_*_config()` in `agent_config.py`
stay — the prompts feed the `/prompts` endpoints and the configs are what
`langgraph_engine._chat_model()` reads.

**Stall recovery is gone; stall detection is not.** Recovery appended a nudge to
`groupchat.messages` and hoped speaker selection picked it up. There is no such
loop in a StateGraph, and the deterministic edges remove the failure mode it
existed for. The watchdog still labels a session that stops making progress, and
still monitors scan jobs — that half was never AutoGen-specific.

### The load-bearing problem, and how it was solved
The tool roster existed **only as a side effect of building AutoGen agents**:
`langgraph_tools` had to regex `pentest_agents.py` for
`register_for_llm(name=...)` calls and resolve each callable out of that module's
namespace. Deleting AutoGen would have deleted the tool surface with it.

**`autogen_agents/tool_registry.py`** is the replacement — one declarative
`ToolSpec(name, description, func)` list, generated from the 60 registrations
(49 distinct tools) so nothing was lost. Verified against the old roster while
both existed: **49 names identical, and `lt.TOOL_FUNCS[n] is tr.TOOL_FUNCS[n]`
for all 49** — the same callable objects, not lookalikes.

It also fixed two things the parse could not:
- **Descriptions.** The regex recovered the tool NAME but not the curated
  `description`, so `langgraph_tools` substituted `inspect.getdoc(fn)`. The
  description is what the model reads when choosing a tool, so LangGraph agents
  had been choosing from Python docstrings while the tuned text sat unused.
- **A third copy of the roster.** `mcp_tools_bridge.NATIVE_TOOL_NAMES` was
  hand-maintained and had drifted **both ways**: it listed `start_nikto_scan`,
  which no tool provides (so a real MCP tool of that name would have been skipped
  as a "native duplicate"), and omitted `get_attack_vectors` and
  `start_subdomain_takeover`, which an MCP server could therefore shadow —
  replacing a scope-gated local body with a remote one. Derived from the registry
  now.

### Features the AutoGen path owned, ported before deleting it
Retiring AutoGen without these would have silently removed working
functionality — the same class of gap Phase 4 found five of:
1. **`_finalize_session`** — flow summary, claim validation, KB recommendation
   drain, scan persistence, tracker cleanup. Now called from the LangGraph engine
   in both the success and failure paths (a failed run is when it matters most).
2. **`collect_session_outputs`** — the run's scans + transcript + report written
   to a session directory. The engine had no transcript list to hand it, so one is
   kept alongside the DB writes. *Verified:* `scan_sessions/phase5-retire-proof_40f00a8d/`
   contains `conversation.json` (8091 bytes), `final_report.md`, `manifest.json`.
3. **`metadata.scans` / `scan_summary`** from the scan tracker, which the
   dashboard's per-session scan panel reads.
4. **`auto_run_recommendations`** — accepted by the engine's entry point and then
   *ignored*, so a session launched with it on left its KB recommendations at
   `status='pending'` forever.
5. **The operator prompt config.** `PentestTeam` overlaid the active
   `prompt_configs` row onto `SYSTEM_MESSAGES`; the engine had hardcoded prompts,
   so retiring AutoGen would have turned every saved prompt customisation into a
   store-only setting. The engine now APPENDS the operator prompt to the phase
   default rather than replacing it — the defaults carry the safety contract
   (which tools exist, that a read-only phase must not dispatch, that the agent
   must never execute an exploit), and a prompt field should not be able to talk
   an agent out of those.

### Verified live (observed, quoted)
- `pip show pyautogen` → `WARNING: Package(s) not found`; `import autogen` →
  `ModuleNotFoundError`; `import autogen_service` → OK.
- `GET /pentest/engine` → `{"engine":"langgraph","valid":["langgraph"],"retired":["autogen"],…}`
- A request pinning the retired engine is **warned and run on LangGraph**, not
  failed: `Agent engine 'autogen' (from request) was RETIRED in migration Phase 5
  — pyautogen is no longer installed. Running 'langgraph' instead.` Session
  `40f00a8d…` completed.
- Ported lifecycle confirmed on that session: metadata carried
  `['claim_validation', 'engine', 'phase', 'scan_flow_summary', 'scan_summary',
  'scans', 'steps', 'total_messages']` — `scan_flow_summary` and
  `claim_validation` had never appeared on a LangGraph session before.

### Tests
- **`tests/test_tool_registry.py`** (new, 9 cases) replaces
  `test_langgraph_tool_parity.py` (deleted — there is nothing left to be at parity
  with). Guards: the registry declares ≥49 tools (a hard number, because it is now
  the ONLY declaration and a silent shrink is otherwise invisible); names unique;
  every tool has an LLM-facing description; every spec resolves to a callable;
  every spec is wrapped for LangGraph; the wrapper carries the *registry*
  description, not a docstring; `NATIVE_TOOL_NAMES` is derived, not re-hardcoded;
  and **no module imports `autogen` and `pyautogen` is not in requirements**.
  **Sabotage-proven ×3:** blanked a description → RED; re-hardcoded
  `NATIVE_TOOL_NAMES` → RED; re-added `import autogen` → RED.
- `tests/test_langgraph_phases.py` updated: the roster comes from the registry
  via `ast`, and `test_langgraph_is_the_only_engine` now asserts `autogen` is NOT
  selectable (a selectable engine whose dependency is uninstalled would fail at
  import time inside a background thread) while still being *recognised* as
  retired.
- Full suite: **1226 passed, 361 skipped**, and the same 5 pre-existing
  environmental failures as before this work (see `tests/README.md`).

### Deliberately NOT done
- **The service, container and directory keep the `autogen` name.** Renaming
  would churn `docker-compose.yml`, the TLS cert SAN (`DNS:autogen-agents`), the
  BFF's `autogen_url` setting, ~20 docs and every operator's muscle memory, for
  no functional gain. The docs now say plainly that the name is historical.
- `MAX_CONCURRENT_SCANS` / scope gate / webhook contracts: untouched, because the
  tool bodies never moved.
