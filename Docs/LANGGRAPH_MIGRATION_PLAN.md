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
