# LangGraph: how targets are configured and how the graph is set up

**Private working document.** Generated 2026-09-08 from the code at
`6bdcb50`. Every claim below is cited to `file:line` so it can be re-checked
rather than trusted.

---

## 0. The single most important thing

**The `target` in the LangGraph state is a free-text *description*, not an
address the graph scans.**

```python
class PentestState(TypedDict):
    session_id: str
    target: str          # <- a DESCRIPTION, e.g. "redteam3 external perimeter"
    task: str
    ...
```
`autogen_agents/langgraph_engine.py:320`

It is only ever interpolated into LLM prompts, truncated to 300 characters:

```python
task = (f"Target: {state['target'][:300]}\nTask: {state['task'][:300]}\n"
        "Enumerate the known assets, open ports and existing findings...")
```
`langgraph_engine.py:628` (recon), `:667` (scan)

Actual hosts come from **the database and the scope tables**, never from this
string. That separation is deliberate and it is the reason a typo in the
description cannot cause traffic to the wrong host.

Three consequences worth internalising:

1. Writing `"scan 10.0.0.5"` in the description does **not** authorise 10.0.0.5.
2. The LLM cannot invent a target: every dispatcher re-checks scope itself.
3. To actually change what gets touched you edit **`scope_targets`**, not the
   session description.

---

## 1. The graph

Twelve nodes, built once per session in `build_graph()` at
`langgraph_engine.py:2471`.

```
              START
                │
              recon                     read-only enumeration of what we know
                │
              scan                      plan, and dispatch iff auto_execute
                │
             analyze                    correlate findings ↔ exploits
                │
        ┌───────┴─────────────────┐
        │ _after_analyze          │     both extra phases are OPT-IN
        ▼                         ▼
   surface_plan               exploit_plan
        │                         │
  surface_safe_exec          (candidate?) ──no──┐
        │                         │yes          │
   (impactful?)             exploit_approval     │
    │        │                    │  ⏸ INTERRUPT │
   no    ┌───┴────┐         (approved?)          │
    │  auto      human            │yes           │
    │    │        │ ⏸        exploit_exec        │
    │ surface_  surface_           │             │
    │ auto_exec approval           │             │
    │    │        │                │             │
    │    └────► surface_exec       │             │
    └──────────────┬───────────────┴─────────────┘
                   ▼
                report ──► END
```

Edges: `:2485-2512`. Routers: `_after_analyze` `:2440`, `_after_surface_plan`,
`_after_surface_safe`, `_after_surface_approval`, `_surface_onward`,
`_after_exploit_plan` `:2460`, `_after_exploit_approval` `:2464`.

Both optional phases are independent, and **surface runs first** — the comment
at `_after_analyze` gives the reason: it "can generate impactful candidates the
exploit phase would otherwise duplicate."

### The two pause points

`exploit_approval` and `surface_approval` raise a LangGraph `interrupt`. The
session **parks** — it does not poll, spin, or hold a worker. It resumes only
when an operator answers:

```
POST /api/agent-sessions/{session_id}/approve
```
`dashboard/bff/routers/agent_sessions.py:140`

Because the pause is a checkpoint, `get_pending_approval()` reads it **out of
Postgres**, not out of process memory — "so it is true even if this process
never ran the session" (`langgraph_engine.py:2745`). A restart mid-approval
loses nothing.

---

## 2. Where a target actually comes from

### 2.1 Session launch

```
POST /api/agent-sessions        dashboard/bff/routers/agent_sessions.py:93
   └─► autogen-agents  POST /pentest
         └─► run_langgraph_session_sync(...)   langgraph_engine.py:2649
```

`StartSessionRequest` (`agent_sessions.py:23`) — the target-relevant fields:

| Field | Meaning |
|---|---|
| `target_description` | free text, prompts only (see §0) |
| `surface_target_host` | the ONE host the surface phase enumerates; omit to auto-pick |
| `proxy` | SOCKS egress for this session's scans |
| `port_profile` | named port scope from `knowledge/port_profiles.yaml` |
| `web_profile` | named web depth from `knowledge/web_profiles.yaml` |
| `auto_execute_scans` | whether the scan phase may dispatch at all |
| `enable_exploit_phase` | adds the exploit branch (pauses for approval) |
| `enable_surface_test_phase` | adds the surface branch |
| `engine` | `langgraph` (default) or legacy `autogen` — per-session canary |

There is a live footgun documented in that file: *"model_dump() is what gets
forwarded, so a field missing here is silently dropped no matter what the
autogen service accepts."* A new launch option must be added to this model or
it vanishes without an error.

### 2.2 Surface-phase target resolution

`surface_plan()` at `langgraph_engine.py:2035`:

```python
host = _host_of(state.get("surface_target_request"))       # 1. operator's choice
if not host:
    av = json.loads(_tool(scan_tools.get_attack_vectors,   # 2. highest-risk
                          limit=1, min_risk=40.0))          #    ranked vector
    host = _host_of(vs[0].get("target")) if vs else None
if not host:
    ... "skipping surface tests"                            # 3. skip, loudly
```

Note the third branch: **no target means no tests**, reported as
`{"mode": "no_target"}`. It does not fall back to "everything".

### 2.3 Scope — the gate that actually decides

The description and the ranked vector are *suggestions*. Authorisation lives in
`scope_targets`:

```
scope_targets(id, name, target, target_type, source, added_at, engagement_id)
```

Enforced through one canonical helper so the paths cannot drift:

```python
def _host_in_scope(host: str) -> bool:
    try:
        from etl.scope_gate import enforce_target_scope
        return enforce_target_scope(host) is None
    except Exception:
        return False          # <- FAIL CLOSED
```
`langgraph_engine.py:1467`

Read that `except` carefully: **if scope cannot be read, the answer is "no"**.
An unconfigured or unreachable scope is not permission to scan anything.

`etl/scope_gate.py` provides: `load_dispatch_scope` `:236`, `check_dispatch`
`:282`, `is_in_scope_with_aliases` `:378` (CNAME/alias-aware),
`hosts_in_command` `:275` (extracts hosts from a command string so a target
smuggled into an argument is still checked), `enforce_target_scope` `:414`,
plus `is_halted` `:176` and `over_budget` `:205` — an engagement can be stopped
or capped independently of scope.

Current engagements: `redteam3` (external_pentest, planning), `unknown_scope`
(external_pentest, active), `lab` (other, active).

---

## 3. What each phase is allowed to touch

Capability is enforced by **the tool list, not the prompt** — the `scan()`
docstring is explicit: *"The toolset — not the prompt — is what enforces the
auto_execute contract: with auto_execute off the agent is given NO `start_*`
tool, so it cannot dispatch even if it decides to."* (`:654`)

| Phase | Tools | Can send traffic? |
|---|---|---|
| `recon` | `_READ_ONLY` + `get_passive_recon_plan` | no |
| `scan` | `SCAN_TOOLS_READONLY` ∪ (`SCAN_TOOLS_DISPATCH` iff `auto_execute`) | only when opted in |
| `analyze` | `_READ_ONLY` + exploit matching | no |
| `exploit_plan` | read-only + `queue_exploit_for_approval` | no — only writes a pending row |
| `exploit_exec` | — | yes, post-approval |

`_READ_ONLY` (`:63`) is ten DB queries — "No traffic leaves the platform."

`SCAN_TOOLS_DISPATCH` (`:84`) is 20 discovery/enumeration dispatchers, and the
comment names what is **deliberately excluded**: `start_brutus`,
`start_credential_check` and everything exploit-adjacent, so *"the blast radius
of an autonomous scan phase is enumeration only."*

`tests/test_langgraph_phases.py` pins these sets against
`langgraph_tools.TOOL_NAMES`, "so a rename fails the build instead of silently
shrinking a phase's toolset to nothing."

---

## 4. Model, prompts, budgets

**The backend is resolved from the dashboard DB, not the environment.**

```python
from agent_config import get_llm_config
cfg = (get_llm_config() or [{}])[0]      # dashboard-DB over env
```
`langgraph_engine.py:200`

Azure and OpenAI-compatible endpoints are both supported (`AzureChatOpenAI` /
`ChatOpenAI`, `max_retries=1` — retry is handled by the governor below).
*Checking env vars to find out which model is running will mislead you.*

**Operator prompts append, they never replace** (`_prompt_for`, `:174`):

> "An operator prompt that replaced them outright could talk an agent out of a
> safety property, which is not something a prompt field should be able to do."

**Step budgets** (`PHASE_STEP_BUDGET`, `:398`) — Reconnaissance 20, Scanner 16
(24 with dispatch), Analyzer 26, Exploit 22. Exhaustion is surfaced explicitly
via `_STEP_LIMIT_MARKER` "rather than persisted as if it were the agent's
answer."

**Rate limiting**: `_RateLimitGovernor` `:434`, `_is_rate_limit_error` `:503`,
`_invoke_with_backoff` `:533`. Every phase has a deterministic fallback
(`_recon_deterministic` `:642`, `_scan_deterministic` `:832`,
`_analyze_deterministic` `:887`) "so a session never hard-fails."

There is a good worked example in `scan()` of why the fallbacks are not enough
on their own — the deterministic test plan is appended *regardless* of what the
model produced, because a rate-limited agent once "never called
`get_tool_recommendations`, and answered 'No results yet for redteam3
specifically'."

---

## 5. Persistence

`PostgresSaver.from_conn_string(os.environ["DB_DSN"])` — `_saver_cm()`.
`saver.setup()` is idempotent and creates the tables. Thread id = session id:

```python
cfg = {"configurable": {"thread_id": sid}}
```

Tables: `checkpoints` (390 rows at time of writing), `checkpoint_blobs`,
`checkpoint_writes`, `checkpoint_migrations`.

This is what makes approval durable and resume real, rather than a UI illusion.

---

## 6. Per-session context that is easy to miss

```python
scan_tracker.set_session(sid, port_profile=port_profile, web_profile=web_profile)
LLMMetricsContext.set_session(sid)
```
`langgraph_engine.py:2685`

The comment is worth quoting because all three failures are silent:

> "Same thread-local context AutoGen sets: without it `/scans` is empty for the
> session, `port_profile`/`web_profile` are silently ignored, and no
> `llm_request_metrics` row can be attributed."

Session proxy is set separately via `scan_tools.set_session_proxy(proxy)` `:2674`.

---

## 7. Naming

The directory, container and service are all called `autogen-*`. **AutoGen is
retired**; LangGraph is the default engine and the names are historical. The
legacy GroupChat path is still selectable per session with `engine: "autogen"`
as a canary control. The tool roster is `autogen_agents/tool_registry.py`.

---

## 8. Practical checklist — pointing the graph at a new target

1. Add the host to **`scope_targets`** for the engagement. Nothing else grants
   authorisation, and an empty scope means nothing runs.
2. Confirm the engagement is not halted (`is_halted`) or over budget
   (`over_budget`).
3. `POST /api/agent-sessions` with:
   - `target_description` — for the humans and the prompts
   - `surface_target_host` — if you want a specific host enumerated
   - `auto_execute_scans: true` — otherwise the scan phase only plans
   - `proxy` — required when **block local scans** is on
   - `port_profile` / `web_profile` — depth
4. If you enabled the exploit or surface phase, watch for the pause and answer
   `/approve`. The session waits indefinitely and durably.
5. Verify egress is what you expect. The web-scanner logs it per job:
   `egress proxied through node-manager:10120`.

---

## 9. Where to look when something is wrong

| Symptom | Look at |
|---|---|
| Session did nothing | `auto_execute_scans` false → scan phase plans only |
| Dispatch refused | `scope_targets` for the engagement; the gate fails closed |
| Surface phase skipped | `{"mode": "no_target"}` — no host and no ranked vector ≥ 40 risk |
| Launch option ignored | missing from `StartSessionRequest` → dropped by `model_dump()` |
| Wrong model / cost | dashboard DB `get_llm_config`, **not** env vars |
| Session "stuck" | probably parked on an interrupt — check `/pending-approval` |
| `/scans` empty for a session | `scan_tracker.set_session` context lost |
