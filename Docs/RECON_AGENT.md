# Recon Agent & the KB Recommendation Queue

The recon agent is the background loop that keeps an engagement's scope covered
without an operator driving each scan. This document covers what it dispatches,
how a recommendation moves through the queue, and how to tell a *stalled* agent
from an *idle* one — a distinction that was previously impossible to make from
the outside.

Implementation: `dashboard/bff/services/recon_agent.py`, started from the BFF
lifespan in `dashboard/bff/main.py`. Control endpoints:
`dashboard/bff/routers/recon_agent.py`.

> The BFF is **baked into the `pentest-dashboard` image**, not bind-mounted.
> Editing `services/recon_agent.py` requires
> `docker compose build pentest-dashboard && docker compose up -d pentest-dashboard`.
> Restarting the container alone will run the OLD code.

---

## The cycle

One cycle per engagement, every `interval_sec` (default 300s). The agent's own
poll is `RECON_AGENT_BASE_INTERVAL` (30s); it only runs a cycle for engagements
whose interval has elapsed and whose `pause_until` is in the past.

Each cycle:

1. Runs detection rules over recent findings, creating follow-ups.
2. Dispatches any **seed stages** still missing coverage (see below).
3. **Drains the KB recommendation queue** (Phase 4) — the main event once the
   seed stages are done.
4. Writes a `campaign_events` audit row and updates agent state.

### Seed stages

| Stage | Name | Scan | Touches target |
|---|---|---|---|
| 0 | `passive-whois` | `whois` | no |
| 1 | `passive-dns` | `dnsx` | no |
| 2 | `discovery` | `nmap` (masscan-then-nmap) | **yes** |
| 3 | `fingerprint` | `httpx` | legacy only |
| 4 | `exploit` | `nuclei` | legacy only |

Stages 0–2 always run: they produce the port/service data everything else keys
off. Stages 3–4 run **only** when `config.kb_driven_recon=false`, a fallback for
when scan-recommender or its KB store is unavailable. With the default
(`kb_driven_recon=true`) the KB queue replaces them, so the tool chosen per port
adapts to what is actually listening instead of being hardcoded.

---

## How a recommendation flows

After stage 2 ingests, `_trigger_recommendations_for` in `app/rag-api/api.py`
writes `scan_recommendations` rows per discovered `(ip, port, service)`. Phase 4
drains them through `POST /api/scan-recommendations/run`, which owns
`SCANNER_URLS` routing, idempotency against in-flight jobs, and the
manual-tool fallback.

### Statuses

| Status | Meaning | Leaves the queue? |
|---|---|---|
| `pending` | awaiting dispatch | no |
| `queued` / `completed` | dispatched; a job exists | yes |
| `skipped` | deliberately not run — already covered by service detection, an in-flight duplicate, or a manual-only tool | yes |
| `failed` | dispatch attempted and **permanently** rejected | yes |

`skipped` and `failed` are distinct on purpose. `skipped` is a *decision*
(nmap's `banner` script adds nothing after `-sV` already ran); `failed` is an
*error*.

### Scoping

The drain is scoped by the engagement's **`scope_targets` OR stamped
`assets.engagement_id`**, unioned. Scope alone is authoritative because
`assets.engagement_id` is not always populated — an early version joined only on
assets and returned zero rows for an IP that was plainly in scope, so the queue
could not drain at all. Both sides compare with `host()`: `scan_recommendations.ip`
is `inet` and renders as `192.168.1.150/32`, while `scope_targets.target` is
plain text.

The predicate lives in one constant, `_KB_PENDING_SCOPE_SQL`, shared by the
fetch and the depth `COUNT(*)` so the number reported to the operator cannot
drift from the rows actually considered.

---

## Failure handling: permanent vs transient

A failed dispatch is classified before anything is written back
(`_is_permanent_dispatch_failure`).

**Permanent** — retired immediately as `status='failed'`:

- `Tool 'x' is not in allowed list` — see [TOOL_ROUTING.md](TOOL_ROUTING.md)
- `No automated handler for 'x'`, `Manual tool …`
- Any **4xx** other than 408/429 — the request itself is wrong, so resending it
  unchanged returns the same answer

**Transient** — stays `pending` and is retried next cycle:

- `ConnectError`, `ConnectTimeout`, `ReadTimeout`, `RemoteProtocolError`
- Any **5xx** — the peer's problem, and it may clear
- `408 Request Timeout`, `429 Too Many Requests`
- **Anything unrecognised.** Failing toward a retry costs one dispatch slot;
  failing toward retirement silently discards a recommendation the operator
  never learns was dropped.

Why this matters: retiring on the first failure would throw away valid recon
work every time a scanner container happened to be restarting. Never retiring
would let one broken recommendation sit at the head of the priority-ordered
queue and consume the entire budget forever.

Transient failures increment `extra->>'dispatch_failures'`. On reaching
`MAX_DISPATCH_ATTEMPTS` (default 3) the rec is retired regardless of
classification — the backstop for a permanent failure whose message we did not
recognise.

---

## Reading the cycle log

```
[recon:186640e4] cycle done: dispatched=3, kb_drained=3, kb_failed=0,
                 kb_deferred=12, kb_pending_total=126, followups=0, targets=1
```

| Field | Meaning |
|---|---|
| `dispatched` | scans launched this cycle (seed + KB) |
| `kb_drained` | of those, from the KB queue |
| `kb_failed` | dispatches that errored — each is logged separately with its reason and `[permanent]`/`[transient]` |
| `kb_deferred` | fetched this cycle but over budget; retried next cycle |
| `kb_pending_total` | **the real queue depth** for the engagement |

`kb_deferred` is bounded by the fetch window; `kb_pending_total` is a true
`COUNT(*)`. Compare cycles: if `kb_pending_total` is not falling, the queue is
not draining regardless of what the other counters say.

### Budgets

Dispatches per cycle are capped by **both**:

- `config.max_dispatches_per_cycle` (default 5 for `pentest`, 2 otherwise)
- `MAX_CONCURRENT_RECON_SCANS` minus jobs already running (`RECON_AGENT_MAX_CONCURRENT`, default 3)

So the effective per-cycle ceiling is usually 3. At 3 per 5 minutes a
144-recommendation queue takes roughly four hours, though `skipped` rows clear
almost instantly.

---

## Configuration

Per-engagement, in `recon_agent_state.config` (JSONB):

| Key | Default | Effect |
|---|---|---|
| `profile` | `pentest` | dispatch profile; also sets the default budget |
| `kb_driven_recon` | `true` | drain the KB queue instead of legacy stages 3–4 |
| `max_dispatches_per_cycle` | 5 (pentest) | per-cycle dispatch budget |
| `port_profile` | `top-1000` | port scope for seed nmap |
| `use_kali` | — | allow routing to the Kali container |
| `web_profile`, `proxy`, `scope_names`, `skip_stages`, `use_tunnels`, `exclude_tunnels`, `use_nodes_for_tools`, `tool_node_id`, `exclude_tool_nodes`, `scan_target_types`, `ports` | — | see the module header |

Environment:

| Variable | Default | Effect |
|---|---|---|
| `RECON_AGENT_BASE_INTERVAL` | `30` | agent poll interval (seconds) |
| `RECON_AGENT_MAX_CONCURRENT` | `3` | global cap on concurrent recon scans |
| `RECON_AGENT_MAX_DISPATCH_ATTEMPTS` | `3` | transient failures before a rec is retired |

## Endpoints

| Method | Path |
|---|---|
| GET | `/api/recon-agent/{eid}` — state, config, timestamps |
| POST | `/api/recon-agent/{eid}/enable` · `/disable` · `/pause` · `/run-now` |
| GET | `/api/recon-agent/{eid}/coverage` — per-stage coverage rows |
| GET | `/api/recon-agent/{eid}/log` — campaign events |

## Webhooks

`recon_agent_cycle_started`, `recon_agent_cycle_completed`,
`recon_agent_scan_dispatched`, `recon_agent_kb_dispatched`,
`recon_agent_kb_dispatch_failed`, `recon_agent_kb_queue_drained`,
`recon_agent_blocked`, `recon_agent_auto_disabled`.

---

## Runbook: "the queue never drains"

Work down this list — each step distinguishes a different cause.

**1. Is the agent even running?**

```bash
curl -sk https://localhost:3002/api/recon-agent/<eid> | python3 -m json.tool
```

Check `enabled`, and that `pause_until` is in the past. Note the dashboard is on
**:3001 (http) / :3002 (https)**; the BFF is not directly exposed on :8000.

**2. Is it cycling?**

```bash
docker logs pentest-dashboard --since 20m 2>&1 | grep 'cycle done'
```

No lines ⇒ the loop is not running (check BFF startup logs). Lines present ⇒ go on.

> `last_dispatch_at: null` is **not** proof that nothing has dispatched — see the
> historical note below. Trust the cycle log.

**3. Is the queue actually non-empty for THIS engagement?**

```sql
SELECT status, count(*) FROM scan_recommendations GROUP BY 1;
```

A global count can be misleading: recs are scoped per engagement. If
`kb_pending_total` in the log reads 0 while this query shows rows, the recs
belong to a different engagement, or neither `scope_targets` nor
`assets.engagement_id` links them to this one.

**4. Is the budget being consumed by failures?**

```bash
docker logs pentest-dashboard --since 20m 2>&1 | grep -E 'KB rec (FAILED|skipped)'
```

Each failure now logs its reason and classification. Recurring `[permanent]`
entries for the same tool mean a routing gap — fix it in
[TOOL_ROUTING.md](TOOL_ROUTING.md) rather than waiting.

**5. Are jobs stuck "running", starving the concurrency cap?**

```bash
docker exec pentest-dashboard python3 -c "
import sys; sys.path.insert(0,'/app/bff')
from polling import active_jobs
from collections import Counter
print(Counter(j.get('status') for j in active_jobs.values()))"
```

`running` + `queued` at or above `RECON_AGENT_MAX_CONCURRENT` zeroes the KB
budget and every cycle reports `dispatched=0`.

### Historical failure modes

Recorded because each produced misleading symptoms rather than an error, and
each cost real investigation time:

- **`dict.get(col, "")` against a NULL column.** `action`/`script`/`template`
  are nullable. A NULL arrives as a key that *is present* holding `None`, so the
  `.get` default never applies and `action.lower()` raised `AttributeError`.
  Every nmap rec with a null action failed. Use `(rec.get(col) or "")`.
- **Failed dispatches were discarded.** Results counted as drained or skipped;
  `failed` matched neither, so it was not counted, logged, or persisted. With the
  fetch ordered by priority, the same broken rows returned first every cycle and
  consumed the whole budget — a permanent head-of-line block whose only symptom
  was `dispatched=0`.
- **`last_dispatch_at` erased itself.** Idle cycles PATCHed `None` over the real
  timestamp, so the field only reflected whether the *most recent* cycle
  dispatched. It read as "this agent has never dispatched anything" on a
  perfectly healthy agent.
- **Reported depth was the fetch window.** `kb_pending_left` said 12 while 144
  were pending, and could never show a queue growing faster than it drains.
