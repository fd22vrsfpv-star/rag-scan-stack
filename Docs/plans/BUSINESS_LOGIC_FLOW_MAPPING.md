# Deferred TODO — map business-logic flow paths through web pages

**Status:** deferred, not started. Scoped and measured 2026-10-12.
**Written:** 2026-10-12, from an operator question: *"how could we map the
potential business logic flow paths as they flow through web pages"* — with the
follow-up that it should be *"a graph to check off, to understand shortcuts"*,
and that we should first check whether Burp or ZAP already do it.

## Why

Business-logic flaws are the class our tooling cannot see. A scanner finds a
reflected parameter; it does not find that step 4 of a checkout accepts an
`order_id` produced at step 2 by a different user, or that `/confirm` can be
called without ever visiting `/review`. Those require knowing the **order** of
requests and **who** was allowed to make them — neither of which any of our
collectors records.

WSTG-BUSL-06 (circumvention of workflows) is the test; we have no data shape
that supports it.

## What already exists, and what it does NOT do

Checked 2026-10-12 before proposing anything:

| Tool | What it is | Gap |
|---|---|---|
| [Logic Mapper](https://portswigger.net/bappstore/ecc8609971b34364a16e8804e9e276be) (Burp BApp) | Requests as nodes on an interactive canvas; auto-connects each new request to the previous, manual Ctrl+Click edges, per-step notes, JSON import/export | Per-session, per-tester. Maps the flow you just walked. |
| [WorkflowGuard](https://github.com/aleff-github/WorkflowGuard) (GitHub) | Captures a legitimate multi-step process, generates **out-of-order variants**, compares application state before/after. Action/probe/cleanup lanes. | Self-described 0.3.3 local MVP — early. |
| [Pentest Mapper](https://portswigger.net/bappstore/af490ae7e79546fa81a28d8d0b90874e) (Burp BApp) | Logs requests against a testing checklist, connects API calls to a named flow | Store listing last updated Nov 2023. |
| [FlowState MCP](https://glama.ai/mcp/servers/bsosbjwx8s) | Imports Burp XML / HAR, assigns an actor per import, builds actor/entity/action/state graph. Does not send requests. | Not a Burp extension; separate tool. |
| [ZAP Sequence Scanner](https://zaproxy.org/docs/desktop/addons/sequence-scanner) | Records a sequence and replays it **in order**, scanning each step | Replay-and-verify. No evidence it skips or reorders steps. Alpha add-on. |

**The common gap:** every one of them is per-session and per-tester, and none
carry a **role dimension**. None build a graph across an engagement's whole
accumulated traffic, and none answer "which identity could reach this edge".

That gap is exactly where this platform sits — CLAUDE.md's stated job is to
collect and normalise so testers can import into manual tools. So:

> **Do not rebuild the canvas. Build the graph, and export it into Logic Mapper.**

## What we already hold (measured, not estimated)

Queried against the live DB, 2026-10-12:

```
web_findings                         38,012
  carrying a Referer header          11,676   <- reconstructable edges, zero new traffic
  3xx redirects                         331   <- explicit flow edges
  with response_data                 24,013   <- form actions + links extractable
  POST (state-changing candidates)      997
discovered_params                       797   (url_pattern, param_name, param_location, sample_values)
web_auth_configs                          4   (the portable Auth Profile — the role dimension)
```

**Proof it reconstructs.** A throwaway script over one host's Referer headers
recovered **246 distinct page-to-page edges across 252 nodes**, with no new
scanning. It also showed the limit: most edges were `/dir/` -> `/dir/index.jsp`
crawler artifacts, and only **3** state-changing endpoints surfaced
(`/doLogin`, `/doSubscribe`, `/sendFeedback`).

That is the honest headline: **reachability is free; flow is not.**

## The gap that actually matters

A crawler gives a SET of URLs. A business-logic flow is a PATH through a state
machine. Three properties make it one:

| | have | missing |
|---|---|---|
| Nodes | URLs | — |
| Edges | Referer + 3xx + form actions | — |
| **Order** | — | which step preceded which, in ONE session |
| **Identity** | Auth Profiles exist | which role observed this edge |
| **State** | — | what the server changed; what it handed forward |

Edges can be mined retroactively. **Order, identity and state must be captured**
— they are properties of a session, not of a URL.

Nothing records "these requests happened in this sequence". ZAP's spider and
katana both emit unordered sets, and `Referer` is a lossy proxy that breaks on
SPAs and anything POST-driven. **Burp import and the Playwright scanner both
already see true order and we discard it on ingest.** Preserving request order
and a session id there is the single change that turns this from a reachability
graph into a flow map.

## Plan

Ordered by value per unit of effort. Each phase is independently useful; stop
whenever it stops paying.

### Phase 1 — `flow_edges`, backfilled from existing data
New table `(src_path, dst_path, method, status, role, evidence_source,
observed_count, engagement_id, asset_id)`. Populated from Referer, 3xx
`Location`, and form `action` attributes in `response_data`. **No new traffic.**

Gives reachability immediately. Must carry `engagement_id` per the attribution
invariant, and the listing endpoint must honour `X-Engagement-Id` per the
read-path rule.

*Done when:* the edge count for an engagement is non-zero and a spot-check of
10 edges matches what a tester sees walking the app.

### Phase 2 — mark the spine
Flag nodes reached by POST/PUT/PATCH/DELETE. Those are the flow; everything else
is navigation. On the testfire sample that is 3 nodes out of 252 — the signal is
small and that is the point.

### Phase 3 — data-flow edges (**highest value, nobody else builds this**)
`discovered_params` already stores `sample_values`. If a value appears in a
RESPONSE at step N and in a REQUEST at step N+1, that is a **carried
identifier** — and carried identifiers are where IDOR, workflow-skipping and
price tampering live. A graph of "who produces `order_id`, who consumes it" is
worth more than the page graph.

### Phase 4 — role dimension
Re-crawl under each Auth Profile and **diff the edge sets**. An edge present for
admin and absent for user is an authorization boundary; the same edge
*reachable* by user is a finding. The Auth Profile and the Burp bundle already
exist — nothing diffs their results today.

### Phase 5 — shortcut detection (the operator's "understand shortcuts")
Structural, no traffic:

> For each state-changing node `S`, take every observed path reaching it. If
> node `N` appears in most paths to `S` but a path exists without it, that is a
> candidate workflow bypass. Hypothesis: *"request `S` directly, omitting `N`."*

This maps onto WSTG-BUSL-06 and produces a **testable assertion**, not a
diagram. Weak on today's data (unordered collectors) — it gets strong once
Phase 6 lands.

### Phase 6 — preserve order at ingest
Burp import and Playwright see true sequences. Store request order + a session
id instead of discarding them. This is what makes Phases 3 and 5 real.

### Phase 7 — export to Logic Mapper
Emit the graph in Logic Mapper's JSON import shape so the tester opens our
whole-engagement graph inside the tool they already use. This is the deliverable
that matches the project's stated purpose; the UI work is already done, by
someone else.

## The check-off already exists — do not build new state

`web_findings` carries `workflow_status`, `assigned_to`, `verified_by`,
`verified_at`, `tester_notes`, `report_ready`, `user_tags`. A flow node
aggregates the triage state of its underlying requests, so "which steps have
been tested" is a **view over data we already store**, not a new state machine.

## What would make this a failure

A page graph looks impressive and proves little. The 246 edges recovered in the
proof were mostly crawler artifacts. The measure of success is **"did it
generate a testable hypothesis"** — *"step 3 accepts an `account_id` that step 2
produced; try another account's"* — not node and edge counts.

If Phase 1 lands and nothing downstream consumes it, delete it rather than
leaving a pretty graph in a tab. This codebase has history with features that
were built, embedded, and then read by nobody (see the `rag_documents` note in
CLAUDE.md).

## Open questions

- Is `Referer` worth mining at all, or should we skip straight to Phase 6 and
  only build the graph from ordered captures? The 246-edge proof suggests
  Referer is high-volume and low-signal.
- Does Logic Mapper's JSON shape round-trip cleanly enough to be an export
  target, or does it assume a single recorded session?
- Role diffing needs a crawl per profile. What is the scan-volume cost under
  `MAX_CONCURRENT_SCANS`, and does it need its own budget?
