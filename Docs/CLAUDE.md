# Project: Security Workflow Collector (Pentest/Red Team)

You are an expert software engineer building a tool **for authorized security testing only**.
This application’s purpose is to **collect, normalize, and export findings** from security tools so testers can import them into **manual workflows** (e.g., Burp Suite, issue trackers, reporting templates).


## What success looks like
Build a production-quality app that:
1) Ingests scan outputs from multiple tools (files + CLI output)
2) Normalizes findings into a consistent data model
3) Supports deduplication + “delta” comparisons between runs
4) Exports to formats that manual tools and reporting workflows can consume
5) Provides a simple UI to browse findings and filter by severity, host, port, template, etc.

## Primary user personas
- Pentester / Red teamer running scans and needing a single place to triage results
- Security lead generating consistent exports for downstream tools and reporting

## In-scope (build these)
### Inputs / Parsers
Implement parsers (first-class modules with unit tests) for at least:
- Nmap XML
- Nuclei JSON
- ZAP (JSON or XML)
- Nessus (.nessus XML)
Design parsers to be pluggable so new tools can be added.

### Core data model
Design a normalized schema that supports:
- Target identity: asset, hostname, IP, tags, environment
- Service identity: port, protocol, banner, TLS info
- Finding identity: tool, rule/template id, title, severity, confidence, evidence, timestamps
- References: CVE, CWE, URLs
- Provenance: run id, tool version, command line (sanitized), parser version

### Storage
Use a database ( Postgres with RAG).
Include migrations.

#### Settings → Database mode changes (local / remote tunnel / remote direct)
The DB mode is persisted in `db-config.json`, which docker-compose bind-mounts
into both `container-logs` (`/project/db-config.json`) and `pentest-dashboard`
(`/app/db-config.json`). When changing anything in this flow:
- `db-config.json` MUST exist as a **file** before `docker compose up`. If it is
  missing, Docker silently creates it as a **directory**, after which every read
  returns empty defaults and every write raises `IsADirectoryError` — surfacing
  to the operator as the misleading error **"remote_db_host not configured"** when
  switching modes. Remediation: `rmdir db-config.json && echo '{"mode":"local"}' >
  db-config.json`, then recreate `container-logs` + `pentest-dashboard`.
- `scripts/setup.sh` seeds it as a file (and replaces a stray empty directory);
  `scripts/post-install-check.sh` asserts it is a file. Keep both in sync with any
  change to the mount path or default contents.
- Config is read/written in two places that must stay shape-compatible: the BFF
  `dashboard/bff/routers/settings.py` (save/toggle/get) and `container_logs.py`
  (`_read_db_config`/`_write_db_config`/`_ensure_remote_*`). The on-disk shape may
  be flat or nested `{enabled, mode, config, metadata}`; readers must tolerate both.
- The operator must **Save** remote settings (host/user/key) before switching to a
  remote mode — the switch endpoint reads only the persisted file, not the form.

Complete `db-config.json` variable reference (keep the Settings → Database UI help
box in `dashboard/frontend/src/pages/Settings.tsx` in sync with this table):

| Variable | Type | Required when | Default | Description |
|----------|------|---------------|---------|-------------|
| `mode` | string | always | `"local"` | `"local"` \| `"remote"` (SSH tunnel) \| `"remote_direct"` (SSL) |
| `remote_db_host` | string | remote, remote_direct | `""` | VPS public IP / hostname of the remote Postgres |
| `remote_db_port` | number | remote, remote_direct | `5432` | Postgres TCP port |
| `remote_db_user` | string | remote, remote_direct | `"app"` | Postgres role |
| `remote_db_password` | string | remote, remote_direct (unless key/peer auth) | `""` | Postgres password |
| `remote_db_ssh_user` | string | remote (tunnel) only | `"azureuser"` | SSH login user for the tunnel |
| `remote_db_ssh_key` | string | remote (tunnel) only | `"remote_db.pem"` | Private-key filename in `ssh-keys/` |
| `enabled` | boolean | auto-managed | `false` | Legacy nested-shape flag; true when `mode != local`. Do not hand-edit. |
| `metadata` | object | auto-managed | `{}` | `last_modified`, `last_modified_by`, `note`; written on Save/Toggle. |

Per-mode required set: **local** → only `mode`. **remote** (tunnel) → `remote_db_host`,
`remote_db_ssh_user`, `remote_db_ssh_key`, `remote_db_user`, `remote_db_password`.
**remote_direct** (SSL) → `remote_db_host`, `remote_db_port`, `remote_db_user`,
`remote_db_password` (no SSH key; server needs 5432 open + SSL). The database name is
fixed to `scans` (node_manager `remote_db_name` default) and is not set here.

### Knowledge is RAG-first (retrieve to decide; gate deterministically to act)
The knowledge that says **what to scan and what to do next** — the YAML under
`knowledge/` (enumeration/dispatch rules, service tooling, credential and
service-access methods, port/scan/tool profiles, WSTG maps) plus authored
playbooks — is **data to be retrieved, not only branches in code**. Prefer
loading it into the RAG corpus (`rag_documents`) and having the planner recall it
(`search_knowledge_base` / `POST /rag/knowledge/search`) over hard-coding the same
decision as a deterministic lookup. New knowledge should take effect by being
**loaded and embedded**, not by editing branching logic — that is what lets an
operator add a flow or a method and have the agents use it without a code change.

- **Every `knowledge/*.yaml` that defines scans or actions MUST have an idempotent
  loader that embeds it into `rag_documents`**, run on change (the pattern:
  `autogen_agents/load_agent_capabilities.py`, and the flow sync in
  `app/rag-api/api.py::sync_flows_to_rag`). Ship the loader in the **same change**
  as a new knowledge file, the way an endpoint ships its test. A file that is read
  deterministically but never embedded is retrievable by nobody.
- **Retrieve, then gate — never retrieve to authorize.** RAG decides *what is
  worth doing*; the **deterministic** scope gate and `MAX_CONCURRENT_SCANS` decide
  *whether it may run*, and they stay **fail-closed** (see Authorization gates and
  Scan volume). A retrieved recommendation is still scope-gated and bounded before
  any traffic. RAG proposes; the gate disposes. Authorization and volume are
  **never** a similarity score.
- **The deterministic rules engine stays as the execution backstop.**
  `etl/post_enumeration.load_rules()` (YAML + the DB overlay) still fires proposals
  through the gate — RAG-first changes *what informs the decision*, it does not
  remove the gated dispatch path that actually queues work.
- **A retriever that misses minority docs is not retrieving.** `rag_documents` is
  mostly findings; the knowledge rows are a small minority, and an approximate
  ivfflat scan at the default `probes=1` returns none of them. Any reader raises
  `ivfflat.probes` (transaction-scoped) or exact-scans — see
  `rag_knowledge_search`.
- *Enforced by:* `tests/test_knowledge_rag_coverage.py` (every `knowledge/*.yaml`
  is embedded by a loader or carries a `RAG_LOAD_DEBT` reason; the list ratchets —
  shrink it, and a new undeclared YAML fails by name).
- *Why:* the flows and agent capabilities were embedded into `rag_documents`, but
  no live code read that table — the agents' retrieval hit `exploit_chunks` — so
  "load it into RAG" put knowledge where nothing queried it, and at `probes=1` a
  global search returned only web findings. The read path and this rule exist so
  new knowledge is actually recalled.

### Dedup + Delta
Implement:
- Finding fingerprinting (stable hash) to deduplicate across tools/runs
- “First seen / last seen”
- Delta view: new findings, resolved findings, changed severity/evidence

### Export formats
Implement exports:
- HAR format for burpsuite and ZAP
- JSON (normalized)
- CSV (flattened)
- Optional: SARIF (if feasible)
Exports must be deterministic and documented.

### UI
Provide a lightweight web UI:
- Try to use a fast load of data for responsiveness
- Findings table with filters (severity, tool, host, port, date, status)
- Finding detail page with evidence + references
- Run comparison (delta)
- **Break a busy page into tabs, do not keep stacking panels.** When a page
  grows past ~3-4 substantial panels stacked vertically, split the distinct
  concerns into tabs rather than adding another panel to the scroll. A page the
  operator has to scroll past four unrelated tools to reach the fifth is a page
  that hides its own features. Use the established tab pattern (a local `tab`
  state, a `border-b` tab bar of buttons styled with `cn(...)`, conditional
  render per tab — see `Settings.tsx` and `AIAgents.tsx`); persist the selection
  in `localStorage` (fail-soft) so a refresh does not bounce back to the first
  tab. Keep the always-relevant status on the default tab; give each heavy,
  self-contained tool (foothold, feedback, learned extractors, learned tools,
  gap analysis) its own tab. This is a judgement call about density, not a
  test-enforced invariant — it is a suggestion, applied when a page is clearly
  getting too busy.

### Security
- use TLS and secure communications for any network based traffic
- All scan tools need the abilty to use a remote proxy with different profiles for pentest and redteam 

### Quality
- Unit tests for parsers and fingerprinting
- Save the unit tests so that they can be run indpendantly
- Minimal linting + formatting
- Clear error messages and logging
- Sample data fixtures and a “quickstart”
- ensure that changes made are retrofitted to any installation scripts
- Any new database elements need added to the install scripts
- Any new database elements need added to the health check scripts
- Audit any newly delievered features to ensure a complete and stable implementation is provided. This includes ensuring that api endpoints are fully functional and defined correctly
- Any new feature that performs actions (scans, agent cycles, pipeline stages, etc.) MUST emit webhook events via `POST /webhooks/emit` so external tools (Slack, n8n, etc.) can subscribe. Use descriptive event_type names (e.g. `recon_agent_scan_dispatched`, `pipeline_stage_completed`). Include relevant context (engagement_id, target, scan_type, counts) in the data payload.
## Enforced invariants

Each rule below names the test that FAILS when it is violated. A rule with no
enforcing test is a suggestion, and suggestions do not survive contact with a
large change. Add the test in the same commit as the rule.

### Engagement attribution is mandatory (for collected data)
- **Collected target data MUST be tied to an engagement** — directly via an
  `engagement_id`, or via its `asset_id` (→ `assets.engagement_id`). This is the
  data gathered *about a specific target during an engagement*: scans, assets,
  ports, findings, vulns, web/recon findings, credentials, exploits, sessions/held
  access, observations. "Which engagement is this?" must have an answer for each.
- **Exempt by design** (need NO engagement_id): **techniques / methodology**,
  **follow-up queues** (action items, not collected data), and anything **inherently
  shared across engagements** or **operator config** (knowledge YAML, MITRE map,
  playbooks, port/service advice, per-target tool settings, scope-conflict rows).
  These legitimately have no single engagement — do not force one on them.
- A writer that creates *collected* target data MUST set `engagement_id`, resolving
  it from the target's asset or scope (see
  `exploit_runner/cred_cracker.py::_resolve_engagement`) — do NOT leave it NULL and
  rely on a later backfill trigger.
- **Deleting an engagement's data MUST remove ALL of its collected data.** The purge
  (`_purge_engagement_data`) discovers every `engagement_id`/`asset_id` table
  dynamically AND deletes IP/target-keyed rows for the engagement's target IPs, so a
  row with a NULL `engagement_id` keyed only by IP is still removed and a re-scan
  starts clean. Operator config (scope, schedules, approval rules, prompts, tool
  settings) is kept on a data purge.
- A collected-data table with neither `engagement_id` nor `asset_id` is a gap: add
  attribution or declare it in `ENG_ATTR_DEBT` with a reason (ratchets, shrink it).
  An exempt-by-design table goes in `ENG_ATTR_EXEMPT` with a reason (permanent).
- **Scope entries are per-engagement collected config** — a `scope_targets` row
  defines what an engagement may touch and MUST carry `engagement_id`. The one
  exception is the global `not_in_scope` deny-list, which the dispatch gate reads
  and the writers insert with `engagement_id IS NULL` by design (a cross-engagement
  safety list). Every OTHER scope name with a NULL `engagement_id` is an
  unattributable orphan a purge cannot claim — backfill it to its owning engagement.
- *Enforced by:* `tests/test_engagement_attribution.py` (every collected-data table
  is engagement-attributable, exempt, or declared debt; debt may not rot),
  `tests/test_engagement_purge.py` (a NULL-engagement IP-keyed credential is deleted
  by the purge), `tests/test_cracked_creds_engagement.py` (cracked creds carry the
  engagement), `tests/test_engagement_attribution.py::test_scope_targets_are_engagement_tied`
  (no NULL-engagement scope rows except the global `not_in_scope` deny-list; ratchets).
- *Why:* hashcat-cracked credentials were stored keyed only by `ip` with a NULL
  `engagement_id`, so an engagement data-purge missed them and they kept showing
  after the engagement was cleared. Attribution is what makes engagement isolation,
  reporting, and cleanup work — for the data that belongs to one engagement.

### Engagement + scope filters apply on READS (not just writes)
- Attribution covers the WRITE path; this rule covers the READ path. Every
  listing endpoint that returns engagement-attributable data MUST honor the
  active engagement + the scope filter the operator is working in. Otherwise
  the dashboard shows cross-engagement data under the current engagement
  header and the operator thinks they're looking at scope.
- The frontend's `apiFetch` attaches `X-Engagement-Id` on every call. Every
  listing endpoint MUST read that header (via `_resolve_engagement_id()`)
  and filter — the standard pattern is `WHERE engagement_id = %s OR
  engagement_id IS NULL` (NULL rows are legacy/global, intentionally shown
  in every engagement so pre-attribution data remains reachable).
- An operator-explicit `?all_engagements=true` override is allowed (cross-
  engagement audits need it); UI MUST label the active mode so the operator
  cannot mistake "all engagements" for "this engagement".
- Scope-aware views that list exploits / scans / findings tied to a target
  host SHOULD support `?scope_only=true` to additionally restrict to
  `scope_targets` entries for the current engagement. The default is
  engagement-only (no scope restriction) so the operator can still see
  out-of-scope collected data to review it; a scope filter is opt-in.
- **Check after every change** that touches a listing endpoint OR a frontend
  page that renders a list of exploits / scans / findings / credentials:
  does it respect `X-Engagement-Id`, does it offer the scope toggle, does
  it label the active mode? If the answer to any is no, fix it in the same
  change.
- *Enforced by:* `tests/test_engagement_attribution.py` already covers the
  write path; the read-path audit is informal — add a per-endpoint test as
  each one gets touched. Known-fixed: `/exploit-store`,
  `/software/cves-without-poc`. The rest of the listing surface is a
  ratchet to improve, not break.
- *Why:* the Exploit Store listing used to show every exploit in the
  database regardless of the operator's engagement — a global view
  masquerading as per-engagement. An engagement-only listing is now the
  default; the operator opts in to `all_engagements` explicitly.

### Authorization gates
- Every code path that sends traffic to a host MUST pass the scope gate before
  dispatch. **Fail closed**: no configured scope means nothing runs, because the
  alternative is treating an unconfigured scope as permission to scan anything.
- Override flags (`force`, retry, "run anyway") overrule the platform's
  *suppression* judgement, NEVER the operator's *authorization*. A forced
  out-of-scope dispatch must still be refused.
- Blocked items MUST be labelled in the UI, not silently dropped. A blocked item
  that looks identical to a runnable one reads as a bug when it does nothing.
- When gate logic must be duplicated (e.g. the BFF cannot import
  `etl/scope_gate.py`), add an agreement test pinning both implementations to a
  shared case table.
- *Enforced by:* `tests/test_dispatch_invariants.py::test_no_new_ungated_dispatchers`,
  `tests/test_dispatch_scope.py::test_bff_and_scope_gate_agree`.
- *Why:* dispatch had no scope check at all, and 14 recommendations targeting
  third-party addresses were queued against this engagement — several already
  executed.

### Blind-timing verdicts must be confirmed with a scaled payload
- A latency-based verdict on a PoC (`method=latency` or `latency_anchored`,
  from `assertion.min_seconds`) is NEVER accepted on a single run. A target
  that takes 5s to respond on every request looks identical to a verified
  blind SQLi `SLEEP(5)` when only one elapsed is observed.
- The refine loop MUST re-run the command with a scaled payload (SLEEP(N)
  → SLEEP(N+7) by default, `TIMING_CONFIRM_DELTA_SEC` configurable) and
  verify the second run's elapsed scales with the payload (within a 2.5s
  tolerance). If it scales, the verdict is upgraded to `latency_confirmed`
  / `latency_confirmed_anchored`. If it does NOT scale, the first run was
  a false positive — downgrade to `latency_unconfirmed` and let the loop
  keep refining.
- A command with no recognizable timing payload (no SLEEP / pg_sleep /
  WAITFOR / BENCHMARK) cannot be confirmed → `latency_unconfirmable`,
  advisory only.
- **A timing assertion is only as good as the command under it — and
  "timing mode" keys on the COMMAND, never the assertion.** An assertion's
  `min_seconds` is a *claim* that this is a timing proof; a payload in the
  command is *evidence* of one. Seed the mode from the claim and the
  anti-drift rule (which exists to stop the loop walking away from a real
  blind-timing proof) will refuse the canary assertion the command can
  actually satisfy — for every remaining iteration. So: when an assertion
  carries `min_seconds`, the command carries no payload, and a canary is
  available, the assertion is **deterministically rewritten** to
  `{"expect_regex": <canary>}` before dispatch and again on every refine.
  With no canary there is nothing better to offer and
  `latency_unconfirmable` stands — never invent a regex, that is
  fabricating a proof. The rewrite cannot manufacture a pass: it lands on
  the existing canary path (anchor → anti-drift → reflection guard), where
  "canary absent" is a clean negative.
- The confirmation runs INLINE, deterministically, no LLM involved — can't
  be subverted by model whims or by the operator forgetting to double-check.
  The repair above is inline for the same reason: the model is what produced
  the mismatched assertion, so it is not the thing to ask about fixing it.
- *Enforced by:* `tests/test_timing_confirmation.py` (scaling for each
  payload type, bail-out when nothing to scale, AST-grep that the refine
  loop still calls `_timing_confirmation_rerun` and emits the three
  downstream verdict methods), `tests/test_assertion_drift_repair.py`
  (the repair on the real CVE-2024-4443 / CVE-2024-36412 commands, the
  one verified blind-SQLi command left untouched, every payload form
  preserved, `_timing_mode` not seeded from the assertion, and BOTH call
  sites counted — a name-only check passes while one site is deleted).
- *Why:* sqlmap's own confirmation is the standard; without it, a slow
  target or a WAF with a fixed delay-response reads as "exploited" and
  gets stored as a verified PoC. On CVE-2024-22120 (Zabbix script.execute
  SQLi) the first run blocked for 5s because the server was handling the
  CSRF+session establishment; the exploit itself didn't trigger. A second
  run with `SLEEP(12)` would have blocked only 5s if the server wasn't
  actually executing the payload — immediate downgrade.

### A repeated OUTCOME ends the approach, not just the iteration
- The refine loop's duplicate detector compares the **command the model
  proposes** (`_refine_signature`). Nothing compared the **outcome the target
  returned**, so varying the payload reset the streak while the server
  answered identically until `max_iters`.
- **A repeated outcome is provably zero-information**: whatever changed never
  reached the vulnerable code. After `REFINE_OUTCOME_REPEAT_AT` (default 2)
  identical `_error_signature` values, the loop sets a REQUIRED AXIS and
  **refuses a payload-only edit before dispatch** — same host, path, method,
  parameters and proof mechanism (`_command_axes` / `_axes_differ`). A refused
  command is not dispatched, so it costs no iteration; `_loop_passes` bounds
  the re-asks, and `REFINE_AXIS_EXHAUST_AT` (default 2) stops the build with
  `stop_reason=axis_exhausted`.
- **Never `continue` out of the axis gate.** The top of the loop re-dispatches
  `command`, so falling through spends a real target run re-confirming the
  outcome that triggered the gate.
- **Session plumbing is not an axis** and **percent-encoding is not a change.**
  A nonce/CSRF/session parameter comes and goes with how the command scrapes
  it, and the model freely swaps `x[1][1]=` for `x%5B1%5D%5B1%5D=`. Count
  either and a cosmetic edit reads as a changed axis, so the gate never fires.
- **The repeated outcome's tier names which axis is dead** — 404/probe →
  endpoint, 401/403 → auth, waf → carrier, syntax/refusal → command shape,
  anything else (the app answering *normally*) → parameter. The directive says
  what to change, not "try something else".
- **A signature prior builds hit ≥ `REFINE_KNOWN_DEAD_MIN` (default 3) times
  and NEVER resolved is known-dead** — change axis immediately rather than
  spend two iterations rediscovering it. "Hit often" is not "dead": a
  signature builds got *past* is a solved problem, and the prior fix is the
  useful thing, so `resolved == 0` is required. The lookup excludes the
  current run and fails soft — an unavailable error memory is not evidence
  that the approach works.
- *Enforced by:* `tests/test_refine_loop_escalation.py` (the real
  CVE-2024-4443 pair whose 423 characters differ only by
  `--data-urlencode` → `--data`; plumbing and encoding normalisation; every
  tier mapped; all four layers wired into `_run_refine_poc`; no `continue` in
  the gate; known-dead semantics).
- *Why:* 49 dispatched runs across the five loopers of the 2026-10-13
  focused-10 produced **22 distinct outcomes** — CVE-2023-51483 answered the
  same thing 6 times in 11 runs, CVE-2024-4443 5 times in 11. Every one ran to
  `max_iters`. `error_memory_rows` was 7 on each, so we had already retrieved
  the identical prior error and used it only as prompt advice.

### Scan volume
- Any component that initiates OR triggers a scan MUST bound itself by
  `MAX_CONCURRENT_SCANS`. No component invents a private concurrency number.
- This includes indirect triggers: an endpoint that auto-executes tools as a
  side effect is a scan initiator.
- **Shed, do not queue.** Return 429 fast rather than accepting work that will
  time out. Client timeouts MUST cover the worst *admitted* latency at the
  limit — admitting a request and then abandoning it wastes the work twice.
- *Enforced by:* `tests/test_dispatch_invariants.py::test_no_new_unbounded_scan_initiators`.
- *Why:* `/next_scan` ran once per open port per scan and auto-executed tools
  whose output triggered more calls. The loop fed itself until dispatches timed
  out and were recorded as failures for scans that had actually started.

### Never write a customer's identity into the repo
- **No customer or engagement-target names anywhere in the repository.** Not in
  code, comments, docstrings, commit messages, test fixtures, CLI help strings,
  skill files, `Docs/`, or SQL comments. This repo is PUBLIC.
- That includes anything that identifies them as effectively as a name:
  **hostnames** (`keys3.<customer>.com`), apex domains, internal host lists,
  and findings tied to them ("32 of their hosts are retired", "this estate's
  wildcard is served by..."). A hostname plus a liveness finding is recon
  detail about someone else's estate, not a code comment.
- **Write the behaviour, not the customer.** A comment exists to explain the
  code; the real name adds nothing a placeholder does not:
  - bad:  `# *.sky.<customer>.com is served by 32 retired hosts and 15 live`
  - good: `# a wildcard cert can front a mix of retired and live hosts, so the
            cert alone cannot decide retirement — see the redirect instead`
  Where a concrete example genuinely helps, use `example-corp.com`,
  `legacy-corp.net`, `host-a.example.com` — never a real target.
- **Real engagement data lives in the DATABASE**, which is where scope,
  findings and hosts belong and where the purge can reach them. A name copied
  into a comment is outside every control the platform has: no engagement
  attribution, no purge, no scope gate.
- *How this was found:* on 2026-10-16 a customer's name appeared in **237
  lines of code and 32 commit messages** on a public repo, including specific
  hostnames and which of their hosts were dead. Removing it needed a full
  `git filter-repo` history rewrite and a force-push — and the old commits
  stayed readable by direct SHA afterwards, because a rewrite makes objects
  unreachable rather than deleting them. The cheapest moment to not write a
  customer's name is before writing it.
- *Enforced by:* not enforced yet. A guard would scan tracked files and commit
  messages for a configured deny-list of engagement apex domains, which means
  the deny-list itself must live outside the repo.

### Tests
- Every endpoint MUST have a test that **executes** it. `ast.parse` passing,
  imports succeeding, and containers reporting healthy are NOT verification.
- A guard test MUST be **sabotage-proven**: reintroduce the bug, watch the test
  fail, restore. A guard that cannot fail is worse than none, because it is
  mistaken for coverage.
- Fixtures come from **real captured tool output**, not invented shapes.
- Tests run standalone (`pytest tests/test_x.py`) and **skip** cleanly when
  infrastructure or an optional dependency is missing. A skip says "cannot run
  here"; an error says "broken", and mixing them hides real breakage.
- Keep the suite **green**. A permanently red baseline means a new failure is
  invisible. If a test cannot pass, skip it with a reason or fix it — do not
  leave it failing.
- "Verified" in a summary means observed output, quoted. Not "should work".
- *Enforced by:* `tests/test_fstring_placeholders.py` (runtime-only defects that
  pass every static check), `tests/test_recommendation_listing.py` (endpoints
  must actually execute).
- *Why:* a brace placeholder inside an f-string SQL comment made every
  recommendations query raise `NameError`. `ast.parse` passed, the module
  imported, the container was healthy, and the page silently returned zero rows
  — no test had ever executed that query.

### Endpoint coverage
Coverage is **tiered by what can actually fail**, because there are ~1,150
distinct endpoints and a case per endpoint is not realistic. Every endpoint sits
in exactly one tier, and the tier decides the obligation:

- **Thin proxy** (one upstream call): no hand-written test. The upstream path
  MUST resolve to a route some service declares. 68% of BFF routes are these,
  so one generic check covers them all.
- **Parameterless GET**: covered by the live sweep automatically. No work when
  adding one.
- **Parameterised GET**: MUST have a sample value the sweep can substitute —
  add to `SAMPLE_FROM` (resolved live from a list endpoint, preferred) or
  `SAMPLE_STATIC` (a safe literal). Routes with no sample are reported as
  *unsampled*, never silently skipped.
- **Mutating or logic-bearing** (POST/PUT/PATCH/DELETE, or any handler with real
  logic): MUST ship an executing test **in the same commit**. This is a forward
  ratchet — backfill by risk (dispatch, auth, exploit, cleanup first), not by
  sweep.

Two rules that cut across all tiers:
- **A fallback leg is an endpoint.** Verify every leg or delete it. A dead
  primary with a working fallback is a wasted round-trip on every call; two dead
  legs is an endpoint that can never work, and both look healthy from outside.
- **`except: pass` around an HTTP call hides a 404 forever.** If a call may
  legitimately fail, handle that case explicitly and surface it. Silence here
  turns a broken endpoint into "it returned zero results".
- **`apiFetch` prepends `/api`; callers pass a BARE path.** A frontend caller
  that passes a path already starting with `/api/` requests `/api/api/...`,
  which matches no BFF route. Nothing rewrites it in between: routers mount
  prefix-free, the `/api` prefix is a literal in the decorator (or in
  `APIRouter(prefix=...)`), nginx `proxy_pass` has no URI part, and Vite's dev
  proxy uses the non-rewriting string shorthand. Every `apiFetch` path must also
  resolve to a route some BFF router declares — a path whose only proxy leg is
  missing 404s exactly like a typo'd one.
- **An HTTP status is not an exception.** `httpx` does not raise on 4xx/5xx, so
  `await c.put(...)` returns normally when the write failed. A proxy that does
  not check `resp.status_code` reports failure to the operator as success — and
  if it also triggers an action on that path, the action fires anyway. A
  `try/except Exception` around the call does NOT cover this; it catches only
  transport errors.
- **A service that sends traffic to targets MUST be on `test_net`.** Targets
  live there; a container without that interface has no route, so its packets
  are dropped rather than refused and every connection hangs for the full
  timeout (~135s) before reporting "Could not connect to server". That is
  indistinguishable from a dead target. It is worse to diagnose when the
  dispatcher and the executor differ: `rag-api` sits on both networks, so its
  prerun probe logs a real HTTP status while the command it hands to
  `kali-listener` times out against the same host, port and second. Network
  reachability is **not** the authorization boundary — `etl/scope_gate.py` is —
  so detaching a runner does not make it safer, only broken in a way that reads
  as "target down".
  *Enforced by:* `tests/test_target_network_reachability.py`.
  *Why:* `kali-listener`, the container that actually runs build-PoC commands,
  declared only `agents_net` while every sibling runner declared
  `agents_net` + `test_net`. A focused-10 CVE-Bench run reported
  `stop=target_unreachable` for 5 of 10 CVEs whose targets were up and serving.
  From `rag-api` the URL answered in 0.16 ms; from `kali-listener` it timed out
  after 30 s having never completed a TCP connect. Every verdict that run
  produced described the network, not the exploits.
- **Every SQL column must exist on its table.** A query naming a column the
  table lacks passes import, passes `ast.parse`, reports a healthy container,
  and 500s only when that path executes. Postgres reports only the *first* bad
  column, so **check the whole statement against the DDL**, never just the one
  in the traceback. New tables/columns MUST be declared in `db_init/*.sql` (or
  a runtime `CREATE TABLE`/`ALTER TABLE` the schema parser can see) or every
  query against them is skipped rather than checked.
- **A column's TYPE matters as much as its name.** `text[]` rejects a bare
  string (`malformed array literal: "CWE-79"`) and `jsonb` rejects a bare dict
  (`can't adapt type 'dict'`). Checked for `INSERT` columns and `UPDATE ... SET`
  assignments alike. Where the shape cannot be proven — a bare `d.get("k")` is
  opaque — the feed MUST be declared in `ARRAY_UNVERIFIED`; new undeclared ones
  fail by name, so the class stays caught even where inference cannot reach.
- **Prefer declaring a type over wrapping a value.** The guard reads Pydantic
  field annotations, parameter annotations, `-> list` returns, module-level
  constants, local assignments and the `x or []` idiom. That resolved 18 of the
  original 19 unprovable array feeds *without touching a call site*. Reach for
  `etl/sql_types.as_text_array()` when the shape genuinely is unknown at the
  call site — not to restate a signature that already promises a list. Add new
  normalisers to `LIST_SAFE_FUNCS` or their call sites stay unprovable.
- **A partial unique index is easy to get wrong twice.** In Postgres a NULL in
  any indexed column makes rows non-equal, so uniqueness does not constrain
  NULL-bearing rows at all. `COALESCE` the nullable columns instead of adding a
  `WHERE` predicate, and remember that any `ON CONFLICT` MUST repeat the index
  expression **exactly** or every insert raises "no unique or exclusion
  constraint matching the ON CONFLICT specification".
- **Dedup logic duplicated in SQL needs an agreement test.** `etl/fingerprint.py`
  and the `vulns_dedup` / `web_findings_dedup` triggers both compute the
  fingerprint; the triggers fill it for the ~19 insert sites that supply none.
  If they drift, the same finding gets two fingerprints and the unique index
  stores both. Pin them to a shared case table, and exercise the SQL side
  through the REAL trigger — a re-typed copy of the expression only tests the
  copy.
- **A unique index permits unlimited NULLs.** A NULL fingerprint is an
  unconstrained row that bypasses dedup entirely, so the triggers that fill it
  are load-bearing, not a convenience.
- *Enforced by:* `tests/test_proxy_contracts.py::test_upstream_paths_exist`
  (upstream paths + `PROXY_DYNAMIC`/`PROXY_DEBT` ratchets),
  `tests/test_sql_columns.py::test_every_sql_column_exists` (qualified
  references + `INSERT` column lists, with the `SQL_DEBT` ratchet),
  `tests/test_sql_columns.py::test_sql_param_types_are_compatible` and
  `::test_unprovable_array_feeds_are_declared` (INSERT + UPDATE parameter types,
  `ARRAY_UNVERIFIED` ratchet), `tests/test_sql_types.py` (the normaliser's own
  contract, incl. that its names still match `LIST_SAFE_FUNCS`),
  `tests/test_fingerprint.py` (unit cases + Python↔SQL trigger agreement),
  `tests/test_endpoint_smoke.py` and `scripts/smoke_endpoints.py` (live sweep,
  bare + parameterised), `tests/test_route_contracts.py` (declaration order,
  shadowing), `tests/test_frontend_route_contracts.py` (frontend→BFF: no doubled
  `/api` prefix, every `apiFetch` path resolves to a declared route;
  `FRONTEND_DYNAMIC`/`FRONTEND_DEBT` ratchets),
  `tests/test_exploit_approval_status.py` (a non-2xx upstream status write is
  reported as a failure and fires no execution).
- *Why:* Burp import POSTed every finding to `/findings/web`, a route no service
  has ever declared, inside `except Exception: pass` — so it reported
  `{"ok": true, "imported": 0}` while storing nothing. `/api/exploits/pending`
  had a dead primary AND a dead fallback and returned `{"detail":"Not Found"}`
  forever. `/scope/{name}/analysis` selected `dp.method` and `dp.location` when
  the columns are `http_method` and `param_location`. Containers were healthy,
  the suite was green, the OpenAPI schema listed every one, and 361 proxies had
  never had their far end checked.

  The frontend→BFF edge was the one nobody checked. Nine `apiFetch` call sites in
  `ExploitManager.tsx` passed `/api/sast/...` and `/api/build-poc/reviews...` to a
  helper that already prepends `/api`, so every request went to `/api/api/...`.
  The SAST tab and half the Reviews tab had **never worked**, and because neither
  query destructured `isError`, each 404 rendered as an empty list — "no findings
  yet" rather than "this endpoint does not exist". The same guard immediately
  found a second cause of the identical symptom: the workbench's PoC Hints card
  (list/add/delete) called `/software/poc-hints`, which rag-api declares and the
  BFF proxied nowhere.

  Separately, `approve_exploit` discarded its PUT response entirely — the result
  was not even bound — and returned `{"ok": True}` plus fired the exploit
  regardless. `httpx` does not raise on 4xx/5xx, so a rag-api 500 read as a
  successful approval and the exploit ran against a row the database never marked
  approved. `bulk_action`'s `try/except Exception` looked like it covered this; it
  catches only transport errors.

  The SQL guard's first run found **20** more, the worst being seven in
  `build_existing_target_context()` — whose caller logs the failure as a
  *warning*, so every agent session silently lost the "here is what we already
  know about this target" block and re-ran scans whose data was already in the
  database. Fixing it recovered 6,391 characters of context: 64 ports, 58
  vulns, 778 web findings. Two ingest paths also wrote to columns that do not
  exist, so Censys-discovered services and Playwright's ZAP findings were never
  stored at all.

  `uq_credential_findings_identity` was partial on `username IS NOT NULL` — dead,
  since username is NOT NULL — while the genuinely nullable `auth_type` went
  unconstrained. Two identical inserts with a NULL `auth_type` both stored; with
  `auth_type='password'` the second was correctly rejected. Now
  `COALESCE(auth_type, '')`, with `etl/parse_brutus.py`'s `ON CONFLICT` updated
  to match the expression exactly.

### Installer isolation
- Phases 6-10 of `scripts/setup.sh` must address the stack they just started by
  **(compose project, compose service)** — `scripts/lib/compose-target.sh` — and
  never by `container_name` or a published host port. Both are global: under a
  second project a literal `docker exec rag-postgres` applies the schema to the
  LIVE database, and `curl localhost:8000/health` reports the LIVE stack healthy.
- Every service that sets `container_name:` or publishes a port MUST be reset in
  `docker-compose.rehearsal.yml`. A new one fails by name.
- A rehearsal NEVER enables the `optional` profile (`host-helper` is privileged,
  host-networked, and writes `/etc/systemd/system`).
- Rehearse with `./scripts/rehearse-install.sh`; it fingerprints every
  non-rehearsal container before and after and exits 3 if any changed.
- *Enforced by:* `tests/test_rehearsal_isolation.py`.
- *Why:* the first rehearsal could only run phases 1-5, and the reason recorded
  ("41 hardcoded container names") understated it — starting a second stack
  would have been indistinguishable from the live one, schema writes included.

### Open items (things found but not fixed)
When you find a real problem that is **out of scope for what you are doing**,
record it in `Docs/OPEN_ITEMS.md` instead of fixing it silently or losing it.
Fixing every incidental discovery turns a small change into an unreviewable one;
not recording it means the finding dies with the session. Several entries in that
file were each rediscovered more than once before it existed.

Every item carries **Found / Evidence / Where / Done when / Enforced by**.
`Evidence` is an observation — a count, a query result, quoted output — never
"this looks wrong", because nobody can verify or close that. `Enforced by` is
either a test that fails while the item is open or the literal `not enforced`,
which is an honest and common answer. **Resolved items are deleted, not struck
through**; git history keeps the record.

Do not use it as a parking space for work the user asked for. It is for findings
the current change should not carry.
- *Enforced by:* `tests/test_open_items.py`.
- *Why:* the credential phase being unreachable, post-ex never running and the
  manual approve path recording no reviewer were each noticed and then lost more
  than once, because there was nowhere to put them.

### Known-debt lists
`tests/test_dispatch_invariants.py` carries `SCOPE_DEBT` and `LIMIT_DEBT`,
`tests/test_proxy_contracts.py` carries `PROXY_DYNAMIC` and `PROXY_DEBT`, and
`tests/test_sql_columns.py` carries `SQL_DEBT` and `ARRAY_UNVERIFIED`:
modules that violate the rules above today, each with a reason. They exist to
make the debt visible while keeping the suite green, and they RATCHET — a new
violation fails by name, and a resolved entry must be deleted (a separate test
enforces that). Shrink these lists; do not grow them without a stated reason.

### LLM dispatch — LiteLLM migration (in progress)

`llm_query/` is **in the middle of a migration** from hand-rolled per-provider
adapters to a `litellm.Router` + `litellm.completion()` dispatch. The plan,
rationale, and PR-by-PR rollout live in `Docs/plans/LITELLM_MIGRATION.md`.

**Current status (as of 2026-10-08):**

- **PR 1 (merged):** `llm_query/litellm_router.py` factory builds a
  `litellm.Router` from `common.llm_settings.get_providers()` in parallel to
  the hand-rolled dispatch. 17 agreement tests pin the translation per
  provider type (Azure OpenAI → `azure/<deployment>`, Azure Foundry Anthropic
  → `azure_ai/anthropic/<deployment>`, Ollama → `ollama/<model>`, …). No
  caller behaviour changed.
- **PR 2 (merged):** `_generate_text()` tries LiteLLM first when the
  `LITELLM_ROUTER_ENABLED` env var is on (default: on), falling back to the
  hand-rolled branches on any LiteLLM error. Path telemetry logs
  `llm_query: path=litellm|hand_rolled backend=X model=Y` for every served
  call so the operator can tell which path answered. Live-verified on an
  Ollama call through `/api/generate`.
- **PR 3 (this change — docs only):** every hand-rolled helper the plan
  calls out for eventual removal carries a `# DEPRECATED (LiteLLM migration)`
  marker pointing to this section + the plan. No code deleted yet because
  `chat()`, `embeddings()`, `stream`, and the non-routed branches in
  `generate()` still use them. PR 4 is where those branches get migrated and
  the helpers finally go.
- **PR 4 (gated on a focused-10 CVE-Bench run):** extend LiteLLM to the
  remaining four handlers, smoke-test every configured provider against its
  real endpoint, delete the ~250 lines of hand-rolled helpers
  (`_azure_json_post`, `_openai_json_post`, `_post_with_429_retry`, the
  Foundry Anthropic adapter files, …), remove the kill-switch fallback.

**Model-string shapes LiteLLM uses** (same shapes `entry_for_provider()` +
`litellm_completion_for()` build from the DB provider config):

| provider type           | LiteLLM `model` string              | kwargs            |
|-------------------------|-------------------------------------|-------------------|
| azure (OpenAI deploy)   | `azure/<deployment>`                | api_base, api_key, api_version |
| azure + `claude-*`      | `azure_ai/anthropic/<deployment>`   | api_base, api_key, api_version |
| anthropic (native)      | `anthropic/<model>`                 | api_key           |
| openai (direct)         | `openai/<model>`                    | api_base, api_key |
| ollama                  | `ollama/<model>`                    | api_base          |
| vllm (OpenAI compat)    | `openai/<model>`                    | api_base          |

**Operator rollback:** `LITELLM_ROUTER_ENABLED=false` in the `llm_query`
container env (compose or `docker exec -e`) forces the hand-rolled dispatch
until PR 4 lands and removes the fallback. The kill switch exists so a
LiteLLM-side regression (model shape change, dep conflict, etc.) is
recoverable without a rebuild.

**Why this is deferred, not rushed:** the plan expects the migration to
land only after a focused-10 CVE-Bench run on the current Foundry
Anthropic adapter — that gives us a reference verdict to compare LiteLLM's
dispatch against. Until that reference exists, PR 4's deletions stay out.

## Out-of-scope / constraints

- Focus on defensible engineering: parsing, normalization, reporting, workflow support.

## Implementation rules (Claude Code behavior)
#- Work on no more then one file at a time, sequentially.
- Work on no more then three files at a time. 
- After each change: summarize what changed and why.
- If changes would need to be mirrored in osx or windows, log them in:
  Docs/OS_CHANGES_FOR_MIGRATION.md (date, files changed, platforms, old→new, notes).
- Each session: append EVERY user prompt with timestamp to PROMPT_LOG.md.
- Maintain/update project memory in Docs/Memories.md; avoid duplicates; remove outdated items.
- All tools meet https://agentskills.io/home deployment standards.

## Deliverables per step
When implementing features, always provide:
- File list changed
- Commands to run tests / app locally
- Example input + expected output snippet (small)
- Next steps checklist
- Ensure that new changes will be included in future clean builds installation scripts.
- Ensure that all files required for the build are included in the containers and rebuild as required.
#Do NOT use background agents or background tasks. Do NOT split into multiple agents. Process files ONE AT A TIME, sequentially. Update the user regularly on each step."

Every time you make a change to an app that would also need to be applied , log it in Docs/CHANGES_MADE.md. Include: date, files changed, which platforms it applies to, what specifically changed (old to new values, code snippets if helpful), any notes about platform-specific adaptations completed and/or needed."

Update or remove memories that turn out to be wrong or outdated. Do not write duplicate memories. This can be written to Docs/Memories.md

Every session, after reading these instructions, log each user prompt to PROMPT_LOG.md. Timestamp each entry with date and time.

 this tool is designed for pentesters and redeam members, this is to collect data and help them with the workflow, the data collected will be used to import into manual tools to conduct security tests
Start by proposing the architecture and initial folder structure, then implement the database schema + one parser end-to-end (including tests and sample fixture) before adding more parsers.

for each change update the dashboard version to a date + timestamp. The version string must be updated in ALL FOUR of these locations to stay in sync:
1. `dashboard/frontend/package.json` — the `"version"` field
2. `dashboard/frontend/src/lib/constants.ts` — the `BUILD_VERSION` constant (displayed in the TopBar)
3. `.env` — the `BUILD_VERSION` variable (injected into all service containers via docker-compose)
4. `dashboard/frontend/package-lock.json` — the `version` field in BOTH places it appears
   (top level and `packages[""]`). Added 2026-09-05 when the lockfile was committed:
   `npm ci` refuses to install when it disagrees with `package.json`, so a missed bump
   breaks the CI frontend job rather than just mislabelling the UI.

**Run `scripts/update-version.sh <version>` instead of hand-editing** — it updates all
four. *Enforced by:* `tests/test_build_version_sync.py` (pins the three tracked files;
`.env` is gitignored and machine-local, so asserting on it would redden the suite for a
file the repo does not control).
