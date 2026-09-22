# Open items

Things found while doing something else, that were **not** fixed at the time.

This file exists because the alternative is worse in both directions: fixing
every incidental discovery turns a small change into an unreviewable one, and
*not* recording it means the finding is lost the moment the session ends. Several
items below were each rediscovered more than once before this file existed.

## The rules

* **Evidence, not a hunch.** An item states what was observed — a count, a query
  result, quoted output. "X looks wrong" is not an item; nobody can act on it and
  nobody can close it.
* **Every item is closeable.** It says what would make it done. An item with no
  closing condition is a complaint.
* **Resolved items are DELETED, not struck through.** A file of things that are
  already fine is a file nobody reads. Git history keeps the record.
* **`Enforced by:` is honest.** Either a test that fails while the item is open,
  or the literal text `not enforced` — which is a real and common answer. A
  fake enforcement claim is worse than none.

*Enforced by:* `tests/test_open_items.py` (format, closing conditions, and that
named tests exist).

---

## Pipeline coverage

### Only one HTTP port was discovered on a host serving several
**Found:** 2026-09-11
**Evidence:** `192.168.1.150` has 26 ports recorded and exactly one is
identified as web (`80/http`), while the host serves several. The nmap sub-job
for the wider range failed and the run still read as complete:
`SELECT p.port, p.service FROM ports p JOIN assets a ON a.id=p.asset_id WHERE host(a.ip)='192.168.1.150'`
returns 26 rows, of which the web-ish subset is `[(80, 'http')]`.
**Where:** `nmap_scanner/nmap-api.py` sub-job handling.
**Done when:** a failed sub-job is visible in the scan result rather than
reducing the port list silently.
**Enforced by:** not enforced

## Learned tool selection

### Most services never produce a usable failure signature
**Found:** 2026-09-11
**Evidence:** telnet, mysql, postgres and vnc credential attempts return
`failure_mode: "unknown"` with no error excerpt, so `error_signature()` falls
back to the last output lines and the learner has little to distinguish.
**Where:** `nmap_scanner/cred_checker.py::_classify_hydra_failure` returns
`unknown` for anything it does not recognise, and the raw output is discarded.
**Done when:** the raw stderr of a failed attempt reaches the audit, so the
signature is computed from what the tool actually said.
**Enforced by:** not enforced

## Post-execution review

### Queued re-runs are auto-dispatched with no hold flag
**Found:** 2026-09-11 (documented in `propose_reruns`' own docstring)
**Evidence:** `dashboard/bff/services/recon_agent.py:117` selects
`WHERE sr.status = 'pending'` with no filter on `source`, so post-review
proposals are dispatched like any other recommendation. One gobuster proposal
was dispatched 29 minutes after being queued and recorded `completed` with no
row in `tool_executions`.
**Where:** `dashboard/bff/services/recon_agent.py`.
**Done when:** there is an operator-visible choice between "queue for review" and
"queue for dispatch". Whether the current behaviour is right is an operator
decision, not a code default.
**Enforced by:** not enforced

### Post-access steps needing sudo cannot elevate
**Found:** 2026-09-12
**Evidence:** The post-enumeration phase queued `sudo -l` from
`ssh_methodology.md`, wrapped it for remote execution, and it reached the host —
`Warning: Permanently added '192.168.1.150' (RSA)` then
`[sudo] password for msfadmin:` on stderr, exit 1, no output. Transport,
authentication and the recon-derived algorithm options all worked; only the
elevation did not. `sudo -n` is unavailable on this 2008-vintage host
(`illegal option -n`).
**Where:** `autogen_agents/langgraph_engine.py::_wrap_remote`.
**Done when:** a step that needs elevation can use the credential the platform
already holds. Piping the password to `sudo -S` inside a nested single-quoted
remote command is the obvious route and is quoting-fragile — a password
containing a quote would break the command or worse — so it is stated here
rather than done hastily.
**Enforced by:** not enforced

### Only ssh post-access steps can be reached
**Found:** 2026-09-12
**Evidence:** `_wrap_remote()` returns None for every protocol but ssh, so
post-access steps for smb, mysql, postgresql and the rest are counted in
`unwrappable` and queued for nothing. The playbooks contain 221 read-only steps
across ten protocols; only ssh's can currently run.
**Where:** `autogen_agents/langgraph_engine.py::_wrap_remote`.
**Done when:** the wrapper covers the protocols whose tools are already
allow-listed — `netexec smb -x`, `mysql -e`, `psql -c` all exist and are
allowed.
**Enforced by:** `tests/test_post_enumeration.py::test_an_unreachable_protocol_queues_nothing`
(pins that an unwrappable protocol queues nothing rather than something broken)

## Data and deployment

### Generated curl commands carry a stray trailing quote and die in the shell
**Found:** 2026-09-21 (by the parser agent, while reading real curl output)
**Evidence:** 11 `tool_executions` rows with `tool='curl'` have empty output and
`error` = `/bin/sh: 1: Syntax error: Unterminated quoted string`. The stored
command shows the defect directly:
`curl -sk http://192.168.1.150:80/doc/'` — a trailing apostrophe with no opener.
These probes never reached the network; they died in `/bin/sh`.
**Where:** whatever builds curl probe commands (not yet located — the rows carry
no single distinguishing source, so start from the writers of `tool_executions`
with `tool='curl'`).
**Why it matters:** the runs are recorded as executed-and-fruitless. The new curl
parser correctly reads them as a measured ZERO, which is honest but wrong about
the target — nothing was ever asked of it.
**Done when:** the generator quotes URLs correctly and no stored curl command has
unbalanced quotes.
**Enforced by:** not enforced

### `_learn_against_recent` over-counts support the same way the backfill did
**Found:** 2026-09-21
**Evidence:** `learn_from_tool_executions` was fixed to count distinct
observations, but the LIVE path `etl/tool_learning.py::_learn_against_recent`
(~line 681) still upserts once per distinct recent failure every time another
tool runs, so one failure followed by three runs of tool B stores support=3 for
one observed pairing. `tool_selection_learned` currently holds 65 rows with
max(support)=79.
**Where:** `etl/tool_learning.py::_learn_against_recent`.
**Done when:** the live path counts the same way the backfill now does, so
`support` means one thing in the column regardless of which writer filled it.
**Enforced by:** `tests/test_tool_learning_support.py` (covers the backfill path
only — extend it to the live path when fixing)

### pytest runs write into production tables
**Update 2026-09-21:** the 16 polluted rows were DELETED along with the inflated
counters. The SOURCE is untouched — a test can still write here — so the item
stands on that alone.
**Second table, found 2026-09-21 while re-typing exploit rows:**
`pending_exploits` holds `exploit/unix/misc/pytest_release` ("vector pytest dup"),
**status = 'approved'**, target `198.51.100.152/32`, engagement_id NULL, created
2026-09-16. The module does not exist in Metasploit. Low risk in practice — the
target is an RFC 5737 documentation address in no scope, so the fail-closed
dispatch gate refuses it — but a test left an APPROVED row in the live exploit
queue, which is the same defect with a sharper edge than a learning counter.
**Found:** 2026-09-21
**Evidence:** 16 of the 65 rows in `tool_selection_learned` carry
`phase = '__pytest_phase'`. A test run persisted learned tool-selection state into
the live table, and the phase-scoped reset endpoint
(`POST /tool-selection/backfill {"reset": true, "phase": ...}`) will not clear
them unless that phase is named explicitly.
**Where:** whichever test writes `tool_selection_learned` without a rollback —
`tests/conftest.py` cleans a fixed `_CLEANUP_TABLES` list that does not include it.
**Done when:** tests cannot write to live tables — `tests/conftest.py` cleans a
fixed `_CLEANUP_TABLES` list that includes neither `tool_selection_learned` nor
`pending_exploits` — and the stray `pytest_release` row is removed.
**Enforced by:** not enforced


### BUILD_VERSION labels go stale on containers that were not recreated
**Found:** 2026-09-11
**Evidence:** `BUILD_VERSION` is injected at container creation, so a service
that was not recreated after a version bump reports the previous version while
running current code. The UI reads it as the stack's version.
**Where:** `docker-compose.yml` environment blocks; `scripts/update-version.sh`.
**Done when:** the reported version comes from something that changes with the
code, or the health output distinguishes "built at" from "running".
**Enforced by:** not enforced

## Known gaps carried from earlier sessions

### Nothing measures whether retrieval improved
**Found:** before 2026-09-11
**Evidence:** `SELECT count(*) FROM rag_feedback` returns **0** — the table the
bounded re-rank learns from has never received a row, so the loop has not run
once in production. GRPO never runs either, and no metric anywhere records
whether retrieval improved.
**Where:** the RAG feedback path.
**Update 2026-09-21:** the MACHINERY exists and WORKS — `POST /api/rag/eval/run`
replays rated queries into NDCG@K / MRR / recall@K / precision@K in
`rag_eval_runs`. It was run to find out why nothing had been recorded, and it
answered honestly:

    {"ok":true,"ran":false,"reason":"no feedback-rated queries in the window",
     "eval_set_size":0}

The blocker is DATA, not code: `rag_query_log` has 346 rows and `rag_feedback`
has **0**, so there are no operator-labeled helpful chunks to score against. The
endpoint correctly refuses to emit a number rather than reporting a meaningless
0.0 — do not "fix" that into fabricated ground truth.
**Done when:** operators have rated enough queries for an eval set to exist, one
run is recorded, and something re-runs it so a change in retrieval shows as a
change in the numbers. The rating surface, not the evaluator, is the gap.
**Enforced by:** not enforced

## Vector coverage

### The NFS no_root_squash mutating chain is not built (privilege deliberately not granted)
**Found:** 2026-09-13
**Evidence:** The chain needs to `mount(2)` an export, which the unprivileged
kali-listener cannot (`Operation not permitted`). Granting `CAP_SYS_ADMIN` was
trialled (PR #122) and does clear that barrier, but two facts made it not worth
carrying: (1) the lab NFS server refuses the mount anyway — from kali AND from a
host-networked client with `SYS_ADMIN` + a privileged source port,
`mount -o nfsvers=3 192.168.1.150:/ /mnt` → `access denied by server`, even though
`showmount -e` advertises `/ *` — so the capability buys nothing against the only
reachable target; and (2) `SYS_ADMIN` is a broad, near-root-on-host capability on
the container that runs offensive tooling. **Decision (operator, 2026-09-13): do
not grant the privilege at this point.** The `nfs_no_root_squash` vector stays
enumerate-only (`showmount -e`) plus its MSF `nfsmount` seed.
**Where:** `knowledge/service_access_methods.yaml` (`nfs_no_root_squash`),
`etl/access.py` (would source the resulting `ssh_credential`),
`docker-compose.yml` (would carry the capability).
**Done when:** there is a mountable `no_root_squash` target that justifies the
capability, the operator grants it, a helper performs the mount → write
`~/.ssh/authorized_keys` → record `credential_finding` chain, and the planted key
is verified to become held `ssh_credential` access via `discover()`.
**Enforced by:** not enforced

### distcc_exec has no verified non-MSF attempt
**Found:** 2026-09-13
**Evidence:** The `distcc` client is installed (Stage 2) but `distccd_exec`
dispatches via Metasploit only. A native attempt needs the CVE-2004-2687 DIST
protocol job format, which was not verified against the live daemon this session
(the ad-hoc protocol probe was blocked by the auto-mode classifier as RCE
surface). Shipping an unverified exploit format would violate the repo's
"unreachable is not absent / no silent-success probe" norm.
**Where:** `knowledge/service_access_methods.yaml` (`distccd_exec`).
**Done when:** a native distcc job is verified to return command output from the
lab daemon (192.168.1.150:3632) through the scope-gated `/vectors/run`, then added
as the vector's `attempt` with an `expect_shell` assertion.
**Enforced by:** not enforced

### End-to-end reverse shell through a node callback relay is unproven
**Found:** 2026-09-14
**Evidence:** The relay (`ssh -R 0.0.0.0:<lport>:metasploit:<lport>`) and the
reverse-to-node payload wiring are in place and unit-tested, and the relay can be
started against a live node. But a genuine reverse shell from a REAL target
arriving at the node, relaying to central MSF, and landing as a held
`msf_session` has not been observed — the only nodes available are lab SSH nodes
with no target that egresses to them. Also unverified live: that each node's sshd
allows the `GatewayPorts` 0.0.0.0 bind (start_callback_relay reports the failure,
but no lab node has been confirmed either way).
**Where:** `node_manager/ssh_manager.py` (`start_callback_relay`),
`exploit_runner/exploit_runner.py` (`_node_callback_config`).
**Done when:** a target on a node's network throws a reverse shell that arrives via
the relay and is recorded as a held `msf_session` on the central msfrpcd.
**Enforced by:** not enforced

**Blocker identified 2026-09-21 (attempted, refused):** starting a relay on
`rt3_scan1` returns, correctly, a refusal rather than a broken relay:

    relay bound localhost-only on the node (saw: LISTEN 0 128 127.0.0.1:4444 ...).
    The node's sshd has GatewayPorts off, so a target cannot reach node:4444 and
    every callback would be dropped. Set `GatewayPorts clientspecified` (or yes)
    in the node's sshd_config and reload sshd, then start the relay again.

So this is gated on a NODE CONFIG change, not on platform code: the reverse SSH
forward binds loopback-only until `GatewayPorts` is enabled on the node's sshd.
No partial state is left behind (`/callback-relay` reports `active:false` and
`remote_nodes.metadata.callback_relay` stays NULL), which is the right failure
mode — a relay that accepted and silently dropped callbacks would be worse.

Note the knock-on: with no relay anywhere, `_node_callback_config()` returns None
for every dispatch, so MSF exploits resolve to BIND payloads and every one needs
manual approval (etl/bind_payload_policy). Enabling GatewayPorts on one node
lifts that too.

## LLM routing

## Access reconnection

### Dropped msf/bind shells are not re-established after a host reboot
**Found:** 2026-09-15
**Evidence:** The Tier 1 reconnect watcher recovers only credential-backed
access: `etl/access.py::refresh` re-opens SSH with the stored credential, but
`probe()` marks a rebooted host's `msf_session` and `bind_shell` rows `dead` and
nothing re-establishes them. No persistence step exists to catch a boot callback:
`grep -n "persist" exploit_runner/postex.py` returns only the forbidden-token
list, not a persistence installer, and `active_listeners` holds no standing
listener after an exploit completes.
**Where:** `exploit_runner/postex.py` (no persistence install) and
`kali_listener/listener_service.py` (no standing callback listener).
**Done when:** post-ex can optionally install a boot-survivable callback
(scope-gated and approval-gated), and the reconnect watcher registers an inbound
persistence callback in `obtained_access` as recovered access (Tier 2).
**Enforced by:** not enforced

### The reconnect watcher never re-runs the original exploit
**Found:** 2026-09-15
**Evidence:** `autogen_agents/reconnect_watcher.py` is Tier 1 only — it re-probes
existing access and never re-dispatches `obtained_access.source_exploit`. A dead
`msf_session`/`bind_shell` whose vulnerability survived patching stays dead with
no automated re-exploitation, even though `source_exploit` is recorded on the row.
**Where:** `autogen_agents/reconnect_watcher.py`.
**Done when:** after a grace window with no Tier 1 recovery, `source_exploit` is
re-dispatched through the existing scope-gated, `MAX_CONCURRENT_SCANS`-bounded
approval path, gated behind an explicit policy flag (Tier 3).
**Enforced by:** not enforced

## Exploit classification

### Synthetic module ids queued as source=metasploit
**Found:** 2026-09-16
**Evidence:** exploit-runner fired `exploit/metasploitable_root_shell_1524` and
`exploit/drb_remote_codeexec` as `source='metasploit'` pending_exploits; neither
exists in this MSF (`module.exploits` roster has no such leaf), so both fail
`Invalid Module` every scan. `metasploitable_root_shell_1524` is a synthetic id,
not an MSF module path at all.
**Where:** whatever queues these pending_exploits (recommender / langgraph exploit
planning) — it emits made-up exploit_ids under source=metasploit instead of a real
module path or a non-metasploit source.
**Done when:** a pending_exploit with source=metasploit either carries a module
path that resolves against `module.exploits`, or is queued under the correct
source (e.g. a bind-shell access, not an MSF module). The auto-correct now flags
`module_missing` on these (2026-09-16), but the root queuing should not create them.
**Enforced by:** not enforced

### Credential brute-force (hydra) recommended but never auto-dispatched in a session
**Found:** 2026-09-17
**Evidence:** Session msf_sept16-2307 (192.168.1.150, auto_execute) flow-summary
kb_coverage showed `recommended_but_never_run: [{scanner: hydra, recommended: 2,
top_priority: 25, acted_on: false}]` — the credential brute-force was recommended
(priority 25) and never ran, while the langgraph exploit phase ran 12 exploits.
**Where:** hydra maps to credential-check/brutus (`autogen_agents/scan_tools.py:712`),
but the auto-dispatch of pending credential `scan_recommendations` lives in the BFF
`dashboard/bff/services/recon_agent.py` loop (`SELECT ... WHERE sr.status='pending'`),
which is separate from the langgraph session flow. A langgraph auto_execute session
plans/fires exploits but does not dispatch KB credential brute-force recommendations,
so they sit pending until the BFF loop runs or an operator presses Run.
**Done when:** an auto_execute langgraph session dispatches high-priority pending
credential-brute recommendations (scanner hydra/credential-check/brutus) for open auth
services with no held credential, through the SAME scope-gated + MAX_CONCURRENT_SCANS
bounded path as every other dispatcher (fail-closed; no private concurrency number).
**Enforced by:** not enforced

## ZAP authenticated spider does not traverse the logged-in area
- **Found:** 2026-09-19, proving the default-cred -> Auth Profile -> authenticated scan chain on demo.testfire.net.
- **Evidence:** logs show `ZAP form-auth configured ... as user jsmith (id 10)` + `ZAP authenticated scan for http://demo.testfire.net/`, no errors. But `z.core.urls()` after the scan returns 14 URLs, ALL public (/, /doLogin, /images/*) — zero /bank/ authenticated pages. Credentials are valid (default_cred_check confirmed the login redirect).
- **Where:** playwright_scanner/zap_bridge.py scan_with_playwright_session / spider_url (scan_as_user); the ZAP spider seeds from the logged-out homepage, which does not link to /bank until authenticated, and forced-user re-auth is not surfacing those links.
- **Done when:** an authenticated /scan of testfire discovers /bank/main.jsp (+ other post-login paths) in z.core.urls(), and web_findings gains authenticated-only alerts (e.g. IDOR on showAccount).
- **Likely fix:** run the Playwright AUTHENTICATED crawl first to seed the site tree (it browser-logs-in and walks /bank/*), then ZAP scans the seeded tree; or seed known post-login paths before the ZAP spider; verify_authentication should gate this.
- **Enforced by:** not enforced (live-scan behavior).

## Deep ZAP active scan gets terminated mid-scan under host memory pressure
- **Found:** 2026-09-19, running the deep authenticated scan on demo.testfire.net.
- **Evidence:** the authenticated flow works twice (crawl authenticated=true, 102 pages, 7 /bank pages seeded into ZAP). ZAP active scan STARTS and progresses (reached 23%) but ZAP recycles mid-scan: `docker inspect zap` -> RestartCount=2, OOMKilled=false, ExitCode=0 (clean SIGTERM exit, restart:unless-stopped), coinciding with harness "system running low on memory" events. web_findings stays at the 4188 baseline, /bank findings=0 — the /scan job's export never runs because ZAP is gone. playwright-scanner logs show "Failed to resolve 'zap' / Connection refused" during the active scan.
- **Where:** the ZAP active-scan phase of scan_with_playwright_session (playwright_scanner/zap_bridge.py); ZAP `command` JVM + the ajax spider launching browsers spike memory during a full-rule active scan.
- **Done when:** a deep authenticated active scan of testfire completes without ZAP recycling and ingests /bank findings (showAccount IDOR, transfer/transaction business-logic, queryxpath injection).
- **Likely fix:** reduce the active-scan footprint — scope the active scan to the authenticated area (/bank) rather than the whole tree, lower thread_per_host, cap max_scan_duration, and/or disable the ajax spider during the authenticated active scan; or give ZAP exclusive memory headroom. The authenticated crawl/seeding (the capability built this session) is unaffected and verified.
- **Enforced by:** not enforced (live-scan/infra behavior).

