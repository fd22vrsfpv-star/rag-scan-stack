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

### The backfill over-counts pairs
**Found:** 2026-09-12
**Evidence:** 77 `tool_executions` rows produced 284 rule upserts; one failure
pairs against every later run in the window, so `support` reads as 68 for a pair
observed far fewer times.
**Where:** `etl/tool_learning.py::learn_from_tool_executions`.
**Done when:** support counts distinct observations rather than pairings, or the
column is renamed to say what it counts.
**Enforced by:** not enforced

## Post-execution review

### The re-run proposer sees a narrower set than the classifier
**Found:** 2026-09-12
**Evidence:** `propose_reruns` selects only rows that are `failed`/`timeout` or
completed-with-empty-output, while the review classifies from a wider query. An
execution the review calls `remedy: rerun` can therefore be invisible to the
proposer.
**Where:** `app/rag-api/post_review_agent.py::propose_reruns`.
**Done when:** both read the same candidate set, or the divergence is stated in
the report so a remedy that cannot be acted on is visible as such.
**Enforced by:** not enforced

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

### Six tools still have no parser, 632 KB of output unread
**Found:** 2026-09-12
**Evidence:** `GET /parsers/missing` reports **3 covered, 6 missing** —
`nuclei` (4 runs, 515,491 bytes), `curl` (16 runs, 79,383), `ssh-audit` (2 runs,
18,218), `nmap` (38 runs, 14,259), `sqlmap` (3), `whatweb` (2). Wiring the
extractor specs in as a second parser tier already covered `enum4linux-ng`,
`smbclient`, `hydra`, `sslscan`, `medusa` and `gobuster`.
**Where:** `etl/tool_output_parsers.py::PARSERS` and
`knowledge/extractors/*.yaml`.
**Update 2026-09-21:** re-counted from `tool_executions` where
`parsed_results IS NULL` — now 5 tools and ~8.3 MB unread, not 6 and 632 KB:
nuclei (30 runs, 7.8 MB), curl (160, 482 KB), cewl (2, 23 KB), rmg (5, 5.6 KB),
showmount (1, 35 B). nuclei was a different defect and is now FIXED:
`etl/parse_nuclei.py` exists but takes a FILE PATH and writes to the database
(the ingest path), while this column is filled from
`etl/tool_output_parsers.parse_for()`, whose registry did not list nuclei at all.
Every nuclei run was unparsed — 0 with `parsed_results`, ~7.8 MB unread. A pure
text->dict `_nuclei` parser is now registered (tests/test_post_enumeration.py
::test_the_registry_parses_nuclei). Remaining: curl (482 KB), cewl, rmg, showmount.
**Done when:** each tool has a registry parser or an extractor spec.
`POST /parsers/draft?tool=<tool>` drafts one from a stored sample; the gap is
now visible and has a fix rather than being silent.
**Enforced by:** `tests/test_post_enumeration.py::test_a_missing_parser_is_a_distinct_state`
(pins that the absence is a distinct, reportable state and not a zero)

### Post-enumeration outcomes only carry forward for Kali-dispatched commands
**Found:** 2026-09-12
**Evidence:** Acting on the `smbv1-only` proposal dispatched it to the **native
nmap runner** (`Scan started: 0ea66fb6`), which writes to `scans` and never
calls `kali_listener.db_update_tool_execution` — where the write-back hook
lives. The rule stayed `fired=1 executed=0`. Calling
`record_outcome_for_command()` directly resolves it correctly
(`fired=1 executed=1 produced=1 conf=1.0`), so the mechanism works and only the
native path is unhooked.
**Where:** `kali_listener/listener_service.py::_post_enumerate` is the only
caller; the native runners (`nmap_scanner`, `nuclei-runner`, ...) have no
equivalent.
**Done when:** a command completed by any runner resolves its enumeration
observation. The native path finishes in `scans`, so it needs its own hook
rather than a shared one.
**Enforced by:** not enforced

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

### 180 historical rows can never be parsed by the running backfill
**Found:** 2026-09-21
**Evidence:** The backfill in `autogen_agents/langgraph_engine.py` (~line 2279)
filters `started_at > now() - interval '12 hours'` AND
`COALESCE(output,'') <> ''`. The 180 rows with `parsed_results IS NULL` are all
older than that window (newest 2026-09-19), so 0 are eligible; and the
non-empty-output filter excludes the 11 stderr-only curl rows the new parser was
specifically written to read. Parsers now exist for every one of those tools —
the output stays unread for want of a one-off pass, not a parser.
**Where:** `autogen_agents/langgraph_engine.py` backfill query.
**Done when:** a one-off backfill reads the historical rows (an operator decision:
it is a bulk UPDATE over recorded evidence), and the `COALESCE(output,'') <> ''`
filter either admits stderr-only rows or is documented as deliberately excluding
them.
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

### A pytest run wrote into the production learning table
**Found:** 2026-09-21
**Evidence:** 16 of the 65 rows in `tool_selection_learned` carry
`phase = '__pytest_phase'`. A test run persisted learned tool-selection state into
the live table, and the phase-scoped reset endpoint
(`POST /tool-selection/backfill {"reset": true, "phase": ...}`) will not clear
them unless that phase is named explicitly.
**Where:** whichever test writes `tool_selection_learned` without a rollback —
`tests/conftest.py` cleans a fixed `_CLEANUP_TABLES` list that does not include it.
**Done when:** tests cannot write to the live learning table (add it to the
cleanup list, or point the test at a scratch phase that the cleanup removes), and
the 16 existing rows are cleared.
**Enforced by:** not enforced


### One asset carries no engagement
**Found:** 2026-09-11
**Evidence:** After the attribution backfill, 136 of 137 assets resolved.
`74.123.154.158` remains unattributed — its host is in no scope. Re-checked
2026-09-21: still exactly one (`SELECT count(*) FROM assets WHERE engagement_id
IS NULL` = 1, the same host).
**Where:** `scope_targets`; `db_init/ensure_all_tables.sql::propagate_engagement_to_assets`.
**Done when:** the host is either in a scope or removed. It is reported by
`scripts/ensure_db_schema.sh` as "not an error", which is correct.
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

## LLM routing

### script_executor's exploit-code generation talks to raw ollama, not the router
**Found:** 2026-09-14
**Evidence:** `exploit_runner/script_executor.py:33` sets
`OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://ollama:11434")` and the
LLM call at ~:371 POSTs there with a forced `model=LLM_MODEL` (`gemma4:26b`).
docker-compose sets `OLLAMA_URL` to raw ollama for the exploit_runner service,
and per Docs/Memories no raw ollama exists in this deployment — so this
exploit-code generation path 404s / never produces output here, and it bypasses
the per-task LLM router entirely (unlike the analysis callers converted in the
`route-analysis-callers-by-task` change).
**Where:** `exploit_runner/script_executor.py` (the `OLLAMA_URL` generate call
and the two `LLM_URL` `/ollama/chat` calls at ~:857 and ~:1086).
**Update 2026-09-21:** mostly done. Two generation paths now POST to `LLM_URL`
(llm_query) with `"task": "exploit_gen"` — script_executor.py:1015 and :1256. ONE
call site remains on raw ollama: `txt_to_exploit()` (lines 336-426) posts to
`{OLLAMA_URL}/api/generate` at line 403, and it is exploit-code generation too
("Generate an executable exploit from a .txt description using LLM"), so on this
deployment it still 404s.
**Done when:** `txt_to_exploit` routes through llm_query with `task="exploit_gen"`
and no forced env model, the way the other two paths already do, OR is confirmed
dead and removed.
**Enforced by:** not enforced

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

### exploit_type is uniformly 'rce', even for auxiliary/post scanners
**Found:** 2026-09-15
**Evidence:** Every `pending_exploits` row carries `exploit_type='rce'`, including
pure scanners and info-gathering modules that never open a shell — e.g.
`auxiliary/scanner/ssh/ssh_login_pubkey`, `auxiliary/gather/dns_info`,
`auxiliary/scanner/http/robots_txt`. A live query counted 27 executed/failed
auxiliary/* rows, all tagged `rce`. The Foothold Agent no-callback queue therefore
has to re-derive the real class from `exploit_id`/`exploit_title` (the module path)
rather than trusting `exploit_type`.
**Where:** wherever `pending_exploits` rows are created (the exploit
recommender / ingest that sets `exploit_type`).
**Done when:** `exploit_type` reflects the real MSF module class — an
`auxiliary/*` or `post/*` module is not `rce` — so downstream consumers can trust
the column instead of pattern-matching the module path.
**Enforced by:** not enforced

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

### command-exec transport: bash /dev/tcp reverse shell
**Found:** 2026-09-16
**Evidence:** Operator noted a future command-exec option: trigger a bash
`/dev/tcp/<lhost>/<lport>` shell through a proven RCE, as another way to run
follow-up commands (alongside webshell handle and MSF module re-invocation).
**Where:** exploit-runner command-exec capability (POST /command-exec/run) — add a
`/dev/tcp` transport that opens a bash TCP shell to a listener.
**Done when:** /command-exec/run can run follow-up commands via a bash /dev/tcp
channel when the target has bash and outbound to the node is reachable.
**Enforced by:** not enforced

### no_session auto-correct flips to reverse behind NAT/proxy
**Found:** 2026-09-16
**Evidence:** usermap_script no_session auto-correct flipped bind->reverse with
PAYLOAD=cmd/unix/pingback_reverse LHOST=172.18.0.15 (a container IP the target
cannot reach through the SOCKS proxy) — doomed. A proxied target reaches nothing
by reverse unless a node relay/callback host is set.
**Where:** exploit_runner._next_correction no_session branch (flips connect_style).
**Update 2026-09-21:** the dangerous half is fixed — `_next_correction` now forces
`connect_style="bind"` when the dispatch is proxied and no callback_host is set,
instead of flipping to a reverse payload aimed at an unroutable container LHOST.
What remains is the word ALTERNATE: `_pick_payload` is deterministic, so forcing
bind re-picks the SAME payload that just failed, making the correction a no-op
retry. (Note it now interacts with the bind-payload policy: a forced bind still
requires manual approval, which an already operator-approved exploit satisfies.)
**Done when:** the correction tries a DIFFERENT bind payload than the one that
failed — e.g. by excluding the last-tried payload from the candidate list.
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

