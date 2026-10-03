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

**Update 2026-09-22:** node provisioning now sets `GatewayPorts clientspecified`
by default (`scripts/provision-standard-node.sh` and `-safe.sh`), so newly
provisioned nodes can host a relay. EXISTING nodes are unchanged — rt3_scan1 et al
were provisioned before this and still need the sshd edit applied by hand before
a relay will start. The refusal remains the correct behaviour until then.

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

## build-poc exploit uses a hardcoded Zabbix `sid` instead of the extracted CSRF token
- **Found:** 2026-10-03, verifying CVE-2024-22120 (Zabbix) after the access-enumeration + id-enforcement fixes landed.
- **Evidence:** v2 run log `CVE-2024-22120_172.18.0.40_1791066352.jsonl` — the generated command extracts a fresh token into `$CSRF_TOKEN` but the POST body hardcodes `sid=a6094b4f052fd133adc335382f0297f6` (127 occurrences across 30 iters; `grep -o "csrf-token=\$CSRF_TOKEN\|sid=a6094b4f[0-9a-f]*"` returns 127× the hardcoded sid, 0× the extracted token). Zabbix's `sid` IS the per-request CSRF token; a stale one makes `script.execute` reject every request BEFORE the time-based SQLi in `clientip` runs — so no latency signal is ever produced. hostid enforcement worked (hostid=10084 throughout); auth succeeded (supplied_variant).
- **Where:** synth/refine prompt builder in `app/rag-api/api.py` (session establishment bakes a `sid` into guidance that the model copies verbatim); the fix belongs near `_enforce_resolved_object_ids` — a session-token (sid/CSRF) must be extracted live per request and substituted, not pinned to a captured value.
- **Done when:** the generated CVE-2024-22120 PoC sends the freshly-extracted token (`sid=$CSRF_TOKEN`) and the blind-timing SQLi produces a confirmed latency verdict (`latency_confirmed`).
- **Enforced by:** not enforced (exploit-generation quality; live run).

## build-poc refine drifts a blind-timing SQLi from a latency assertion to expect_regex
- **Found:** 2026-10-03, same CVE-2024-22120 v2 run.
- **Evidence:** synth starts with a latency assertion (`final_assertion {min_seconds:5}` in v1), but v2's final assertion is `{"expect_regex":"POCz04dba0158e"}` with `verification_method: regex_missed`. CVE-2024-22120 is a BLIND time-based SQLi — the canary never appears in the response, so an expect_regex proof can never fire. The `timing_assertion_regressed` refine pattern (`knowledge/refine_error_patterns.yaml`) triggers on `prev_assertion_has: ["min_seconds"]`, so once the model has already dropped min_seconds the pattern can't re-assert it.
- **Where:** `app/rag-api/api.py` `_run_refine_poc` assertion handling + `knowledge/refine_error_patterns.yaml` (`timing_assertion_regressed`).
- **Done when:** for a CVE whose origin_family/synth is blind-timing, the refine loop keeps the latency assertion shape across iterations (deterministically re-anchored), never silently switching to expect_regex.
- **Enforced by:** not enforced.
