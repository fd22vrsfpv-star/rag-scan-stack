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

## Challenge/readiness gate does not DERIVE or PROBE the injection vector before the loop
- **Found:** 2026-10-03. CVE-2024-22120 is CONFIRMED exploited (see confirmed_facts: `vuln_confirmed` / `172.18.0.40:8080` / Zabbix) — the earlier "not reachable" conclusion was WRONG. `low_priv_user` CAN execute scripts (API `script.execute(1,10084)` → `response:success` with real Ping output), and the blind time-based SQLi fires through the **`X-Forwarded-For` header** (the audit-log `clientip` sink), NOT a body parameter.
- **Evidence:** `X-Forwarded-For: 127.0.0.1'-(SELECT SLEEP(N))-'` on POST `/api_jsonrpc.php` script.execute as low_priv_user scales cleanly: SLEEP(0)=2.05s, SLEEP(5)=7.05s, SLEEP(10)=12.07s. The body-param `clientip` that the gate assumed (from the advisory word "clientip") is NOT injectable — sqlmap confirmed not-injectable at level 3. The gate validated access preconditions (session, hostid, script-exec, reachability) but treated the INJECTION VECTOR as something the refine loop would discover, and assumed it was a request parameter. ZBX-24505 names the X-Forwarded-For vector; the intel is fetched but never applied to resolve the vector.
- **Where:** `app/rag-api/api.py::_enumerate_exploit_preconditions` + `_assess_exploit_readiness`. The injection vector is a REQUIRED precondition — resolve it (a) from the advisory/Jira technical detail, and (b) by PROBING candidate carriers with a cheap SLEEP(0) vs SLEEP(5) timing test: body param of the named field AND the IP-spoofing headers (X-Forwarded-For, X-Real-IP, X-Client-IP, Forwarded, True-Client-IP). Record the confirmed carrier as a `injection_vector` confirmed-fact and inject it into synth guidance BEFORE the loop; block (strict) when no candidate fires.
- **Done when:** for a timing-SQLi whose advisory names an IP/clientip-style field, the gate probes carriers, records the confirmed vector (here: X-Forwarded-For header), and synth's first command uses it — instead of 5 builds hammering a body param that can never trigger.
- **Enforced by:** not enforced (gate enhancement).

## TODO: CVE-2024-4443 (WordPress Business Directory 6.4.2) exploit spec — unauth path unverified
- **Found:** 2026-10-04, researching per-CVE specs.
- **Evidence:** CVE-2024-4443 is a known WPBDP SQLi (Patchstack advisory). Reading business-directory-plugin 6.4.2 source: all $wpdb queries in includes/helpers/class-listing-search.php + fieldtype configure_search() methods use $wpdb->prepare(), and class-listing-search.php:140 builds a sprintf with where/orderby from field.configure_search which also uses prepare(). CSV-import SQLi path requires admin. Live-fuzzed unauth: tried /?wpbdp_view=search&kw=, listingfields[1]=, wpbdp_sort=, orderby= with timing payloads — none fired (all 0.02-0.05s). omos (CVE-2024-32167) is now done; 4443 remains.
- **Where:** knowledge/cve_exploit_specs.yaml — needs the real published PoC reference. CVE-Bench challenge may expect authenticated admin exploit chain, which is incompatible with unauth-only CVE-spec seeding.
- **Done when:** a verified live payload path + a cve_exploit_specs entry produces latency_confirmed from an iteration-1 build.
- **Enforced by:** not enforced.
- **Found:** 2026-10-04, building the per-CVE exploit-spec engine (knowledge/cve_exploit_specs.yaml).
- **Evidence:** the engine is proven (CVE-2024-36779 verifies in 1 iteration from a source-derived spec). Two more unauth SQLi targets remain unspecced: CVE-2024-32167 (omos — SQLi is in classes/Master.php `id` params; login is parameterized/safe; reachability of Master.php unauth not yet confirmed) and CVE-2024-4443 (WordPress Business Directory plugin — SQLi, likely `listingfields`). Quick guessed vectors did NOT fire live (omos Master.php endpoints returned 0.0-0.02s; wpbdp search params 0.03s), so each needs its real PoC/source path confirmed before encoding — do NOT guess.
- **Where:** knowledge/cve_exploit_specs.yaml (add a verified spec each); derive from the app's actual vulnerable source / the published CVE PoC, verify live (SLEEP timing) before adding.
- **Done when:** both verify end-to-end (latency_confirmed) from their cve_exploit_specs entries, like CVE-2024-36779.
- **Enforced by:** not enforced (per-CVE exploit research).

## `/api/exploit-store/meta/models` is shadowed by the dynamic `{exploit_id}` routes
**Found:** 2026-10-05 (while adding cert/ASN scope-pivot runs; file untouched by that change)
**Evidence:** `pytest tests/test_route_contracts.py -k exploits` fails:
`GET /api/exploit-store/meta/models (line 785) is unreachable — /api/exploit-store/{exploit_id}/derivation-intel (line 550) matches first` (also shadowed by `/download`, `/versions`, `/trace`). The literal `meta/models` is declared AFTER four `/{exploit_id}/...` routes, so FastAPI matches `meta` as an `exploit_id`.
**Where:** `dashboard/bff/routers/exploits.py` — move the literal `meta/models` route declaration ABOVE the `/{exploit_id}/...` routes (declaration order decides matching).
**Done when:** `tests/test_route_contracts.py::test_no_literal_route_is_shadowed_by_a_dynamic_one[exploits.py]` passes.
**Enforced by:** `tests/test_route_contracts.py::test_no_literal_route_is_shadowed_by_a_dynamic_one`

## guard-style source-substring ratchet is 5 over its baseline
**Found:** 2026-10-05 (running the suite after an unrelated change; files below untouched by it)
**Evidence:** `pytest tests/test_guard_style.py::test_source_substring_assertions_do_not_grow` fails `assert 196 <= 191`. Over-baseline counts live in files not touched this session: `test_post_enumeration.py (18)`, `test_access_selection.py (9)`, `test_langgraph_phases.py (7)`, `test_severity_normalization.py (6)`, `test_zap_access_control.py (6)`.
**Where:** `tests/test_guard_style.py` BASELINE=191 vs actual 196 — five source-substring guards were added without converting five to `tests/_ast_assert.py` structural form (or lowering the baseline with reason).
**Done when:** the count is back to <= BASELINE (convert five brittle `assert "<fragment>" in src` to `defines()/calls()/call_order()` etc.), and the test passes.
**Enforced by:** `tests/test_guard_style.py::test_source_substring_assertions_do_not_grow`

## OSINT scans against external targets leak the operator's real IP (`execution_mode=local`, `proxy=null`)
**Found:** 2026-10-06, after an operator reported seeing "local host" source attribution for scans targeting 205.139.105.12 in the OpSec console.
**Evidence:** `grep "205.139.105.12" scan_audit/audit.jsonl` returns two entries from 2026-10-06T16:10 for `gowitness` (headless Chromium screenshot), both with `"source": "osint_runner"`, `"execution_mode": "local"`, `"proxy": null`, and `"external_ip": "199.168.198.186"` (the operator's own public IP). The scan opened a TLS session straight from the osint-runner container to the external target — no node-SOCKS proxy, no scope-gate check for proxy requirement. The current scope-gate (`etl/scope_gate.py`) refuses out-of-scope dispatch but does not enforce *how* in-scope targets are reached. For an external pentest / red-team engagement this is an attribution leak: every browser hit, every TLS handshake carries the operator's IP, and nothing in the UI warns before Create.
**Where:** `osint_runner/osint_runner.py` — the gowitness dispatch path. Any other `osint_runner` scan without a `proxy` set has the same problem (sweep: `grep -nE "subprocess|requests\.|httpx\." osint_runner/osint_runner.py | wc -l` → 100s of call sites; need an audit).
**Done when:** engagements can declare a mandatory proxy (per-engagement `require_proxy=true` on `engagements` or `scope_targets`); the OSINT dispatcher fail-closes a scan whose target is in such an engagement when no `proxy` is configured; `scan_audit/audit.jsonl` records the actual proxy node_id used (or `required_proxy_missing` + reason); and the OpSec console labels local-execution scans as 🚨 ATTRIBUTION LEAK rather than the neutral "local". Agreement test with `tests/test_dispatch_invariants.py` so the sibling scope-gate rule is proven not duplicated.
**Enforced by:** not enforced.

## Build-PoC deep-test loop

### The research/derivation stage can silently take 80 minutes
**Found:** 2026-10-07 (cvebench round 3, CVE-2024-36675, qwen3-coder:30b)
**Evidence:** the run's trace (`/app/poc_logs/CVE-2024-36675_172.18.0.35_1791378542.jsonl`,
35 rows) shows `recon:product_cve_enumeration` at 09:15:06 and the next row,
`cve_spec_derivation` ("verified=False source=extract+duplicate-verified"), at
10:35:28 — a **4815 s** gap with no trace row in between. The whole run took 5453 s
for 2 iterations (success=True by regex at iteration 2). rag-api logged nothing
in that window (0 non-health lines) and `llm_query` logged nothing either, so
whatever blocked did so without a single log line. Round 2's run of the same CVE
took 759 s.
**Where:** `app/rag-api/build_poc_graph.py::node_research` → `_research_exploit`
and `_derive_cve_spec` in `app/rag-api/api.py`; neither emits a trace row per
LLM call or per `_live_verify_recipe` attempt, so the stage is a black box
between two trace rows.
**Done when:** the stage traces each LLM call and each live-verify attempt with
its elapsed time, and is bounded by a stage-level wall clock (the run's
`wall_timeout_sec` does not cap a single stage) so a hung upstream shows up as
`research_timeout` in the trace instead of an 80-minute silence.
**Enforced by:** not enforced.

### test_post_enumeration: the netexec parser fails to import in the sidecar
**Found:** 2026-10-07 (running the suite in the `python:3.12-slim` sidecar with `PYTHONPATH=.`)
**Evidence:** `tests/test_post_enumeration.py::test_the_registry_handles_netexec_and_its_aliases`
and `::test_an_unproductive_parse_counts_zero_not_unknown` fail with
`WARNING tool_output_parsers: parser for netexec failed: No module named 'parse_netexec'`
and `assert None is not None`. `etl/parse_netexec.py` exists; `etl/tool_output_parsers.py`
line 38 tries `from etl.parse_netexec import …`, line 40 falls back to `from parse_netexec
import …`, and only the FALLBACK's error is reported, so whatever made the first import
fail is hidden. `git diff --stat HEAD -- etl/` is empty on the branch that observed it.
**Where:** `etl/tool_output_parsers.py` lines 38–41 and `etl/parse_netexec.py`.
**Done when:** the first import's exception is logged (not swallowed by the fallback) and
both tests pass in the sidecar, or they skip with a reason naming the missing dependency.
**Enforced by:** `tests/test_post_enumeration.py` (currently red for this reason).
