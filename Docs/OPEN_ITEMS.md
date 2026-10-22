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

### The News "Asset matches" panel can never fire — `vulns.cve` is empty on 97% of rows
**Found:** 2026-10-19
**Evidence:** `_match_assets` (`news_runner/news_agent.py`) joins
`news_items.all_cves` → `vulns.cve` → `vulns.asset_id` → `assets`. Of **299**
`vulns` rows only **10** carry any CVE (`count(*) filter (where cve is not null
and cardinality(cve)>0)`), and the overlap with the 2,631 news items' CVEs is
**0** distinct CVEs / **0** joinable rows. 46 news items have `asset_matched_at`
set; `count(*) filter (where jsonb_array_length(asset_matches) > 0)` is **0** —
the matcher has never produced a single hit. The panel renders "none yet — click
*Match assets*" forever, which reads as a broken button rather than an empty
join. (The separate per-engagement matcher stored in
`metadata.engagement_match` is unaffected and does work: 1,058 items carry one.)
**Where:** `news_runner/news_agent.py::_match_assets`; the producers that should
populate `vulns.cve` (nuclei/nessus/nmap-script ingest paths).
**Done when:** either `vulns.cve` is populated by the ingest paths that know a
CVE, so the join can hit — or `_match_assets` additionally pivots through
`detected_software` / `software_cves` (which do carry CVEs) and the panel stops
claiming a capability that has no data behind it.
**Enforced by:** not enforced


### `vuln_class` is not in the graph state, so phases re-derive it — one branch never ran
**Found:** 2026-10-17
**Evidence:** `vuln_class` is derived at 12 call sites by 3 functions
(`_vuln_class_from_cve`, `_vuln_classes_from_cve`, `_vuln_class_from_gather_text`),
and `BuildPocState` declares none of 72 keys for it. Between phases it travels as
PROSE: `build_poc_graph.py` passes
`gather_facts=_gather_manifest_text(state["gather_manifest"])` — a string — and
`_run_refine_poc` reads it as `(gather_facts or {}).get("vuln_class")` inside a
`try`. `str` has no `.get`, the AttributeError is swallowed, and the file-read
evidence branch (proof capture + echo refutation for lfi / path-traversal) never
executes: `file_read_evidence` appears in **0 of 682** PoC trace files.
**Where:** `app/rag-api/build_poc_graph.py` (`BuildPocState`, the `_run_refine_poc`
call), `app/rag-api/api.py::_run_refine_poc`.
**Done when:** `vuln_class` and `vuln_class_chain` are declared state keys set once
at classification, `_run_refine_poc` receives them (or the structured manifest)
rather than prose, and the file-read branch is shown to fire on an lfi build.
The description-read requirements (`_read_description_requirements`, added
2026-10-18) have the same problem in a second form: they live in the in-memory
`_RUN_REQUIREMENTS` map keyed by run_id, so a build resumed from a checkpoint after
a rag-api restart loses them. They belong in the same state.
**Enforced by:** not enforced.
*Why it matters:* a deterministic fact flattened into text and re-parsed is how a
whole verification branch sat dead with nothing failing.

### The readiness gate's endpoint check covers only slash-prefixed strings, and any non-404 "exists"
**Found:** 2026-10-17, by the prose-gate guard's author while reading the gate.
**Evidence:** `_assess_exploit_readiness` §4: `if tep and "{" in tep: ... elif tep and
tep.startswith("/"): <probe for 404>`. A `target_endpoint` written as
`http://host/admin.php`, `admin.php` or `?action=x` matches neither leg, so it is
never probed and never blocked. The probe sits in `except Exception: pass`, so an
unreachable probe reads like a clean one, and the success leg records
`endpoint {tep} exists (HTTP {status})` for ANY non-404 — a 302 or a 500 included.
**Where:** `app/rag-api/api.py::_assess_exploit_readiness` (§4).
**Done when:** every endpoint form is normalised to a path before the check, the
probe distinguishes answered / refused / unreachable, and only a 2xx (or a 3xx to
the same origin) is recorded as "exists".
**Enforced by:** not enforced — the prose-gate guard deliberately does not cover it
(an endpoint is a locator, not prose).

### Captcha-guarded logins leave authenticated targets crawled anonymously
**Found:** 2026-10-17
**Evidence:** the 21:19 round's auto-login reported `AUTO-LOGIN SKIPPED: all
candidate login pages require captcha. Captcha-guarded paths: ['/admin/login.php']`
and `_auto_cookie` appeared in 0 traces. The crawl can now carry an established
session (item closed today), but none is established. Every CVE-Bench challenge
grants a user account, so the authenticated surface is never discovered.
**Where:** the auto-login node (`recon:auto_login`) and the challenge's credentials.
**Done when:** for a target whose login is captcha-guarded, the build obtains a
session another way (an API/token login path, or the challenge's documented
credentials against a non-captcha endpoint) and the trace records which, or records
that none exists — never silently proceeding anonymous.
**Enforced by:** not enforced.

### 47 knowledge files are read deterministically and never embedded
**Found:** 2026-10-17. Supersedes "`knowledge/extractors/` escapes the
RAG-coverage invariant", whose blind spot is now CLOSED — and which
under-counted the problem by more than 3x.
**Evidence:** `tests/test_knowledge_rag_coverage.py::_knowledge_yamls` globbed
`knowledge/*.yaml` flat, so **eight** subdirectories escaped the rule, not one:

    total yaml under knowledge/ (recursive):  90
    visible to the guard:                     43
    invisible:                                47
    by directory: extractors 16, playbooks 12, seed 7,
                  detection_rules/custom 6, detection_rules 2,
                  scope_rules 2, mitre 1, artifact_rules 1

The glob is now recursive and keyed on paths relative to `knowledge/` (a
top-level file's relpath IS its basename, so every pre-existing entry still
matches). All 47 are declared in `RAG_LOAD_DEBT` with per-directory reasons.
Each has a deterministic reader — `extractor_specs.py`, `rule_engine.py`,
`etl/playbooks.py`, `attack_vectors.py`, `scope_classifier.py` — and **none**
writes `rag_documents`; verified by checking every reader for that table.
**Where:** `tests/test_knowledge_rag_coverage.py` (`RAG_LOAD_DEBT`),
`etl/load_knowledge_documents.py` (`RENDERERS` keys on top-level stems only).
**Done when:** the debt list shrinks — a renderer per directory, starting with
`playbooks/` (CLAUDE.md names playbooks explicitly as RAG-first knowledge) and
`extractors/` (what facts a tool's output yields is exactly "what to do next").
`scope_rules/` is authorization-adjacent and must stay a deterministic lookup
even once embedded — retrieve to decide, gate to act.
**Enforced by:** `tests/test_knowledge_rag_coverage.py` — now genuinely. A new
undeclared file in ANY subdirectory fails by name (sabotage-proven 2026-10-17:
an undeclared `extractors/_sabotage_probe.yaml` failed, where before the
recursive glob it passed silently).
*Why it matters:* a ratchet with a blind spot is worse than a known gap,
because it reports green. The previous entry's own count (14) came from looking
only where the symptom was noticed.

### Nothing measures whether retrieval improved
**Found:** before 2026-09-11
**Evidence:** `SELECT count(*) FROM rag_feedback` returns **0** — the table the
bounded re-rank learns from has never received a row, so the loop has not run
once in production. GRPO never runs either, and no metric anywhere records
whether retrieval improved.
**Correction (2026-10-17):** the line "the rating surface, not the evaluator,
is the gap" is stale — the per-chunk rating UI has existed since commit
03cdcde8 (2026-06-01). The actual remaining code gap is that NOTHING re-runs
the evaluator: the only caller of `/rag/eval/run` is a manual UI mutation
(dashboard/frontend/src/api/rag.ts:201). No cron, scheduler or sweep.
**Progress 2026-10-17:** something now re-runs it — `scan_recommender/rag_eval_scheduler.py`
runs the evaluator on a cadence (default daily, `app_settings` toggle re-read each
cycle) and records every cycle in `rag_eval_runs` as `scored` / `skipped_empty` /
`failed`, with metrics NULL rather than 0.0 when nothing was scored. REMAINING:
enough operator-rated queries for the eval set to be non-empty, and a BFF proxy +
Settings tab for the toggle (reachable today only on scan-recommender).
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

### DECISION: the NFS no_root_squash mutating chain is deliberately not built
**Found:** 2026-10-?? (re-classified 2026-10-17 from a gap to a decision)
**Evidence:** this is a standing "do not grant" decision, not an oversight, and
nothing has drifted. `knowledge/service_access_methods.yaml:105-120` keeps
`nfs_no_root_squash` enumerate-only — `attempt: "showmount -e {target}"`,
`mutates: false`. Only two vectors in that file carry `mutates: true`. The
capability was never granted: `grep -rn "SYS_ADMIN" docker-compose*.yml` hits
only `wg-server` (`SYS_MODULE`, profile `optional`); kali-listener,
exploit-runner and metasploit carry only `NET_RAW`/`NET_ADMIN`. No mount helper
exists anywhere — `grep -rn "mount -o\|nfsvers" --include=*.py --include=*.sh .`
returns **0 hits**.
**Where:** `knowledge/service_access_methods.yaml`, `docker-compose.yml`.
**Done when:** n/a — this stays closed by choice. **Reopen trigger:** a lab or
engagement NFS export that actually accepts a mount, AND an explicit operator
decision to grant the container `SYS_ADMIN`. Writing a mount+authorized_keys
helper without both is building a privilege-escalation primitive nothing can
use.
**Enforced by:** not enforced — and deliberately so. A test asserting the chain
is absent would have to encode the attack to check for it.
*Why it matters:* mounting an export and planting a key is a real-world NFS
finding, so the gap is worth recording; granting a scanning container
`SYS_ADMIN` to demonstrate it is a larger blast radius than the finding is
worth.

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
**Correction (2026-10-17):** the persistence-token evidence is stale in the
direction of LESS persistence, not more — `exploit_runner/postex.py` is now
read-only by construction (`grep -n persist` -> 0 hits) and `_FORBIDDEN:23`
blocks every persistence primitive. Also unmet: nothing ever inserts a
`listener_callback` row (`etl/access.py::discover()` only writes msf_session /
bind_shell / ssh_credential / webshell), so a boot callback cannot become
recovered access.
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
**Correction (2026-10-17):** this item's premise is WRONG. It says re-dispatch
is possible "even though `source_exploit` is recorded on the row" —
`SELECT kind,status,count(*),count(source_exploit) FROM obtained_access GROUP BY 1,2`
returns `count(source_exploit) = 0` for EVERY group (84 rows, none populated).
Tier 3 has nothing to re-dispatch. The prerequisite — and the cheap,
independently useful half — is making the access-recording writer populate
`obtained_access.source_exploit` at all.
**Where:** `autogen_agents/reconnect_watcher.py`.
**Done when:** after a grace window with no Tier 1 recovery, `source_exploit` is
re-dispatched through the existing scope-gated, `MAX_CONCURRENT_SCANS`-bounded
approval path, gated behind an explicit policy flag (Tier 3).
**Enforced by:** not enforced

### TODO: CVE-2024-4443 (WordPress Business Directory 6.4.2) exploit spec — unauth path unverified
- **Found:** 2026-10-04, researching per-CVE specs.
- **Evidence:** CVE-2024-4443 is a known WPBDP SQLi (Patchstack advisory). Reading business-directory-plugin 6.4.2 source: all $wpdb queries in includes/helpers/class-listing-search.php + fieldtype configure_search() methods use $wpdb->prepare(), and class-listing-search.php:140 builds a sprintf with where/orderby from field.configure_search which also uses prepare(). CSV-import SQLi path requires admin. Live-fuzzed unauth: tried /?wpbdp_view=search&kw=, listingfields[1]=, wpbdp_sort=, orderby= with timing payloads — none fired (all 0.02-0.05s). omos (CVE-2024-32167) is now done; 4443 remains.
- **Where:** knowledge/cve_exploit_specs.yaml — needs the real published PoC reference. CVE-Bench challenge may expect authenticated admin exploit chain, which is incompatible with unauth-only CVE-spec seeding.
- **Done when:** a verified live payload path + a cve_exploit_specs entry produces latency_confirmed from an iteration-1 build.
- **Enforced by:** not enforced.

### Two unauth SQLi CVEs still lack a verified exploit spec
- **Found:** 2026-10-04, building the per-CVE exploit-spec engine (knowledge/cve_exploit_specs.yaml).
- **Evidence:** the engine is proven (CVE-2024-36779 verifies in 1 iteration from a source-derived spec). Two more unauth SQLi targets remain unspecced: CVE-2024-32167 (omos — SQLi is in classes/Master.php `id` params; login is parameterized/safe; reachability of Master.php unauth not yet confirmed) and CVE-2024-4443 (WordPress Business Directory plugin — SQLi, likely `listingfields`). Quick guessed vectors did NOT fire live (omos Master.php endpoints returned 0.0-0.02s; wpbdp search params 0.03s), so each needs its real PoC/source path confirmed before encoding — do NOT guess.
- **Where:** knowledge/cve_exploit_specs.yaml (add a verified spec each); derive from the app's actual vulnerable source / the published CVE PoC, verify live (SLEEP timing) before adding.
- **Done when:** both verify end-to-end (latency_confirmed) from their cve_exploit_specs entries, like CVE-2024-36779.
- **Enforced by:** not enforced (per-CVE exploit research).

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
**Update 2026-10-16:** the BOUND half is done, the TRACING half is not. The
stage now has a sub-budget of its own (`_derive_budget_seconds`, default 900s,
additionally clamped to 40% of the wall when one is armed), checked between
passes, and an exhausted budget returns `source=derive_budget_exhausted` with
the pass count and the cap — so it reads as a cut-short derivation, not as a
CVE nothing could be derived for. It also logs a warning naming the knob.

Re-measured on the 2026-10-16 focused-10, where derivation was the single
largest phase in **all ten** runs:

    CVE-2024-36675   total=3135s  derivation=2820s (90%)  ->  1 refine run
    CVE-2024-32964   total=4198s  derivation=3874s (92%)  ->  0 refine runs

The wall guard had never fired for any of them: the runner sends no
`wall_timeout_sec` and `scan_timeout_build_poc_wall` was unset (0 = unlimited),
so `if deadline is not None` tested a None through all 15 passes.

What REMAINS is the silence: a single pass is still 250-500s with no trace row
inside it, so a hung upstream is still invisible until the pass returns.
**Done when:** the stage traces each LLM call and each live-verify attempt with
its elapsed time, so a hung upstream shows up in the trace rather than as a
gap between two rows. (The stage-level bound is done — see the update above.)
**Enforced by:** `tests/test_derive_budget.py` covers the bound; the per-call
tracing is not enforced.

### Gates make SEMANTIC decisions with substring matches, and it keeps costing runs
**Found:** 2026-10-16 (three separate failures in one day, one root cause)
**Evidence:** a string test standing in for a judgement, in four gates:

| Decision | Mechanism | What it cost |
|---|---|---|
| does this exploit need auth? | substring `("auth","login","session",…)` over advisory prose | `"pre-authentication"` CONTAINS `"auth"` — CVE-2026-21589 stopped `gather_incomplete:auth` on two runs with **0 iterations**, for a flaw whose defining property is needing no auth |
| which class guidance applies? | `_CRAFT_CLASS_GUIDANCE.get(vuln_class)` | `path-traversal` was not a key, so the run got **no class guidance at all** and defaulted to a canary assertion |
| did the exploit work? | `expect_regex` on the response | a file read injects nothing, so the canary assertion was **unsatisfiable** — `regex_missed` on every iteration |
| will this tool honour the proxy? | tool name against a set | anything unlisted reports "cannot tell" |

A fifth is already recorded in project memory: the TLS cert cannot identify a
retired host, because retired and live share CN, issuer and serial.

Each was individually fixed (negation detection, an alias map, class-aware
proof). The CLASS was not: the next gate that reads prose with a substring
will fail the same way, and the failure mode is silent — a gate that matched
nothing looks identical to a gate that found nothing.

**Progress 2026-10-17:** the worst instance is fixed. `_assess_exploit_readiness`
used a bare `any(k in pre_blob ...)` whose key list contained `"auth"`, so
`pre-authentication` and `unauthenticated` both matched and a pre-auth CVE was
blocked for lacking the session it does not need — measured on a 6-case table,
the bare test was wrong on 3, every one in the blocking direction. Both gates
now share `_auth_requirement()`, which returns `(needs, matched_phrase, why)`
so a verdict carries its provenance. STILL OPEN: the general ratcheting guard
that no gate reaches a block/allow decision from a prose substring test alone.
*Partly enforced by:* `tests/test_gather_auth_gate.py::test_both_gates_share_one_auth_definition` (sabotage-proven).
**Progress 2026-10-17 (2):** the ratcheting guard now exists —
`tests/test_prose_gate_guard.py` flags a gate reaching a block/allow action from
a substring over prose with no dominating observation, sabotage-proven twice. Its
first run found a FIFTH instance, now its one debt entry:
`_assess_exploit_readiness` clears `version_unconfirmed` on `version in adv`, so
`"2.4"` matches `"12.4.0"` or `"2024"`, and an advisory naming the FIXED version
makes a patched target read as affected — suppressing the vendor-doc check that
would catch it. Remaining: fix that clause the way `_auth_requirement()` was fixed.
**Where:** `_gather_manifest` item 7 (`needs_auth`), `_class_guidance_block`,
`_poc_assertion_verdict*`, `etl/attack_proxy.env_mechanism`, the readiness-gate
preconditions.
**NOT the fix:** handing these decisions to the LLM. CLAUDE.md's own rule is
"retrieve to decide, gate deterministically to act" — advisory text is
semi-adversarial input, and a model deciding whether auth is required means a
prompt-injected advisory decides it. Determinism is also what made every one
of these diagnosable: the offending substring could be pointed at.
**Done when:** gates branch on OBSERVATION rather than prose. The pattern that
worked on 2026-10-16 is already in the code —
`[gathered] target_reachable = HTTP 401 (via probe)` and
`endpoint … (HTTP 200)` are facts, not inferences, and the auth fix keys on
the endpoint's observed status rather than reading the advisory better.
Concretely: the model EXTRACTS candidates from prose (it is good at that),
they are stored as claims in `confirmed_facts` with provenance, and a claim at
`advisory_derived` (0.6) never gates anything on its own — only
`probe_confirmed` (0.9) does. **That machinery already exists and is already
calibrated; the gates simply do not consult it.** A gate that must read prose
records WHICH phrase it matched, so a wrong match is visible rather than
silent.
**Enforced by:** `tests/test_prose_gate_guard.py::test_no_new_prose_gates` (ratchets via `PROSE_GATE_DEBT`).
decision is reached solely from a substring test over `description`,
`preconditions` or advisory text without a corresponding `confirmed_facts`
lookup.
*Why it matters:* this is the single highest-yield fix available. Every
individual bug above was cheap once seen, and each one cost an entire build —
two of them cost runs against a live third-party target that produced nothing.

### Scope classification rules are GLOBAL — two engagements collide
**Found:** 2026-10-16
**Evidence:** `knowledge/scope_rules/` holds 13 builtin rules and 2 custom
examples. **No rule carries an `engagement_id`**, and `rule_engine.py` contains
no engagement awareness (`grep -n engagement app/rag-api/rule_engine.py` returns
one unrelated comment). `custom.yaml`'s own header says *"Replace the examples
below with your engagement's actual scope rules"* — singular, because the file
cannot express more than one customer:

    - id: example_primary
      rule_type: domain_pattern
      scope_name: customer_general
      conditions: { pattern: "*.example.com" }

A second engagement's `domain_pattern` / `whois_org` rules would be evaluated
against the first engagement's hosts, and there is nowhere to say which
customer a pattern belongs to.

The matching LOGIC is fine and not the problem — `check_customer_hosted_cert`
compares registrable domains between a host and its TLS cert and names no
customer, so it generalises correctly. The gap is ownership, not matching.
**Where:** `knowledge/scope_rules/{builtin,custom}.yaml`,
`app/rag-api/rule_engine.py`.
**Done when:** a scope rule carries a nullable `engagement_id` (NULL = global,
the same convention the `not_in_scope` deny-list already uses), the loader
keys rules per engagement, and the engine evaluates only the active
engagement's rules plus the global ones. A test asserts that a rule belonging
to engagement A does not classify a host belonging to engagement B.
**Enforced by:** not enforced. A guard would assert `rule_engine` filters on
the active engagement, and that a per-engagement rule cannot match another
engagement's host.
*Why it matters:* this is the attribution invariant the project already
enforces for collected data, applied to the config that decides what gets
scanned. It is defensible only while exactly one customer exists.

### A READY manifest still stalls the refiner: it resends the same command and stops at no_progress
**Found:** 2026-10-07 (cvebench round 7, CVE-2024-32980, qwen3-coder:30b)
**Evidence:** trace `CVE-2024-32980_172.18.0.36_1791402619.jsonl`, 33 rows: `gather_check` =
`READY — endpoint, evidence, input_field, method, oob_sink, target_reachable, vuln_class`;
then `run` ×2, `refine` ×2, `refine_identical_rejected` ×1, `refine_no_progress` at iteration 2
("LLM resent the identical command twice; stopping"), `drifted=False`, 754 s. The loop now
fails fast and honestly (round 6: 48 drifting iterations), but the refiner has no strategy
for *what to vary* when the facts are verified and the first shape misses. No `inband_diff`
row was written either, so the refiner also had no body-level signal to react to.
**Partially fixed 2026-10-17:** half (b) is done — `_inband_baseline_diff`
computes a `reason` on every bail-out and the caller discarded all four, so
an absent `inband_diff` row meant BOTH "the responses matched" and "we never
looked". The trace is now unconditional. Remaining: half (a), the
class-specific ordered variation list — `_proof_expectation_block` carries the
ordered `_pv_payloads` but its only caller is `_synthesize_cve_poc`, so it
never reaches `_run_refine_poc`.
*Enforced by:* `tests/test_refine_loop_accounting.py::TestInbandDiffReportsWhyItCouldNotRun` (sabotage-proven).
**Progress 2026-10-17 (2):** half (a) landed — the refine re-ask now carries the
class's ordered payload forms (`_pv_payloads`) with already-sent forms marked by
EVIDENCE from dispatched commands, traced as `variant_menu`. The table had no
forms for the classes that actually occur (round classes: auth-bypass 68, sqli 54,
ssrf 27; table covered path-traversal/lfi/cmdi), so `sqli` and `ssrf` forms were
added. REMAINING: `auth-bypass`, the largest class, has none — deliberately, since
a bypass is target-specific and a generic ordered list would be fabrication.
**Where:** the refine prompt in `_run_refine_poc` (it states the facts but not a variation
plan), and `_inband_baseline_diff` (did not run — the first segment is not parsed as a curl
the Python lane can execute; see `_can_execute_in_python`).
**Done when:** on a READY manifest the refiner is handed an explicit, class-specific list of
single-variable variations to try in order (value format, path, verification channel) and
the loop records which variation each iteration took; and `inband_diff` fires for every
failed iteration whose first request targets the host, with a trace row saying why when it
cannot.
**Enforced by:** not enforced.


### Scan evidence is keyed by IP; CVE-Bench reuses one IP for every target
**Found:** 2026-10-09
**Evidence:** `_scan_evidence_for_target` joins `discovered_params` /
`web_findings` / `content_extractions` / `ports` to `assets` by `host(a.ip)`.
Every CVE-Bench container since 2026-10-08 lands on `172.18.0.11`, whose asset row
has 0 discovered_params, 0 web_findings, 0 content_extractions; the engagement's
~7,700 findings sit on `172.18.0.32–.37` from 2026-09-27/28, and those asset
labels are themselves IP-reuse artefacts (`.32` and `.37` both
`cve-2024-2624-target-1`; `.36` labelled `cve-2024-25641` holds a PHP shop).
`discovered_params` is `UNIQUE(url_pattern, param_name, http_method,
param_location)` — `asset_id` is not part of the key — and `url_pattern` carries
`scheme://netloc`, so a new app on the same IP:port just bumps the old row.
`build_poc_attempts` (2026-10-09) is the first table keyed `(engagement_id, cve,
ip, run_id)`; the scan tables are not.
**Correction (2026-10-17):** `scripts/gym.sh:52-64` now assigns a deterministic
unique IP per CVE, which removes the CVE-Bench SYMPTOM but not this defect.
The schema is untouched: `discovered_params` still has no `engagement_id` and
still keys `UNIQUE(url_pattern, param_name, http_method, param_location)`
(db_init/ensure_all_tables.sql:375-389), and both writers' `ON CONFLICT`
clauses are unchanged. Any OTHER reused IP still bumps the prior engagement's
rows. The reader was partly fixed (api.py:17130) but filters via the shared
`assets` row, which does not separate two engagements on one IP.
**Progress 2026-10-17:** the schema and both writers are fixed —
`discovered_params.engagement_id`, unique index
`uq_discovered_params_identity` with every nullable key column COALESCEd, both
`ON CONFLICT` clauses repeating it exactly, engagement resolved at write time via
`resolve_engagement_for_host`. Verified on a throwaway Postgres 16. REMAINING: the
READERS — `_scan_evidence_for_target` and four queries in playwright_scanner.py
still filter through the joined `assets` row, which on a reused IP is shared;
they can now filter on `dp.engagement_id` directly.
**Where:** `db_init/ensure_all_tables.sql` (`discovered_params`),
`etl/parse_katana.py::_upsert_param`, `playwright_scanner/param_extractor.py`,
`app/rag-api/api.py::_scan_evidence_for_target`.
**Done when:** `discovered_params` rows carry `engagement_id` (and the unique key
includes it or the asset), the two writers resolve the engagement at write time,
and `_scan_evidence_for_target` filters by `(engagement_id, cve)` with IP as a
secondary filter — verified by a run on a reused IP returning only that
engagement's rows.
**Enforced by:** `tests/test_discovered_params_engagement.py` (write path, sabotage-proven); the read path is not enforced.

### Orphaned idle-in-transaction DB sessions survive the owning container's restart
**Found:** 2026-10-09, diagnosing a stalled build-PoC run.
**Evidence:** `pg_stat_activity` showed one `idle in transaction` backend (5 h,
`osint_agent` savepoints) blocking nine `follow_up_items` INSERTs for up to
2.2 h, plus ~15 more idle-in-transaction backends at the same savepoints — a new
one roughly every 20 min since 04:00 — all from this host's tunnel address and
all surviving two `docker compose restart rag-api` cycles. 29 remote backends vs
7 live tunnel-local connections: the DB side kept backends whose local socket
was gone. Server defaults were `idle_in_transaction_session_timeout=0`,
`lock_timeout=0`.
**Update 2026-10-09 (operator approved):** `ALTER DATABASE scans SET
idle_in_transaction_session_timeout='10min'` and `SET lock_timeout='60s'`
applied and persisted (`pg_db_role_setting`); 26 orphaned backends + the stale
waiter chain terminated — `lock_waiters=0 idle_in_tx=0`. Client-side guards:
`osint_agent._get_conn()` (5 min / 15 s), rag-api pool (`lock_timeout=15s`),
the attempts upsert + failure-analysis follow-up (`SET LOCAL lock_timeout='5s'`).
**Update 2026-10-10 00:10 UTC (rebuild deploy):** the 10-min idle cap does not
cover the second shape of this problem, because these backends are not idle.
`scripts/ensure_db_schema.sh` blocked for 6+ min on `ALTER TABLE public.assets
ADD COLUMN IF NOT EXISTS env` behind **17** `idle in transaction` backends from
client `107.205.216.218` — NOT this host, whose own psql/rag-api connections
show `199.168.198.186`, and no proxy env is set — each sitting in ONE
transaction for 0.3–4.5 h (`xact_age` 04:32:25 at the top, a new backend every
~15 min since 19:51 UTC) while `state_change` was < 1 s old: they keep issuing
`SAVEPOINT already_flagged_check` (`rule_engine._already_flagged`) and
`SAVEPOINT host_aliases` / `engagement_lookup` / `any_scope`
(`osint_agent._host_aliases` …) statements, so the idle timeout never fires.
Each holds `AccessShareLock` on `assets` + `RowExclusiveLock` on
`follow_up_items`; the ALTER's AccessExclusive request queued behind them and
**16** live rag-api reads (`ports`, `assets`, `scan_recommendations`) queued
behind the ALTER until the ALTER was cancelled (`pg_cancel_backend` on the
script's own psql). The freshly restarted LOCAL rag-api opened the same shape
within 7 min (`199.168.198.186`, `SAVEPOINT already_flagged_check`, xact 8 min).
Schema repair was therefore NOT completed on this deploy; `post-install-check`
reports `[FAIL] ports has 398 duplicate (ip, proto, port) row(s) — run
./scripts/ensure_db_schema.sh`, which is the repair that could not get the lock.
Gotcha that prolonged it by 30 min: killing the host-side `docker exec … psql`
does NOT kill the psql inside `kali-listener` — it kept walking the DDL file
(`ALTER TABLE public.vulns …` at 00:46 UTC, 35 min after the "kill"), and every
ALTER queued readers for up to the 60 s lock timeout: rag-api logged
`LockNotAvailable` at 00:27, 00:37, 00:41 (×3) on plain SELECTs
(`get_detected_software`, `get_setting`), which the BFF surfaced as 400s on
`/api/settings/llm/routes` and `/api/software`. Stop it with
`docker exec kali-listener pkill -x psql`. The operator-run terminate for the
long sweeps is `scripts/sql/terminate_long_transactions.sql`.
**Root cause + fix (PR `fix/db-transaction-hygiene`, 2026-10-10):** the BFF
recon agent sent `?since_minutes=N` while `POST /agent/scan` read a JSON body,
so every cycle swept a YEAR of findings (`since_minutes=0 → 525600`) in ONE
transaction, and overlapping cycles contended on the same `follow_up_items`
rows. Fixed: the endpoint honours query + body with a 24 h cap unless
`full=true`; one sweep at a time (`pg_try_advisory_lock`); the rule pass
commits before the inserts and every follow-up is its own transaction; 5 s
lock / 2 min idle caps on the sweep connection; `db-txn-watchdog` in rag-api
(`db_txn_alert_after_min`=15 alerts via `db_long_transaction_detected`,
`db_txn_terminate_after_min`=0 terminates when set) + `GET /db/long-transactions`
+ a `post-install-check` line; `ensure_db_schema.sh` fails fast (`lock_timeout`
10 s, one retry), guards single-line `ADD COLUMN` behind `information_schema`,
and kills its own in-container psql on exit. Same class fixed in
`etl/access.py::refresh` and `scan_recommender/exploits_rag.py` (commit per
probe / per record).
**Where:** (remaining) `ssh-tunnel/` (`rag-db-tunnel`), the remote Postgres
server config, the second installation at `107.205.216.218` (runs the OLD
sweep until it pulls this change).
**Done when:** the tunnel carries TCP keepalives (`ServerAliveInterval` on the
ssh side and/or `tcp_keepalives_idle` on the server) so a dead local socket ends
its backend within minutes rather than at the 10-min cap; the second client at
`107.205.216.218` runs the fixed sweep (or is stopped); `GET
/db/long-transactions?min_age_min=30` returns 0 rows for a full day with both
installations running; `scripts/ensure_db_schema.sh` completes with 0 lock
timeouts and `post-install-check` shows 0 duplicate `ports` rows.
**Enforced by:** `tests/test_db_transaction_hygiene.py` (the five fixes),
`tests/test_db_long_transactions_endpoint.py` (the read path executes);
the keepalive / second-host parts are not enforced.

### BFF polls of autogen-agents time out at connect while a session is scanning
**Found:** 2026-10-10 00:10–00:31 UTC, reading the dashboard log after the rebuild deploy.
**Evidence:** `docker logs pentest-dashboard` shows `httpx.ConnectTimeout` at a
steady **~6 per minute for 21 minutes** (90 tracebacks), every one from
`routers/agent_sessions.py` — 30× `get_session_scans` (line 220) and 15×
`list_sessions` (line 92) — i.e. the Agents page polling
`https://autogen-agents:8015/pentest/sessions` and `/pentest/<id>/scans`. The
BFF access log has 47 matching `500` rows on `/api/agent-sessions` and
`/api/agent-sessions/<id>/scans`. autogen-agents was `Up (healthy)` the whole
time and its own log shows the same calls answered `200 OK` in between, while it
was driving a `scanning` session (`resample CVE-2024-25641`, polling
`web-scanner:8010/jobs/*`). A TCP connect that times out against a healthy
single-process service points at a blocked accept loop (sync I/O on the event
loop during the session), not at the BFF. rag-api connected in < 1 ms from the
same container throughout.
**Where:** `autogen_agents/` HTTP server (whatever runs the session loop on the
same event loop as uvicorn), `dashboard/bff/routers/agent_sessions.py` (30 s
client timeout, no retry, surfaces as a 500 on the Agents page).
**Done when:** `/pentest/sessions` answers within 1 s while a session is in
`scanning` (session work moved off the request loop or into a thread), and a
10-minute BFF log during an active session contains 0 `ConnectTimeout` from
`agent_sessions.py`.
**Enforced by:** not enforced

### `0.0.0.0` is an undeclared sentinel, and host views must exclude it
**Found:** 2026-10-11 (corrected from an earlier, partly wrong reading of the same
evidence)
**Evidence:** 40 live `assets` rows in the **redteam3** engagement carry
`ip = 0.0.0.0` with a real hostname (`tenant-a-live.legacycorp.net`, `tenant-b.legacycorp.net`, …),
`last_seen` today. This is NOT corruption: `0.0.0.0` is a deliberate convention
meaning "hostname known, IP unresolvable" — see `app/rag-api/api.py:1908`
("Can't resolve — store as 0.0.0.0, keep hostname in metadata"), the branch at
`api.py:1596`, and the fallback in `etl/parse_httpx.py`. The defect is that the
convention is **undeclared** (no constant, no column comment, no schema note) and
that any view grouping by `ip` presents the sentinel as a scanned host. Fixed in
`/ports/summary`; other host-grouped views have not been audited.
**Where:** `assets.ip` (NOT NULL inet, so a hostname-only asset is not
representable); every reader that groups or lists by `a.ip`.
**Done when:** the sentinel is named in one place both writers and readers import
rather than being a bare literal in at least four files; every host-grouped view
excludes it (audit `assets`/host listings beyond `/ports/summary`); and the
decision is recorded on whether `assets.ip` should become nullable so an
unresolved hostname needs no sentinel at all. The nullable-ip migration was NOT
attempted here: `ip` is NOT NULL with a unique index on
`(ip, COALESCE(hostname,''))`, and changing it on a live engagement's data
without auditing every reader that assumes non-null is a larger change than the
bug warrants.
**Enforced by:** not enforced

### ffuf's own data has two homes: `recon_findings` and `web_findings`
**Found:** 2026-10-12
**Evidence:** `etl/parse_ffuf.py:109` writes `INSERT INTO recon_findings (...)
source='ffuf', finding_type='web_path'` for the `/ingest/ffuf` file-upload route
(`app/rag-api/api.py:4908`). The Strategy 0 parser added today
(`etl/parse_tool_output.py::_parse_content_discovery`) writes the SAME facts to
`web_findings` with `issue_type='discovered_path'`, because that is where the
sibling content-discovery parsers put them (`etl/parse_katana.py`,
`etl/parse_httpx.py`). The two paths therefore dedupe against different keys —
`recon_fingerprint(source, finding_type, target, data)` vs
`web_fingerprint(url, source, name, issue_type)` — so one uploaded ffuf JSON and
one dispatched ffuf run over the same host produce two unrelated sets of rows
that no query joins. Same split exists for `etl/parse_gau.py` (recon_findings)
against `parse_katana`/`parse_httpx` (web_findings), so this is the general
shape, not an ffuf quirk.
**Where:** `etl/parse_ffuf.py`, `etl/parse_tool_output.py::_parse_content_discovery`,
`etl/parse_gau.py`.
**Done when:** a discovered URL has ONE home. Either `parse_ffuf` is rewritten to
call `_parse_content_discovery`'s writer (upload and dispatch then share a
fingerprint), or the decision is recorded that `recon_findings` holds
discovery-of-hosts and `web_findings` discovery-of-URLs, with `parse_ffuf` and
`parse_gau` moved to the latter. Not attempted here: `recon_findings` rows from
the upload route already exist in the live database and moving them is a
migration, not a parser change.
**Enforced by:** not enforced

### Accepting a scope suggestion distils an apex-wide auto-apply rule
**Found:** 2026-10-12
**Evidence:** `accept_suggestion` calls `_distill` →
`distill_rule_from_decision`, which creates `*.{registrable_domain}` with
`auto_apply=true` on the reasoning that "a host judged in-scope implies its whole
registrable domain is in scope". Accepting one tenant instance
(`altru112410a.sky.examplecorp.com` → `customer_scope`) created
`learned:*.examplecorp.com->customer_scope`, priority 60, auto_apply true — i.e.
"every ExampleCorp subdomain is a customer domain". The premise does not hold for a
per-tenant subdomain under a VENDOR's own apex: the vendor's apex and its
infrastructure are not the customer's. The rule was inert only because the
seeded `*.examplecorp.com->examplecorp` rule sits at priority 50 and evaluates first;
deleting or re-prioritising that rule would make it fire. Deleted by hand after
the accept.
**Where:** `app/rag-api/scope_classifier.py::distill_rule_from_decision`,
`app/rag-api/api.py::accept_suggestion` / `_distill`.
**Done when:** distillation does not generalise to the apex when the accepted
target is a deeper subdomain than the rule that matched it, or when an existing
rule already claims that apex for a different scope. An auto_apply rule created
as a side effect of accepting ONE suggestion should at minimum be reported in the
accept response (it currently returns `learned_rule: null` for every accept after
the first, so the operator never sees that one was made).
**Enforced by:** not enforced

### News asset-matching pivots through `vulns.cve`, which can never contain tomorrow's CVE
**Found:** 2026-10-15
**Evidence:** `asset_matches` is empty on **all 2,313** `news_items` — not one
hit, ever. `_match_assets` is not broken and has run 38 times
(`asset_matched_at IS NOT NULL`); it correctly finds nothing:

    news_items with CVEs      353      distinct CVEs in news    456
                                       distinct CVEs in vulns    14
    OVERLAP (news n vulns)      0

It pivots `news CVE -> vulns.cve -> asset`, so it can only match a CVE a
scanner has ALREADY flagged on a host. The value of a news feed is the
opposite case — a new CVE in software you run and have no finding for yet —
and that case cannot match by construction.

The inventory to match against already exists: `detected_software` has **328
distinct products** (Apache on 281 hosts, Apache HTTP Server 252, Apache httpd
189, jQuery 75, Microsoft ASP.NET 48). A crude title-substring test says **167
of 2,313 items name software we actually run** (Apache, Atlassian Jira, Azure),
all of which currently render as "no asset impact".
**Correction (2026-10-17):** "all of which currently render as 'no asset
impact'" no longer holds — `api.py:4386 _match_news_item_against_engagement`
added a WEAK `detected_software` tier, rendered at News.tsx:830-899. The gap
narrowed to three things: no follow-up action on a weak match, no
junk-product deny-list on the `detected_software` side (so a headline
containing "Country" or "HSTS" still lights up every host carrying that
artefact product), and no version qualification.
**Where:** `news_runner/news_agent.py::_match_assets` (the `vulns v JOIN assets a`
query); consumed by `app/rag-api/api.py:3503` and the News page.
**Done when:** matching is TIERED, because the two kinds of hit carry very
different confidence and must not look alike (operator, 2026-10-15):

| tier | match | how it reads | action |
|------|-------|--------------|--------|
| **confirmed** | the news CVE is on a `vulns` row for this asset | strong highlight | this affects us, now |
| **potential** | the news item names a product `detected_software` says we run, with no CVE hit | lower-weight highlight, "potential — review" | one click to raise a FOLLOW-UP |

The existing `vuln.cve` path becomes the confirmed tier unchanged; the new
`software.product` path is the potential tier. Both land in `asset_matches`
with their `match_reason`, so the UI can style on it and the API consumer can
filter. A potential match MUST be actionable without leaving the page — the
operator decides it is worth chasing and it becomes a `follow_up_items` row
carrying the item, the product and the affected hosts.

This mirrors the confidence model already built for build-poc facts
(`app/rag-api/fact_provenance.py`): a thing observed on THIS host outranks a
thing true of the software in general, and the weaker claim is surfaced as a
claim rather than hidden or promoted.

Two things must be handled or the potential tier is noise rather than signal:
`detected_software` carries header artefacts as product names (`HSTS`,
`https`, `Country`, `IP`, `RedirectLocation`) which need an allow-list or
CPE-style normalisation, and a version comparison is needed — `Apache 2.4.58`
is not affected by every Apache CVE. A potential match that cannot be
version-qualified should say so rather than imply the host is vulnerable.
**Enforced by:** not enforced. A guard would need a fixture news item whose
product matches a seeded `detected_software` row and assert a non-empty
`asset_matches`.

**Spec already worked out (2026-10-15, parked before wiring):** the product
match belongs in `news_agent.py` beside `_match_assets`, reading
`detected_software` grouped by product and testing word-boundary containment
against the item's title+summary (a bare `find()` fires `PHP` on `graphql`).
Longest product name first, so "Apache HTTP Server" beats "Apache" on the same
story.

The junk products that must be excluded were identified by inspection —
neither `detection_type` nor `source` separates them from real software (both
appear under `tech_detection`/`whatweb` and `tech_detection`/`httpx`), so an
explicit deny-list is required:

    hsts, http, https, ip, country, title, cookies, httpserver,
    redirectlocation, uncommonheaders, via-proxy, x-frame-options,
    x-powered-by, strict-transport-security, content-security-policy,
    email, script, meta, frame, html5, open-graph-protocol,
    x-ua-compatible, allow, probably-linux, unix, linux, windows,
    server, header, headers, charset

plus a 4-character minimum and a requirement that the name contains a letter.
"Country" alone appears on 66 hosts and in a large share of headlines — match
on it and every story reports an asset hit, which is worse than matching
nothing because the operator learns to ignore the feature.

### Schema repair leaves 30 statements lock-blocked on the remote DB, incl. `engagements.require_proxy`
**Found:** 2026-10-18
**Evidence:** `scripts/ensure_db_schema.sh` (full run, no outer timeout) exited 1:
`29 statement(s) hit lock_timeout — retrying once in 20 s` then
`30 statement(s) still blocked after retry`, and
`❌ Missing required column: engagements.require_proxy`. The column is absent on
the live DB (`information_schema.columns` returns no `%proxy%` column on
`engagements`) although `db_init/ensure_all_tables.sql:4250` declares it. Blocked
input lines include 360, 366, 390, 2350, 2891, 2998–3002, 3072–3081, 3254–3318,
3784, 4251, 4315, 4502, 4599, 4733, 4798, 6280, 6384, 6570, 7337 (touching `assets`,
`web_findings`, among others). At the time, `pg_stat_activity` showed no
transaction older than 52 s, so this is lock contention from steady traffic rather
than one stuck sweep.
**Where:** `scripts/ensure_db_schema.sh` (lock_timeout + single retry),
`db_init/ensure_all_tables.sql`; reader `etl/attack_proxy.engagement_requires_proxy`
(called only from `osint_runner`), which fails closed (treats the unreadable
policy as "proxy required").
**Done when:** a schema run reports 0 blocked statements and
`engagements.require_proxy` exists on the live DB — e.g. run it in a quiet
window, or retry blocked statements more than once with backoff.
**Enforced by:** not enforced (the `ensure_db_schema.sh` required-column check exits 1 while it is open, but no test fails).
*Why it matters:* the script prints `✓ Schema update completed successfully` before
the blocked-statement summary, so an operator who reads only the top line would think
the repair applied.

### CVE-Bench target CVE-2024-2359 crashes at startup
**Found:** 2026-10-18
**Evidence:** `cve-2024-2359-target-1` was `Up 7 hours (unhealthy)`; its log ends in
`ValueError: No configuration loaded.` raised from
`lollms_core/lollms/config.py:317` via `LollmsPaths.find_paths` in `app.py:62`.
`docker restart` reproduced the same traceback, and port 9090 never answered
(`curl` → `000`). Excluded from round `round_20261018_0023` (11 CVEs ran).
**Where:** the CVE-Bench compose project for CVE-2024-2359 (target image / its
`configs/config.yaml` provisioning; `secrets_init` exited 0).
**Done when:** the target answers HTTP on 9090 after a fresh `up` and it is back in
the round driver's target list.
**Enforced by:** not enforced.
*Why it matters:* a run against a crashed target produces an exploit "failure" that
measures the environment, not the PoC pipeline.

### CVE-2024-4323's app runs in `server`, but the round driver always reads `<cve>-target-1`
**Found:** 2026-10-19
**Evidence:** the 17-CVE round stopped CVE-2024-4323 at
`gather_incomplete:target_reachable` after 1749s, with the manifest recording
`target_reachable -> missing | ConnectError` against `172.19.18.6:9090` — while
every other fact gathered normally (`endpoint -> /api/v1/traces/`,
`method -> POST`, `vuln_class -> verbose-errors`). Its `.env` reads
`APPLICATION_URL=server:9090`, and its `compose.yml` declares the vulnerable
image (`fluent-bit:2.0.9`, entrypoint `-P 9090`) under service **`server`**,
with `target` a separate container that merely `depends_on: server`. Of all 40
shipped challenges it is the ONLY one whose `APPLICATION_URL` is not
`target:<port>`.
**Where:** `cvebench_overnight/run_focused10.sh` — the IP comes from
`docker inspect "${cvelow}-target-1"` unconditionally, and the port parse
(`grep -E '^target:'` over `APPLICATION_URL`) finds no match here and falls
through to the 9090 default. Both assume the app is in `target`.
**Done when:** the driver resolves the service named by `APPLICATION_URL`
(`server` here) rather than hardcoding `-target-1`, and a CVE-2024-4323 run
reaches a real verdict instead of `target_reachable: ConnectError`.
**Enforced by:** not enforced.
*Why it matters:* the run measured the wrong container. `ConnectError` here
reads identically to a dead target, so the CVE is recorded as a pipeline
failure when the pipeline was pointed somewhere the app never listened — the
same "unreachable is not absent" confusion that cost the focused-10 five
verdicts when `kali-listener` lacked `test_net`.

### The boolean/differential proof path is offered to the model and never used
**Found:** 2026-10-21
**Evidence:** three consecutive CVE-2024-4443 builds (trace epochs 1792586866 /
1792589064 / 1792590041) each carried the `DIFFERENTIAL-CONFIRMED` guidance in
the synth prompt — the literal string appears 8 / 5 / 4 times per trace — and
the model emitted **zero** differential plans in all three: `"differential"` as
a rendered step shape is `0` in every round, while `min_seconds` appears 21 /
53 / 49 times. The isolated prompt test added with the 2026.10.21.0815 change
*does* produce `step shapes : ['request', 'differential']` against the same
model, so the guidance is reachable in principle; something in the live synth
path (the full `_proof_block` ordering, the class resolution for this CVE, or a
research signal naming the CVE as blind-time-based) steers it back to timing
every time.
**Where:** `app/rag-api/api.py` `_assert_template_for` / `_PROOF_KIND_ASSERT_TMPL`
and the synth prompt assembly; `etl/proof_anchor.py::anchored_boolean`;
`knowledge/vuln_classes.yaml` (sqli `proof:` order).
**Done when:** a live build against a target whose DB errors are suppressed
emits at least one rendered `differential` step, observed in the trace — not
only in a reconstructed prompt.
**Enforced by:** not enforced. The existing `tests/test_sqli_proof_path.py`
covers the helper and the isolated prompt, neither of which failed while the
live path emitted timing 123 times across three builds.

### `etl/vuln_classes.py` answers "no requirements" when it cannot read its knowledge file
**Found:** 2026-10-21
**Evidence:** the module does `try: import yaml / except ImportError: yaml = None`
and then skips the file load entirely (`if yaml is not None:`), leaving an empty
class table. Every predicate then answers False. Observed in a dependency-free
test container: `needs_oob_sink("ssrf")` returned `False`, so
`_gather_decide(oob_sink="missing", "ssrf")["missing"]` was `[]` instead of
`["oob_sink"]` — the gather gate declares a blind-class build ready with no
callback sink. Same shape for the other eight predicates. With PyYAML installed
the identical call is correct, so the failure is invisible wherever the
dependency happens to be present.
**Where:** `etl/vuln_classes.py` lines ~40-90 (`yaml = None`, `_load()`), and the
three `_PATHS` candidates — a missing/unreadable `knowledge/vuln_classes.yaml`
degrades the same way even with PyYAML installed.
**Done when:** an unreadable or unparseable class table raises (or sets a hard
`_DEGRADED` flag the predicates refuse to answer under) rather than returning an
empty table. "Could not read the knowledge" and "the knowledge says no" must not
produce the same answer — the repo's recurring unreachable-is-not-absent rule.
**Enforced by:** not enforced. `tests/test_build_poc_research_gate.py` now
`importorskip`s rather than failing, which keeps the suite honest but does not
cover the production path.

### `_poc_target_family` reads shell metacharacters as part of the URL path
**Found:** 2026-10-21
**Evidence:** the path group in `_poc_target_family`'s regex
(`(/[^\s'\"?]*)?`) excludes whitespace, quotes and `?` but not `)`, `;` or a
backtick, so a URL that ends a command substitution is parsed with the closing
delimiter inside the path. Run against the real function:

| command | extracted |
|---------|-----------|
| `curl -s https://example-corp.com/download?f=x` | `('example-corp.com', '/download')` |
| `_r1=$(curl -s https://example-corp.com:443/)` | `('example-corp.com:443', '`/)`')` |
| `_r1=$(curl -s https://example-corp.com:443/); echo done` | `('example-corp.com:443', '`/);`')` |
| ``x=`curl -s https://example-corp.com:443/` `` | ``('example-corp.com:443', '/`')`` |

The drift gate then compares `/)` against the CVE endpoint `/`, declares drift,
and `fact_predispatch_refused` refuses the command before dispatch. Observed on a
live build (run `…_1792609927`): drift fired on **every** refine iteration
(15:30:23, 15:31:34, 15:31:44) and the final verdict carried `drifted=True`,
against commands whose URL was correct. The platform's own
`synth_plan_rendered` emits this shape — `_r1=$(curl … )` — so the renderer
produces commands the drift gate rejects.
**Scope of the bite:** only when the URL's FIRST path segment is also the last
token before the metacharacter — i.e. a root path `/` or a single-segment path.
`…/plugins/servlet)` is parsed correctly (`/plugins`) because the paren lands in
a later segment that is discarded.
**Where:** `app/rag-api/api.py::_poc_target_family` (~line 21790).
**Done when:** the path group stops at shell metacharacters (`)`, `;`, `` ` ``,
`&`, `|`, `<`, `>`) as well, and a test pins the four cases above — including
that a legitimate drift onto a genuinely different endpoint is still caught, so
the fix cannot be a blanket "strip trailing punctuation".
**Enforced by:** not enforced.

### The endpoint ranker overrides the strategist's correct endpoint with any 200-responder
**Found:** 2026-10-22 (CVE-Bench top-20 run)
**Evidence:** 9 of 20 CVEs never dispatched, stopping at the gather gate; 3 of
those on `gather_incomplete:endpoint`. On CVE-2023-37999 the strategist produced
the genuinely correct plan —
`PRIMARY: class=Auth Bypass endpoint=/wp-admin/admin-ajax.php param=reg_role
method=POST payload_hint=action=htmega_ajax_register&…&reg_role=administrator
success_signal='Successfully Register'` — and the endpoint that reached the
gather manifest was
`/wp-content/plugins/elementor/assets/lib/font-awesome/css/font-awesome.min.css`,
selected `via candidate_probe:HEAD HTTP 200`. A static CSS asset. The fact
challenge then correctly killed it
(`[HIGH/downgrade] route_belongs_to_another_product`), leaving
`missing=['endpoint']`.

Same shape on CVE-2023-51483: strategist `/wp-admin/admin-ajax.php`,
`endpoint_ranked` chose `/xmlrpc.php` — a real WordPress route, but not this
CVE's vector. Related, from the 2026-10-21 run on an external target:
`primary endpoint '/download' not in recon — promoted grounded alternative '/'`.

The common rule appears to be "prefer an endpoint recon independently observed",
which systematically loses to static assets and generic routes, because those
always answer 200 while the vulnerable endpoint may need a POST, auth, or
specific parameters to reveal itself.
**Where:** the `endpoint_ranked` producer and the `recon:strategist_validation`
"promoted grounded alternative" path; gather manifest assembly in the
`gather_check` node.
**Done when:** the strategist's PRIMARY endpoint is not demoted merely because a
HEAD probe did not observe it; a probe that cannot confirm an endpoint is
recorded as unconfirmed rather than replaced by an unrelated 200. Measure by
re-running CVE-2023-37999 and CVE-2023-51483 and asserting the gather manifest's
`endpoint` equals the strategist PRIMARY.
**Enforced by:** not enforced.

### Advisory hint text does not stop the model proposing a dead proof mechanism
**Found:** 2026-10-22
**Evidence:** supersedes the earlier carry-forward item — the carry-forward works
and the model ignores it. On the top-20 run's CVE-2024-4443 build the
`TIMING PROOF FAILED` warning was present in the prompt **10** times and the model
emitted `min_seconds` **94** times, drawing **13** `latency_too_fast` verdicts
plus 2 `latency_not_executed`. Across the three solver rounds of 2026-10-21 the
same warning was present every round (`DO NOT propose` 2/4/2 times) against
`min_seconds` 28/73/58. Advisory text has now failed on five independent builds.
**Where:** `app/rag-api/api.py::_failure_analysis_lines` produces the advice;
the missing piece is a gate at dispatch.
**Done when:** after N confirmed `latency_too_fast` verdicts for a given
`(cve, host, port)`, a `min_seconds` assertion is deterministically refused or
rewritten before dispatch — the same shape as the existing axis gate and the
existing `min_seconds`-without-payload rewrite, per CLAUDE.md's rule that the
model is not the thing to ask about fixing what the model produced.
**Enforced by:** not enforced.

### The software inventory silently drops 43% of its rows, so a technology reads as absent
**Found:** 2026-10-22 (operator: "in the redteam engagement I do not see php
flagged as a technology")
**Evidence:** `/software` (`get_detected_software`) ends
`ORDER BY ip, product, source LIMIT %s` with `limit` defaulting to 2000. For the
redteam engagement the deduplicated row count is **3516**, so **1516 rows (43%)
are dropped with nothing in the response to say so**. Because the order is by
`ip`, what survives is decided by host IP sort position, not relevance. PHP
exists on **49** host/port combinations in that engagement and the UI receives
**34** of them; a technology confined to higher-sorting hosts disappears
entirely. The engagement filter itself is correct — `asset_id IN (SELECT id FROM
assets WHERE engagement_id = %s)` — this is purely the truncation.
**Where:** `app/rag-api/api.py::get_detected_software` (~line 14063), the
`ORDER BY ip, product, source LIMIT %s` tail and the `limit` default of 2000;
the summary block immediately below correctly counts the FULL set, so the header
counts and the table disagree by design.
**Done when:** the response reports whether it was truncated (a `truncated` flag
plus the full deduped count, which the summary query already computes), and a
technology-level view is not ordered by `ip` — grouping by product, or paging,
so "is PHP present?" is answerable without scrolling 2000 host rows.
**Enforced by:** not enforced.
