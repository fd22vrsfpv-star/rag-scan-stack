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

### Post-exploitation enumeration never runs
**Found:** 2026-09-11
**Evidence:** With pre-approval on for `lab` and a reachable exploit target, the
pipeline reached `exploit_exec` and stopped. No post-ex enumeration ran and no
session artefacts were collected.
**Where:** `autogen_agents/langgraph_engine.py` — there is no phase after
`exploit_exec` other than `report`.
**Done when:** a successful exploit is followed by an enumeration step whose
output is ingested like any other tool output.
**Enforced by:** not enforced

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

### `ssh` is not installed in the Kali container, so the derived fix cannot run
**Found:** 2026-09-12
**Evidence:** The correct option is now derived automatically —
`-oHostKeyAlgorithms=+ssh-rsa` from the intersection of what recon recorded
(`ssh-audit:host-key-ssh-rsa`, `ssh-audit:host-key-ssh-dss`) and what the client
supports (`ssh -Q key`) — and it is **verified to work**: from the host,
`ssh -oHostKeyAlgorithms=+ssh-rsa msfadmin@192.168.1.150` negotiates, while the
same command without it gives
`no matching host key type found. Their offer: ssh-rsa,ssh-dss`.
But `docker exec kali-listener ssh` returns
`failed to run command 'ssh': No such file or directory`, which is why `ssh` is
not on the 50-tool allow-list.
**Where:** `kali_listener/Dockerfile`; `_FALLBACK_ALLOWED_TOOLS`.
**Done when:** `openssh-client` is installed in the listener image and `ssh` is
on the allow-list. Both are operator decisions — `ssh host '<command>'` is
general-purpose remote execution — so they are stated here rather than taken.
**Enforced by:** `tests/test_credential_followups.py::test_every_followup_names_a_tool_the_platform_can_run`
(keeps the catalogue honest about what is runnable today)

### A tool with no parser is recorded as having produced nothing measurable
**Found:** 2026-09-12
**Evidence:** the netexec run above wrote 6,816 bytes and `parsed_results` was
NULL, because no parser handles netexec output. It is now recorded
`success = false, failure_signature = NULL` — honest, but it means the learner
gets no signal at all from any tool without a parser.
**Where:** `etl/parse_tool_output.py` (no netexec branch);
`kali_listener/listener_service.py::_learn_from_execution`.
**Done when:** netexec output is parsed, or the generic parser extracts enough
that a run can be judged productive or fruitless.
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

### Most tools have no parser, so their outcomes stay unresolved
**Found:** 2026-09-12
**Evidence:** `enum4linux-ng` returned **9,525 bytes** of real findings and
`result_count()` returned None because only netexec has a parser. That is now
recorded as *unresolved* rather than `produced=false` — correct, but it means
`smbclient`, `enum4linux-ng` and `nmap` proposals can never resolve, so rules
proposing them can never be judged.
**Where:** `etl/tool_output_parsers.py::PARSERS` has three entries, all netexec.
**Done when:** the tools the enumeration rules propose (`smbclient`,
`enum4linux-ng`, `nmap`) have parsers, or `output_analysis.analyse_output()` is
used as the fallback judge.
**Enforced by:** `tests/test_post_enumeration.py::test_an_unmeasured_outcome_is_not_recorded_as_zero`
(pins that the absence is not recorded as a zero)

## Data and deployment

### One asset carries no engagement
**Found:** 2026-09-11
**Evidence:** After the attribution backfill, 136 of 137 assets resolved.
`74.123.154.158` remains unattributed — its host is in no scope.
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
**Done when:** a measurement exists, even a crude one.
**Enforced by:** not enforced

### Manual exploit approval records no reviewer
**Found:** before 2026-09-11
**Evidence:** The wildcard/rule approval path records `reviewed_by`; the manual
approve path does not, so an audit cannot say who approved an exploit.
**Where:** the manual approval handler in `app/rag-api/api.py`.
**Done when:** the manual path records the operator the same way
`update_exploit_status` does.
**Enforced by:** not enforced

### There is no per-task LLM routing table
**Found:** before 2026-09-11
**Evidence:** No routing table exists — a lookup for `llm_routing`,
`model_routing` and `llm_task_routes` in `information_schema.tables` returns
**0**. A caller's requested model is honoured, but which model *should* serve
which task lives only in each caller's hardcoded choice.
**Where:** the LLM selection path.
**Done when:** routing is data rather than each caller's guess.
**Enforced by:** not enforced
