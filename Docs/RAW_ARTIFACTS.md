# Raw Artifact Store & Native JSON Output

Complete, untruncated tool output kept for post-analysis and LLM processing,
plus the use of each tool's own JSON format where one exists.

## Why this exists

Everything downstream of a scan was lossy, in three places at once:

| Where | Loss |
|---|---|
| `tool_executions.output` | Written **only** by kali-listener. Scanner services and `targeted_recon` had no durable home at all. |
| Native JSON files | Read, POSTed to the parser, then `unlink`ed — the one authoritative structured artifact was the only thing never kept. |
| `/ingest/tool-output` → findings | Truncates at 200 KB; each finding keeps 8 KB of `raw_output`. Fine for display, useless as a source of truth. |

Separately, structure was being **guessed** from CLI text. The table strategy
read crackmapexec's whitespace-aligned SMB banner as a header row, so the data
became the column names:

```
[*]_unix_(name:metasploitable)_(domain:localdomain)_(signing:false)_(smbv1:true)
```

Where a tool can emit JSON itself, that is authoritative and free.

## Native JSON

Every flag below was read off `--help` **inside the kali-listener image**, not
assumed. Note that only nuclei writes JSON to stdout:

| Tool | Flag | Destination |
|---|---|---|
| `nuclei` | `-jsonl` | **stdout** (JSONL) |
| `whatweb` | `--log-json=<file>` | file |
| `enum4linux-ng` | `-oJ <file>` | file (appends `.json` itself) |
| `dnsrecon` | `--json <file>` | file |
| `sqlmap` | `--report-json=<file>` | file |
| `crackmapexec`, `netexec`, `nikto` | — | no JSON option in this image; text path retained |

Rules the implementation follows (`kali_listener/listener_service.py`):

- A tool **not** in the map is left alone. Appending an unsupported flag would
  fail the whole run — worse than parsing its text.
- An explicit operator-supplied JSON flag is **never** overridden.
- File paths are unique per invocation, so concurrent runs don't share a file.
- When native JSON is produced, **both** copies are archived: the JSON is the
  better machine input, but stdout often carries warnings, timing and banners
  the JSON file omits entirely.

Concrete difference for `whatweb http://192.168.1.150`:

```
stdout : \x1B[1m\x1B[34mhttp://192.168.1.150\x1B[0m [200 OK] \x1B[1mApache\x1B[0m[...
json   : [{"target":"http://192.168.1.150","http_status":200,
           "plugins":{"Apache":{"version":["2.2.8"]}, ...}}]
```

## Storage model — `raw_artifacts`

Deduped on `(tool, COALESCE(target,''), content_sha256)`. Re-running an
unchanged scan yields byte-identical output; paying an LLM to re-read it is
pure waste. Repeats bump `last_seen` / `occurrences` and **do not** reset
`llm_status`.

Key columns: `content` (verbatim, untruncated), `content_format`
(`json` | `jsonl` | `xml` | `text` | `empty`, auto-detected), `native_json`,
`byte_size`, `first_seen` / `last_seen` / `occurrences`, provenance
(`tool`, `command`, `target`, `port`, `service`, `exec_id`, `job_id`,
`scan_id`, `source`), and the processing queue
(`llm_status`, `llm_model`, `llm_processed_at`, `llm_result`, `llm_error`,
`llm_attempts`).

`llm_status` is CHECK-constrained to `pending | processing | done | failed |
skipped`, so a typo'd status fails loudly instead of creating a state nothing
polls.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/ingest/raw-artifact` | Store one tool's complete output (upsert) |
| GET | `/artifacts` | List/filter (`llm_status`, `tool`, `target`, `source`, `content_format`, `include_content`, `limit`, `offset`) |
| GET | `/artifacts/stats` | Queue depth and bytes by status |
| POST | `/artifacts/claim` | Atomically claim pending work (`limit`, `tool`, `llm_model`) |
| GET | `/artifacts/{id}` | One artifact with full content |
| POST | `/artifacts/{id}/processed` | Record the LLM outcome |
| GET | `/artifacts/{id}/actions` | Follow-on actions derived from the artifact |
| POST | `/artifacts/{id}/actions/queue` | Queue chosen actions as scan recommendations |

Content is omitted from listings unless `include_content=true` — these rows are
deliberately large.

### LLM post-processing loop

```bash
# 1. claim a batch (FOR UPDATE SKIP LOCKED — concurrent workers get disjoint sets)
curl -sk -X POST "$API/artifacts/claim?limit=5&llm_model=claude-opus-5" \
     -H "x-api-key: $API_KEY"

# 2. ... analyse artifact.content, which is complete and unmodified ...

# 3. report back
curl -sk -X POST "$API/artifacts/$ID/processed" -H "x-api-key: $API_KEY" \
     -H 'content-type: application/json' \
     -d '{"llm_status":"done","llm_model":"claude-opus-5",
          "llm_result":{"summary":"SMBv1 enabled, signing disabled","severity":"high"}}'
```

Claimed rows sit in `processing`. If a worker dies they stay there rather than
being silently lost — requeue with
`UPDATE raw_artifacts SET llm_status='pending' WHERE llm_status='processing' AND llm_processed_at IS NULL`.

## UI — Scan Results

`/scans/results` (sidebar: **Operations → Scan Results**).

A filterable table of every stored output (tool, target, format, size,
occurrences, processing state). Native-JSON rows are badged, since that is the
copy worth reading. Opening a row gives two tabs:

**Raw Output** — the complete bytes, JSON/JSONL pretty-printed, with copy and
download. Nothing is truncated for display.

**Follow-On Actions** — what to do next, derived from the content itself.

### How follow-on actions are created

Three routes, all landing in the same place:

| Route | Trigger | Result |
|---|---|---|
| **Automatic** | Rule sets `auto_queue: true`; fires when new output is stored | Queued as **pending** — never executed |
| **Manual** | You tick suggestions and press Queue | Queued as pending |
| **Manual, edited or written** | Edit a suggested command, or write your own | Queued as pending |

**Automatic queuing never runs anything.** Actions land as `pending` and wait
for a human to press Run, so the audit trail shows what was proposed — and on
what evidence — before anything touches a target. Only rules that explicitly
opt in with `auto_queue: true` do this, and an action that `needs_input` can
never auto-queue however its rule is written, because an un-runnable command
sitting in the queue is just noise. Re-storing byte-identical output does not
re-queue.

Toggle it globally (persisted in `app_settings.artifact_auto_queue`):

```bash
curl -sk -X POST "$API/artifacts/auto-queue" -H "x-api-key: $KEY" \
     -H 'content-type: application/json' -d '{"enabled": false}'
```

Turning it off stops new proposals appearing; it never touches what is already
queued.

### Manual and edited actions

`POST /artifacts/{id}/actions/queue` accepts three fields together:

```json
{
  "action_ids": ["smbv1_enabled"],
  "overrides":  {"credentials_found": {"script": "netexec smb 10.0.0.1 -u msfadmin -p msfadmin --shares"}},
  "custom_actions": [{"title": "RPC enumeration", "scanner": "rpcinfo",
                      "script": "rpcinfo -p 10.0.0.1", "priority": 72}]
}
```

`overrides` is the **only** way to queue a `needs_input` action: queuing one
un-edited returns 400 with the offending command, rather than parking a
command that will fail at dispatch. Note this covers two distinct cases — a
`{brace}` placeholder the substituter could not fill, and a rule that declared
`needs_input` because its script carries literal stand-ins like `USER`/`PASS`
that no substituter would notice. Custom `scanner` names are validated as bare
tool names (`^[a-zA-Z0-9_.-]+$`), matching the executor's own allowlist check.

### The rules themselves

Rules live in **YAML** under `knowledge/artifact_rules/` — `builtin.yaml` plus
`custom/*.yaml`, mirroring the existing detection-rule engine. `knowledge/` is
a read-only bind mount, so **edits take effect on the next analysis with no
rebuild and no restart**; a custom rule reusing a builtin `id` overrides it, and
`enabled: false` switches one off.

Rules are **tool-scoped**: `tools: [crackmapexec, netexec, nmap]` limits a rule
to those tools' output, and `["*"]` (or omitting it) applies everywhere. Before
this, whatweb output and crackmapexec output were evaluated against an identical
set of patterns whether or not they could possibly apply.

A malformed rule is skipped with a logged error and reported through
`GET /artifacts/auto-queue` (`rule_errors`), which the UI surfaces — otherwise a
broken file silently means "no follow-ups ever", indistinguishable from "nothing
to act on". `scripts/post-install-check.sh` asserts rules load and that none
failed to parse.

Rule evaluation itself is pure functions in `app/rag-api/artifact_actions.py` —
no database, no network — so behaviour is testable on fixtures alone. Four
constraints shape the rules, each learned from a real failure in this codebase:

1. **Every suggestion cites its evidence** — the exact line that triggered it,
   shown in the UI. A follow-up an operator cannot justify is one they cannot
   act on.
2. **Tool chatter is not evidence.** crackmapexec prints
   `Generating SSL certificate` while creating its *own* config directory; that
   proposed a TLS audit of a host showing no TLS. `strip_tool_noise()` drops
   these lines, and a test pins both halves — the noise must not fire, and
   genuine TLS evidence must still fire.
3. **Nothing is hidden as "already done."** Each action is checked against
   `tool_executions`, matching the tool AND the command's distinctive tokens,
   and shown as `ran N×` rather than suppressed. Suppressing on assumption
   previously hid 63 NSE scripts that had never actually run. A tool that ran
   with *different* arguments reports `tool_ran_count` and is NOT claimed as
   already run.
4. **Only the artifact's own target is ever acted on.** Hosts merely mentioned
   in output (a redirect to twitter.com, a banner citing twiki.org) are never
   turned into scan targets.

Commands with unresolved placeholders — recovered credentials, for instance —
are marked **needs input** rather than presented as runnable.

### Queuing

Actions are inserted into `scan_recommendations` with `source='artifact'` and `extra` carrying `artifact_id`, `rule_id`, `rationale`
and `evidence`, plus `queued_by` (`auto` / `manual` / `manual-edited`). This
deliberately reuses the existing recommendation path
rather than adding a second executor: that table already has a dispatcher, a
force-run override for skipped items, and a UI. Queued actions are run from the
Recommendations page like any other, and the results come back as new
artifacts — closing the loop.

Webhook: `artifact_actions_queued`.

## Webhooks

- `raw_artifact_stored` — `{artifact_id, tool, target, bytes, content_format, native_json, new}`
- `raw_artifact_processed` — `{artifact_id, tool, target, llm_status, llm_model}`
- `artifact_actions_queued` — `{artifact_id, target, queued, action_ids}`

## Install & health

`raw_artifacts` is created by `db_init/ensure_all_tables.sql` (mirrored in
`setup_alldb.sql`). `scripts/ensure_db_schema.sh` asserts the table plus
`uq_raw_artifacts_identity` (without it the upsert **raises**, so nothing is
ever archived) and `idx_raw_artifacts_llm_status` (the queue scan).

## Tests

```bash
pytest tests/test_raw_artifacts.py -v      # 26 tests: JSON flags, archive, queue
pytest tests/test_artifact_actions.py -v   # 32 tests: rules, YAML loading, scoping
```

The action tests pin the failure modes that matter: rules firing on tool
chatter, suggestions without evidence, placeholders presented as runnable, and
mentioned hosts becoming targets. The JSON-flag tests parse `apply_json_output` out of the listener
source rather than importing the module, so they run without fastapi installed.
The DB tests skip cleanly when no Postgres is reachable:

```bash
TEST_DB_DSN="postgresql://app:PASS@rag-postgres:5432/scans" pytest tests/test_raw_artifacts.py
```
