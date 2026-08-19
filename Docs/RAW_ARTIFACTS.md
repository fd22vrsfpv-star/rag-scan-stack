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

## Webhooks

- `raw_artifact_stored` — `{artifact_id, tool, target, bytes, content_format, native_json, new}`
- `raw_artifact_processed` — `{artifact_id, tool, target, llm_status, llm_model}`

## Install & health

`raw_artifacts` is created by `db_init/ensure_all_tables.sql` (mirrored in
`setup_alldb.sql`). `scripts/ensure_db_schema.sh` asserts the table plus
`uq_raw_artifacts_identity` (without it the upsert **raises**, so nothing is
ever archived) and `idx_raw_artifacts_llm_status` (the queue scan).

## Tests

```bash
pytest tests/test_raw_artifacts.py -v
```

26 tests. The JSON-flag tests parse `apply_json_output` out of the listener
source rather than importing the module, so they run without fastapi installed.
The DB tests skip cleanly when no Postgres is reachable:

```bash
TEST_DB_DSN="postgresql://app:PASS@rag-postgres:5432/scans" pytest tests/test_raw_artifacts.py
```
