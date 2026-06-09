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

### Security
- use TLS and secure communications for any network based traffic
- All scan tools need the abilty to use a remote proxy with different profiles for pentest and redteam 

### Quality
- Unit tests for parsers and fingerprinting
- Minimal linting + formatting
- Clear error messages and logging
- Sample data fixtures and a “quickstart”
- ensure that changes made are retrofitted to any installation scripts
- Any new database elements need added to the install scripts
- Any new database elements need added to the health check scripts
- Audit any newly delievered features to ensure a complete and stable implementation is provided. This includes ensuring that api endpoints are fully functional and defined correctly
- Any new feature that performs actions (scans, agent cycles, pipeline stages, etc.) MUST emit webhook events via `POST /webhooks/emit` so external tools (Slack, n8n, etc.) can subscribe. Use descriptive event_type names (e.g. `recon_agent_scan_dispatched`, `pipeline_stage_completed`). Include relevant context (engagement_id, target, scan_type, counts) in the data payload.
## Out-of-scope / constraints

- Focus on defensible engineering: parsing, normalization, reporting, workflow support.

## Implementation rules (Claude Code behavior)
- Work on ONE file at a time, sequentially.
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
Do NOT use background agents or background tasks. Do NOT split into multiple agents. Process files ONE AT A TIME, sequentially. Update the user regularly on each step."

Every time you make a change to an app that would also need to be applied , log it in Docs/CHANGES_MADE.md. Include: date, files changed, which platforms it applies to, what specifically changed (old to new values, code snippets if helpful), any notes about platform-specific adaptations completed and/or needed."

Update or remove memories that turn out to be wrong or outdated. Do not write duplicate memories. This can be written to Docs/Memories.md

Every session, after reading these instructions, log each user prompt to PROMPT_LOG.md. Timestamp each entry with date and time.

 this tool is designed for pentesters and redeam members, this is to collect data and help them with the workflow, the data collected will be used to import into manual tools to conduct security tests
Start by proposing the architecture and initial folder structure, then implement the database schema + one parser end-to-end (including tests and sample fixture) before adding more parsers.

for each change update the dashboard version to a date + timestamp. The version string must be updated in ALL THREE of these locations to stay in sync:
1. `dashboard/frontend/package.json` — the `"version"` field
2. `dashboard/frontend/src/lib/constants.ts` — the `BUILD_VERSION` constant (displayed in the TopBar)
3. `.env` — the `BUILD_VERSION` variable (injected into all service containers via docker-compose)
