# OS Changes for Migration

## 2026-08-28 (part 2) — embedder TLS mount is the one thing to mirror

### Files Changed
`docker-compose.yml` (embedder + embedder-gpu), `scan_recommender/*`,
`app/rag-api/scope_classifier.py`, `autogen_agents/*`. Full list in
Docs/CHANGES_MADE.md (2026-08-28 part 2).

### Platforms Affected
**One real item, plus notes.**

1. **The `embedder` service now needs `./certs:/certs:ro` and a `command:`
   override to serve TLS** — it had neither and served plain HTTP while every
   caller used `https://embedder:8030`. Any platform-specific compose file that
   REPLACES the embedder service definition (rather than merging into it) must
   carry both, or embeddings break again with
   `SSLError WRONG_VERSION_NUMBER`. Today `docker-compose.mac.yml` and
   `docker-compose.azure.yml` do not touch `embedder`, so they inherit the base
   definition and need no edit — verify that before a port.
   The same applies to `embedder-gpu`, which takes over the `embedder` network
   alias under the `gpu` profile.

2. **`EMBED_BACKEND` / `EMBEDDER_URL` are new base-compose env vars.** Defaults
   (`auto`, `https://embedder:8030`) are correct for every platform. A mac/Windows
   `.env` copied from an older `.env.example` falls back to them.

3. **The mac/azure overlays exist because Ollama runs natively there.** That is
   exactly the situation the embeddings bug came from on Linux: the code assumed
   `ollama:11434` was reachable. `EMBED_BACKEND=auto` no longer assumes it, and
   the scan-recommender entrypoint now checks whether the ollama hostname
   resolves before waiting 60s for it. A native-Ollama host WILL resolve its
   configured `OLLAMA_HOST`, so the wait still happens there — intended.

4. **AutoGen retirement needs no OS-specific work.** No new mounts, ports or
   paths; `pyautogen` simply leaves `autogen_agents/requirements.txt`, which every
   platform builds from.

## 2026-08-28 — LangGraph Phase 4 (default engine flip): no OS-specific work

### Files Changed
`docker-compose.yml`, `.env`, `.env.example`, `autogen_agents/*`,
`dashboard/*`, `app/rag-api/webhooks/router.py`, `db_init/*`, `scripts/*`.
See Docs/CHANGES_MADE.md (2026-08-28) for the full list.

### Platforms Affected
**None differentially.** Logged for completeness, with three notes for a port:

1. **New env vars are base-compose only.** `AGENT_ENGINE` (default now
   `langgraph`) and `LANGGRAPH_EXPLOIT_PHASE` (default `false`) live in
   `docker-compose.yml`'s autogen-agents `environment:` block.
   `docker-compose.mac.yml` and `docker-compose.azure.yml` override only
   `depends_on` plus a few extra env keys, so the base values merge through —
   there is nothing to mirror. A mac/windows `.env` copied from an older
   `.env.example` simply falls back to the compose defaults.
2. **No new mounts, ports or host paths.** The LangGraph checkpoint tables live
   in the same `scans` Postgres the stack already uses; the checkpointer is a
   library, not a service.
3. **Windows/macOS note on the ollama dependency.** The mac and azure overlays
   exist because Ollama runs natively rather than as a container. Unrelated to
   this change, but the `get_scan_recommendations` 500 seen during Phase 4
   verification is exactly that class of problem on Linux too:
   `scan_recommender/exploits_rag.py` embeds via `OLLAMA_HOST` and there is no
   ollama container in this deployment. A port should point it at the
   `embedder` service instead of assuming ollama is reachable.

## 2026-08-11 (part 3) — walkthrough converter: no OS-specific work

### Files Changed
- `knowledge/prompts/walkthrough_to_seed.md`, `scan_recommender/scan_recommender.py`,
  `dashboard/bff/routers/kb.py`, `scripts/walkthrough-to-seed.sh`, UI panel.

### Platforms Affected
**None differentially.** Logged for completeness, plus two notes for a future port:

1. **No new mounts or env vars.** The guiding prompt is read from the existing
   `./knowledge:/knowledge:ro` mount at `/knowledge/prompts/walkthrough_to_seed.md`.
   `WALKTHROUGH_PROMPT_PATH` and `WALKTHROUGH_LLM_TIMEOUT` exist as overrides but are
   unset by default.
2. **`scripts/walkthrough-to-seed.sh` is bash + curl + jq**, matching
   `import-knowledge.sh`. On Windows it needs WSL or Git Bash, the same as every other
   script in `scripts/` — no new constraint. It shells out to `import-knowledge.sh` for
   the dry-run using `$SCRIPT_DIR`, so it works from any working directory.

### Notes
- Conversion quality varies with `LLM_BACKEND` (a small local Ollama model drafts rougher
  entries than a hosted one), but the review gate makes either safe. That is a quality
  difference, not a platform one.
- The Ollama backend sends `format: "json"` and returns JSON rather than the requested
  YAML. Harmless — `yaml.safe_load` parses JSON, and the schema is identical. Any future
  backend added to `ollama_query()` should keep that tolerance.


## 2026-08-10 (part 2) — web scan profiles + report import: no new OS-specific work

### Files Changed
- `knowledge/web_profiles.yaml` (new data file), `autogen_agents/web_profiles.py`,
  `etl/parse_nikto.py`, `etl/parse_zap_file.py`, `dashboard/bff/routers/imports.py`.

### Platforms Affected
**None differentially.** Recorded here so the migration log stays complete, and to note two
things a Windows/macOS port would otherwise trip over:

1. **No new bind mounts.** The web profiles ride the `./knowledge:/knowledge:ro` mount added
   earlier today (see the entry above); `autogen-agents` and `pentest-dashboard` already have
   it. Nothing further to add to `docker-compose.mac.yml`.
2. **Upload temp paths are POSIX-shaped.** `_save_upload_to_tmp` in `app/rag-api/api.py`
   writes to `/tmp/...`. That is a *container* path — rag-api runs Linux regardless of the
   host OS — so it needs no Windows adaptation. Only a native (non-Docker) Windows port of
   rag-api would need `tempfile.gettempdir()` instead, and that port does not exist.

### Notes
- Report parsing is pure Python + stdlib XML/JSON; no platform-specific binaries were added.
  Nikto/ZAP themselves do not need to be installed to *import* their reports.
- Line endings: the parsers read with `encoding="utf-8", errors="replace"`, so CRLF reports
  produced on Windows import correctly without conversion.


## 2026-08-10 — knowledge/ mount added to two more containers (port profiles)

### Files Changed
- `docker-compose.yml` — added `./knowledge:/knowledge:ro` to the `pentest-dashboard` and
  `autogen-agents` service blocks. It was already mounted into `rag-api` and
  `scan-recommender`.

### Platforms Affected
- **Linux / macOS:** no adaptation needed. `docker-compose.mac.yml` overrides only
  `depends_on`, `environment`, `ports` and `platform` for these services — it does **not**
  override `volumes`, so the bind mount merges in automatically from the base file. Verified
  with `docker compose config -q`.
- **Windows:** relative bind mounts of a repo directory behave the same under Docker Desktop
  (WSL2 backend). No path translation required since the source path is repo-relative
  (`./knowledge`) and the container target is absolute (`/knowledge`). If a Windows user runs
  Docker Desktop with the Hyper-V backend and the repo lives outside a shared drive, this
  mount will fail the same way the pre-existing `./knowledge` mounts on `rag-api` /
  `scan-recommender` already would — so it introduces no new Windows-specific risk.

### Old → New
```yaml
# autogen-agents
      - ./mcp/third_party:/app/third_party:ro
+     - ./knowledge:/knowledge:ro
      - ./certs:/certs:ro

# pentest-dashboard
      - ./db-config.json:/app/db-config.json:rw
+     - ./knowledge:/knowledge:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
```

### Notes
- **Failure mode if the mount is missing:** the loader
  (`dashboard/bff/services/port_profiles.py`) does not crash — it logs an error naming the
  mount, serves a reduced built-in set (`top-100`, `web`, `all`) and reports
  `degraded: true` from `GET /api/port-profiles`. `top-1000` becomes unavailable and any
  request for it returns a clear error rather than silently substituting a narrower scope.
- `scripts/post-install-check.sh` asserts `degraded` is false, so a missing mount is caught
  at install time rather than mid-engagement.
- No `PORT_PROFILES_PATH` env var needs setting; it defaults to
  `/knowledge/port_profiles.yaml` and is only there for tests.


## 2026-05-04 — WSL2 / fresh Linux: surface unzip + jq prereq up front

### Files Changed
- `scripts/setup.sh` — added `unzip` and `jq` to required-deps check.
- `scripts/build-go-tools.sh` — fail-fast prereq guard at top (docker / curl / unzip) with platform-specific install hints, instead of dying mid-build with a cryptic `unzip: command not found`.

### Platforms Affected
- Linux (Ubuntu/Debian) and WSL2 — base WSL Ubuntu images ship without `unzip`. macOS users typically have it via Xcode Command Line Tools but the guard is harmless there.

### Why
A clean WSL2 install hit `unzip: command not found` 1 minute into `build-go-tools.sh` (vulnx download step). The error was silent (script exited 0 from earlier success path) and confusing. Adding the prereq check to setup.sh + an explicit guard in the Go-build script means a new user sees the missing dep in the first 5 seconds and gets the apt/brew command to fix it.

### Old → New
```bash
# build-go-tools.sh: previously failed mid-loop
unzip -qq -o "$vulnxZIP" vulnx -d "$OSINT_OUT/"
# now guarded at the top:
for cmd in docker curl unzip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: '$cmd' is required but not installed."
        ...
        exit 1
    fi
done
```

## 2026-03-19 — Fix build-go-tools.sh for macOS (Intel + Apple Silicon)

### Files Changed
- `scripts/build-go-tools.sh`

### Platforms Affected
- macOS (Intel x86_64 and Apple Silicon arm64)

### What Changed

| Item | Old (Linux-only) | New (cross-platform) |
|------|-------------------|----------------------|
| `stat` command | `stat -c%s` (GNU/Linux) | `file_size()` helper: tries `-c%s`, falls back to `-f%z` (macOS) |
| vulnx download | Hardcoded `linux_amd64` | Detects target arch, downloads `linux_amd64` or `linux_arm64` |
| Docker build platform | Implicit (host default) | Explicit `--platform linux/amd64` or `linux/arm64` based on host |
| GOARCH/GOOS env | Not set (implicit) | Explicit `GOOS=linux GOARCH=amd64/arm64` passed to container |

### Notes
- All binaries are always Linux — they run inside Docker containers, not on the host
- On Apple Silicon, the script auto-detects arm64 and builds native linux/arm64 binaries (no Rosetta emulation needed)
- The Docker containers need `--platform` to avoid architecture mismatch on macOS Docker Desktop
- katana, ffuf, naabu, httpx, tlsx and all OSINT tools are affected by this fix

## 2026-05-14 — WireGuard Frontend UI Implementation

### Files Changed
- `dashboard/frontend/src/api/nodes.ts`, `dashboard/frontend/src/lib/types.ts`, `dashboard/frontend/src/pages/Nodes.tsx`, `dashboard/frontend/package.json`

### Platforms Affected
- All platforms (cross-platform React/TypeScript frontend)

### Notes
- Pure frontend implementation with no platform-specific requirements
- QR code libraries (`react-qr-code`, `qr-code-styling`) are cross-platform JavaScript
- No OS-specific changes needed — builds identically on Windows, macOS, and Linux
- Frontend compiled to static assets served by nginx container

## 2026-08-15 — SSH ControlMaster socket path (macOS-specific)

**Files:** `node_manager/ssh_manager.py`
**Platforms:** macOS (Docker Desktop) — Linux hosts unaffected.

`SSH_CONTROL_DIR` moved `/tmp/ssh-ctrl` -> `/dev/shm/ssh-ctrl`.

On Docker Desktop for macOS the container's `/tmp` is a bind mount of the host
(`/run/host_mark/private on /tmp type fakeowner`). ssh's `muxserver_listen` binds a unix socket
then hard-links it into place, and that link fails there with EBADF:

```
muxserver_listen: link mux listener /tmp/ssh-ctrl/ctrl-<id>.xxxx
    => /tmp/ssh-ctrl/ctrl-<id>: Bad file descriptor
```

Authentication succeeds first, so the failure looks like a credentials problem and is not. On a
Linux host `/tmp` is an ordinary container filesystem and the original path works, which is why
this never appeared there. Overridable via `SSH_CONTROL_DIR`; falls back to `/var/tmp/ssh-ctrl`
if `/dev/shm` is unavailable.
