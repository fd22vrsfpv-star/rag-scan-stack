# `scripts/` — Build, Operate & Maintain

This directory holds the install/build scripts, plus operational tooling for
databases, TLS, versioning, remote nodes, and dev↔prod sync. Run everything
from the **project root** (e.g. `./scripts/setup.sh`), not from inside `scripts/`.

---

## Quick Build (the short list)

For a fresh clone on Linux/macOS, one command does everything:

```bash
./scripts/setup.sh          # Windows: ./scripts/setup.ps1
```

`setup.sh` runs these phases in order — each is also a standalone script you can
re-run individually if a phase fails:

| # | Phase | What runs | Standalone script |
|---|-------|-----------|-------------------|
| 1 | Check dependencies | Docker, Compose, Go, unzip, … | — |
| 2 | Build Go security tools | Compiles httpx/naabu/katana/subfinder/… into `*/bin/` | `./scripts/build-go-tools.sh` |
| 3 | Generate `.env` | Secure random credentials + API key | — |
| 4 | Infrastructure | Kong API key wiring + **TLS certs** | `./scripts/generate-certs.sh` |
| 5 | Docker build | `docker compose build` | — |
| 6 | Start services | `docker compose up -d` | — |
| 7 | Apply DB schema | Creates all required tables | `./scripts/ensure_db_schema.sh` |
| 8 | Health check | Quick smoke test | — |

Then verify the whole stack end-to-end:

```bash
./scripts/post-install-check.sh     # tables + Go binaries + container health + API endpoints
```

To pull updates and rebuild later:

```bash
./scripts/update.sh                 # git pull → rebuild → re-apply schema → restart
```

> **TLS note:** every uvicorn service mounts `./certs:/certs:ro` and starts with
> `--ssl-keyfile=/certs/server.key --ssl-certfile=/certs/server.crt`. If those
> files are missing the containers crash-loop on `FileNotFoundError`.
> `setup.sh` (phase 4) generates them automatically; run
> `./scripts/generate-certs.sh` by hand if you ever wipe `certs/`.

---

## Detailed Script Reference

### Build & Install

| Script | Purpose |
|--------|---------|
| `setup.sh` | **Unified installer** for Linux/macOS — runs the 8-phase build above from a fresh clone to a running stack. |
| `setup.ps1` | Same unified installer for **Windows** (PowerShell). |
| `build-go-tools.sh` | Compiles all Go security tools for both `arm64` and `amd64`. Outputs to `osint_runner/bin/`, `pd_runner/bin/` (local arch) plus `bin-amd64/`/`bin-arm64/` for remote nodes. |
| `generate-certs.sh` | Generates the self-signed TLS cert/key pair in `certs/` used for inter-service HTTPS. Idempotent — skips if certs already exist. |
| `post-install-check.sh` | End-to-end health audit: verifies all DB tables, Go tool binaries, container health, and API endpoints (RAG API + dashboard BFF). Run this to diagnose a failed build. |
| `deploy.sh` | First-time deployment on a new machine / ongoing deploys: checks prerequisites, creates the Docker network and directories, sets up config, optionally starts services. |
| `update.sh` | Pull latest code, rebuild containers, re-apply DB schema, and restart services. |
| `fix-etl-imports.sh` | One-off repair of ETL import paths across services (web_scanner, osint_runner, …). |

### Database

| Script | Purpose |
|--------|---------|
| `ensure_db_schema.sh` | Ensures every required database table exists; safe to re-run. Called by `setup.sh` phase 7. |
| `check-remote-db-status.sh` | Reports whether the `.env` is pointed at the local or remote (WireGuard) database. |
| `toggle-remote-db.sh` | `on` / `off` / `status` — switch between local and remote Postgres while preserving the configured remote IP. |
| `cleanup_out_of_scope.sql` | SQL to purge findings/assets that fall outside engagement scope. |
| `fix_scope_detection.sql` | SQL fix-up for scope-detection data. |

### TLS & Secrets

| Script | Purpose |
|--------|---------|
| `generate-certs.sh` | (see Build & Install) self-signed certs for inter-service TLS. |
| `vault-seed.sh` | One-time helper to seed HashiCorp Vault with secrets read from `.env` (only needed with the `vault` compose profile). |

### Versioning & Maintenance

| Script | Purpose |
|--------|---------|
| `update-version.sh` | Bumps the build version string in all three required locations (`.env`, `dashboard/frontend/package.json`, `dashboard/frontend/src/lib/constants.ts`). Usage: `./scripts/update-version.sh 2026.05.27-01`. |
| `cleanup-old-files.sh` | Deletes scan-output files older than `RETENTION_DAYS` to prevent disk exhaustion. |
| `setup-cleanup-cron.sh` | Installs a daily (3 AM) cron job that runs `cleanup-old-files.sh`. |

### Remote Nodes, WireGuard & Tunnels

| Script | Purpose |
|--------|---------|
| `provision-standard-node.sh` | Full provisioning of a new remote scan node. |
| `provision-standard-node-safe.sh` | Same, with auto-recovery + SSH safeguards to prevent lockouts. |
| `wireguard-node-setup.sh` | Pre-installs WireGuard and dependencies on a remote node. |
| `wireguard-node-setup-safe.sh` | Same, with SSH-lockout safeguards and auto-recovery. |
| `create-wg-peer.sh` | Creates a new WireGuard peer (allocates the next free IP). |
| `reset-wireguard-installation.py` | Resets stuck WireGuard peer installs back to `not_attempted`. |
| `auto-ip-detection.py` | Detects current reachable node IPs and updates node metadata to avoid stale addresses. |
| `build-tunnel-manager.sh` | Builds the Go tunnel-manager binary. |
| `test-tunnel-manager.sh` | Checks the tunnel-manager service + systemd unit. |
| `test-wg-connection.sh` | Tests WireGuard peer reachability and the SOCKS proxy. |

### Testing & Diagnostics

| Script | Purpose |
|--------|---------|
| `post-install-check.sh` | (see Build & Install) full-stack audit. |
| `test-assets-filtering.sh` | Exercises the assets API endpoint and its filters (uses `-k` for self-signed TLS). |
| `capture-screenshots.py` | Captures screenshots of key dashboard pages (needs `playwright`). |

### `optional/` — Dev↔Prod Sync & Extras

These are convenience scripts not part of the core build. Highlights:

| Script | Purpose |
|--------|---------|
| `configure-sync.sh` | One-time: configure target prod host/user/path; tests SSH and updates the sync scripts. |
| `sync-to-prod.sh` | rsync code dev→prod. Flags: `--restart`, `--build`. Excludes `.env`, `.git/`, caches, large model/output dirs. |
| `watch-and-sync.sh` | Watches for file changes and auto-syncs (optionally `--restart`). Needs `inotify-tools`. |
| `quick-deploy.sh` | One-command sync + build + restart, optionally for a single service. |
| `sync-push.sh` / `sync-pull.sh` | Push/pull DB changes to/from the remote DB via the sync API. |
| `migrate-db-to-remote.sh` | Dump local Postgres and restore it to a remote VPS. |
| `test-remote-db.sh` | Verify the WireGuard tunnel + remote Postgres connectivity. |
| `check_system_health.sh` | Comprehensive system health check. |
| `init_db.sh`, `db_tables.sh`, `create_software_view.py` | DB bootstrap / table-dump / `detected_software` view helpers. |
| `dev_up.sh`, `bootstrap_repo.sh` | Dev bring-up and repo bootstrap helpers. |
| `basic_scan.sh`, `chk_open_ports.sh`, `chkresults.sh`, `masscan_load_file.sh`, `masscanNmapJobRequest.sh`, `runme.sh`, `run_me.sh` | Example/ad-hoc scan-driver scripts. |
| `zap_mcp_bridge.py` | Bridge between ZAP and the MCP layer. |

See the git history of `optional/` for the older dev↔prod sync workflow notes
(SSH key setup, IntelliJ run configs, troubleshooting).

---

**Last updated:** 2026-05-27
