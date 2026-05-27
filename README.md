# RAG Scan Stack

An open-source workflow collector for **authorized** penetration testing and red team engagements. Normalizes output from a dozen+ security tools into one engagement-scoped finding model, manages forward infrastructure (WireGuard, SSH, SOCKS, cloud nodes with IP rotation), pushes findings straight into Burp Suite, and exposes an OPSEC timeline that audits every scan, agent decision, and node action.

> **Authorized testing only.** This tool is built for engagements you have written permission to perform. Read [`AUTHORIZED_USE`](#authorized-use) before running it.

---

## What it does

- **Collects and normalizes** output from Nmap, Nuclei, ZAP, Nessus, gowitness, katana, wafw00f, subfinder, ssh-audit, sslscan, and more into one fingerprinted finding model with engagement-scoped dedup and "first seen / last seen" tracking.
- **Tracks deltas across runs** — what's new, what's gone, what changed severity, since the last scan of the same scope.
- **Pushes findings into Burp Suite** via a bundled Jython extension (`burp-extension/RagScanBridge.py`). Filter by scope, engagement, host, severity, or source tool. Pulls real HTTP request/response pairs (not synthetic) so issues land in *Target > Issues* ready to triage.
- **Manages forward infrastructure** — WireGuard peers auto-provisioned per node, DigitalOcean and AWS droplet provisioning with reserved-IP rotation, SOCKS chaining via a tunnel manager, and profile-based proxy routing (pentest vs. redteam).
- **OPSEC timeline + alerts** — every scanner dispatch, node action, and agent decision is a timeline entry. Alerts fire on out-of-scope target attempts, anomalous scan rates, and any agent recommendation that breaches the engagement boundary. Webhook events emit to Slack, n8n, or a SIEM in real time.
- **Optional LLM agents**, grounded in your engagement's own findings (RAG over pgvector — not generic CVE prose). Off by default. Every recommendation is a timeline entry, every action is reviewable.
- **Exports** — Burp via the plugin (above), SARIF for AppSec hand-off, deterministic JSON and CSV for reporting and ticketing.

---

## Quickstart

Requires: Docker + Docker Compose, GNU make, ~20 GB free disk for images and indexes.

```sh
git clone https://github.com/fd22vrsfpv-star/rag-scan-stack.git
cd rag-scan-stack
make setup          # one-time: generates secrets, certs, env file
make up             # builds and starts the stack (local Postgres by default)
```

The dashboard comes up at **https://localhost:3002** (self-signed cert on first boot). Check container health with:

```sh
make db-status
docker compose ps
```

Stop the stack:

```sh
make down
```

Reset everything (destroys local DB data):

```sh
make clean
```

---

## Components

| Service / dir | Purpose |
|---|---|
| `dashboard/` | React frontend + FastAPI BFF. Engagements, scope, findings, OPSEC timeline, settings. |
| `app/rag-api/` | Core API — assets, findings, scans, exports, recon, RAG retrieval over pgvector. |
| `node_manager/` | Provisions and tracks remote nodes (DO/AWS), WireGuard peers, SSH tunnels, SOCKS chains. |
| `tunnel-manager/` | Native Go service for tunnel lifecycle, port allocation, profile-based proxy routing. |
| `nmap_scanner/`, `nuclei_runner/`, `osint_runner/`, `pd_runner/`, `playwright_scanner/`, `web_scanner/`, `brutus_runner/`, `news_runner/` | Tool-specific scanner runners. Each is a parser + executor + audit emitter. |
| `etl/` | Normalization and fingerprint pipelines for each input format. |
| `exploit_runner/` | Optional headless Metasploit / web-PoC runner for cleared exploitation steps. |
| `autogen_agents/`, `scan_recommender/` | Optional LLM agents and RAG-grounded scan recommendation. |
| `burp-extension/` | Jython extension that ingests findings into Burp Issues. |
| `db_init/` | Postgres schema (`ensure_all_tables.sql`) + verification (`ensure_db_schema.sh`). |
| `knowledge/` | Scope rules and playbook content used by the recommender's RAG retrieval. |

---

## Authorized use

This is a workflow tool for security testing engagements you have **written authorization** to perform. It is *not* an attack platform, and it ships with engagement scope enforcement, audit trails, and OPSEC alerts intended to make authorized-only operation the path of least resistance.

Operators are expected to:

- Run only against assets covered by a written engagement scope.
- Keep engagement isolation enforced — never reuse credentials, findings, or scope data across engagements without explicit authorization.
- Treat the audit trail as discoverable and reportable to the engagement owner.

The maintainers do not condone or support unauthorized use.

---

## Security disclosure

If you find a vulnerability in this stack itself (not a finding it surfaced about a target), please open a private security advisory via GitHub's *Security* tab on this repository, or email `fd22vrsfpv-star@privaterelay.appleid.com`. Please do not file public issues for security problems.

---

## Contributing

Contributions welcome — bug reports, parsers for new tools, scanner integrations, exporters, OPSEC alert rules. Open an issue first for anything non-trivial so we can talk about scope before code is written.

---

## License

[Apache License 2.0](LICENSE). Copyright the project contributors.
