# Future Features / Backlog

Candidate features noted during development. Not commitments — a place to capture
ideas so they aren't lost. Move an item into an issue/PR when picked up.

## Tor gateway as an egress option
- **Idea:** offer Tor as a selectable egress gateway (alongside the node SOCKS
  proxies and the configurable `web_research.proxy`) for outbound OSINT / web
  research / passive recon — so those lookups can egress over Tor instead of the
  platform's own IP or a fixed VPS.
- **Why:** OPSEC — web-research and OSINT queries reveal what products/targets are
  being investigated; Tor decouples that from the operator's infrastructure.
- **Shape:** a `tor` service (or existing SOCKS on 9050) selectable per-profile,
  wired the same way DDG/web-research proxying already is (`web_research.proxy`),
  and optionally as a scan-egress profile in node-manager. Scope-gated dispatch and
  the fail-closed rules are unchanged; this is only an egress path.
- **Caveats:** many targets block Tor exit nodes; keep it OPT-IN per task, never the
  default for active scanning against a client's assets.
