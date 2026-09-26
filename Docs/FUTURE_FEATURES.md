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

<!-- Added 2026-09-25 (prompted). -->

## Load bounded knowledge by name for the planner; keep RAG for findings
- **Idea:** the planner loads the curated `knowledge/*.yaml` decision packs
  deterministically **by name** (a catalog of name+description in context, the
  planner selects and the whole doc is injected). Reserve pgvector / `rag_documents` similarity search for the large, fuzzy
  findings corpus, not for the small bounded knowledge set.
- **Why:** the knowledge YAML is a small curated minority in `rag_documents`, and an
  approximate `ivfflat` scan at `probes=1` returns none of it — the exact bug the
  read path works around by raising probes / exact-scanning. Load-by-name deletes
  that whole failure class for the decision knowledge.
- **Shape:** a name→doc loader + a `load_knowledge(names)` path for the LangGraph
  planner; keep `search_knowledge_base` for findings recall. Deterministic gate and
  scope rules unchanged. See OPEN_ITEMS.
- **Caveats:** must stay in sync with the RAG loader so embedded and by-name views do
  not drift; a large future knowledge set may still want retrieval.

## PoC-required findings + coverage reconciliation gate
- **Idea:** refuse to mark a finding validated without evidence / a working PoC, and
  do not let an agent run "finish" until it has reconciled a coverage ledger (what
  was tested and found safe — the negative space) and validated any attack chains.
- **Why:** a proven-exploit reporting model requires a working PoC + evidence +
  a computed CVSS, gates "finish" on a coverage ledger, and verifies referenced
  HTTP-exchange IDs against the proxy. We have dedup and match_confidence
  but no evidence-required gate and no tested-but-safe ledger.
- **Shape:** a required-evidence check at the finding writer; a `coverage` table +
  a finish gate in the LangGraph flow; verify evidence HTTP IDs via the Burp/proxy
  bridge we already have.
- **Caveats:** don't block legitimate low-signal recon findings; make the PoC
  requirement apply to *validated/exploited* findings, not raw observations.

## Trust filed artifact IDs over agent prose
- **Idea:** when one agent consumes another's work (or when the UI reports what an
  agent did), read the actual filed row/report IDs from the DB, never the LLM's
  narrative claim that it filed something.
- **Why:** reading a subagent's real filed report IDs from shared state rather
  than trusting its completion prose is hallucination resistance that matches our
  "verified = observed output" rule.
- **Shape:** coordination/handoff points assert on persisted IDs; the analysis
  chokepoints already centralize ingest, so pin the count there.
- **Caveats:** none material; this is a robustness tightening.

## Cap tool/command output at the tool boundary
- **Idea:** bound every tool/command result (bytes + lines) before it is stored or
  enters agent history, not only at the DB column.
- **Why:** bounding every tool result before it enters history. Our "127 MB of
  stderr emptied two pages" incident was the same problem caught one layer too late.
- **Shape:** a shared bounding wrapper at the tool-execution / ingest sink
  (`/ingest/tool-output` and the kali listener), with the cap configurable.
- **Caveats:** keep a truncation marker + full-output pointer so nothing looks
  silently empty.

## Run budget cap + per-turn tool-call limiter
- **Idea:** bound an agent run by cost budget and cap tool calls per turn, alongside
  the existing `MAX_CONCURRENT_SCANS` and scope gate.
- **Why:** a per-run cost budget and a per-turn tool-call limiter bound spend and
  runaway loops — a different axis from concurrency, and one our self-feeding
  `/next_scan` loop showed we need.
- **Shape:** a per-run budget (LLM + dispatch) checked in the LangGraph loop and a
  per-turn tool-call ceiling; surface the stop reason in the UI.
- **Caveats:** budget stop must be fail-safe (stop, don't half-finish); keep it
  distinct from the scope gate (authorization is never a budget).

## SARIF as a first-class always-emitted export + diff-scoped CI mode
- **Idea:** always emit SARIF 2.1.0 (not "optional/if feasible") as part of a fixed
  per-run artifact set, and add a diff-scoped review mode that reports only what a
  change introduced or newly reaches.
- **Why:** always emitting `findings.sarif` + report.md + vulnerabilities.json +
  run.json is what makes CI/PR integration clean; and a `diff` scan mode is a real
  methodology, not just data-layer delta.
- **Shape:** promote the SARIF exporter to always-on; add a diff scope input to the
  agent flow with an explicit "what is in scope / what not to report" contract.
- **Caveats:** SARIF determinism must hold (stable ordering/ids) for CI diffs.
