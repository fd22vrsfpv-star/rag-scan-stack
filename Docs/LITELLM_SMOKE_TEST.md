# LiteLLM migration — PR 4 smoke-test checklist

**Status gate:** this checklist must pass GREEN before the cleanup follow-up
PR (which deletes the hand-rolled helpers in `llm_query/llm_query.py`)
can merge. See `Docs/plans/LITELLM_MIGRATION.md` for the full migration
plan and `Docs/CLAUDE.md` → *LLM dispatch — LiteLLM migration* for the
PR-by-PR status.

The plan explicitly gates deletions on a focused-10 CVE-Bench run —
without a reference verdict the previous dispatch produced, we can't
tell if a LiteLLM regression crept in.

---

## 1. Confirm `path_in_use=litellm` on `/ollama/litellm-status`

```bash
curl -sfS http://localhost:8002/ollama/litellm-status | python3 -m json.tool
```

Expect:
- `kill_switch_enabled: true`
- `router_available: true`
- `litellm_importable: true`
- `path_in_use: "litellm"`
- a non-empty `aliases` list matching every enabled provider in Settings → LLM

Any `false` field is a NO-GO — fix before touching the provider list.

## 2. Fire the smoke-test script

```bash
./scripts/litellm-smoke.sh
```

Reads the alias list from `/ollama/litellm-status` and fires one `/api/generate`
call per alias with the prompt `Return only the two-letter word OK.` For each
alias, scans the `llm_query` container logs for the per-call path telemetry
line (`llm_query: path=litellm|hand_rolled backend=X model=Y`) added in PR 2
and reports PASS / FAIL / HTTP-ERR.

**Verdicts:**

| Verdict        | Meaning                                                         | Action
|----------------|-----------------------------------------------------------------|--------
| `PASS` (green) | `path=litellm` served this provider                             | continue
| `FAIL` (red)   | `path=hand_rolled` — LiteLLM errored, fallback saved the call   | **BLOCK CLEANUP** — read `docker compose logs llm_query | grep "LiteLLM path failed"` for the reason and either fix the provider config (api_version, endpoint) or report a LiteLLM bug upstream and pin an older version
| `HTTP-ERR`     | Both paths returned an upstream error (model not pulled, 401)   | Config issue, not a LiteLLM issue; fix the provider's own config and re-run
| `SKIP`         | Alias listed in `SKIP_PROVIDERS=…`                              | explicitly ignored

Exit status: `0` = every attempted alias PASS, `1` = any FAIL, `2` = pre-flight
failed (status endpoint unreachable, no aliases).

Environment knobs:

| Variable          | Default                              | Purpose
|-------------------|--------------------------------------|---------
| `LLM_QUERY_URL`   | `http://localhost:8002`              | override for remote probes
| `STATUS_PATH`     | `/ollama/litellm-status`             | status endpoint path (router prefix differs by mount config)
| `GENERATE_PATH`   | `/api/generate`                      | the ollama-compat generate endpoint
| `PROMPT`          | `Return only the two-letter word OK.`| the probe payload
| `SKIP_PROVIDERS`  | *(empty)*                            | comma-separated aliases to skip (e.g. an expensive provider you don't want billed for a smoke test)
| `TIMEOUT_SEC`     | `120`                                | per-provider request timeout

Example — skip Anthropic native (expensive) and probe only Azure + Ollama:

```bash
SKIP_PROVIDERS="anthropic:claude-sonnet-4-20250514" ./scripts/litellm-smoke.sh
```

## 3. Run focused-10 CVE-Bench through the LiteLLM path

This is the **reference verdict** the plan gates PR 4 on. The LiteLLM
dispatcher must produce the same end-to-end outcome the previous
dispatcher did on the same 10 CVEs. Steps:

1. Snapshot the current `qa/focused-10` verdict table before touching
   `LITELLM_ROUTER_ENABLED` (so you have a reference even if the switch
   was already on).
2. Confirm `path_in_use: "litellm"` on `/ollama/litellm-status`.
3. Launch focused-10 against the same engagement + target as the reference
   run.
4. After it finishes, compare verdicts PoC-by-PoC. Any PoC that regressed
   on LiteLLM but passed on hand-rolled is a blocker — inspect the trace,
   file an upstream bug or pin, then re-run before shipping deletions.

## 4. Watch logs for 24h of real traffic

With the kill switch ON (default from PR 2 onwards), monitor:

```bash
docker compose logs -f llm_query | grep -E "path=|LiteLLM path failed"
```

Any `path=hand_rolled` line that isn't an operator forcing
`LITELLM_ROUTER_ENABLED=false` is a signal that LiteLLM errored on a
real call. Fix or pin before shipping deletions.

## When the checklist is GREEN

The follow-up cleanup PR can:

- Delete every function in `llm_query/llm_query.py` marked
  `# DEPRECATED (LiteLLM migration)` (grep for the marker — 14 helpers).
- Delete the per-backend branches in `_generate_text`, `generate` (non-
  routed), `chat`, `embeddings`, `stream` that call those helpers.
- Remove the `LITELLM_ROUTER_ENABLED` env override (replace with a
  hard-coded `True` or remove the gate entirely).
- Shrink `llm_query/llm_query.py` by ~250 lines.

Until then, the hand-rolled dispatch stays as the fallback. The cost
of keeping it is ~500 lines of now-dormant code; the cost of deleting
it without the GREEN checklist is a 503 on every provider LiteLLM
can't serve.
