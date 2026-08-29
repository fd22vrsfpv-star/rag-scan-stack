# Tests

88 test modules. `pytest.ini` confines collection to `tests/`.

This file replaces a version that documented exactly one module
(`test_validation.py`) out of 88 and told you to `pip install pytest` on a host
that has no pip.

## Running them

**There is no pytest on this host and none in any container image.** Run the
suite in a throwaway container:

```bash
# Source-level tests (most of tests/). No stack needed.
docker run --rm -v "$PWD":/repo -w /repo python:3.12-slim \
  sh -c "pip install --quiet pytest pytest-asyncio requests pyyaml psycopg2-binary fastapi httpx; \
         python -m pytest tests/ -q"

# Tests that call the live stack (https://localhost:3002) need host networking.
docker run --rm --network host -v "$PWD":/repo -w /repo python:3.12-slim \
  sh -c "pip install --quiet pytest requests; python -m pytest tests/test_endpoint_smoke.py -q"

# Tests that need the agent dependencies (langgraph, langchain-core, psycopg2)
# must run INSIDE the agent container, which is where those deps live.
docker exec autogen-agents pip install --quiet --target /tmp/pt pytest
docker cp tests/test_langgraph_phases.py autogen-agents:/tmp/
docker exec -e PYTHONPATH=/tmp/pt -e AUTOGEN_AGENTS_DIR=/app autogen-agents \
  python /tmp/pt/bin/pytest /tmp/test_langgraph_phases.py -q

# DB-backed modules, via a throwaway 127.0.0.1-only forwarder:
scripts/run_db_tests.sh
```

A single module runs standalone: `pytest tests/test_fingerprint.py -v`.

**67 of the 88 modules skip themselves** when their dependency or the stack is
absent. A skip means "cannot run here"; an error means "broken". Never convert
one into the other — mixing them hides real breakage.

**Consequence for authors:** a guard that only runs where the agent
dependencies are installed will, in practice, never run. Prefer reading source
with `ast` over importing the module, so the check works on a bare checkout.
`tests/test_langgraph_phases.py` and `tests/test_tool_registry.py` both do this.

## What is actually enforced

CLAUDE.md's rule is that *"a rule with no enforcing test is a suggestion"*. These
are the tests that make the invariants real. Each carries a **ratcheting debt
list**: a new violation fails by name, and a resolved entry must be deleted (a
separate test enforces the deletion).

| Invariant | Test | Debt list |
|---|---|---|
| Every host-contacting path passes the scope gate (fail-closed) | `test_dispatch_invariants.py::test_no_new_ungated_dispatchers` | `SCOPE_DEBT` |
| Every scan initiator respects `MAX_CONCURRENT_SCANS` | `test_dispatch_invariants.py::test_no_new_unbounded_scan_initiators` | `LIMIT_DEBT` |
| The BFF and `etl/scope_gate.py` agree | `test_dispatch_scope.py::test_bff_and_scope_gate_agree` | — |
| Every BFF proxy names a path some service declares | `test_proxy_contracts.py::test_upstream_paths_exist` | `PROXY_DYNAMIC`, `PROXY_DEBT` |
| Every SQL column exists on its table | `test_sql_columns.py::test_every_sql_column_exists` | `SQL_DEBT` |
| Every SQL parameter TYPE is compatible (`text[]` vs bare string, `jsonb` vs dict) | `test_sql_columns.py::test_sql_param_types_are_compatible` | `ARRAY_UNVERIFIED` |
| Python and the SQL dedup triggers compute the same fingerprint | `test_fingerprint.py` | — |
| No f-string placeholder is undefined at runtime | `test_fstring_placeholders.py` | — |
| Route declaration order / no shadowed routes | `test_route_contracts.py` | — |
| No live endpoint returns 5xx | `test_endpoint_smoke.py` + `scripts/smoke_endpoints.py` | `EXPECTED_5XX` |
| The agent tool registry is the only roster, and AutoGen is gone | `test_tool_registry.py` | — |
| Agent phase toolsets, and that exploit execution stays behind the approval interrupt | `test_langgraph_phases.py` | — |

### What is NOT enforced

CLAUDE.md requires that a **mutating or logic-bearing endpoint ships an
executing test in the same commit**. Nothing fails today when one does not —
there is no test that enumerates mutating routes and demands coverage. By the
file's own definition that rule is currently a *suggestion*. The same is true of
"guard tests must be sabotage-proven" and "fixtures come from real captured
output": both are conventions, honoured by hand.

Closing the first gap would follow the pattern already used four times above: a
guard that enumerates POST/PUT/PATCH/DELETE handlers, checks each against a
coverage map, and carries a `TEST_DEBT` ratchet.

## Writing a test here

1. **Executing beats importing.** `ast.parse` passing, the module importing and
   the container reporting healthy are not verification. Call the thing.
2. **Sabotage-prove a guard.** Reintroduce the bug, watch it go red, restore, and
   record the proof in the module docstring. A guard that cannot fail is worse
   than none, because it is mistaken for coverage.
3. **Skip, don't fail, on a missing dependency** — and skip with a reason.
4. **Fixtures come from real captured tool output** (`tests/fixtures/`), not
   invented shapes.
5. **Say WHY in the docstring.** Most modules here open with a `WHY THIS EXISTS`
   section naming the defect that motivated them. That is what makes the test
   survivable when someone later wonders whether it still matters.

## Markers

Registered in `pytest.ini`: `unit`, `integration`, `database`, `e2e`,
`scan_recommender`, `playwright`. Select with `-m`, e.g. `pytest -m unit`.

## Baseline: green

`pytest tests/` → **1233 passed, 361 skipped, 0 failed** (2026-08-28).

The five failures previously listed here were fixed, not suppressed. Three were
real product bugs (a 2s health probe against a 4.2s endpoint; the local
`postgres` container counted as a core failure in remote-DB mode; a
`session-bundle` 500 from dereferencing a list-shaped payload) and two were bad
assertions (a scope allow-list silently truncated at 500 rows; facet sums
compared against a total the API documents as answering a different question).
See Docs/CHANGES_MADE.md, 2026-08-28 part 3.

Two guards were made honest rather than lenient:

- **Timeouts are no longer counted as 5xx.** `test_no_endpoint_returns_5xx`
  reports only `>= 500`; `test_slow_endpoints_are_declared` reports timeouts
  against a `KNOWN_SLOW` list with measured times. Merging them made a genuine
  500 look like the same class of problem as an endpoint that takes 13 seconds —
  and it hid one: `/api/tools/executions` only became visible once the timeouts
  stopped masking it.
- **Health assertions require confirmation.** This suite hammers the stack while
  it runs, so one failed probe cannot distinguish "the service is down" from
  "its probe timed out under the load this test run is generating".
  `test_all_core_services_are_healthy` now needs the same service to fail two
  consecutive observations, the second with the response cache busted.

### Previously intermittent — root-caused and fixed (2026-08-29)

`/api/tools/executions` and `/api/wg/peers` used to 500 during full-suite runs
with `server does not support SSL, but SSL was required`. It was **not load and
not TLS** — a concurrency ramp through the tunnel showed 0 failures at 60
simultaneous connections.

The sweep itself caused it. `GET /api/settings/database/compare` **started the
local Postgres** to read its stats, and `docker compose up -d rag-postgres`
gives that container the `rag-postgres` network alias. Docker DNS then
round-robins between the SSL-less local database and the remote tunnel, so a
share of every service's connections failed — hence "intermittent", and hence
only under the sweep.

Fixed by defaulting that endpoint to `start_local=false`, plus a Docker event
watcher that strips the alias from any local Postgres that claims it. Two
consecutive full-suite runs are clean.

**If you see this error again**, do not look at load or at the endpoint that
reported it. Run:

```bash
docker exec autogen-agents getent hosts rag-postgres   # more than one IP = split brain
docker ps --filter label=com.rag-scan-stack.role=db-proxy
```

`rag-postgres` must resolve to exactly one address: the `rag-db-tunnel` sidecar.
Note that `sslmode=require` is what makes this fail LOUDLY — without it the
stack would silently use the wrong database. Do not relax it to make the error
go away.
