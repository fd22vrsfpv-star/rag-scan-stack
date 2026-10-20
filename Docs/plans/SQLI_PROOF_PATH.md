# A proof path for SQL injection — prove the CVE, then release the exploitation

**Status:** in progress. Code written, NOT deployed — the 20-CVE benchmark of
2026-10-20 is in flight and this rewrites how the largest class in it is
verified. Landing mid-stream would make that run uninterpretable.
**Written:** 2026-10-20, from the trace archive (5,269 dispatched rows,
2026-09-28 → 2026-10-20).

## The operator's framing

> "the intent is to just prove the CVE, we do not need to run sqlmap, but any
> sqlmap run should be tracked in the scans"
> "once we have a poc, then that can be a selective run that is released"

Two phases, and they have been conflated:

| phase | goal | tools | gate |
|---|---|---|---|
| **prove** | the vulnerability exists, reproducibly | minimal, deterministic, no sqlmap | scope gate only |
| **release** | extract data, enumerate, demonstrate impact | sqlmap and friends | operator release + approval |

Everything below is about phase one. Phase two already has its machinery —
`BuildPocRequest.release`, the approval rules, the graded `database_access`
goal — and needs wiring, not invention.

## Why the current proof path underperforms

`knowledge/vuln_classes.yaml` declares, for `sqli`:

```yaml
proof: [echo, timing, oob]
```

Those are the only proofs the class can express, so a blind SQLi has exactly
one route: timing. The archive says what that costs.

**Verdict method on SQL-class run rows:**

| method | rows | what it means |
|---|---|---|
| `latency_too_fast` | **920** | the injected SLEEP did not delay anything |
| `latency_too_slow` | 178 | blocked past `max_seconds` |
| `latency_not_executed` | 74 | no timing payload to execute |
| `latency_unconfirmable` | 23 | nothing to scale |
| `latency_connection_error` | 20 | |
| `latency` | 305 | landed in the window |
| `regex` | 31 | in-band proof |

**1,215 timing attempts went wrong against 305 that landed.** The dominant
failure, `latency_too_fast` at 920, is the payload never reaching the SQL
parser at all — a `SLEEP(5)` that returns instantly was not evaluated.

The two cheapest and most certain SQLi proofs are not in the vocabulary:

* **Error-based.** One request. A DB syntax error naming the engine
  (`You have an error in your SQL syntax ... near`) proves attacker input
  reached the parser. Nothing but a database emits that string.
* **Boolean differential.** Two requests. `' AND 1=1--` and `' AND 1=2--`
  returning *different* responses proves the DB evaluated the expression.
  Deterministic, no clock, immune to a slow target or a WAF delay — the two
  things that make timing verdicts unreliable (and that
  `TIMING_CONFIRM_DELTA_SEC` exists to work around).

## A wider gap found on the way

Across 36 classes the YAML declares six proof kinds. `etl/proof_anchor.py`
implements four:

| kind | classes declaring it | anchor |
|---|---|---|
| echo | 23 | `anchored_echo` |
| oob | 13 | `anchored_oob` |
| status_change | 9 | **none** |
| side_effect | 8 | **none** |
| timing | 7 | `anchored_timing` |
| file_content | 4 | `anchored_file_content` |

17 class-declarations name a proof kind with no anchor behind it. They fall
through to the generic self-declaration path, which means for those classes
`cve_anchored: true` is the entire verification. Pre-existing, out of scope
here, recorded so it is not rediscovered — see `Docs/OPEN_ITEMS.md`.

## The change

### 1. Knowledge first

`vuln_classes.yaml` gains `boolean` and `error` on `sqli` (and on
`sql_injection` aliases). A new proof method should take effect by being
loaded, per CLAUDE.md's RAG-first rule — not by editing a branch.

### 2. Two anchors

`etl/proof_anchor.py` gains `anchored_boolean` and `anchored_error`. An anchor
*is* a verification rule, so it must be code; one function per kind is the
existing pattern.

* `anchored_error` — the assertion matches a DB error signature from a known
  table (the `file_content` precedent: a content signature the command asked
  for). The signature table is knowledge, so new engines are a YAML edit.
* `anchored_boolean` — anchors on a *differential*, not a string: the
  assertion must name two responses that differ. A single response cannot
  anchor a boolean proof, because "the page rendered" is not evidence.

### 3. A differential step in the plan format

`etl/http_request.py` gains a step shape that issues a pair and asserts they
differ:

```json
{"id": "bool-proof", "differential": {
   "true":  {"request": {...payload AND 1=1...}},
   "false": {"request": {...payload AND 1=2...}},
   "must_differ": "body"}}
```

This is also what unblocks the timing gap found on 2026-10-20: a timing proof
needs `date` arithmetic, cannot be expressed as a plan, and therefore falls
back to hand-written shell — which is where the remaining `shell_syntax`
refusals in the current run come from. A declarative `timing` step closes the
same hole.

### 4. Proof order

Cheapest and most certain first: **error → boolean → echo/union → timing**.
Timing becomes the last resort it should always have been, still gated by the
scaled-payload confirmation that already exists.

### 5. sqlmap leaves the proof path, and becomes visible

sqlmap has run **173 times** (`tool_handoff.tested`, `ran=True`), confirming
on **7 (4%)**. `tool_executions` has **zero** rows for it — the handoff
dispatches directly rather than through the recorded path, so every one of
those runs is invisible to scan history, the monitor and any audit view.
"Any sqlmap run should be tracked in the scans" is currently false.

Two separable changes:
* **Track it.** The handoff writes a `tool_executions` row per invocation.
  Self-contained, no behaviour change, fixes an audit hole.
* **Move it to phase two.** Proof does not invoke sqlmap. A released run does.

Worth recording why the 4% is not sqlmap being weak: all 7 confirmations are
simple form POSTs with a named parameter (`-p username`). Elsewhere it is
handed a crippled technique set (`--technique=T` on 136 of 175 — time-based
only, the slowest and least certain of the five) or a broken request (**42 of
175, 24%, carry an unexpanded `$VAR`** such as `sid=$CSRF_TOKEN`, so the app
rejects it before any injection test). Both only matter in phase two, where
time is not scarce — which is why neither is in this plan's critical path.

## What this does NOT change

* The scope gate and `MAX_CONCURRENT_SCANS`. Proof methods decide what counts
  as evidence; they never decide whether a packet may be sent.
* The timing confirmation. A latency verdict still needs its scaled re-run.
* The canary anchor chain. A boolean or error proof is an *additional* route
  to anchored, never a way around one.

## Rollout

| step | state |
|---|---|
| 1. `anchored_error` + `anchored_boolean` + tests | in progress |
| 2. `boolean`/`error` on the sqli class | pending |
| 3. differential + timing steps in `http_request` | pending |
| 4. proof order, cheapest first | pending |
| 5. sqlmap → `tool_executions` | pending |
| 6. sqlmap out of the proof path | pending |

**Deploy gate:** nothing ships until the in-flight benchmark reaches a
breaking point. A rag-api rebuild kills the running CVE (`verified=?`, 0-byte
artifacts) — that is how the 2026-10-19 validation build was lost.

**Measurement:** the same 20 CVEs, and the number to watch is not the verified
count but the shift in verdict method — `latency_too_fast` should stop being
the single largest outcome, because a boolean proof does not care how fast the
target answers.
