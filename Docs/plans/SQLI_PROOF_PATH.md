# A proof path for SQL injection — prove the CVE, then release the exploitation

**Status:** steps 1-6 written and tested, NOT deployed — the 20-CVE benchmark of
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

17 class-declarations named a proof kind with no anchor behind it. They fell
through to the generic self-declaration path, which means for those classes
`cve_anchored: true` was the entire verification.

**Closed 2026-10-20.** Both turned out to be mechanisms already built:

* `status_change` IS a differential — its own guidance says "a 200 alone
  proves nothing, because the honest request returns 200 too". It anchors on
  the same declared pair `boolean` does.
* `side_effect` needs the canary in the assertion AND a read-back in the
  command. "State changed" is only provable if we can name what it changed to,
  and the request causing the effect "usually returns a perfectly ordinary
  200" — so without a second request nothing observed the change.

A ratchet now fails if any kind declared in `vuln_classes.yaml` has no
`anchored_*` function, so the gap cannot silently reopen.

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

## Step 9 (found 2026-10-20 mid-run): the prompt overrides its own guidance

Steps 1-8 deployed and the new anchors fired **zero** times. The capability is
live and unreachable, for a reason the isolated prompt test could not show.

`_assert_tmpl` is computed independently of the proof-kind list:

```python
elif "echo" in _vc_proof_kinds(_listener_vc):
    _assert_tmpl = '{"expect_regex": "%s"}' % canary
```

`sqli` declares `echo` among its kinds, so every sqli build is handed a
hard-coded CANARY assertion template — sitting in the return-shape instruction,
right beside guidance telling the model to prefer an error or boolean proof.
The template is concrete and the guidance is prose further up. The model
follows the template.

Evidence from the run: every assertion is `['cve_anchored', 'expect_regex']`,
including on all three builds that resolved as `sqli`. The proof-kind guidance
reached the prompt correctly (6 of 12 synth calls carry it — exactly the 3
sqli builds × 2 calls each); the model simply had no template for anything but
echo.

This is also why the isolated test on 2026-10-20 showed the opposite: that
prompt carried no `_assert_tmpl`, so the guidance was the only instruction
present and the model reached straight for error-based.

**Fix:** `_assert_tmpl` follows the FIRST declared proof kind rather than
jumping to `echo` whenever it appears anywhere in the list. The list is
ordered cheapest-first, which was the point of ordering it.

**What the deployed run still proved:** `latency_too_fast` went from 920
lifetime to **0**. Removing timing as the class default worked. The proofs
meant to replace it are a separate, still-unverified claim.

## What this does NOT change

* The scope gate and `MAX_CONCURRENT_SCANS`. Proof methods decide what counts
  as evidence; they never decide whether a packet may be sent.
* The timing confirmation. A latency verdict still needs its scaled re-run.
* The canary anchor chain. A boolean or error proof is an *additional* route
  to anchored, never a way around one.

## Rollout

| step | state |
|---|---|
| 1. `anchored_error` + `anchored_boolean` + tests | **done** |
| 2. `boolean`/`error` on the sqli class | **done** |
| 3. differential + timing steps in `http_request` | **done** |
| 4. proof order, cheapest first | **done** (in `is_anchored` and the class list) |
| 5. sqlmap → `tool_executions` | **done** (`_record_tool_execution`) |
| 6. sqlmap out of the proof path | **done** (flag-reversible) |
| 7. the synth prompt teaches the new step shapes | **done** — verified live against the model |
| 8. phase two: a released run that executes the derived commands | **done** |

All eight steps are written and tested. Nothing is deployed.

### Step 8: `POST /exploit-store/{id}/released-run`

Where an operator runs a command the proof path derived and deliberately did
not. Four conditions, each load-bearing:

* **409 on an unverified PoC.** Running an enumeration tool against a
  vulnerability nobody has proven is a scan, not an exploitation, and it is
  already available in the recon phase.
* **The scope gate**, unconditional and fail-closed — *including* over an
  operator-supplied `command` override, which is applied BEFORE the gate so it
  cannot slip past it. CLAUDE.md: an override overrules the platform's
  suppression judgement, never the operator's authorization.
* **`MAX_CONCURRENT_SCANS`.** This initiates a scan, so it takes a slot and
  sheds with 429 rather than queueing.
* **`tool_executions`.** A tool this platform ran is a scan.

The BFF proxy checks the upstream status rather than assuming it: httpx does
not raise on 4xx/5xx, and this endpoint's refusals ARE the safety story —
returning a 409 as success would report a refused exploitation as a completed
one. All three refusal paths are executed in the test, not asserted
structurally.

### What step 7 cost, and what it found

Capability is not reachability, so the prompt change was verified against the
real model rather than assumed. Three defects came out of that, none of which
a unit test would have found:

1. Told the vuln was BLIND, the model chose **error-based** — one request, a
   broken quote, asserting on MySQL's own parser message. That is the intended
   outcome: before this, a blind SQLi had only `timing` and would have written
   a SLEEP.
2. It sent `"data"` instead of `"body"`, and `normalise` **silently dropped
   it** — both arms of a boolean proof rendered as bare POSTs with no payload.
   A proof that could not fire, with no reason recorded anywhere; the same
   unreachable-is-not-absent shape this repo keeps hitting. Aliases are
   accepted now (`data`, `payload`, `params`, `header`, `cookie`, …) and an
   unrecognised field is REFUSED with a message naming what is supported.
3. It referenced the arms **by step id** rather than inlining them — a better
   shape than the one designed, because it avoids repeating a request and the
   arms stay self-describing in the trace. As written it would have issued
   FOUR requests for a two-request proof; a referenced step is now consumed by
   the differential and not issued again.

The format moved toward what the model actually produces, which is the right
direction of travel for a contract it has to satisfy on every build.

Two reversals kept while 7 and 8 are outstanding:

* `BUILD_POC_RUN_TOOLS=true` — puts tool execution back in the proof path.
* `BUILD_POC_STRUCTURED_PLAN=false` — restores the pre-plan synth contract.

**Deploy gate:** nothing ships until the in-flight benchmark reaches a
breaking point. A rag-api rebuild kills the running CVE (`verified=?`, 0-byte
artifacts) — that is how the 2026-10-19 validation build was lost.

**Measurement:** the same 20 CVEs, and the number to watch is not the verified
count but the shift in verdict method — `latency_too_fast` should stop being
the single largest outcome, because a boolean proof does not care how fast the
target answers.
