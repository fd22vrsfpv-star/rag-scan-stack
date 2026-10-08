# strix_overnight — Strix side of the CVE-Bench head-to-head

Runs [Strix](https://github.com/usestrix/strix) against the same CVE-Bench
targets `cvebench_overnight/run_focused10.sh` is working on, in parallel,
so we can diff "our stack vs a bare agent" verdict-by-verdict.

## How it works

**Follower mode.** `run_focused10_strix.sh` tails
`cvebench_overnight/progress_focused.log`. When focused-10 writes
`scoped CVE-X -> IP:PORT`, this runner fires `strix -n -m quick` at the
same URL — in a background subshell, so focused-10 keeps moving onto
the next CVE while Strix is still working on the previous one. Both
agents end up pentesting the same target at the same time.

This is deliberate: `gym.sh` can only bring one CVE's containers up at
a time, so having Strix independently cycle `gym.sh up/down` would
collide. Following the lead's log skips the whole state machine.

## Fairness constraints

Both runs share:
- Same CVE list (whatever focused-10 iterates through)
- Same target containers (the ones focused-10 brings up via gym.sh)
- Same scope gate (focused-10 writes `scope_targets`; Strix inherits)
- Same LLM backend (default: local ollama/qwen3-coder:30b)
- Same engagement (`cvebench`), so cost tracking in `llm_request_metrics`
  attributes to one bucket

Strix caps per CVE: `--max-budget $1.00`, `--max-turns 50`, `-m quick`.
`cvebench_overnight` caps at `max_iters=15`. Tune in `strix.env` for a
tighter head-to-head.

## Launch

```bash
# From repo root, with cvebench_overnight already running:
cd strix_overnight
# Optional: edit strix.env to point at Azure / different model / tighter budget
nohup bash run_focused10_strix.sh > nohup_strix.log 2>&1 &
echo "pid=$!"
```

The follower will catch up on any CVEs focused-10 has already scoped
and fire Strix on each. It exits when the lead writes `ALL 10 DONE`
and all in-flight Strix runs drain.

## Outputs

- `strix_overnight/progress_strix.log` — one line per CVE start/finish
- `strix_overnight/results/<CVE>/strix.log` — Strix's full stdout
- `strix_overnight/results/<CVE>/verdict.json` — `{verdict, exit_code,
  elapsed_sec, findings_count, strix_mode, strix_llm}`
- `~/strix_runs/<run-name>/` — Strix's own detailed artefacts
  (findings JSON, PoCs, screenshots)

## Verdict comparison (post-run)

```bash
# Side-by-side: focused-10 vs Strix verdicts for every CVE both touched.
python3 scripts/compare_cvebench_strix.py \
  cvebench_overnight/results_focused \
  strix_overnight/results \
  > comparison.md
```

(That comparison script is a follow-up — the artefacts land in a
diff-able shape right now.)

## Known gaps

- **Strix's sandbox is a Docker container.** Its default network may not
  reach `172.18.0.X` targets on our `agents_net`. If a run can't connect,
  attach the sandbox to the compose network (needs a Strix config knob) or
  bind the targets on `host.docker.internal`.
- **Non-zero exit = findings.** Strix's convention; our verdict JSON
  translates `rc=1` → `findings_reported`. A real "did it find THE CVE"
  judgement needs to read the finding titles — the `findings_count`
  field is a crude signal.
- **Cost tracking.** Strix's LLM calls go through its own LiteLLM, so
  they bypass our `llm_request_metrics`. Follow-up: wrap `STRIX_LLM` to
  go through `llm_query` instead of talking to ollama directly, and
  everything lands in the same stats panel.

## When to use

- Running `cvebench_overnight` to produce a reference verdict table
- Before shipping a dispatcher change (so you have the previous Strix
  numbers to diff against)
- Investigating whether a specific CVE requires more than our pipeline
  supplies (did Strix find it with no RAG context? our pipeline should
  too)
