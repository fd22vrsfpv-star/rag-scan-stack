# focused-10, 2026-10-13 14:53 — STOPPED at 1/10 to deploy fixes

Version `2026.10.13.2045`, iteration cap 7. Stopped on operator request so three
pending fixes (delete-by-id, drawer asset resolution, `/scope/move`) could ship.

## The one result, and what it proves

    CVE-2024-22120  verified=False  latency_too_fast  stop=dup_exit
                    it=3  TR=3  axis_req=1  passes=2  1510s

### Against the two prior runs of the same CVE

| | 2026-10-12 | f13 (pre-fix) | f15 (this) |
|---|---|---|---|
| iterations | 5 | **7** (max_iters) | **3** |
| target runs | 5 | 7 | 3 |
| `refine_axis_required` | — | **4** | **1** |
| `refine_passes` | not reported | not reported | **2** |
| stop | dup_exit | max_iters | dup_exit |
| wall clock | — | 2548s | 1510s |

## CONFIRMED by this run

**The spent-axis fix.** `axis_req` fired once instead of cycling four times on
the same axis, and the build stopped at iteration 3 instead of exhausting the
budget. On f13 the same axis was re-demanded at iterations 4,5,6,7 while
`outcome_repeat` climbed 2,3,4,5.

**The per-pass metrics fix.** `passes=2` is reported, so a two-pass build no
longer hides its first pass. On f13 the single most interesting event of the run
— a payload-only command refused before dispatch and successfully re-asked —
appeared nowhere in the metrics.

## NOT exercised by this run — do not claim these

**Precondition detection.** The trace shows `axis: "parameter"`,
`app_success: false`. This run's target answered
`{"message":"Attack unsuccessful.","status":false}`, not the
`{"message":"Data uploaded successfully"}` that made f13 a precondition case.
The heuristic is earned by a success body and there wasn't one, so it correctly
did not fire — but it is still unvalidated on real traffic.

**Ladder escalation.** `axes_spent: []` — only one axis was ever demanded, so
the ladder never had to escalate.

**`axis_exhausted`.** Never reached.

The CVEs that would exercise those are **CVE-2024-36412** and **CVE-2024-4443**,
whose apps answered with success bodies while the exploit did not fire. Neither
ran here.

## Honest summary

One of three escalation fixes is validated against a real target. The build is
materially more efficient — 3 iterations instead of 7, 25 minutes instead of 42
— and the verdict is unchanged: `latency_too_fast`, not verified. Faster and
more honest, not yet more successful.
