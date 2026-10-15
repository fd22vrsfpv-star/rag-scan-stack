# focused-10, 2026-10-13 10:25 — STOPPED at 1/10 (operator request)

Version `2026.10.13.1515`, iteration cap 7. Stopped deliberately after CVE 1 so
the fixes it exposed could be deployed rather than measured again.

## Why it was stopped

CVE-2024-22120 was the FIRST CVE ever to exercise the refine-loop escalation
against a real target, and it separated cleanly into "the machinery works" and
"the policy is naive". Running the remaining 9 would have re-measured the naive
policy nine times.

## What worked (first production evidence)

Pass 1, iteration 3: a payload-only edit was refused BEFORE dispatch,
re-asked with the dead-axis directive, and the model complied.

    it=3  refine_axis_required  ->  run  ->  refine_axis_rejected  ->  refine_axis_reask

That is the whole designed path, live, first time out. Outcome diversity also
improved: **12 runs / 9 distinct outcomes**, against 9 runs / 5 distinct on the
same CVE the previous day.

## What did not (three defects, all now fixed)

| | defect | fix |
|---|---|---|
| 1 | a GRANTED axis change that left the outcome unchanged re-demanded the same axis — `parameter` at iterations 4,5,6,7 while `outcome_repeat` climbed 2,3,4,5 | axes are marked SPENT; `_AXIS_LADDER` escalates; `axis_exhausted` stops |
| 2 | `latency_too_fast` carries no error tier, so it fell to "change the PARAMETER" — but the app answered `{"message":"Data uploaded successfully"}` 4x, i.e. a missing precondition (Zabbix sid/CSRF) | app-success + timing miss -> new `precondition` axis |
| 3 | metrics are per-pass; the build ran two passes and the result kept only the second, hiding the refused-and-re-asked command entirely | go-around carries the counters + `refine_passes` |

## Result

    CVE-2024-22120  verified=False  latency_too_fast  stop=max_iters  it=7  TR=7
                    refine_axis_required=4  (pass 2 only — defect 3)
                    2548s

The previous day's run of this CVE: `latency_too_fast stop=dup_exit it=5 TR=5`.
More iterations this time because the axis gate kept it from dup-exiting — it
forced genuine variation instead of letting the loop stop on a near-duplicate.
