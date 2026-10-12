# focused-10, 2026-10-11 19:29 — stopped after 3/10 to deploy queued fixes

First run where all three preconditions held at once: the attack path could
reach targets (kali-listener on test_net), all five P1 fixes were present AND
baked into the image, and the DB started clean.

| # | CVE | Time | Stop reason |
|---|-----|------|-------------|
| 1 | CVE-2024-22120 | 2059s | max_iters |
| 2 | CVE-2024-3408  |  845s | identical_resend |
| 3 | CVE-2024-32511 | 3060s | dup_exit |

0/3 verified, but **0 target_unreachable** — every stop reason describes an
exploit outcome rather than a connectivity failure. The previous run lost 5 of
10 to the network before the exploit logic ran.

Signals worth keeping:
* CVE-2024-22120 resolved its template vars from confirmed_facts (0 unresolved
  `{hostid}`/`{scriptid}` placeholders across 11 commands) and ran 19 real
  iterations. In the pre-fix run it hung silently after recon with a 0-byte
  result; in the compromised run it reported target_unreachable.
* CVE-2024-3408 finished in 845s vs 1939s previously — it reaches
  identical_resend faster, i.e. the repeated-strategy detection bails instead of
  grinding to max_iters.

Stopped deliberately at 4/10 (CVE-2023-51483 in flight, discarded) to rebuild
rag-api for three queued changes that cannot deploy mid-run: POC- token naming,
review.md section index, and the /ports/summary engagement filter.
