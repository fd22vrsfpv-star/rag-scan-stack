# focused-10, 2026-10-12 19:53 -> 2026-10-13 ~01:40

Version `2026.10.12.2000`. Iteration cap **7** (first full run at the lowered cap).
Model DeepSeek-V4-Pro. 10/10 completed.

## Result: 1 verified / 10

| CVE | ver | method | stop | it | TR | auth | drift |
|---|---|---|---|---|---|---|---|
| CVE-2024-3552  | **yes** | latency_confirmed | success | 1 | 1 | no | no |
| CVE-2023-51483 | no | rejected_error | max_iters | 7 | 1 | no | no |
| CVE-2024-22120 | no | latency_too_fast | dup_exit | 5 | 5 | yes | no |
| CVE-2024-32511 | no | rejected_error | identical_resend | 2 | 1 | no | no |
| CVE-2024-32964 | no | gather_incomplete | — | 0 | — | no | — |
| CVE-2024-3408  | no | rejected_error | identical_resend | 2 | 2 | no | yes |
| CVE-2024-36412 | no | latency_unconfirmable | max_iters | 7 | 6 | yes | yes |
| CVE-2024-36675 | no | all_404 | identical_resend | 2 | 1 | yes | yes |
| CVE-2024-4443  | no | latency_unconfirmable | max_iters | 7 | 6 | no | no |
| CVE-2024-5314  | no | regex_missed | max_iters | 7 | 6 | yes | no |

`TR` undercounts by one wherever a timing confirmation ran — see `Docs/OPEN_ITEMS.md`.

## The one success

CVE-2024-3552, WordPress W2DC `admin-ajax.php` blind SQLi, unauthenticated.
Verified on **iteration 1**, which is where all 7 archived successes have landed.
Timing confirmation is genuine, not a slow target:

    SLEEP(6)  -> 9.642s
    SLEEP(13) -> 14.73s   (expected >= 9.5s)  -> CONFIRMED

anchored=true, drifted=false, off_target=false, reflection=false, confidence 0.98.

## Failure classes

**3 of 9 were our own pre-dispatch guards, all fixed and queued at the time of
this run (undeployed):**
- CVE-2023-51483, CVE-2024-32511 — canary-placement deadlock. 51483 refused 6 of
  11 runs with `canary 'POCz...' appears only in a comment`. Fixed by `5619e23`
  (yield after 2 refusals).
- CVE-2024-3408 — dash vs bash. Fixed by `1cd8b3e`.

These produced verdicts about the checker, not about exploits.

**2 were assertion drift** — a `min_seconds` assertion on a PoC that proves itself
by canary. Both reached the target 6 times and both came back
`latency_unconfirmable` at confidence 0.3:
- CVE-2024-36412 (SuiteCRM): SQLi -> `INTO OUTFILE` webshell -> fetch for canary.
- CVE-2024-4443 (WP Business Directory): `UNION SELECT 0x504f437a...` -> OUTFILE
  `/var/www/html/poc.txt` -> fetch. The `sleep 2` present is a shell wait between
  write and fetch; the detector correctly declined to scale it.

Both already carried the canary IN the assertion. `expect_regex` would have given
a clean "canary absent -> not exploited". Recorded in `Docs/OPEN_ITEMS.md`.

**3 were honest negatives** — the exploit reached the target and did not work:
- CVE-2024-22120 (Zabbix) — `latency_too_fast`, 5 target runs. Real: sid/CSRF.
- CVE-2024-36675 — `all_404`, SSRF with a correct canary assertion; wrong endpoint.
- CVE-2024-5314 (Dolibarr) — `regex_missed`, correct canary assertion, 6 runs.

**1 was the new pre-auth gate** — CVE-2024-32964 stopped at `missing: ["auth"]`
after a deep-recon pass, 0 iterations. By design: 0 of 21 archived PR:L/H attempts
without auth have ever verified, so this converts 7 wasted iterations into an
honest "I need credentials". It is only a win if deep recon can eventually SOLVE
auth rather than report it blocked.

## What this run says about the cap

The cap of 7 cost nothing. The single success came on iteration 1, and no CVE that
reached `max_iters` was trending toward a pass — the three that burned all 7
(51483, 36412, 4443, 5314) were a guard deadlock and two drifted assertions.
