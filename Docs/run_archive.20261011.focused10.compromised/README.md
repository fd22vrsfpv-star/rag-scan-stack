# focused-10, 2026-10-11 13:25-18:23 — COMPROMISED, do not use as a baseline

Three independent faults, none of which this run could have measured around:

1. **kali-listener had no route to targets** (fixed 2867d10). It executes the
   PoC commands and declared only `agents_net`; targets live on `test_net`, so
   every attack curl blackholed ~135s. 5 of 10 CVEs ended
   `stop=target_unreachable` against hosts that were up and serving.
2. **rag-api was recreated mid-run at 17:10**, reverting the five P1 fixes
   (they had been `docker cp`'d into the running container; `api.py` is baked
   into the image, so a recreate discards them). CVE-2024-36675 (17:11-17:46)
   and CVE-2024-4443 (17:47-18:23) therefore ran WITHOUT the fixes.
3. **CVE-2024-32964 was killed** by that same recreate — recorded as
   `verified=? stop=` with an empty verdict.

Net: CVEs 1-7 had the fixes but mostly could not reach their targets; CVE 8 was
killed; CVEs 9-10 ran on reverted code. Nothing here measures the P1 fixes.
