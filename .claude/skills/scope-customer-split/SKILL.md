---
name: scope-customer-split
description: Analyze an engagement's scope, classify each host as owned / customer / review, and move customer-hosted sites out to `customer_scope` (retained + deny-listed) before an external pentest. Use when a scope includes shared-hosting platforms (e.g. Blackbaud/Convio, Squarespace, Shopify, a SaaS's per-tenant subdomains) whose subdomains belong to different CUSTOMERS, not the target org.
---

# Scope customer-split

Separate **customer-hosted** sites from an engagement's **testable** scope. Customer
sites (a nonprofit's tenant on the target's SaaS, a customer's own domain CNAME'd to
the target) must NOT be hit by an external pentest — testing them attacks a third
party and their data. This skill classifies every scope host, then moves the customer
set to `customer_scope`: retained and UI-visible, removed from the scanned scope,
added to the global `not_in_scope` deny-list, and skipped by the recon agent.

## Guiding principles (do not skip)

- **Err toward exclusion.** Include a host in the test scope only with POSITIVE
  evidence the target org OWNS it. Anything unproven goes to REVIEW for a human, not
  into scope and not auto-moved.
- **Per-host, never a domain wildcard.** Customers share the target's domains (e.g.
  `<customer>.convio.net`), so a `*.convio.net` rule would wrongly exclude the
  target's OWN platform infra. Classify and move host-by-host. (The move endpoint is
  per-host by design for exactly this reason.)
- **Dry-run first.** Always present the classification and get explicit confirmation
  before moving anything. The move is reversible (targets can be restored) but a wrong
  move hides a real target or a wrong keep tests a customer.
- **Typosquats are not ownership.** Lookalike apexes (`b1ackbaud.com`, `blackboud.com`)
  are REVIEW, never auto-include — they may be malicious or unrelated and are out of
  scope unless the operator confirms the org registered them defensively.

## Inputs

- **engagement**: name or id (e.g. `redteam3`).
- Optional config (derive sensible defaults from the data, confirm with the operator):
  - `owned_apex_tokens`: substrings that mark an apex as target-owned
    (e.g. for Blackbaud: `blackbaud`, `convio`, `luminate`, `targetanalysis`,
    `friendsaskingfriends`, `netcommunity`, `campblackbaud`).
  - `shared_hosting_domains`: apexes the org owns but whose SUBDOMAINS are per-customer
    tenants (e.g. `convio.net`). The apex + infra subdomains are owned; tenant
    subdomains are customer sites.
  - `brand_tokens`: the org's OTHER product/brand names that live on SEPARATE apexes
    (for Blackbaud: `etapestry`, `kintera`, `raisersedge`, `yourcause`, `npengage`,
    `netcommunity`, `targetamerica`, `friendsasking`, `justgiving`, `luminate`). Without
    this an owned brand apex looks "unrecognised" and is wrongly flagged customer — the
    REVIEW step MUST check brand_tokens before dropping an apex. Also watch for
    TYPOSQUATS (edit-distance / IDN `xn--` lookalikes of the org name) and the org's
    exec PERSONAL domains — both are EXCLUDE, never test scope.
  - `infra_tokens`: subdomain labels that mark a shared-hosting subdomain as the org's
    OWN infra, not a tenant (e.g. `cluster`, `management`, `mgmt`, `admin`, `pub`,
    `api`, `mail`, `smtp`, `ns`, `vpn`, `gateway`, `lb`, `node`, `secure`, `www`,
    `cdn`, `origin`, `static`, `ops`, `monitor`).

## Steps

1. **Resolve the engagement id.**
   `docker exec -i rag-api python3 -c "..."` →
   `SELECT id FROM engagements WHERE name = '<engagement>'`.

2. **Load the scope.** `SELECT DISTINCT target FROM scope_targets WHERE engagement_id=%s
   AND name NOT IN ('customer_scope','excluded','not_in_scope')` (skip the reserved
   buckets so re-runs are idempotent).

3. **Pull liveness signals** (for prioritisation + to sanity-check the split):
   resolved hostnames from `assets` (`engagement_id=%s`), and live web hosts from
   `web_findings` joined to `assets`. A host with live web is a real target; a host
   that never resolved is low priority regardless of class.

4. **Classify each host** into `INCLUDE` / `CUSTOMER` / `REVIEW`:
   - apex = last two labels (use a fuller PSL split for multi-part TLDs if present).
   - **CUSTOMER** — a `shared_hosting_domains` subdomain whose first label (and no
     label) is an `infra_token` → a per-tenant subdomain; also any host on a
     customer-owned apex. Reason: "shared-hosting per-customer tenant" / "customer
     domain".
   - **INCLUDE** — apex contains an `owned_apex_tokens` substring; OR the shared-hosting
     apex itself; OR a shared-hosting subdomain that matches an `infra_token`. Reason:
     "org-owned apex" / "shared-hosting platform infra".
   - **REVIEW** — anything else: unrecognised apexes, possible typosquats, campaign
     domains. Never auto-include or auto-move. Flag typosquats explicitly.
   - **Owned-domain tenants** — the org's OWN apex can still host per-CUSTOMER
     instances: numbered/product tenant subdomains like `altru<N>.sky.<owned>`,
     `s<N>a<N><app>.renxt.<owned>`, `<product><digits>.<owned>`. Apex-match alone marks
     these INCLUDE, but each `<N>` is a different customer's instance — classify them
     CUSTOMER (or REVIEW if it's an org-operated multi-tenant SHARD rather than a
     single customer's site; that is an operator call). Watch for false positives:
     mail/PTR hosts (`o778.ptr4192...`) match a digit-pattern but are infra, not tenants.

5. **Present the dry-run**: counts for INCLUDE / CUSTOMER / REVIEW; how many of each
   are live/resolved; the FULL REVIEW list (with typosquats called out); and a sample
   of CUSTOMER and INCLUDE. Ask the operator to confirm the CUSTOMER set to move, and
   to adjudicate REVIEW (they may reclassify some REVIEW → CUSTOMER or INCLUDE).

6. **Apply** (only after confirmation). Move the confirmed CUSTOMER hosts in batches
   of ≤500 to keep each request fast:
   ```
   docker exec rag-api sh -lc 'curl -s -k -X POST \
     https://localhost:8000/engagements/<EID>/scope/mark-customer-sites \
     -H "x-api-key: $API_KEY" -H "Content-Type: application/json" \
     -d "{\"targets\": [ ...batch... ], \"scope_name\": \"customer_scope\"}"'
   ```
   The endpoint (per host, in bulk SQL): removes them from the scanned scope, files
   them under `customer_scope`, adds them to the global `not_in_scope` deny-list,
   resolves matching customer-site follow-ups, tags the assets `customer-site`, and
   emits a `customer_scope_excluded` webhook. The recon agent then skips them.

7. **Verify**: re-count `scope_targets` by `name` for the engagement — the scanned
   scope (e.g. `blackbaud`) should have dropped by the moved count and `customer_scope`
   risen by it; confirm a spot-check host is now in `not_in_scope`. Report the final
   testable count and the REVIEW items still awaiting a human decision.

## Output

- A short table: INCLUDE (testable) / CUSTOMER (moved) / REVIEW (pending), with live
  counts.
- The list of REVIEW items needing adjudication (typosquats highlighted).
- The final testable target count for the external pentest.

## Notes

- Restore a wrongly-moved host with `POST /scope/restore` / delete its `not_in_scope`
  row, then re-add to the scanned scope — tell the operator this is reversible.
- This skill decides WHICH hosts are customers; the move mechanics live in the
  platform (`mark-customer-sites`). Do not re-implement the move.
