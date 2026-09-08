# Web scan tuning — profiles, stages, ZAP controls, proxy, wordlists

Operator reference for everything that shapes a web scan. Written 2026-09-08;
line references are to the tree at that date and are worth re-checking rather
than trusting.

Companion documents: `Docs/AI_SCAN_WALKTHROUGH.md` (the end-to-end trace),
`Docs/CHANGES_MADE.md` (why each of these exists, with the measurements).

---

## 1. Profiles — the main dial

One choice sets stages, wordlist, depth and severity together, so they cannot
drift apart. Defined in `knowledge/web_profiles.yaml`, resolved once at the BFF
edge (`dashboard/bff/services/web_profiles.py`).

| Profile | Stages | Wordlist | Paths | Depth | Nuclei severity |
|---|---|---|---|---|---|
| `quick` | wafw00f, katana, nuclei | common | 25 | 1 | high,critical |
| `standard` *(default)* | + playwright, gobuster | medium | 100 | 3 | medium+ |
| `deep` | **all 7, incl. ZAP** | big | 500 | 5 | info+ |
| `api` | katana, nuclei | api | 200 | 4 | medium+ (`api,exposure,misconfig`) |
| `passive-web` | wafw00f, katana | common | 10 | 1 | — |
| `custom` | sentinel: your form fields verbatim | | | | |

**ZAP only runs under `deep`.** A profile fills only keys you left unset, so
anything you type explicitly wins.

## 2. Stages

`wafw00f` → `katana` → `playwright` → `gobuster` → `nikto` → `nuclei` → `zap`

Two routes spell the gating oppositely; the BFF sets both from one stage list:

- `POST /jobs/pipeline-scan` — `skip_*` (opt-out). The only route that takes **auth**.
- `POST /jobs/web-scan` — `do_gobuster` / `do_playwright` / `do_katana` / `do_zap` (opt-in).

## 3. Per-scan fields

| Field | Notes |
|---|---|
| `target_url` / `target_urls[]` | |
| `wordlist` | alias or absolute path under `/opt/seclists` — see §7 |
| `max_paths_to_visit` / `limit`, `crawl_depth` | |
| `proxy` | SOCKS egress — see §6 |
| `auth` | `ScanAuth`, pipeline only — see §5 |
| `zap_tuning` | `ZapTuning`, see §4 |

---

## 4. ZAP controls

Every `zap_tuning` field defaults to `None`, meaning "use the env default", so a
caller that passes nothing gets configured behaviour and no scan changes shape
by accident.

### 4.1 Passive scanner

| Field | Env | Default | Effect |
|---|---|---|---|
| `pscan_during_active_scan` | `ZAP_PSCAN_DURING_ACTIVE_SCAN` | `false` | keep passive scanning on during the active scan |
| `pscan_only_in_scope` | `ZAP_PSCAN_ONLY_IN_SCOPE` | `true` | ZAP's own default is `false` — it passive-scans third-party resources the target merely links to |
| `max_alerts_per_rule` | `ZAP_MAX_ALERTS_PER_RULE` | `0` | 0 = unlimited |
| `disable_pscan_rules` | `ZAP_DISABLE_PSCAN_RULES` | `""` | CSV of rule ids |

> **Rule ids are validated against ZAP's registry.** `disableScanners` returns
> `{"Result":"OK"}` for ids it has never heard of, so an unvalidated list is a
> disable that silently does nothing. Unknown ids are reported.

> **Not every passive scanner has a rule id.** An add-on can register a raw
> `PassiveScanner` with no id, which never appears in `pscan/view/scanners` and
> cannot be disabled this way. That is why `wappalyzer` had to be removed
> outright rather than switched off — see §8.

`apply_zap_tuning()` — `web_scanner/web_scan.py:1235`.
`pscan_paused()` — `:1313`. It restores in a `finally`, because passive scanning
is process-wide state on a long-lived ZAP: restoring only on the happy path
means one failed scan silently costs every passive finding until a restart.

### 4.2 Active scanner bounds

ZAP ships the active scanner **unbounded in all three dimensions that matter**.

| Field | Env | ZAP default | Ours |
|---|---|---|---|
| `thread_per_host` | `ZAP_THREAD_PER_HOST` | 64 | **8** |
| `max_rule_duration_mins` | `ZAP_MAX_RULE_DURATION_MINS` | 0 (unlimited) | **5** |
| `max_scan_duration_mins` | `ZAP_MAX_SCAN_DURATION_MINS` | 0 (unlimited) | **60** |

The rule-duration bound is the **general** one: capping threads fixed the rule
we found, capping per-rule runtime stops whichever rule runs away next.

### 4.3 Per-category passes

`ZAP_ASCAN_SPLIT` (default `true`) runs the active scan as five passes, using
ZAP's own policy categories:

```
Injection → Server Security → Information Gathering → Miscellaneous → Client Browser
```

**Client Browser is last** because it launches a real browser
(`DomXssScanRule` → Firefox via Selenium) and is by far the likeliest to fail.
Each pass banks its findings before the next starts, so a later crash cannot
take earlier results with it. Each pass gets `max_wait / 5`.

> **Budget note.** Splitting changes how the budget is *divided*, not how much
> there is. At the 900s default each category gets 180s. For a large
> application, raise `max_wait`.

`ZAP_ASCAN_SPLIT=false` restores single-pass behaviour.
`ascan_policies_restored()` — `:1381`; `_run_active_pass()` — `:1410`.

> Policy enablement is **server-global**. Leaving a subset enabled silently
> narrows every later scan in that ZAP, so it is restored in a `finally`, and
> falls back to all five when the prior state cannot be read.

### 4.4 Progressive findings

`ZAP_DRAIN_INTERVAL` (default `60`) — findings are stored after the spiders and
every N seconds during the active scan, so a ZAP death costs one interval rather
than the whole run. Idempotent: it calls `parse_zap_alerts(dedupe=True)`, the
same ETL the end-of-scan path uses. `drain_zap_alerts()` — `:914`.

### 4.5 Other ZAP env

```
ZAP_MEM_LIMIT=12g            ZAP_JVM_HEAP=8g
ZAP_SPIDER_MAX_WAIT=300      ZAP_MAX_SPIDER_SEEDS=14
ZAP_SEED_BUDGET=180          ZAP_SEED_TIMEOUT=10
ZAP_API_TIMEOUT=60           ZAP_SESSION_MAX_MESSAGES=20000
```

Installer defaults stay at `6g`/`3g`: raising memory was **measured not to fix**
the growth, and a 12g `mem_limit` on a small host is a worse first experience
than a tuned scan.

### 4.6 Observability

`GET /api/zap/status` reports `reachable`, `version`, `messages`, **`pscan_queue`**,
`pscan_only_in_scope`, `busy`, spider and active-scan progress. `pscan_queue` is
the number that predicts a memory death — the queue is unbounded and holds whole
HTTP messages, so a depth that climbs and does not come back down is the failure
in progress. A warning is attached above 5000.

---

## 5. Authenticated scanning

`ScanAuth`, pipeline route only. Either `credential_vault_id` (a credential the
platform already holds) **or** inline `username`/`password`, plus `login_url`,
`login_request_data`, and at least one of `logged_in_regex` / `logged_out_regex`.

> The indicator is **required**, not optional. Without it ZAP cannot detect a
> session drop and will happily scan the login page over and over, reporting a
> clean authenticated pass that never was.

Credentials are never logged — only username, type and vault id.
`configure_zap_auth()` — `:1032`.

---

## 6. Proxy / egress

`proxied_scan()` — `web_scanner/web_scan.py:2036`. One implementation for every
route.

- **Fails closed.** The proxy is probed first; if it cannot be established the
  job **fails**. Scanning from this host's own address after the operator asked
  for proxied egress is the one outcome worse than not scanning.
- **Internal traffic bypasses it.** `ALL_PROXY` applies to *every* host, so
  without a `NO_PROXY` the scanner's own calls to playwright-scanner,
  nuclei-runner, rag-api, ZAP and Postgres would be sent to your egress node —
  breaking the stages *and* handing internal hostnames to a remote node in SOCKS
  CONNECT requests. The bypass list is derived from the stack's own service URLs.
- **Global state is restored** on exit; `ALL_PROXY` and ZAP's SOCKS setting
  outlive the job otherwise.

> **A model that does not declare `proxy` silently drops it.** The BFF injects
> `payload["proxy"]` on every scan payload, and Pydantic defaults to
> `extra="ignore"`. A receiving request model without the field discards it with
> no error — the gate passes, the job file records the proxy, and the traffic
> goes out direct. `tests/test_scan_proxy_forwarding.py` pins this for every
> route.

All five web-scanner scan routes now declare it: `web-scan`, `pipeline-scan`,
`gobuster`, `nikto-scan`, `content-recon`.

---

## 7. Wordlists

Aliases: `small`, `medium`, `big`, `common`, `raft-small`, `raft-medium`,
`raft-large`, `quickhits`, `api` — or an absolute path under `/opt/seclists`.

Sizes worth knowing before choosing:

| Alias | Entries |
|---|---|
| `medium` | 220,559 |
| `big` | 1,273,832 |

The gobuster stage adds `-x php,html,txt`, so `big` is roughly **5.1M requests**.
Against an external target through a SOCKS proxy that does not fit the 600s
default — plan the timeout, or use a smaller list.

Two behaviours to know:

- **Bad paths are reported at boot**, not ten minutes into a scan. A stale
  `WORDLIST` cost a full pipeline once: it crawled, rendered and spidered, then
  failed content discovery on a path that had been wrong since startup. The
  fallback is **loud** — the log names what was asked for, what was used, and
  how to fix it. `_resolve_default_wordlist()` — `:92`, `missing_wordlists()` — `:128`.
- **A timeout keeps what was found.** `TimeoutExpired` used to propagate past
  the parse and the DB write, discarding every path already discovered. The
  result now carries `timed_out` and `complete` so a caller cannot mistake a
  truncated run for "there is nothing else here". `gobuster_dir_with_paths()` — `:559`.

---

## 8. Add-ons deliberately not installed

`wappalyzer` ("Technology Detection") — removed. Its passive rule took **40–110
seconds per message** (including 110s on an 8.8 KB JPEG) and drove ZAP to
11.98 GiB. Removing it held the crawl **flat at 2.335 GiB** where it had
previously died.

Coverage cost: none measured. WSTG INFO-08/09 are credited from whatweb/httpx
evidence, not from this rule.

`zap/addons.txt` records the full evidence and the three things that did **not**
work, so the line is not re-added by someone reading it as a missing capability.
`tests/test_zap_addon_policy.py` ratchets it.

---

## 9. Quick diagnosis

| Symptom | Look at |
|---|---|
| ZAP scan produced nothing | was `deep` selected? ZAP runs under no other profile |
| ZAP died mid-scan | `GET /api/zap/status` → `pscan_queue`; check `zap.log` for slow passive rules |
| Findings lost on a crash | `ZAP_DRAIN_INTERVAL` — should be non-zero |
| One category never ran | `Active scan passes:` log line names each pass and marks incomplete ones |
| Later scans find less | policies or passive scanning left disabled — both restore in a `finally`, check for a `FAILED to restore` error |
| Scan egressed from the wrong IP | the receiving model must **declare** `proxy`; see §6 |
| gobuster failed | wordlist path (boot log) or timeout vs. wordlist size (§7) |
| Authenticated scan looks unauthenticated | missing `logged_in_regex` / `logged_out_regex` |
