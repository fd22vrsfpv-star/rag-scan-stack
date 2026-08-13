# Knowledge Base Guide

How to get knowledge into the stack, how the AI uses it, and how to turn a lab
walkthrough into reusable guidance.

---

## The four layers

They stack. A general playbook and a rule for one port both apply to the same
target; nothing shadows anything else.

| Layer | Holds | Lives in | Scope |
|---|---|---|---|
| **Methodology corpus** | How to approach a class of target | `knowledge/playbooks/*.md` | Retrieved generally |
| **Service tooling** | Which tools/MSF modules/nuclei tags fit a service | `knowledge/service_tools.yaml` + `kb_service_overrides` | Per service |
| **Operator prompts** | What to *do* when something is found | `service_prompts` table | service / port / port+service / technology |
| **Training documents** | Reference material to retrieve | `exploit_chunks` (`source_repo='training'`) | service / port / technology |

The important distinction: **service tooling picks the tool, operator prompts
change the plan.** "Run snmpwalk on SNMP" is tooling. "On this engagement, SNMP
is the fastest route to the internal topology — pull the ARP cache before
anything else" is a prompt.

---

## Layer 1 — Methodology corpus

Bulk import. Drop markdown in and ingest the directory:

```bash
cp my-notes/*.md knowledge/playbooks/
./scripts/import-knowledge.sh --playbooks
```

Or from the dashboard: **Knowledge Base → Re-ingest playbooks**.

Chunking is heading-aware and never splits a fenced code block; the section
header travels with the chunk so retrieved context stays readable. Ingest is an
atomic replace per file, so editing a playbook and re-running updates it rather
than duplicating chunks.

## Layer 2 — Service tooling

- **Shipped defaults:** `knowledge/service_tools.yaml` (read-only mount —
  restart `scan-recommender` after editing)
- **Per-install overrides:** Knowledge Base page, or `PUT /kb/services/{name}`

## Layer 3 — Operator prompts

The **Service Prompts** page, or bulk via the importer. Four selector types:

| selector_type | Requires | Fires when |
|---|---|---|
| `port_service` | service + port | that service on that exact port |
| `tech` | tech | httpx/whatweb detected that technology |
| `port` | port | anything on that port, even unfingerprinted |
| `service` | service | that service on any port |

**Precedence: `port_service` → `tech` → `port` → `service`.** Specificity always
beats `priority`; priority only breaks ties inside one tier. All matches are
injected, most specific first.

With no matching rule the injected block is empty and the AI's prompt is
byte-identical to its stock form — knowledge is strictly additive.

## Layer 4 — Training documents

Reference material that should be retrievable without steering tool choice.
Either attach `training_notes` to a prompt rule (indexed automatically on save)
or ingest standalone via the `service_docs:` section of a seed file.

---

## Bulk import

```bash
./scripts/import-knowledge.sh --file knowledge/seed_prompts.example.yaml --dry-run   # preview
./scripts/import-knowledge.sh --file knowledge/seed_prompts.example.yaml             # apply
./scripts/import-knowledge.sh --playbooks                                            # corpus only
```

Create-or-update on the selector tuple, so re-running is safe and is the normal
way to edit a seeded ruleset — change the file, re-run. `--dry-run` prints what
would change without writing. See `knowledge/seed_prompts.example.yaml` for the
format; it is a complete worked SNMP example.

Targets `scan-recommender` (`:8013`) directly so seeding works with the dashboard
down. Use `--api https://localhost:3002/api` to go through the BFF instead.

---

## Turning a lab walkthrough into knowledge

A walkthrough is a narrative about **one box**. The knowledge base wants
**technique that generalises**. The conversion is a filter, and it is worth doing
by hand the first few times because the judgement is the valuable part.

### 1. Split the walkthrough by what was *found*, not by what was *done*

Walkthroughs read chronologically: scanned, found 161, ran snmpwalk, found
creds, pivoted. Re-index it by discovery — each open port or detected
technology is a candidate rule.

### 2. For each discovery, ask what you'd want the AI to know *next time*

Keep it if it would apply to a different host running the same thing. Drop
anything box-specific.

| From the walkthrough | Keep? | Why |
|---|---|---|
| "SNMP was open on 161" | ✗ | A finding, not knowledge |
| "Community string was `public`" | ✓ generalised | → "try default community strings first" |
| "The flag was in /home/user" | ✗ | Box-specific |
| "snmpwalk on 1.3.6.1.2.1.4.22.1.2 gave the ARP cache, which revealed the internal subnet" | ✓ | Reusable technique with a reason |
| "Version 2.1.3 of the app was vulnerable" | ✓ as a `tech` rule | Applies wherever that stack appears |

### 3. Choose the layer by how specific the lesson is

- Sequenced approach for a whole class of target → **playbook markdown**
- "When you see X, do Y first" → **prompt rule**
- Command syntax, OID lists, default credential tables → **training notes** on
  that rule

### 4. Pick the narrowest selector that is still true

If the lesson only holds on the standard port, use `port_service`. If it holds
wherever the service appears, use `service` — otherwise it silently won't fire
on a non-standard port. When unsure, write both, as the SNMP example does: a
narrow rule with the detail and a broad one with the principle.

### 5. Write it into a seed file and dry-run it

```bash
$EDITOR knowledge/seed/snmp.yaml
./scripts/import-knowledge.sh --file knowledge/seed/snmp.yaml --dry-run
./scripts/import-knowledge.sh --file knowledge/seed/snmp.yaml
```

Keeping seed files in git makes the knowledge reviewable and diffable, which
matters more than it sounds once several people are adding rules.

### 6. Verify against the resolver, not against your memory of what you wrote

```bash
curl -sk "https://localhost:8013/kb/prompts/resolve?service=snmp&port=161" | jq
```

This runs the same resolution the scan recommender uses, so it shows the real
injected text. The Service Prompts page has the same thing as a Resolve panel.

### 7. Confirm it changed behaviour

Re-run a recommendation against a host with that service and check the output
actually shifted:

```bash
curl -sk "https://localhost:8013/next_scan?ip=<ip>&service=snmp&port=161&use_ollama=true&persist=false" | jq
docker logs scan-recommender --tail 50 | grep "prompt augmented"
```

If the log line is absent, nothing matched — check the selector before blaming
the model.

### Doing it automatically

`scripts/walkthrough-to-seed.sh` runs the steps above through the configured LLM:

```bash
./scripts/walkthrough-to-seed.sh writeups/lab01.md
./scripts/walkthrough-to-seed.sh writeups/lab01.md --focus "Active Directory only"
```

It writes `knowledge/seed/<name>.yaml`, prints what was flagged, and automatically
dry-runs the importer so you see exactly what would land. Applying stays a separate,
explicit command. The same thing is available in the dashboard under **Service Prompts →
Draft rules from a walkthrough**, which shows each proposal with an accept/discard tick.

**It never writes to the database.** Anything that looks box-specific — credentials,
flag values, password hashes, lab IP ranges — is written **commented out** with a
`# !REVIEW <reason>` line. Commented entries are invisible to the importer, so they
cannot reach live scanning unless you deliberately un-comment them.

Flagging rather than deleting is deliberate: the patterns overlap with knowledge worth
keeping. `tomcat:tomcat` trips the credential-pair rule but is a genuine vendor default;
SNMP guidance legitimately names `public` and `private`. You decide which is which.

#### From a URL

```bash
./scripts/url-to-guide.sh https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/
./scripts/url-to-guide.sh https://example.test/guide --depth 1 --max-pages 5
```

Fetches the page, reduces it to markdown, and produces **both** outputs — a seed
YAML of per-service rules and a cleaned playbook for the corpus. The UI equivalent
is the **From a URL** tab in the drafting panel.

Server-side fetching is an SSRF primitive, so it is constrained: http/https only,
the hostname is resolved and **every** returned address checked before connecting,
every redirect hop is re-validated, and the response is size-capped. Private,
loopback and cloud-metadata addresses are refused unless you pass
`--allow-internal`, which exists for deliberate internal sources like a wiki.

Long pages are converted **section by section** and merged. A whole documentation
page in one request causes the model to narrate, exhaust its output budget and
return truncated JSON — which shows up as zero rules. Chunking also improves
quality, since the model considers one service at a time.

#### Coverage — check what it missed

Both converters report which services the document mentions but did **not** become
rules, plus anything the model deliberately skipped and why:

```
COVERAGE: 4/17 KB-known services became rules (24%) — 10 rules total
Also covered, outside the KB's vocabulary: distccd, dvwa, mutillidae, samba
Not covered: dns, https, lpd, phpmyadmin, portmap, smb
```

A thin conversion is otherwise indistinguishable from a thin document. Detection
uses the KB's own vocabulary (97 services + aliases + 17 tech signatures), and
reports the **canonical** name — a guide saying "Samba" shows as `smb`, because
that is the value a rule must carry to fire.

The percentage counts only KB-known services, so rules for things the KB has no
vocabulary for (distccd, mutillidae) are listed separately rather than dragging
the number down.

If services you care about are missing, re-run with `--focus` naming them.

#### The gap pass

The chunk pass asks "find everything", which a local model does unreliably on a long
catalogue. Since the coverage report already knows what was missed, a second pass
re-asks for each missed service **individually** — a focused prompt naming one service
is a task a small model handles far better.

On by default; `--no-gap-pass` skips it, as does unticking **Second pass for missed
services** in the UI panel. Cost scales with the gap, not the document, and is capped
by `WALKTHROUGH_GAP_MAX` (default 15).

In the browser the same report appears above the drafted rules. Note the proxy
timeouts: `dashboard/nginx.conf` gives the two convert routes 1800s/1200s while the
rest of `/api/` stays at 300s. If you raise the BFF timeouts in
`dashboard/bff/routers/kb.py`, raise these too — nginx is in front and must be the
looser of the two, or its generic 504 replaces the BFF's specific message.

```
GAP PASS: re-asked for 15 missed service(s), recovered 5 rule(s)
```

Measured on the Rapid7 guide: a chunk pass that returned only 2 rules (one chunk
response was unparsable) was lifted to 7 by the gap pass. It is a **floor under
first-pass variance** — the same input and settings produced 10 rules on one run and
2 on the next, which is the real problem with a local model.

It is not a cure. Focused calls are more reliable, not reliable: mysql, smb, ftp and
others still came back empty. Two knobs if you need more: `WALKTHROUGH_GAP_MAX` and
`WALKTHROUGH_CHUNK_CHARS` (6000; smaller may help, unmeasured).

Roughly 15 extra calls costs ~15 minutes on a local `gemma4:31b`.

#### Extraction quality depends on the model

The guiding prompt now adapts: a **narrative walkthrough** of one box yields a few
well-judged rules, while an **enumerative reference** covering many services should
yield roughly one rule per service. A small local model still under-extracts on a
long catalogue — the Rapid7 Metasploitable guide covers ~20 services and a local
`gemma4:31b` produces 10–11. A hosted `LLM_BACKEND` does better. The coverage
report exists so that gap is visible rather than assumed away.

#### A runbook instead of rules

`knowledge/prompts/runbook_from_guide.md` is a copy-paste prompt for Claude that
turns the same source into a **runbook you follow** — ordered per-service steps
with reasons, stop conditions and evidence to capture — rather than rules the
scanner applies. Use the converter for rules, that prompt for prose.

#### Steering what it extracts

Three layers, most specific last:

1. `knowledge/prompts/walkthrough_to_seed.md` — the shipped default
2. A saved override — the **Guiding prompt** editor in the UI panel, or
   `PUT /kb/walkthrough-prompt`. Saving an empty string reverts to the default.
3. `--focus "..."` — one-off steering for a single run

It is also shown your existing rules for services named in the walkthrough, so it
extends them instead of proposing near-duplicates that would overwrite on import.

#### Still read the output

The model drafts; it does not decide. Check each rule is technique rather than trivia,
that the selector is the narrowest one still true, and that nothing box-specific is
active. A plausible-sounding fabrication in a rule is worse than no rule, because it
will steer real scans with apparent authority.

---

## The feedback loop

| Signal | Where | Effect |
|---|---|---|
| Wrong tool picked | `POST /kb/feedback` | suppress / add-tool / add-overlap, applied within 20s |
| Bad retrieval | thumbs up/down on Knowledge Base | rows in `rag_feedback` |
| Export corpus | `POST /rag/training/export` | JSONL in `./datasets` for `grpo_trainer` |
| Retrieval quality | `POST /rag/eval/run` | nDCG / MRR / recall over a query set |

---

## Reference

| Endpoint | Purpose |
|---|---|
| `GET /kb/prompts` · `POST` · `PUT /{id}` · `DELETE /{id}` | Prompt rule CRUD |
| `GET /kb/prompts/resolve?service=&port=&tech=` | Exactly what would be injected |
| `GET /kb/web-guidance?ip=&service=&port=&tech=` | Guidance + suggested nuclei tags for a web target |
| `POST /rag/service-docs/ingest` · `GET /rag/service-docs` · `DELETE /{id}` | Training documents |
| `POST /rag/playbooks/ingest` | Re-ingest the markdown corpus |
| `POST /kb/walkthrough/convert` | Draft rules from a walkthrough (returns proposals, never writes) |
| `GET\|PUT /kb/walkthrough-prompt` | The guiding prompt; PUT an empty string to revert |
| `GET /kb/services` · `PUT /kb/services/{name}` | Service tooling overrides |

All are proxied through the BFF under `/api/…` and available directly on
`scan-recommender:8013`.

### Related

- `knowledge/seed_prompts.example.yaml` — worked SNMP example
- `knowledge/port_profiles.yaml` / `knowledge/web_profiles.yaml` — scan scope, not knowledge
- `Docs/CLAUDE.md` — project build rules
