# Tool → Service Routing

Which container runs which tool, and where a scan recommendation gets dispatched.

## Why this exists

`scan_recommendations` names a **tool** (`scanner` column). Dispatch has to turn
that into a **service endpoint**. The map lives in
`dashboard/bff/routers/assets.py` → `SCANNER_URLS`, and a tool with no entry falls
through to the Kali container, which tries `apt-get install <scanner>`.

That fallback is wrong whenever the stack already runs a service for the tool.
`katana`, `naabu` and `tlsx` were skipped as *"missing on kali"* while `pd-runner`
was serving `/jobs/katana`, `/jobs/naabu` and `/jobs/tlsx` with the binaries
installed. **Check this table before adding a tool to `MANUAL_TOOLS` or leaving it
unmapped.**

## Inventory

Taken from each service's actual `@app.post("/jobs/...")` routes.

| Service | Tools it owns |
|---|---|
| **nmap_scanner** | `nmap`, `masscan` — via `masscan-then-nmap`, `masscan-only`, `full-scan`, `nmap-udp`, `smb-vuln-scan`, `credential-check` |
| **nuclei-runner** | `nuclei` |
| **web-scanner** | `gobuster`, `nikto`, `content-recon`, `web-scan`, `pipeline-scan` |
| **pd-runner** | `httpx`, `naabu`, `katana`, `tlsx`, `whatweb`, `ffuf` |
| **osint-runner** | `subfinder`, `dnsx`, `alterx`, `vulnx`, `amass`, `gau`, `waybackurls`, `wafw00f`, `gowitness`, `whois`, `trufflehog`, `subzy`, `crtsh`, `shuffledns`, `golinkfinder`, `dns-enum`, `service-enum`, `subdomain-takeover`, `email-enum`, `censys`, `uncover`, `asnmap`, `cloudlist`, `mapcidr`, `chaos`, `passive-recon`, `recon-pipeline`, `greyhatwarfare` |
| **brutus-runner** | `hydra`, `medusa`, `ncrack` — all via `/jobs/brutus` |
| **exploit-runner** | `metasploit` — queued into the approval workflow, never auto-exploited |
| **kali-listener** | Genuinely CLI-only tools. The **fallback**, not the default. |

## Adding a tool

Both steps are required:

1. An entry in `SCANNER_URLS` mapping the scanner name to the service URL.
2. A payload branch in `dispatch_rec()` building that service's request body.

A URL without a payload branch yields `"No automated handler for '<scanner>'"`.

When a tool is served by a container but not yet mapped, dispatch now says so
explicitly rather than reporting it as missing from Kali:

```
'katana' is served by pd-runner /jobs/katana but is not in SCANNER_URLS —
route it there rather than installing it on kali
```

## Deliberately on Kali, not a service

Genuinely interactive or one-shot CLI tools with no service wrapper:
`curl`, `telnet`, `netcat`, `vncviewer`, `lftp`, `ftp`, `psql`, `mysql`,
`rpcinfo`, `showmount`, `smtp-user-enum`, `ssh-audit`, `swaks`, `rmg`.

### Installed ≠ runnable: there are TWO gates

A tool reaches execution on Kali only if it clears **both**:

1. **Installed** — present in `kali_listener/Dockerfile`.
2. **Allowlisted** — present in the effective allowlist that
   `/tools/execute` checks (`get_allowed_tools()`: the node-manager tool
   registry, falling back to `_FALLBACK_ALLOWED_TOOLS` in
   `kali_listener/listener_service.py`, always minus Metasploit).

These are easy to conflate and this document previously did. `irssi` is
installed by the Dockerfile but is **not** allowlisted, so every dispatch
returned `HTTP 400: Tool 'irssi' is not in allowed list`. Being in the list
above means "no service wrapper exists", **not** "it will run".

Check the live list rather than assuming:

```bash
docker exec kali-listener python3 -c "
import json,urllib.request,ssl
d=json.load(urllib.request.urlopen('https://127.0.0.1:8019/tools/allowed',
    context=ssl._create_unverified_context(),timeout=10))
t=d.get('tools') or []
print(len(t),'allowed'); print(sorted(t))"
```

### Tool-name aliases

The recommender's name for a tool and the registry's name are not always the
same, which produced a rejection indistinguishable from "not installed".
`TOOL_ALIASES` in `listener_service.py` canonicalises the name **only when the
alias itself is not allowlisted**:

| Recommender emits | Canonical | Why |
|---|---|---|
| `nc` | `netcat` | KB emits `nc`; registry lists `netcat`; `/usr/bin/nc` and `/usr/bin/netcat` are both present (netcat-traditional) |

This cannot widen the allowlist — the canonical name must still be allowed on
its own merits, so an alias for a disallowed tool is still rejected. Metasploit
has no alias and stays reachable only through the Exploit Manager approval
queue.

**Before adding an alias, verify both sides**: that the alias is a name the
recommender actually emits, and that the canonical name is both allowlisted and
present as a binary in the image. `ncat` and `cme` were considered and rejected
— neither binary exists here, so aliasing them would swap a clear "not in
allowed list" rejection for a confusing exec failure.

### Package names

Tools are installed in `kali_listener/Dockerfile`. Note the package name often
differs from the tool name — the runtime auto-installer apt-installs the scanner
name verbatim and fails for exactly that reason:

| Tool | Kali package |
|---|---|
| `avahi-browse` | `avahi-utils` |
| `snmp-check` | `snmpcheck` |
| `tftp` | `tftp-hpa` |
| `vncviewer` | `tigervnc-viewer` |
| `ntpq`, `ntpdate` | `ntpsec`, `ntpsec-ntpdate` |
| `xspy`, `xwd` | `x11-apps`, `x11-utils` |

## Not available anywhere

| Tool | Why |
|---|---|
| `metasploit` (as a Kali install) | The stack runs a dedicated `metasploit` container with msfrpcd. Recommendations need **routing** to `exploit-runner`, not a ~2 GB second copy inside Kali. |
| `katana`, `rmg` (as Kali packages) | Not in the Kali repos — verified with `apt-cache policy`. `katana` is served by pd-runner instead; `rmg` would need a vendored upstream download. |
| `irssi` | Installed, but not allowlisted. An interactive IRC client is arguably manual-only by nature; it currently routes to a manual follow-up. Allowlisting it is an operator decision, not an oversight. |

## What happens to a tool that routes nowhere

Dispatch does not fail silently. An unroutable recommendation:

1. returns `status="failed"` with the reason in `detail`;
2. gets a **manual follow-up filed automatically**, carrying a runnable command
   wired to the real target (`Manual step: <tool>`, deduplicated — a second
   failure for the same tool reports `created: false` because the follow-up
   already exists);
3. is retired as `status='failed'` by the recon agent so it stops consuming the
   dispatch budget — but **only if the failure is permanent**. See
   [RECON_AGENT.md](RECON_AGENT.md#failure-handling-permanent-vs-transient).

So a genuinely manual tool degrades into a documented manual step rather than an
invisible gap. When you see the same `[permanent]` failure recur, the fix
belongs in this file — either a `SCANNER_URLS` entry, an alias, or an explicit
decision to leave it manual.
