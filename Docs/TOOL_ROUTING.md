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
`curl`, `telnet`, `netcat`, `vncviewer`, `irssi`, `lftp`, `ftp`, `psql`, `mysql`,
`rpcinfo`, `showmount`, `smtp-user-enum`, `ssh-audit`, `swaks`, `rmg`.

These are installed in `kali_listener/Dockerfile`. Note the package name often
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
