# OS Changes for Migration

## 2026-05-04 — WSL2 / fresh Linux: surface unzip + jq prereq up front

### Files Changed
- `scripts/setup.sh` — added `unzip` and `jq` to required-deps check.
- `scripts/build-go-tools.sh` — fail-fast prereq guard at top (docker / curl / unzip) with platform-specific install hints, instead of dying mid-build with a cryptic `unzip: command not found`.

### Platforms Affected
- Linux (Ubuntu/Debian) and WSL2 — base WSL Ubuntu images ship without `unzip`. macOS users typically have it via Xcode Command Line Tools but the guard is harmless there.

### Why
A clean WSL2 install hit `unzip: command not found` 1 minute into `build-go-tools.sh` (vulnx download step). The error was silent (script exited 0 from earlier success path) and confusing. Adding the prereq check to setup.sh + an explicit guard in the Go-build script means a new user sees the missing dep in the first 5 seconds and gets the apt/brew command to fix it.

### Old → New
```bash
# build-go-tools.sh: previously failed mid-loop
unzip -qq -o "$vulnxZIP" vulnx -d "$OSINT_OUT/"
# now guarded at the top:
for cmd in docker curl unzip; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: '$cmd' is required but not installed."
        ...
        exit 1
    fi
done
```

## 2026-03-19 — Fix build-go-tools.sh for macOS (Intel + Apple Silicon)

### Files Changed
- `scripts/build-go-tools.sh`

### Platforms Affected
- macOS (Intel x86_64 and Apple Silicon arm64)

### What Changed

| Item | Old (Linux-only) | New (cross-platform) |
|------|-------------------|----------------------|
| `stat` command | `stat -c%s` (GNU/Linux) | `file_size()` helper: tries `-c%s`, falls back to `-f%z` (macOS) |
| vulnx download | Hardcoded `linux_amd64` | Detects target arch, downloads `linux_amd64` or `linux_arm64` |
| Docker build platform | Implicit (host default) | Explicit `--platform linux/amd64` or `linux/arm64` based on host |
| GOARCH/GOOS env | Not set (implicit) | Explicit `GOOS=linux GOARCH=amd64/arm64` passed to container |

### Notes
- All binaries are always Linux — they run inside Docker containers, not on the host
- On Apple Silicon, the script auto-detects arm64 and builds native linux/arm64 binaries (no Rosetta emulation needed)
- The Docker containers need `--platform` to avoid architecture mismatch on macOS Docker Desktop
- katana, ffuf, naabu, httpx, tlsx and all OSINT tools are affected by this fix

## 2026-05-14 — WireGuard Frontend UI Implementation

### Files Changed
- `dashboard/frontend/src/api/nodes.ts`, `dashboard/frontend/src/lib/types.ts`, `dashboard/frontend/src/pages/Nodes.tsx`, `dashboard/frontend/package.json`

### Platforms Affected
- All platforms (cross-platform React/TypeScript frontend)

### Notes
- Pure frontend implementation with no platform-specific requirements
- QR code libraries (`react-qr-code`, `qr-code-styling`) are cross-platform JavaScript
- No OS-specific changes needed — builds identically on Windows, macOS, and Linux
- Frontend compiled to static assets served by nginx container
