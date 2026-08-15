#!/usr/bin/env bash
#
# inventory-node.sh — ask a provisioned node what it can actually run, and feed
# that to the recommendation validator.
#
# The automated catalog refresh only sees the local scanner containers. Scans
# execute on remote/provisioned nodes whose toolsets differ, so a validator built
# only from local containers will reject TTPs that the node could run perfectly
# well. This is the manual pass that fixes that: it interrogates a real node over
# the existing SSH exec path and merges the result into
# knowledge/tool_catalogs.local.json, which refresh-tool-catalogs.sh treats as
# authoritative and never overwrites.
#
# What it collects:
#   binaries      — every executable on PATH, plus /usr/local/bin and the
#                   provisioning venv (which is where pip-installed CLI tools land)
#   nmap_scripts  — the .nse scripts actually present on THAT node
#   msf_modules   — module paths present, in msfconsole syntax
#
# Usage:
#   ./scripts/inventory-node.sh <node_id>
#   ./scripts/inventory-node.sh <node_id> --dry-run
#   ./scripts/inventory-node.sh <node_id> --common     # also report common Kali
#                                                      # tools this node LACKS
#   ./scripts/inventory-node.sh <node_id> --api https://localhost:3002/api
#
# Prereqs: curl, jq, python3. The node must be online and SSH-reachable.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

API="${DASHBOARD_API:-https://localhost:3002/api}"
NODE_ID=""
DRY_RUN=false
CHECK_COMMON=false
SUPP="knowledge/tool_catalogs.local.json"

# Commonly-used Kali tools that are NOT in the provisioning list. The PATH sweep
# already records whatever is present; this list exists to report what is
# ABSENT, which a sweep can never tell you. A recommendation naming something
# from here that the node lacks will fail at dispatch, so knowing the gap up
# front is the point.
_COMMON_KALI_TOOLS="
arp-scan arping bettercap bloodhound-python cadaver cewl chisel cme dig dirb
dnsenum dnsrecon dsniff enum4linux ettercap exiftool fping ftp gobuster hashcat
hping3 hydra ike-scan impacket-secretsdump impacket-smbclient john ldapsearch
masscan medusa mitm6 msfvenom nbtscan ncat ncrack netcat netdiscover nikto nmap
nping onesixtyone openssl proxychains4 psql rdesktop redis-cli responder
rpcclient rpcinfo showmount smbclient smbmap snmpwalk socat sqlmap sslscan
sslyze ssh-audit swaks tcpdump telnet tshark wafw00f wfuzz whatweb whois
wireshark wpscan xfreerdp
"

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --api)        API="${2:-}"; shift 2 ;;
        --dry-run|-n) DRY_RUN=true; shift ;;
        --common)     CHECK_COMMON=true; shift ;;
        --out)        SUPP="${2:-}"; shift 2 ;;
        --help|-h)    usage 0 ;;
        -*) echo "Unknown option: $1" >&2; usage 1 ;;
        *)  NODE_ID="$1"; shift ;;
    esac
done

for cmd in curl jq python3; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "ERROR: '$cmd' is required." >&2; exit 1; }
done
[[ -n "$NODE_ID" ]] || { echo "ERROR: no node id given." >&2; usage 1; }

# Run a command on the node through the existing SSH exec route.
node_exec() {
    local script="$1"
    jq -n --arg c "$script" '{command:$c}' \
      | curl -sk --max-time 180 -X POST "${API}/nodes/${NODE_ID}/ssh/exec" \
             -H 'Content-Type: application/json' -d @- \
      | jq -r '.stdout // ""'
}

echo "Interrogating node ${NODE_ID}…"

# Sanity check first: a dead node returns empty output for everything, and
# writing an empty inventory would tell the validator the node has NO tools.
probe="$(node_exec 'echo NODE_OK; id -un')"
if ! grep -q NODE_OK <<<"$probe"; then
    echo "ERROR: node did not respond over SSH — is it online?" >&2
    echo "  (an empty inventory would wrongly narrow the validator, so refusing)" >&2
    exit 1
fi
echo "  reachable as: $(echo "$probe" | tail -1)"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# `IFS=:; for d in $PATH` is a bashism: zsh does NOT word-split unquoted
# parameters, and these nodes run zsh, so $PATH stayed a single string and the
# inventory came back with only the literal directories — 33 entries for a box
# with 139 tools. Splitting with tr works in both shells.
node_exec '{ echo "$PATH" | tr ":" "\n"; echo /usr/local/bin; echo /opt/pentest-venv/bin; } \
           | while read -r d; do [ -d "$d" ] && find "$d" -maxdepth 1 -type f -perm -u+x 2>/dev/null | sed "s|.*/||"; done' \
    | sed '/^$/d' | sort -u > "$TMP/binaries"
printf "  %-14s %5d\n" binaries "$(wc -l < "$TMP/binaries" | tr -d ' ')"

node_exec 'ls /usr/share/nmap/scripts/*.nse 2>/dev/null | xargs -n1 basename 2>/dev/null | sed "s/\.nse$//"' \
    | sed '/^$/d' | sort -u > "$TMP/nmap_scripts"
printf "  %-14s %5d\n" nmap_scripts "$(wc -l < "$TMP/nmap_scripts" | tr -d ' ')"

# msfconsole syntax (exploit/…), not the on-disk directory name (exploits/…).
node_exec 'for d in /usr/share/metasploit-framework/modules /opt/metasploit-framework/modules /usr/src/metasploit-framework/modules; do
             [ -d "$d" ] && find "$d" -name "*.rb" 2>/dev/null | sed "s|.*/modules/||; s|\.rb$||"; done' \
    | sed '/^$/d' \
    | sed 's|^exploits/|exploit/|; s|^payloads/|payload/|; s|^posts/|post/|; s|^encoders/|encoder/|; s|^nops/|nop/|' \
    | sort -u > "$TMP/msf_modules"
printf "  %-14s %5d\n" msf_modules "$(wc -l < "$TMP/msf_modules" | tr -d ' ')"

if [[ "$CHECK_COMMON" == true ]]; then
    echo ""
    echo "Common Kali tools — presence on this node:"
    # Ask the node once rather than per-tool: one round trip, and `command -v`
    # is the same test the provisioner's `check` uses.
    list="$(echo $_COMMON_KALI_TOOLS | tr -s ' ' ' ')"
    res="$(node_exec "for t in ${list}; do if command -v \"\$t\" >/dev/null 2>&1; then echo \"+ \$t\"; else echo \"- \$t\"; fi; done")"
    present="$(echo "$res" | grep -c '^+' || true)"
    missing="$(echo "$res"  | grep -c '^-' || true)"
    echo "  present: ${present}    missing: ${missing}"
    echo "$res" | grep '^+' | sed 's/^+ //' >> "$TMP/binaries" || true
    sort -u -o "$TMP/binaries" "$TMP/binaries"
    echo ""
    echo "  MISSING (a recommendation naming these will fail at dispatch):"
    echo "$res" | grep '^-' | sed 's/^- /    /' | paste -sd' ' - | fold -s -w 96 | sed 's/^/  /'
fi

if [[ "$DRY_RUN" == true ]]; then
    echo ""
    echo "--- dry run: would merge into $SUPP ---"
    for f in binaries nmap_scripts msf_modules; do
        echo "  $f: $(head -8 "$TMP/$f" | tr '\n' ' ')…"
    done
    exit 0
fi

python3 - "$TMP" "$SUPP" "$NODE_ID" <<'PY'
import json, os, sys, datetime
tmp, supp, node_id = sys.argv[1], sys.argv[2], sys.argv[3]

def load(name):
    p = os.path.join(tmp, name)
    return sorted({l.strip() for l in open(p)} - {""}) if os.path.exists(p) else []

existing = {}
if os.path.exists(supp):
    try:
        existing = json.load(open(supp))
    except Exception as e:
        print(f"  WARNING: {supp} unreadable ({e}) — starting fresh")

added = 0
for key in ("binaries", "nmap_scripts", "msf_modules"):
    have = set(existing.get(key) or [])
    new = set(load(key))
    if not new:
        continue                      # nothing collected: leave the key untouched
    merged = sorted(have | new)
    added += len(merged) - len(have)
    existing[key] = merged

note = existing.setdefault("_comment", [])
if isinstance(note, list):
    stamp = (f"Inventoried from node {node_id} on "
             f"{datetime.date.today().isoformat()} by scripts/inventory-node.sh")
    note = [l for l in note if not l.startswith("Inventoried from node")]
    note.append(stamp)
    existing["_comment"] = note

with open(supp, "w") as fh:
    json.dump(existing, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"\n  merged {added} new entr(ies) into {supp}")
PY

cat <<EOF

Next:
  1. Rebuild the merged catalog:
       ./scripts/refresh-tool-catalogs.sh
  2. Restart the recommender so it reloads:
       docker compose restart scan-recommender

The node's tools are now authoritative for the validator: a recommendation using
something only that node has will no longer be rejected.
EOF
