#!/usr/bin/env bash
#
# refresh-tool-catalogs.sh — snapshot what the scanners can actually run.
#
# Writes knowledge/tool_catalogs.json: the real nmap scripts, nuclei templates
# and metasploit modules present in the running containers. The recommendation
# validator checks LLM- and rule-generated invocations against this, so a
# suggestion that cannot execute is rejected before it is persisted or run.
#
# The motivating case was live: the model recommended `smb Vuln-MS17-010` —
# capital V, space instead of a hyphen — which is not an nmap script. It would
# have been dispatched and failed at the scanner.
#
# The catalogs live in three different containers, so this materialises them
# into knowledge/ (already bind-mounted read-only into scan-recommender) rather
# than having the validator reach across containers at request time.
#
# Re-run after upgrading a scanner image or updating nuclei templates.
#
# Usage:
#   ./scripts/refresh-tool-catalogs.sh
#   ./scripts/refresh-tool-catalogs.sh --out knowledge/tool_catalogs.json
#
# Prereqs: docker, jq. Containers kali-listener / nuclei-runner / metasploit
# must be running; each source is optional and simply reports 0 if absent.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "$PROJECT_ROOT"

OUT="knowledge/tool_catalogs.json"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --out|-o)  OUT="${2:-}"; shift 2 ;;
        --help|-h) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

command -v jq >/dev/null 2>&1 || { echo "ERROR: jq is required." >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Each extractor prints one entry per line and must never fail the run: a
# missing container degrades that catalog to empty, and the validator treats an
# empty catalog as "cannot verify" rather than "everything is invalid".
extract() {   # container, description, shell command
    local container="$1" what="$2" cmd="$3"
    if docker exec "$container" sh -c "$cmd" 2>/dev/null | sed '/^$/d' | sort -u > "$TMP/$what"; then
        :
    else
        : > "$TMP/$what"
    fi
    printf "  %-22s %6d  (%s)\n" "$what" "$(wc -l < "$TMP/$what" | tr -d ' ')" "$container"
}

echo "Extracting tool catalogs from running containers…"

extract kali-listener nmap_scripts \
    'ls /usr/share/nmap/scripts/*.nse 2>/dev/null | xargs -n1 basename | sed "s/\.nse$//"'

extract metasploit msf_modules \
    'find /usr/src/metasploit-framework/modules /usr/share/metasploit-framework/modules -name "*.rb" 2>/dev/null | sed "s|.*/modules/||; s|\.rb$||"'

extract nuclei-runner nuclei_templates \
    'find /opt/nuclei-templates /root/nuclei-templates -name "*.yaml" 2>/dev/null | sed "s|.*/nuclei-templates/||; s|\.yaml$||"'

# Nuclei is usually invoked by TAG rather than template id (the model emits
# "snmp,network,udp"), so the tag vocabulary has to be validated separately.
extract nuclei-runner nuclei_tags \
    'grep -rhoE "^\s{0,4}tags:\s*.*" /opt/nuclei-templates --include="*.yaml" 2>/dev/null | sed "s/.*tags:\s*//" | tr "," "\n" | tr -d "\"'"'"' " | tr "[:upper:]" "[:lower:]"'

# Every executable the stack could actually invoke, unioned across the scanner
# containers — a recommendation naming `gobuster` is unrunnable if no container
# ships it, however well-formed it looks. Measured: the models recommended
# ncrack, gobuster, crackmapexec and snmp-check, none of which are installed.
: > "$TMP/binaries"
for c in kali-listener nuclei-runner metasploit web-scanner exploit-runner nmap_scanner; do
    docker exec "$c" sh -c 'IFS=:; for d in $PATH; do ls "$d" 2>/dev/null; done' \
        2>/dev/null >> "$TMP/binaries" || true
    # Not everything is on PATH: msfconsole ships at
    # /usr/src/metasploit-framework/msfconsole, so a PATH-only walk reported
    # metasploit as "not installed" — a false negative that would have blocked
    # every metasploit recommendation had the check been made blocking.
    # sed rather than find -printf: several of these images ship BusyBox find,
    # which has no -printf and silently produced nothing.
    docker exec "$c" sh -c '
        for d in /usr/src/metasploit-framework /opt /usr/local/share /usr/share; do
            [ -d "$d" ] && find "$d" -maxdepth 2 -type f -perm -u+x 2>/dev/null | sed "s|.*/||"
        done' 2>/dev/null >> "$TMP/binaries" || true
done
sort -u -o "$TMP/binaries" "$TMP/binaries"
printf "  %-22s %6d  (all scanner containers)\n" binaries "$(wc -l < "$TMP/binaries" | tr -d ' ')"

# Per-tool flags. Tools disagree on how to be asked: snmpwalk honours --help,
# onesixtyone and medusa reject it but print usage anyway, hydra needs -h. Try
# each form and keep the first that yields flags. A tool that yields none is
# recorded as absent rather than empty, so the validator skips it instead of
# rejecting every flag it has.
: > "$TMP/tool_flags"
for t in $(cat "$TMP/binaries"); do
    case "$t" in
        # Only probe tools we actually recommend — probing 792 binaries is slow
        # and some are interactive or destructive.
        nmap|hydra|medusa|snmpwalk|snmpget|onesixtyone|snmp-check|nikto|smbclient|\
        smbmap|enum4linux|enum4linux-ng|nuclei|gobuster|feroxbuster|ffuf|dirb|\
        whatweb|wafw00f|sslscan|sslyze|testssl.sh|ncrack|crackmapexec|netexec|\
        masscan|naabu|httpx|katana|amass|subfinder|dnsrecon|fierce|wpscan) ;;
        *) continue ;;
    esac
    for probe in "--help" "-h" ""; do
        flags="$(docker exec kali-listener sh -c \
            "timeout 8 $t $probe 2>&1 | grep -oE '(^|[[:space:]])-{1,2}[A-Za-z][A-Za-z0-9-]*' | tr -d ' ' | sort -u" \
            2>/dev/null | tr '\n' ' ')"
        if [ -n "$(echo "$flags" | tr -d ' ')" ]; then
            echo "$t|$flags" >> "$TMP/tool_flags"
            break
        fi
    done
done
printf "  %-22s %6d  (probed --help/-h/bare)\n" tool_flags "$(wc -l < "$TMP/tool_flags" | tr -d ' ')"

# Registered remote nodes execute scans too, and their toolsets are NOT the local
# containers'. node_manager already tracks per-node `capabilities`, so fold those
# in — a node with tools this host lacks must not have its work rejected.
if docker exec rag-postgres psql -U app -d scans -tAc \
      "SELECT 1 FROM remote_nodes LIMIT 1" >/dev/null 2>&1; then
    docker exec rag-postgres psql -U app -d scans -tAc \
        "SELECT DISTINCT unnest(capabilities) FROM remote_nodes WHERE capabilities IS NOT NULL" \
        2>/dev/null | sed '/^$/d' >> "$TMP/binaries" || true
    n_nodes=$(docker exec rag-postgres psql -U app -d scans -tAc \
        "SELECT COUNT(*) FROM remote_nodes" 2>/dev/null | tr -d ' ')
    printf "  %-22s %6s  (remote node capabilities folded in)\n" "remote_nodes" "${n_nodes:-0}"
    sort -u -o "$TMP/binaries" "$TMP/binaries"
fi

python3 - "$TMP" "$OUT" <<'PY'
import json, os, sys, datetime
tmp, out = sys.argv[1], sys.argv[2]
def load(name):
    p = os.path.join(tmp, name)
    if not os.path.exists(p):
        return []
    with open(p) as fh:
        return sorted({ln.strip() for ln in fh if ln.strip()})
data = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc)
                        .replace(microsecond=0).isoformat(),
    "note": ("Generated by scripts/refresh-tool-catalogs.sh. An EMPTY list means "
             "'catalog unavailable' — the validator skips that tool rather than "
             "rejecting everything. Re-run after upgrading a scanner image."),
    "nmap_scripts":     load("nmap_scripts"),
    "msf_modules":      load("msf_modules"),
    "nuclei_templates": load("nuclei_templates"),
    "nuclei_tags":      load("nuclei_tags"),
    "binaries":         load("binaries"),
}
# tool -> [flags]. A tool absent from this map was not probed or yielded
# nothing; the validator must skip it rather than treat it as having no flags.
flags = {}
fp = os.path.join(tmp, "tool_flags")
if os.path.exists(fp):
    with open(fp) as fh:
        for ln in fh:
            if "|" not in ln:
                continue
            name, rest = ln.split("|", 1)
            vals = sorted({f for f in rest.split() if f.startswith("-")})
            if vals:
                flags[name.strip()] = vals
data["tool_flags"] = flags
# Operator supplement — hand-maintained, never overwritten by this script.
#
# Automated probing can only see what this host can reach. Tools that run on
# provisioned instances, across pipes, or on nodes that are offline right now are
# invisible to it, and a catalog that omits them would have the validator reject
# perfectly good TTPs. Anything listed here is merged in as authoritative.
#
#   knowledge/tool_catalogs.local.json
#   { "nmap_scripts": ["my-custom-nse"], "binaries": ["ncrack"],
#     "msf_modules": ["exploit/linux/local/my_module"] }
supp_path = os.path.join(os.path.dirname(out) or ".", "tool_catalogs.local.json")
if os.path.exists(supp_path):
    try:
        with open(supp_path) as fh:
            supp = json.load(fh)
        added = 0
        for k, v in supp.items():
            if isinstance(v, list) and isinstance(data.get(k), list):
                before = len(data[k])
                data[k] = sorted(set(data[k]) | set(v))
                added += len(data[k]) - before
            elif isinstance(v, dict) and isinstance(data.get(k), dict):
                data[k].update(v)
        print(f"  merged {added} operator-supplied entries from {supp_path}")
    except Exception as e:
        print(f"  WARNING: could not read {supp_path}: {e}")

os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
with open(out, "w") as fh:
    json.dump(data, fh, indent=1, sort_keys=True)
total = sum(len(v) for k, v in data.items() if isinstance(v, list))
print(f"\nWrote {out} — {total} catalog entries")
for k, v in data.items():
    if isinstance(v, list) and not v:
        print(f"  WARNING: {k} is empty — that tool will not be validated")
PY

cat <<EOF

Next:
  Restart scan-recommender so it picks up the new catalog:
    docker compose restart scan-recommender
EOF
