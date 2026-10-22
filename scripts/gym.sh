#!/usr/bin/env bash
# CVE-Bench gym helper for the rag-scan-stack platform.
#
# Brings a CVE-Bench target up as an ISOLATED network target the platform can
# scan, wires it onto the stack's agents_net, and registers it under the
# `cvebench` engagement's scope (so the fail-closed scope gate allows it).
#
#   ./gym.sh up   CVE-2024-2624     # pull+start, attach to agents_net, add scope
#   ./gym.sh down CVE-2024-2624     # stop target, remove its scope rows
#   ./gym.sh list                   # show running gym targets + their scope
#
# Notes:
#  - The target IP on agents_net is dynamic; `up` re-reads it and upserts scope,
#    so re-run `up` after a restart to refresh the IP.
#  - CVE-Bench's own Kali "agent" sandbox is stopped — the PLATFORM is the attacker.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
# Resolve THROUGH symlinks. /opt/cve-bench/gym.sh is a symlink into this repo,
# so `dirname "${BASH_SOURCE[0]}"` is the symlink's directory (/opt/cve-bench)
# and REPO_ROOT came out as /opt — a directory with no .env, which is where the
# lookup below silently found nothing. Hand-rolled rather than `readlink -f`:
# that is GNU-only, and this script is deliberately macOS-portable.
_gym_self="${BASH_SOURCE[0]}"
while [ -L "$_gym_self" ]; do
  _gym_link="$(readlink "$_gym_self")"
  case "$_gym_link" in
    /*) _gym_self="$_gym_link" ;;
     *) _gym_self="$(dirname "$_gym_self")/$_gym_link" ;;
  esac
done
REPO_ROOT="$(cd "$(dirname "$_gym_self")/.." && pwd)"
# Same knob docker-compose uses for rag-api's /opt/cve-bench mount, so the gym
# and the CTF goal extractor read ONE checkout. Env wins, then .env, then the
# Linux default. A relative path is relative to the repo (as compose treats it).
# `|| true` is load-bearing. Under `set -euo pipefail` a grep that matches
# NOTHING fails the pipeline and kills the script right here — so the
# `:-/opt/cve-bench` default on the next line was unreachable in precisely the
# case it exists for: a .env without this key. The script then exited 0 with no
# output, and every caller read that as "the target failed to start".
CVEBENCH_DIR="${CVE_BENCH_DIR:-$(grep -E '^CVE_BENCH_DIR=' "$REPO_ROOT/.env" 2>/dev/null | tail -1 | cut -d= -f2- || true)}"
CVEBENCH_DIR="${CVEBENCH_DIR:-/opt/cve-bench}"
case "$CVEBENCH_DIR" in /*) ;; *) CVEBENCH_DIR="$REPO_ROOT/${CVEBENCH_DIR#./}" ;; esac
[ -x "$CVEBENCH_DIR/run" ] || { echo "CVE-Bench not found at $CVEBENCH_DIR (git clone https://github.com/uiuc-kang-lab/cve-bench.git there, then uv sync)"; exit 1; }
NET="test_net"
ENGAGEMENT="cvebench"
cd "$CVEBENCH_DIR"

# CVE-Bench's own ./run uses bash-4 syntax (${x,,}); macOS ships bash 3.2, where
# it dies with "bad substitution" AFTER pulling. Run it with a bash >= 4.
_RUN_BASH=""
for _b in "$BASH" /opt/homebrew/bin/bash /usr/local/bin/bash; do
  [ -x "$_b" ] && [ "$("$_b" -c 'echo ${BASH_VERSINFO[0]}')" -ge 4 ] 2>/dev/null && { _RUN_BASH="$_b"; break; }
done
[ -n "$_RUN_BASH" ] || { echo "CVE-Bench ./run needs bash >= 4 (macOS: brew install bash)"; exit 1; }
# ./run also calls GNU `timeout -v` (not on macOS); coreutils' gnubin supplies
# it. Scoped to ./run so the rest of this script keeps the system tools.
_GNUBIN=""
for _d in /opt/homebrew/opt/coreutils/libexec/gnubin /usr/local/opt/coreutils/libexec/gnubin; do
  [ -x "$_d/timeout" ] && { _GNUBIN="$_d:"; break; }
done
command -v timeout >/dev/null || [ -n "$_GNUBIN" ] || { echo "CVE-Bench ./run needs GNU timeout (macOS: brew install coreutils)"; exit 1; }
_run() { PATH="${_GNUBIN}$PATH" "$_RUN_BASH" ./run "$@"; }

# CVE-Bench publishes linux/amd64 images only; on Apple Silicon the pull fails
# with "no matching manifest for linux/arm64/v8". Docker Desktop runs amd64
# under emulation when asked. An explicit DOCKER_DEFAULT_PLATFORM wins.
if [ "$(uname -m)" = "arm64" ] || [ "$(uname -m)" = "aarch64" ]; then
  export DOCKER_DEFAULT_PLATFORM="${DOCKER_DEFAULT_PLATFORM:-linux/amd64}"
fi

# Static target IP inside test_net. On a /24 (setup.sh default, TEST_NET_SUBNET)
# platform services get .1-.62 from the network's --ip-range and targets get a
# deterministic .64-.254, probing forward past any address already in use so two
# CVEs whose numbers collide mod 191 still get distinct IPs. On a legacy /16
# the original 172.x.{1-254}.{1-254} mapping is kept.
_static_ip() {  # $1 = numeric CVE suffix, $2 = target container (may hold an IP already)
  local subnet base prefix used n i cand
  subnet=$(docker network inspect "$NET" -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}')
  base=${subnet%/*}; prefix=${subnet#*/}
  used=$(docker network inspect "$NET" -f '{{range .Containers}}{{.Name}}={{.IPv4Address}} {{end}}' \
         | tr ' ' '\n' | grep -v "^$2=" | sed -E 's#.*=##; s#/.*##')
  if [ "$prefix" = "24" ]; then
    n=$(( $1 % 191 ))
    for i in $(seq 0 190); do
      cand="${base%.*}.$(( 64 + (n + i) % 191 ))"
      echo "$used" | grep -qx "$cand" || { echo "$cand"; return 0; }
    done
    echo "no free target address left in $subnet" >&2; return 1
  fi
  echo "$(echo "$base" | cut -d. -f1-2).$(( ($1 / 254) % 254 + 1 )).$(( $1 % 254 + 1 ))"
}

_eid() {  # ensure the cvebench engagement exists; print its id
  docker exec -i rag-api python3 - "$ENGAGEMENT" <<'PY'
import os,sys,uuid,psycopg2
name=sys.argv[1]
c=psycopg2.connect(os.environ["DB_DSN"],connect_timeout=8);c.autocommit=True;cur=c.cursor()
cur.execute("SELECT id FROM engagements WHERE name=%s",(name,));r=cur.fetchone()
if r: print(r[0])
else:
    eid=str(uuid.uuid4());cur.execute("INSERT INTO engagements (id,name) VALUES (%s,%s)",(eid,name));print(eid)
c.close()
PY
}

cmd="${1:-}"; cve="${2:-}"
lc=$(printf '%s' "$cve" | tr '[:upper:]' '[:lower:]')  # not ${x,,}: bash 3.2 (macOS) lacks it
case "$cmd" in
  up)
    [ -n "$cve" ] || { echo "usage: $0 up CVE-YYYY-NNNNN"; exit 1; }
    _run pull "$cve"
    # A multi-arch base already present for the host arch (ubuntu:22.04 for
    # secrets_init) is SKIPPED by `./run pull`, then rejected at `up` with
    # "does not provide the specified platform (linux/amd64)". Pull every image
    # the challenge uses for the forced platform so `up` finds the right variant.
    if [ -n "${DOCKER_DEFAULT_PLATFORM:-}" ]; then
      for _img in $(_run compose "$cve" config --images 2>/dev/null | sort -u); do
        docker pull -q --platform "$DOCKER_DEFAULT_PLATFORM" "$_img" >/dev/null \
          || echo "warn: could not pull $_img for $DOCKER_DEFAULT_PLATFORM"
      done
    fi
    _run up "$cve" --no-build
    docker stop "${lc}-agent-1" 2>/dev/null || true
    # CVE-Bench creates an `agent_internet` network for its own Kali sandbox,
    # which we stop on the line above because the PLATFORM is the attacker. The
    # network is then pure waste — and it is what exhausts Docker's address
    # pools: bringing up the focused-10 failed at 8 with "all predefined
    # address pools have been fully subnetted", and the failure reads like a
    # target problem rather than a pool problem.
    docker network rm "${lc}_agent_internet" 2>/dev/null || true
    tgt="${lc}-target-1"
    # Deterministic static IP per CVE so targets never share an IP (see
    # _static_ip). Numeric suffix e.g. 22120 from CVE-2024-22120.
    cve_num=$(echo "$cve" | grep -oE '[0-9]+$')
    static_ip=$(_static_ip "$((10#$cve_num))" "$tgt")
    # Disconnect first in case a prior run left a different IP
    docker network disconnect "$NET" "$tgt" 2>/dev/null || true
    docker network connect --ip "$static_ip" "$NET" "$tgt" 2>/dev/null || true
    ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "'"$NET"'").IPAddress}}' "$tgt")
    [ -n "$ip" ] || { echo "could not read target IP on $NET"; exit 1; }
    echo "assigned static IP $ip for $cve (from cve_num=$cve_num)"
    # The app's real port is per-CVE — read it from APPLICATION_URL's first
    # `target:<port>` entry (e.g. 9090, 8080, 80), not a hardcoded 9090. This is
    # what stops us pointing the platform at the wrong port (Zabbix=8080, etc.).
    port=$(grep -E '^APPLICATION_URL=' "src/critical/challenges/$cve/.env" 2>/dev/null \
            | cut -d= -f2 | tr ',' '\n' | grep -E '^target:' | head -1 | cut -d: -f2)
    port=${port:-9090}
    echo "resolved app port for $cve: $port"
    eid=$(_eid)
    docker exec -i rag-api python3 - "$eid" "$cve" "$ip" "$port" <<'PY'
import os,sys,uuid,psycopg2
eid,cve,ip,port=sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4]
c=psycopg2.connect(os.environ["DB_DSN"],connect_timeout=8);c.autocommit=True;cur=c.cursor()
# clear any prior rows for this CVE, then add fresh IP + URL (correct port)
cur.execute("DELETE FROM scope_targets WHERE engagement_id=%s AND name LIKE %s",(eid,f"cvebench-{cve.lower()}-%"))
for nm,tgt,tt in [(f"cvebench-{cve.lower()}-ip",ip,"ip"),
                  (f"cvebench-{cve.lower()}-url",f"http://{ip}:{port}","url")]:
    cur.execute("""INSERT INTO scope_targets (id,name,target,target_type,source,engagement_id,added_at)
                   VALUES (%s,%s,%s,%s,'cvebench_gym',%s,now())""",(str(uuid.uuid4()),nm,tgt,tt,eid))
print(f"scoped {cve} -> {ip}:{port} under engagement 'cvebench' ({eid})")
c.close()
PY
    ;;
  down)
    [ -n "$cve" ] || { echo "usage: $0 down CVE-YYYY-NNNNN"; exit 1; }
    _run down "$cve" || true
    # Remove this CVE's networks so the address pool is actually returned.
    # `./run down` leaves them behind, and an orphaned network holds its
    # subnet forever — ten of them were sitting idle from previous rounds.
    for _n in "${lc}_agent_internet" "${lc}_private_network" "${lc}_target_network"; do
      docker network rm "$_n" 2>/dev/null || true
    done
    eid=$(_eid)
    docker exec -i rag-api python3 - "$eid" "$cve" <<'PY'
import os,sys,psycopg2
eid,cve=sys.argv[1],sys.argv[2]
c=psycopg2.connect(os.environ["DB_DSN"],connect_timeout=8);c.autocommit=True;cur=c.cursor()
cur.execute("DELETE FROM scope_targets WHERE engagement_id=%s AND name LIKE %s",(eid,f"cvebench-{cve.lower()}-%"))
print(f"removed scope for {cve}")
c.close()
PY
    ;;
  prune-nets)
    # Reclaim subnets from CVE-Bench networks that have NO containers attached.
    # Deliberately NOT `docker network prune`: that would also remove unrelated
    # idle networks belonging to other stacks.
    _freed=0
    for _n in $(docker network ls --format '{{.Name}}' | grep -E '^cve-[0-9]{4}-[0-9]+_'); do
      if [ "$(docker network inspect "$_n" --format '{{len .Containers}}' 2>/dev/null)" = "0" ]; then
        docker network rm "$_n" >/dev/null 2>&1 && { echo "  freed $_n"; _freed=$((_freed+1)); }
      fi
    done
    echo "reclaimed $_freed empty CVE-Bench network(s); $(docker network ls -q | wc -l) remain"
    ;;
  list)
    echo "== running gym targets =="
    docker ps --filter "name=-target-1" --format '{{.Names}}\t{{.Status}}' | grep -i cve || echo "(none)"
    echo "== cvebench scope =="
    docker exec -i rag-api python3 - <<'PY'
import os,psycopg2
c=psycopg2.connect(os.environ["DB_DSN"],connect_timeout=8);cur=c.cursor()
cur.execute("""SELECT s.name,s.target,s.target_type FROM scope_targets s
               JOIN engagements e ON e.id=s.engagement_id WHERE e.name='cvebench' ORDER BY s.name""")
for r in cur.fetchall(): print(" ",r)
c.close()
PY
    ;;
  *) echo "usage: $0 {up|down CVE-YYYY-NNNNN | list}"; exit 1;;
esac
