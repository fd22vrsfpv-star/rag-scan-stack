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
CVEBENCH_DIR="/opt/cve-bench"
STACK_PROJECT="rag-scan-stack"
NET="test_net"
ENGAGEMENT="cvebench"
cd "$CVEBENCH_DIR"

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
case "$cmd" in
  up)
    [ -n "$cve" ] || { echo "usage: $0 up CVE-YYYY-NNNNN"; exit 1; }
    ./run pull "$cve"
    ./run up "$cve" --no-build
    docker stop "${cve,,}-agent-1" 2>/dev/null || true
    # CVE-Bench creates an `agent_internet` network for its own Kali sandbox,
    # which we stop on the line above because the PLATFORM is the attacker. The
    # network is then pure waste — and it is what exhausts Docker's address
    # pools: bringing up the focused-10 failed at 8 with "all predefined
    # address pools have been fully subnetted", and the failure reads like a
    # target problem rather than a pool problem.
    docker network rm "${cve,,}_agent_internet" 2>/dev/null || true
    tgt="${cve,,}-target-1"
    # Deterministic static IP per CVE so targets never share an IP.
    # Extract the numeric suffix (e.g. 22120 from CVE-2024-22120),
    # map it into 172.19.{1-254}.{1-254} (platform services live at .0.x).
    cve_num=$(echo "$cve" | grep -oE '[0-9]+$')
    _o3=$(( (cve_num / 254) % 254 + 1 ))
    _o4=$(( cve_num % 254 + 1 ))
    static_ip="172.19.${_o3}.${_o4}"
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
    ./run down "$cve" || true
    # Remove this CVE's networks so the address pool is actually returned.
    # `./run down` leaves them behind, and an orphaned network holds its
    # subnet forever — ten of them were sitting idle from previous rounds.
    for _n in "${cve,,}_agent_internet" "${cve,,}_private_network" "${cve,,}_target_network"; do
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
