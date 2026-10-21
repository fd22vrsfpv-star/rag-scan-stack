#!/usr/bin/env bash
# Work ONE CVE until it is solved, learning from each failure.
#
#   ./scripts/solve_cve.sh CVE-2024-4443 [rounds]
#
# Each round: build -> read the verdict -> if it failed, derive a hint from
# that build's own trace and persist it -> build again. A hint is scoped to
# (cve, target) and is prepended to synth guidance, so the next round starts
# knowing what the last one learned.
#
# WHY A LOOP AND NOT MORE ITERATIONS: `max_iters` bounds attempts INSIDE one
# build, all sharing the recon, the class decision and the plan that build
# started with. When the approach itself is wrong, more iterations refine the
# wrong approach — that is what `axis_exhausted` and `dup_exit` are telling
# you. A new round re-runs recon and re-decides, carrying forward only what
# was learned.
#
# IT STOPS. Three ways, and the middle one matters most:
#   * verified              -> solved, stop
#   * no progress           -> the same (stage, stop_reason) twice running
#                              means the hint changed nothing. Looping on that
#                              burns the target and the budget for free; this
#                              is the round-level form of the repeated-outcome
#                              rule in CLAUDE.md.
#   * rounds exhausted      -> stop and report
#
# Authorization is unchanged: every build goes through the same scope gate and
# MAX_CONCURRENT_SCANS bound as any other dispatch. This schedules work, it
# does not widen what may be touched.
set -uo pipefail
cd "$(dirname "$0")/.."

CVE="${1:-}"
ROUNDS="${2:-5}"
STALL_AT="${SOLVE_STALL_AT:-2}"
[ -n "$CVE" ] || { echo "usage: $0 CVE-YYYY-NNNNN [rounds]" >&2; exit 2; }

EID=$(docker exec rag-api python3 -c "
import psycopg2
c=psycopg2.connect('postgresql://app:app@172.203.226.44:5432/scans?sslmode=require').cursor()
c.execute(\"select id from engagements where name='cvebench'\"); print(c.fetchone()[0])
" 2>/dev/null | tr -d '\r')
[ -n "$EID" ] || { echo "could not resolve the cvebench engagement" >&2; exit 3; }

# The target must already be scoped and up — gym.sh does that, and leaving it
# to the caller keeps this script out of the business of starting targets.
read -r IP PORT < <(docker exec rag-api python3 -c "
import psycopg2
c=psycopg2.connect('postgresql://app:app@172.203.226.44:5432/scans?sslmode=require').cursor()
c.execute(\"select ip, port from build_poc_attempts where cve=%s order by created_at desc limit 1\", ('$CVE',))
r=c.fetchone()
print(r[0], r[1] or 9090) if r else print('', '')
" 2>/dev/null | tr -d '\r')
[ -n "${IP:-}" ] || { echo "no known target for $CVE — run it once through the round driver first" >&2; exit 4; }

echo "=== solving $CVE against $IP:$PORT — up to $ROUNDS rounds, stall at $STALL_AT"
prev_sig=""; stall=0

for round in $(seq 1 "$ROUNDS"); do
  echo
  echo "--- round $round/$ROUNDS  $(date '+%H:%M:%S')"
  printf '{"cve":"%s","ip":"%s","port":%s,"max_iters":7,"recon_first":true,"recon_source":"basic","release":true}' \
    "$CVE" "$IP" "$PORT" > /tmp/solve_body.json
  docker cp /tmp/solve_body.json rag-api:/tmp/solve_body.json >/dev/null 2>&1
  docker exec rag-api /tmp/runpoc.sh /tmp/solve_body.json /tmp/solve_result.json "$EID" >/dev/null 2>&1

  # The verdict comes from the attempt row, not the HTTP body: the result file
  # has reported a stale verdict before (2026-10-09).
  read -r VERIFIED STAGE STOP SID < <(docker exec rag-api python3 -c "
import psycopg2
c=psycopg2.connect('postgresql://app:app@172.203.226.44:5432/scans?sslmode=require').cursor()
c.execute('select verified, stage_reached, stop_reason, exploit_store_id from build_poc_attempts '
          'where cve=%s order by created_at desc limit 1', ('$CVE',))
r=c.fetchone() or (None,'?','?',None)
print(r[0], r[1] or '?', r[2] or '?', r[3] or '')
" 2>/dev/null | tr -d '\r')

  echo "    verified=$VERIFIED stage=$STAGE stop=$STOP"
  if [ "$VERIFIED" = "True" ]; then
    echo
    echo "=== SOLVED on round $round — exploit_store $SID"
    exit 0
  fi

  sig="${STAGE}|${STOP}"
  if [ "$sig" = "$prev_sig" ]; then
    stall=$((stall + 1))
    echo "    same outcome as last round ($stall/$STALL_AT)"
    if [ "$stall" -ge "$STALL_AT" ]; then
      echo
      echo "=== STALLED after $round rounds — '$sig' $((stall+1))x running."
      echo "    The hint is not changing the outcome; more rounds will not either."
      exit 1
    fi
  else
    stall=0
  fi
  prev_sig="$sig"

  # Learn from this round. derive-hint reads the build's OWN trace and
  # persists a poc_hint scoped to (cve, target); the next round's synth sees
  # it. No hint-worthy signal is a normal answer, not an error.
  if [ -n "$SID" ]; then
    H=$(docker exec rag-api sh -c "curl -sk -X POST \
      'https://localhost:8000/exploit-store/$SID/derive-hint' \
      -H \"x-api-key: \$API_KEY\" -H 'X-Engagement-Id: $EID'" 2>/dev/null)
    echo "    hint: $(echo "$H" | head -c 160)"
  fi
done

echo
echo "=== NOT SOLVED after $ROUNDS rounds (last: $prev_sig)"
exit 1
