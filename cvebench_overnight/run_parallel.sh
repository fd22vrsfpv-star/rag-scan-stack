#!/usr/bin/env bash
# Run a CVE list N-at-a-time by launching N instances of run_focused10.sh with
# DISJOINT CVE lists.
#
#   ./run_parallel.sh 2                       # whole focused-10, 2 at a time
#   ./run_parallel.sh 2 CVE-2024-4443 CVE-...  # an explicit list
#
# Why instances rather than parallelising the loop inside run_focused10.sh:
# that loop does per-CVE database cleanup, target bring-up, dispatch and
# teardown, and making it concurrent would mean auditing every one of those
# steps for shared state. Disjoint lists give the same throughput with the
# per-CVE body unchanged and already proven.
#
# WHAT MAKES DISJOINT LISTS SAFE (checked, not assumed):
#   * Every per-CVE artefact is keyed by the CVE: results_focused/<cve>.*,
#     /tmp/bf_<cve>.json and /tmp/rf_<cve>.json inside rag-api. Disjoint lists
#     never collide on any of them.
#   * Each instance gets its own CVEBENCH_LOG, so the progress logs do not
#     interleave into an unreadable mess.
#   * `DELETE FROM confirmed_facts WHERE target LIKE '%<ip>%'` is per-target,
#     and targets CANNOT share an IP. gym.sh assigns a deterministic static
#     address per challenge -- 172.19.{(n/254)%254+1}.{n%254+1} from the CVE's
#     numeric suffix -- precisely so "targets never share an IP" (its own
#     comment). Verified by computing it for all 40 shipped challenges: zero
#     collisions. So neither lane's delete can touch the other's proven facts.
#
#     This is the one assumption worth re-checking if the addressing scheme
#     ever changes: two CVEs mapping to one IP would turn that DELETE into
#     silent cross-contamination between lanes, and nothing would report it.
#   * PRERUN_UP is computed per instance. Because the lists are disjoint, an
#     instance only ever tears down targets it brought up itself.
#
# BOUNDS: MAX_CONCURRENT_SCANS is 5 stack-wide, so 2 concurrent builds sit
# inside it. Do not raise N without re-checking that -- the scan-volume
# invariant is per stack, not per script.
set -u
cd "$(dirname "$0")"

N="${1:-2}"
shift || true

if [ "$#" -gt 0 ]; then
  CVES=("$@")
else
  CVES=(
    "CVE-2024-22120" "CVE-2024-3408" "CVE-2024-32511" "CVE-2023-51483"
    "CVE-2024-3552" "CVE-2024-36412" "CVE-2024-5314" "CVE-2024-32964"
    "CVE-2024-36675" "CVE-2024-4443"
  )
fi

if ! [ "$N" -ge 1 ] 2>/dev/null; then
  echo "usage: $0 <parallelism> [CVE ...]" >&2; exit 2
fi
if [ "$N" -gt 3 ]; then
  echo "refusing N=$N: MAX_CONCURRENT_SCANS is 5 stack-wide and each build" >&2
  echo "dispatches more than one scan. Raise deliberately, not by habit." >&2
  exit 2
fi

# Round-robin so the lanes finish at roughly the same time even when the CVEs
# differ wildly in cost (18 min to 70 min observed).
for lane in $(seq 0 $((N-1))); do
  lane_cves=""
  idx=0
  for cve in "${CVES[@]}"; do
    [ $((idx % N)) -eq "$lane" ] && lane_cves="$lane_cves $cve"
    idx=$((idx+1))
  done
  lane_cves="${lane_cves# }"
  [ -z "$lane_cves" ] && continue
  log="$(pwd)/progress_lane$((lane+1)).log"
  echo "lane $((lane+1)): $lane_cves"
  echo "  log: $log"
  CVEBENCH_CVES="$lane_cves" CVEBENCH_LOG="$log" \
    setsid nohup ./run_focused10.sh > "/tmp/lane$((lane+1)).out" 2>&1 < /dev/null &
  disown
  # Stagger the starts: both lanes otherwise race to `gym.sh up` and to the
  # same per-CVE cleanup connection at the same instant.
  sleep 20
done

echo
echo "launched $N lanes. watch with:"
echo "  tail -f $(pwd)/progress_lane*.log"
