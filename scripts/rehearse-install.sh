#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  rehearse-install.sh — run a full fresh install beside the live stack
# ═══════════════════════════════════════════════════════════════════════════
#
#   ./scripts/rehearse-install.sh                 # phases 1-10 from origin/main
#   ./scripts/rehearse-install.sh --ref HEAD      # rehearse the working branch
#   ./scripts/rehearse-install.sh --build-only    # phases 1-5, as before
#   ./scripts/rehearse-install.sh --keep          # leave the stack up to poke at
#   ./scripts/rehearse-install.sh --teardown-only # clean up a previous run
#
# WHAT THIS IS FOR
# ----------------
# The installer is the least-exercised code in the repo: it runs once per
# machine, and the machines that matter are the ones nobody has yet. The first
# rehearsal found four defects, one of which made a fresh install impossible on
# the host the stack was already running on.
#
# It could only cover phases 1-5 (`--no-start`). Phases 6-10 were "not
# rehearsable" — not because a second stack could not be built, but because
# starting one would have been indistinguishable from the live one:
# `container_name` and published ports are global, so `docker exec rag-postgres`
# and `curl localhost:8000/health` reach whichever stack got there first. A
# rehearsal that applies its schema to the production database is worse than no
# rehearsal.
#
# Two changes make 6-10 safe, and this script is the third:
#   * docker-compose.rehearsal.yml   — no container_name, no published ports,
#                                      its own network, no docker.sock
#   * scripts/lib/compose-target.sh  — the installer addresses containers by
#                                      (project, service), so it can only ever
#                                      talk to the stack it just started
#
# THE GUARD
# ---------
# Before and after, the live stack is fingerprinted: container id, name and
# started-at for every running container NOT in this rehearsal's project. Any
# difference is a failure, printed as a diff. Uptime is deliberately not part of
# it (it always changes); the START TIME is, because a restart changes it.
#
# set -u only: a failing phase must still reach the teardown and the final
# live-stack comparison, so failures are checked explicitly rather than by -e.

set -uo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"

# ── Configuration ─────────────────────────────────────────────────────────
WORK_DIR="${REHEARSAL_DIR:-/opt/fresh-rehearsal}"
PROJECT="${REHEARSAL_PROJECT:-freshrehearsal}"
REF="origin/main"
BUILD_ONLY=false
KEEP=false
TEARDOWN_ONLY=false

while [ $# -gt 0 ]; do
    case "$1" in
        --ref)           REF="${2:?--ref needs a git ref}"; shift 2 ;;
        --dir)           WORK_DIR="${2:?--dir needs a path}"; shift 2 ;;
        --project)       PROJECT="${2:?--project needs a name}"; shift 2 ;;
        --build-only)    BUILD_ONLY=true; shift ;;
        --keep)          KEEP=true; shift ;;
        --teardown-only) TEARDOWN_ONLY=true; shift ;;
        -h|--help)
            sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown option: $1 (use --help)"; exit 1 ;;
    esac
done

C_OK=$'\033[0;32m'; C_ERR=$'\033[0;31m'; C_WARN=$'\033[1;33m'
C_INFO=$'\033[0;36m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
say()  { echo "${C_INFO}[rehearse]${C_OFF} $*"; }
ok()   { echo "${C_OK}[ ok ]${C_OFF} $*"; }
warn() { echo "${C_WARN}[warn]${C_OFF} $*"; }
err()  { echo "${C_ERR}[fail]${C_OFF} $*"; }

# ── Refuse to rehearse INTO the live stack ────────────────────────────────
# The live project is this checkout's own project name. If the rehearsal used
# it, `up` would recreate the live containers with the isolation override
# applied — unpublishing every port on the running stack. That is the single
# worst thing this script could do, so it is checked before anything else.
LIVE_PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$REPO_ROOT")}"
LIVE_PROJECT="$(printf '%s' "$LIVE_PROJECT" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]/_/g')"
if [ "$PROJECT" = "$LIVE_PROJECT" ]; then
    err "rehearsal project '$PROJECT' is the LIVE project name."
    err "That would recreate the running stack with ports unpublished. Refusing."
    exit 1
fi
if [ "$WORK_DIR" = "$REPO_ROOT" ]; then
    err "rehearsal directory is this checkout. Refusing — a rehearsal uses a clean clone."
    exit 1
fi

# ── Live-stack fingerprint ────────────────────────────────────────────────
# Everything running that is NOT ours. Sorted so the diff is stable.
live_fingerprint() {
    docker ps --format '{{.ID}} {{.Names}} {{.CreatedAt}}' 2>/dev/null \
        | grep -v "^[0-9a-f]* ${PROJECT}[-_]" \
        | sort -k2
}

# ── Teardown ──────────────────────────────────────────────────────────────
# Removes the rehearsal's containers, its network and its volumes. Volumes
# matter: a rehearsal that reuses the previous run's database is testing an
# upgrade, not a fresh install, and would hide exactly the "phase 7 never
# created this table" defect it exists to find.
teardown() {
    if [ ! -d "$WORK_DIR" ]; then
        say "nothing to tear down at $WORK_DIR"
        return 0
    fi
    say "tearing down project '$PROJECT'"
    ( cd "$WORK_DIR" 2>/dev/null || exit 0
      COMPOSE_PROJECT_NAME="$PROJECT" docker compose \
          -f docker-compose.yml -f docker-compose.rehearsal.yml \
          --profile local-db --profile gpu down -v --remove-orphans 2>&1 \
        | tail -5 ) || true
    # Belt and braces: anything still labelled with this project.
    local leftovers
    leftovers=$(docker ps -aq --filter "label=com.docker.compose.project=${PROJECT}" 2>/dev/null)
    if [ -n "$leftovers" ]; then
        warn "removing $(echo "$leftovers" | wc -l) leftover container(s)"
        # shellcheck disable=SC2086
        docker rm -f $leftovers >/dev/null 2>&1 || true
    fi
    ok "teardown complete"
}

if [ "$TEARDOWN_ONLY" = true ]; then
    teardown
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════
say "rehearsing ${C_BOLD}${REF}${C_OFF} in ${C_BOLD}${WORK_DIR}${C_OFF} as project ${C_BOLD}${PROJECT}${C_OFF}"
say "live project is '${LIVE_PROJECT}' and must be untouched"

BEFORE="$(live_fingerprint)"
BEFORE_N=$(printf '%s\n' "$BEFORE" | grep -c . || true)
say "live stack before: ${BEFORE_N} container(s)"

# ── Clean clone ───────────────────────────────────────────────────────────
# A rehearsal must start from what git actually has, not from this working
# tree: an uncommitted file that makes the install work is the most common way
# for "it installs fine here" to be wrong.
if [ -d "$WORK_DIR/.git" ]; then
    say "reusing clone at $WORK_DIR (fetching)"
    ( cd "$WORK_DIR" && git fetch --all --quiet && git reset --hard --quiet "$REF" && git clean -xdfq ) \
        || { err "could not refresh the clone"; exit 1; }
else
    if [ -e "$WORK_DIR" ]; then
        err "$WORK_DIR exists but is not a git clone — remove it first"
        exit 1
    fi
    say "cloning $REPO_ROOT -> $WORK_DIR at $REF"
    git clone --quiet "$REPO_ROOT" "$WORK_DIR" || { err "clone failed"; exit 1; }
    ( cd "$WORK_DIR" && git checkout --quiet "$REF" ) || { err "checkout of $REF failed"; exit 1; }
fi
ok "clone at $(cd "$WORK_DIR" && git rev-parse --short HEAD)"

# ── Run the installer ─────────────────────────────────────────────────────
# --non-interactive: no prompts. --rehearsal: layer the isolation override.
# --no-gpu: the gpu profile pulls ollama and a second embedder, neither of
# which the install path itself needs verifying — and both are heavy.
SETUP_ARGS=(--non-interactive --rehearsal --no-gpu)
[ "$BUILD_ONLY" = true ] && SETUP_ARGS+=(--no-start)

say "running: ./scripts/setup.sh ${SETUP_ARGS[*]}"
SETUP_RC=0
( cd "$WORK_DIR" && COMPOSE_PROJECT_NAME="$PROJECT" ./scripts/setup.sh "${SETUP_ARGS[@]}" ) || SETUP_RC=$?
if [ "$SETUP_RC" -eq 0 ]; then
    ok "setup.sh exited 0"
else
    err "setup.sh exited ${SETUP_RC}"
fi

# ── Verify the rehearsal stack, not the live one ──────────────────────────
CHECK_RC=0
if [ "$BUILD_ONLY" = false ]; then
    say "running post-install-check.sh against project '$PROJECT'"
    ( cd "$WORK_DIR" && COMPOSE_PROJECT_NAME="$PROJECT" ./scripts/post-install-check.sh ) || CHECK_RC=$?
    [ "$CHECK_RC" -eq 0 ] && ok "post-install-check passed" || err "post-install-check exited ${CHECK_RC}"
fi

# ── Did we disturb the live stack? ────────────────────────────────────────
AFTER="$(live_fingerprint)"
AFTER_N=$(printf '%s\n' "$AFTER" | grep -c . || true)
LIVE_RC=0
if [ "$BEFORE" = "$AFTER" ]; then
    ok "live stack untouched: ${AFTER_N} container(s), same ids and start times"
else
    err "LIVE STACK CHANGED — ${BEFORE_N} container(s) before, ${AFTER_N} after"
    diff <(printf '%s\n' "$BEFORE") <(printf '%s\n' "$AFTER") | head -40 || true
    LIVE_RC=1
fi

# ── Teardown ──────────────────────────────────────────────────────────────
if [ "$KEEP" = true ]; then
    warn "--keep: project '$PROJECT' left running"
    warn "  inspect: cd $WORK_DIR && COMPOSE_PROJECT_NAME=$PROJECT docker compose -f docker-compose.yml -f docker-compose.rehearsal.yml ps"
    warn "  clean up: ./scripts/rehearse-install.sh --teardown-only"
else
    teardown
fi

echo ""
echo "──────────────────────────────────────────────"
echo " ref              ${REF}"
echo " setup.sh         $([ "$SETUP_RC" -eq 0 ] && echo PASS || echo "FAIL (${SETUP_RC})")"
if [ "$BUILD_ONLY" = false ]; then
echo " post-install     $([ "$CHECK_RC" -eq 0 ] && echo PASS || echo "FAIL (${CHECK_RC})")"
fi
echo " live stack       $([ "$LIVE_RC" -eq 0 ] && echo UNTOUCHED || echo DISTURBED)"
echo "──────────────────────────────────────────────"

# A disturbed live stack is the most serious outcome and must dominate the exit
# status, so it is checked last and reported on its own code.
[ "$LIVE_RC" -ne 0 ] && exit 3
[ "$SETUP_RC" -ne 0 ] && exit 1
[ "$CHECK_RC" -ne 0 ] && exit 2
exit 0
