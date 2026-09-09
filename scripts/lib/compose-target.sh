#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  compose-target.sh — address THIS project's containers, never another's
# ═══════════════════════════════════════════════════════════════════════════
#
# Sourced by scripts/setup.sh, scripts/post-install-check.sh and
# scripts/rehearse-install.sh.  Not executable on its own.
#
# WHY THIS EXISTS
# ---------------
# The installer addressed containers by their hardcoded `container_name:`
# (`docker exec rag-postgres psql ...`, `curl http://localhost:8000/health`).
# Container names and published ports are GLOBAL to the daemon and to the host,
# so under a second compose project every one of those calls silently reaches
# the FIRST stack.  Concretely, before this file existed:
#
#   * Phase 7 of a rehearsal install would have applied its schema to the LIVE
#     production database, because `docker exec rag-postgres` resolves to
#     whichever container owns that name.
#   * Phase 9's health checks would have reported the LIVE stack healthy and
#     called it a successful fresh install.
#   * post-install-check.sh would have verified the live stack's tables, 14
#     `docker exec <name>` call sites deep.
#
# That is why phases 6-10 were documented as "not rehearsable": not because a
# second stack could not be started, but because starting one would have been
# indistinguishable from — and destructive to — the running one.
#
# THE MECHANISM
# -------------
# Every compose-managed container carries two labels:
#
#   com.docker.compose.project   the project (directory name, or
#                                $COMPOSE_PROJECT_NAME)
#   com.docker.compose.service   the service name in docker-compose.yml
#
# Looking a container up by (project, service) is exact, needs no profile
# flags, and cannot stray into another project — which is precisely what
# addressing by `container_name` cannot promise.  It also keeps working when a
# service has no `container_name:` at all, which is how the rehearsal override
# isolates a second stack (see docker-compose.rehearsal.yml).
#
# THREE OUTCOMES, NOT TWO
# -----------------------
# Every lookup here distinguishes "found" / "not running" / "could not ask".
# Collapsing the last two into "absent" is the recurring bug in this repo: a
# probe that could not run gets reported as a negative result.  Callers branch
# on the exit status:
#
#   0  found / ran
#   1  answered, negative — this project has no such container running
#   2  could not ask — docker missing, daemon down, permission denied
#
# shellcheck shell=bash

# ── Project resolution ─────────────────────────────────────────────────────
# Compose derives the project name from $COMPOSE_PROJECT_NAME, else from the
# basename of the project directory, lowercased with anything outside
# [a-z0-9_-] replaced by an underscore.  We mirror that so a lookup matches the
# labels compose actually wrote.
ct_project() {
    local raw="${COMPOSE_PROJECT_NAME:-}"
    if [ -z "$raw" ]; then
        raw="$(basename "$(pwd)")"
    fi
    printf '%s' "$raw" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_-]/_/g'
}

# ── Is docker usable at all? ───────────────────────────────────────────────
# Distinguishes "no docker binary" and "docker present but daemon unreachable"
# from a successful query that simply returned nothing.  `docker ps` failing is
# NOT docker being absent.
ct_docker_ok() {
    command -v docker >/dev/null 2>&1 || return 2
    docker ps -q >/dev/null 2>&1 || return 2
    return 0
}

# ── ct_cid <service> ───────────────────────────────────────────────────────
# Print the container id for this project's <service>.
#   0 = printed an id, 1 = no such container running, 2 = could not ask.
ct_cid() {
    local service="$1" id
    ct_docker_ok || return 2
    id=$(docker ps -q \
            --filter "label=com.docker.compose.project=$(ct_project)" \
            --filter "label=com.docker.compose.service=${service}" \
            2>/dev/null | head -n1) || return 2
    [ -n "$id" ] || return 1
    printf '%s' "$id"
    return 0
}

# ── ct_cid_any <service> ───────────────────────────────────────────────────
# As ct_cid, but also matches a STOPPED container (`docker ps -a`).  Used when
# reporting on one-shot services (wait-for-db, vault-init, ollama-init) whose
# normal end state is "exited 0" — for those, "not running" is not a fault.
ct_cid_any() {
    local service="$1" id
    ct_docker_ok || return 2
    id=$(docker ps -aq \
            --filter "label=com.docker.compose.project=$(ct_project)" \
            --filter "label=com.docker.compose.service=${service}" \
            2>/dev/null | head -n1) || return 2
    [ -n "$id" ] || return 1
    printf '%s' "$id"
    return 0
}

# ── ct_exec <service> <cmd...> ─────────────────────────────────────────────
# Run a command inside this project's <service>.  Never falls back to a
# same-named container belonging to another project: if this project does not
# have it, the answer is 1 (or 2), not somebody else's container.
#
# Exit status is the COMMAND's status when the command ran; 1/2 when it could
# not be started.  A command exiting 1 and a container that does not exist are
# therefore indistinguishable to a caller that only tests `if ct_exec ...` —
# callers who need to tell them apart should resolve with ct_cid first, which
# is what ct_sql does below.
ct_exec() {
    local service="$1"; shift
    local id
    id=$(ct_cid "$service"); local rc=$?
    (( rc == 0 )) || return $rc
    docker exec "$id" "$@"
}

# ── ct_exec_env <service> <VAR=value> <cmd...> ─────────────────────────────
# ct_exec with one environment variable passed in.  Keeps callers from having
# to interpolate values into a shell string, which is how quoting bugs get in.
ct_exec_env() {
    local service="$1" envspec="$2"; shift 2
    local id
    id=$(ct_cid "$service"); local rc=$?
    (( rc == 0 )) || return $rc
    docker exec -e "$envspec" "$id" "$@"
}

# ── ct_hostport <service> <container_port> ─────────────────────────────────
# Print the host port this project publishes for <service>'s <container_port>,
# e.g. `ct_hostport rag-api 8000` -> 8000 on the live stack.
#
# Health checks MUST go through this rather than a literal `localhost:8000`.
# The rehearsal override unpublishes ports entirely, so a literal port would
# check the live stack and pass — the single most misleading way this could
# fail.  No mapping is outcome 1: ask inside the container instead.
ct_hostport() {
    local service="$1" cport="$2" id mapping
    id=$(ct_cid "$service"); local rc=$?
    (( rc == 0 )) || return $rc
    mapping=$(docker port "$id" "${cport}/tcp" 2>/dev/null | head -n1) || return 2
    [ -n "$mapping" ] || return 1
    # "0.0.0.0:8000" / "[::]:8000" -> 8000
    printf '%s' "${mapping##*:}"
    return 0
}

# ── ct_curl <service> <container_port> <path> [curl args...] ───────────────
# Probe an HTTP(S) endpoint of this project's <service> FROM INSIDE that
# container, so no published port is required and the probe cannot land on
# another project's stack.  Tries https then http: services in this stack are
# mixed, and a TLS service answering an http:// probe looks exactly like a
# service that is down.
#
# 0 = endpoint answered, 1 = did not answer, 2 = could not probe.
ct_curl() {
    local service="$1" cport="$2" path="$3"; shift 3
    local id
    id=$(ct_cid "$service"); local rc=$?
    (( rc == 0 )) || return $rc
    local scheme
    for scheme in https http; do
        if docker exec "$id" curl -sfk --max-time "${CT_CURL_TIMEOUT:-5}" \
                "$@" "${scheme}://127.0.0.1:${cport}${path}" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# ── ct_http_code <service> <container_port> <path> [curl args...] ──────────
# Like ct_curl, but prints the HTTP STATUS CODE instead of the body — a check
# that wants to tell 401 from 404 from 500 needs the number, and "curl failed"
# is not a status.  Tries https then http and prints the first attempt that
# produced a real code; prints 000 when neither answered.
#
# 0 = printed a real code, 1 = printed 000 (nothing answered),
# 2 = could not probe (no such container in this project / docker unusable).
ct_http_code() {
    local service="$1" cport="$2" path="$3"; shift 3
    local id code scheme
    id=$(ct_cid "$service"); local rc=$?
    (( rc == 0 )) || return $rc
    for scheme in https http; do
        code=$(docker exec "$id" curl -sk -o /dev/null \
                    -w '%{http_code}' --max-time "${CT_CURL_TIMEOUT:-10}" \
                    "$@" "${scheme}://127.0.0.1:${cport}${path}" 2>/dev/null) || code=""
        if [ -n "$code" ] && [ "$code" != "000" ]; then
            printf '%s' "$code"; return 0
        fi
    done
    printf '000'
    return 1
}

# ── ct_sql <sql> ───────────────────────────────────────────────────────────
# Run one statement against THIS project's database and echo the result the way
# `psql -tA` would: one row per line, columns joined by '|', booleans as t/f,
# NULL as empty.
#
# Two routes, in order:
#   1. this project's `rag-postgres` container, when the local-db profile is up
#   2. any of this project's DB-connected services, using its own DB_DSN
#
# Route 2 is not a nicety: in `remote` / `remote_direct` mode there is no
# rag-postgres container at all, and route 1 answering "no container" must not
# be read as "no database".  It is also why this cannot simply grep
# `docker ps` for the NAME rag-postgres — in a rehearsal that name belongs to
# the live stack, so the check would silently verify the wrong database.
#
# The SQL travels through the environment, never interpolated into the python
# source, so quotes in a statement cannot break the command.
#
#   0 = ran (result on stdout), 1 = ran but failed, 2 = no database reachable
ct_sql() {
    local sql="$1" out="" rc
    local svc

    if out=$(ct_exec rag-postgres psql -U app -d scans -tAc "$sql" 2>&1); then
        printf '%s' "$out"; return 0
    fi

    for svc in rag-api autogen-agents scan-recommender; do
        ct_cid "$svc" >/dev/null 2>&1 || continue
        # The status must be captured on the SAME line as the assignment:
        # after `fi`, `$?` is the status of the `if` statement (0 when the
        # condition was simply false), not of the command that ran.
        out=$(ct_exec_env "$svc" "SQL=$sql" python3 -c '
import os, sys, psycopg2
try:
    conn = psycopg2.connect(os.environ["DB_DSN"])
except Exception as exc:
    sys.stderr.write("connect: %s" % exc); sys.exit(3)
cur = conn.cursor()
cur.execute(os.environ["SQL"])
if cur.description:
    for row in cur.fetchall():
        print("|".join(
            "t" if v is True else "f" if v is False else "" if v is None else str(v)
            for v in row))
' 2>&1); rc=$?
        if (( rc == 0 )); then
            printf '%s' "$out"; return 0
        fi
        # The container exists and the command ran but failed — that is a real
        # SQL/connection error worth reporting, not "keep looking".
        if (( rc != 2 )); then
            printf '%s' "$out"; return 1
        fi
    done

    printf '%s' "${out:-no database reachable in project '$(ct_project)' (tried rag-postgres, rag-api, autogen-agents, scan-recommender)}"
    return 2
}
