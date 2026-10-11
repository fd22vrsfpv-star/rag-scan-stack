#!/usr/bin/env bash
# scripts/socks-attach.sh — one SOCKS5 proxy on 127.0.0.1 that reaches every
# live CVE-Bench challenge, without editing CVE-Bench itself.
#
# Each CVE-Bench challenge spins up its own `cve-<id>_target_network`. This
# script keeps a single `socks-cve` container attached to BASE_NET plus every
# cve-*_target_network that still has a non-SOCKS container on it.
#
# Usage:
#   scripts/socks-attach.sh up         # start/reuse + reconcile attachments
#   scripts/socks-attach.sh refresh    # same as up (default)
#   scripts/socks-attach.sh status     # show container + attachments + live CVE nets
#   scripts/socks-attach.sh down       # remove the SOCKS container
#
# Env knobs:
#   SOCKS_NAME       (default: socks-cve)
#   SOCKS_PORT       (default: 1080)
#   SOCKS_BIND       (default: 127.0.0.1) — set to 0.0.0.0 if a Burp running on
#                     Windows (WSL2 NAT mode) needs to reach this; WSL's own
#                     localhost-forwarding then makes Windows 127.0.0.1 resolve
#   SOCKS_IMAGE      (default: serjs/go-socks5-proxy)
#   SOCKS_BASE_NET   (default: "agents_net test_net") — space-separated; ALL are
#                     always kept attached. test_net is where CVE-Bench targets
#                     are scoped, so dropping it leaves the proxy unable to reach
#                     them (hangs until timeout, looks like a dead target).
#   SOCKS_NET_PATTERN (default: ^cve-.*_target_network$) — which nets to reconcile
#
# "Bounce safe": every call recomputes live CVE target networks from docker
# state, connects to any that are missing, and disconnects from any that no
# longer have a challenge container on them. A container restart preserves
# attachments; a container recreate also works because `reconcile` rebuilds.

set -euo pipefail

SOCKS_NAME="${SOCKS_NAME:-socks-cve}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
SOCKS_BIND="${SOCKS_BIND:-127.0.0.1}"
SOCKS_IMAGE="${SOCKS_IMAGE:-serjs/go-socks5-proxy}"
# Space-separated list, ALL kept attached and never disconnected by reconcile.
# test_net is load-bearing: CVE-Bench targets are scoped by their test_net
# address (gym.sh assigns a static one per CVE), so a proxy without it has no
# route to the host it is meant to reach — packets are dropped, not refused, so
# the symptom is a full-timeout hang that looks like a dead target rather than a
# connection error. agents_net alone is NOT enough.
BASE_NETS="${SOCKS_BASE_NET:-agents_net test_net}"
# First entry is the creation network; the rest are connected right after.
BASE_NET="${BASE_NETS%% *}"
PATTERN="${SOCKS_NET_PATTERN:-^cve-.*_target_network$}"

usage() {
    sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

have_docker() {
    command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 2; }
}

# Networks matching PATTERN that still have at least one non-SOCKS container.
# `return 0` at the end: an EOF `read` and a pattern-less `grep` both return 1,
# and under `set -o pipefail` that would abort the caller for no good reason.
live_cve_nets() {
    local n count
    { docker network ls --format '{{.Name}}' 2>/dev/null | grep -E "$PATTERN" || true; } \
    | while read -r n; do
        [ -z "$n" ] && continue
        count=$(docker network inspect "$n" \
            --format '{{range $k,$v := .Containers}}{{$v.Name}}{{"\n"}}{{end}}' 2>/dev/null \
            | grep -v -F -x "$SOCKS_NAME" | grep -c . || true)
        [ "${count:-0}" -gt 0 ] && echo "$n"
    done
    return 0
}

current_attachments() {
    { docker inspect "$SOCKS_NAME" \
        --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' 2>/dev/null \
        || true; } | grep -v '^$' || true
    return 0
}

ensure_running() {
    if ! docker inspect "$SOCKS_NAME" >/dev/null 2>&1; then
        if ! docker network inspect "$BASE_NET" >/dev/null 2>&1; then
            echo "base network '$BASE_NET' does not exist — set SOCKS_BASE_NET to a live net" >&2
            exit 3
        fi
        # REQUIRE_AUTH=false: open SOCKS. SOCKS_BIND defaults to 127.0.0.1
        # (loopback-only); set it to 0.0.0.0 when a Burp on Windows (WSL2 NAT
        # mode) needs to reach it via WSL's own localhost-forwarding.
        # A failed `docker run` (most often: the published port is already
        # taken) still leaves a created-but-unnetworked container behind. The
        # `elif` below would then `docker start` that husk — it comes up with no
        # port binding and none of the base networks, which looks like a running
        # proxy but reaches nothing. Remove it and fail loudly instead.
        if ! docker run -d --name "$SOCKS_NAME" --restart=unless-stopped \
            --network "$BASE_NET" -p "${SOCKS_BIND}:${SOCKS_PORT}:1080" \
            -e REQUIRE_AUTH=false \
            "$SOCKS_IMAGE" >/dev/null; then
            docker rm -f "$SOCKS_NAME" >/dev/null 2>&1 || true
            echo "failed to start $SOCKS_NAME on ${SOCKS_BIND}:${SOCKS_PORT}." >&2
            echo "if the port is already allocated, pick another:" >&2
            echo "  SOCKS_PORT=3003 $0 up" >&2
            exit 4
        fi
        echo "started $SOCKS_NAME on ${SOCKS_BIND}:${SOCKS_PORT} (base: $BASE_NET)"
        # Attach the remaining base networks. Done here rather than via repeated
        # --network because `docker run` accepts only one at creation.
        for n in $BASE_NETS; do
            [ "$n" = "$BASE_NET" ] && continue
            if docker network inspect "$n" >/dev/null 2>&1; then
                docker network connect "$n" "$SOCKS_NAME" 2>/dev/null \
                    && echo "  + $n (base)"
            else
                echo "  ! base network '$n' does not exist — skipped" >&2
            fi
        done
    elif ! docker ps --format '{{.Names}}' | grep -qx "$SOCKS_NAME"; then
        docker start "$SOCKS_NAME" >/dev/null
        echo "restarted $SOCKS_NAME"
    fi
}

reconcile() {
    have_docker
    ensure_running
    local want have want_all
    want=$(live_cve_nets | sort -u)
    have=$(current_attachments | sort -u)
    # Every base network is always wanted; never disconnect one. This is what
    # re-attaches test_net if something detached it, so a reconcile repairs the
    # "proxy cannot reach the target" state rather than only reporting it.
    want_all=$(printf '%s\n%s\n' "$(printf '%s\n' $BASE_NETS)" "$want" \
        | sort -u | sed '/^$/d')
    # Connect missing
    comm -23 <(printf '%s\n' "$want_all") <(printf '%s\n' "$have") | while read -r n; do
        [ -z "$n" ] && continue
        if docker network connect "$n" "$SOCKS_NAME" 2>/dev/null; then
            echo "  + $n"
        fi
    done
    # Disconnect stale (only within PATTERN — never BASE_NET or other unrelated nets).
    # grep returns 1 when there's nothing stale: expected and not an error, so
    # swallow it inside the compound to keep `set -e` + `pipefail` happy.
    { comm -13 <(printf '%s\n' "$want_all") <(printf '%s\n' "$have") \
        | { grep -E "$PATTERN" || true; } ; } | while read -r n; do
        [ -z "$n" ] && continue
        if docker network disconnect "$n" "$SOCKS_NAME" 2>/dev/null; then
            echo "  - $n"
        fi
    done
    local published
    published=$(docker inspect "$SOCKS_NAME" --format '{{range $p,$b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}}:{{.HostPort}} {{end}}{{end}}' 2>/dev/null | head -c 128)
    echo "attachments:"
    current_attachments | sed 's/^/  /'
    echo "listen: socks5://${published:-${SOCKS_BIND}:${SOCKS_PORT}}"
}

status() {
    have_docker
    if docker inspect "$SOCKS_NAME" >/dev/null 2>&1; then
        echo "$SOCKS_NAME: $(docker inspect "$SOCKS_NAME" --format '{{.State.Status}}')"
        local published
        published=$(docker inspect "$SOCKS_NAME" --format '{{range $p,$b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}}:{{.HostPort}} {{end}}{{end}}' 2>/dev/null | head -c 128)
        echo "listen: socks5://${published:-${SOCKS_BIND}:${SOCKS_PORT}}"
        echo "attachments:"
        current_attachments | sed 's/^/  /'
    else
        echo "$SOCKS_NAME: not present"
        echo "listen: socks5://${SOCKS_BIND}:${SOCKS_PORT} (not running)"
    fi
    echo "live CVE target networks:"
    live_cve_nets | sed 's/^/  /' || true
}

down() {
    have_docker
    if docker inspect "$SOCKS_NAME" >/dev/null 2>&1; then
        docker rm -f "$SOCKS_NAME" >/dev/null
        echo "removed $SOCKS_NAME"
    else
        echo "$SOCKS_NAME: not present"
    fi
}

case "${1:-refresh}" in
    up|refresh|"")  reconcile ;;
    down|stop)      down ;;
    status)         status ;;
    -h|--help|help) usage 0 ;;
    *)              usage 2 ;;
esac
