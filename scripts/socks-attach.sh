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
#   SOCKS_PORT       (default: 1080)      — bound to 127.0.0.1 only
#   SOCKS_IMAGE      (default: serjs/go-socks5-proxy)
#   SOCKS_BASE_NET   (default: agents_net) — always kept attached
#   SOCKS_NET_PATTERN (default: ^cve-.*_target_network$) — which nets to reconcile
#
# "Bounce safe": every call recomputes live CVE target networks from docker
# state, connects to any that are missing, and disconnects from any that no
# longer have a challenge container on them. A container restart preserves
# attachments; a container recreate also works because `reconcile` rebuilds.

set -euo pipefail

SOCKS_NAME="${SOCKS_NAME:-socks-cve}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
SOCKS_IMAGE="${SOCKS_IMAGE:-serjs/go-socks5-proxy}"
BASE_NET="${SOCKS_BASE_NET:-agents_net}"
PATTERN="${SOCKS_NET_PATTERN:-^cve-.*_target_network$}"

usage() {
    sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

have_docker() {
    command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 2; }
}

# Networks matching PATTERN that still have at least one non-SOCKS container
live_cve_nets() {
    local n count
    docker network ls --format '{{.Name}}' | grep -E "$PATTERN" 2>/dev/null | while read -r n; do
        [ -z "$n" ] && continue
        count=$(docker network inspect "$n" \
            --format '{{range $k,$v := .Containers}}{{$v.Name}}{{"\n"}}{{end}}' 2>/dev/null \
            | grep -v -F -x "$SOCKS_NAME" | grep -c . || true)
        [ "${count:-0}" -gt 0 ] && echo "$n"
    done
}

current_attachments() {
    docker inspect "$SOCKS_NAME" \
        --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' 2>/dev/null \
        | grep -v '^$' || true
}

ensure_running() {
    if ! docker inspect "$SOCKS_NAME" >/dev/null 2>&1; then
        if ! docker network inspect "$BASE_NET" >/dev/null 2>&1; then
            echo "base network '$BASE_NET' does not exist — set SOCKS_BASE_NET to a live net" >&2
            exit 3
        fi
        docker run -d --name "$SOCKS_NAME" --restart=unless-stopped \
            --network "$BASE_NET" -p "127.0.0.1:${SOCKS_PORT}:1080" \
            "$SOCKS_IMAGE" >/dev/null
        echo "started $SOCKS_NAME on 127.0.0.1:${SOCKS_PORT} (base: $BASE_NET)"
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
    # BASE_NET is always wanted; never disconnect it.
    want_all=$(printf '%s\n%s\n' "$BASE_NET" "$want" | sort -u | sed '/^$/d')
    # Connect missing
    comm -23 <(printf '%s\n' "$want_all") <(printf '%s\n' "$have") | while read -r n; do
        [ -z "$n" ] && continue
        if docker network connect "$n" "$SOCKS_NAME" 2>/dev/null; then
            echo "  + $n"
        fi
    done
    # Disconnect stale (only within PATTERN — never BASE_NET or other unrelated nets)
    comm -13 <(printf '%s\n' "$want_all") <(printf '%s\n' "$have") \
        | grep -E "$PATTERN" | while read -r n; do
        [ -z "$n" ] && continue
        if docker network disconnect "$n" "$SOCKS_NAME" 2>/dev/null; then
            echo "  - $n"
        fi
    done
    echo "attachments:"
    current_attachments | sed 's/^/  /'
    echo "listen: socks5://127.0.0.1:${SOCKS_PORT}"
}

status() {
    have_docker
    if docker inspect "$SOCKS_NAME" >/dev/null 2>&1; then
        echo "$SOCKS_NAME: $(docker inspect "$SOCKS_NAME" --format '{{.State.Status}}')"
        echo "listen: socks5://127.0.0.1:${SOCKS_PORT}"
        echo "attachments:"
        current_attachments | sed 's/^/  /'
    else
        echo "$SOCKS_NAME: not present"
        echo "listen: socks5://127.0.0.1:${SOCKS_PORT} (not running)"
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
