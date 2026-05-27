#!/bin/bash
set -e

CONFIG_DIR="/root/.sliver"
CLIENT_CONFIG_DIR="/root/.sliver-client/configs"
OPERATOR_CONFIG="$CLIENT_CONFIG_DIR/node-manager.cfg"

mkdir -p "$CLIENT_CONFIG_DIR"

echo "[sliver-entrypoint] Starting Sliver server daemon..."
sliver-server daemon &
DAEMON_PID=$!

# Wait for daemon to initialize (check for DB file updates as readiness signal)
echo "[sliver-entrypoint] Waiting for Sliver daemon to initialize..."
MAX_WAIT=90
WAITED=0
while [ "$WAITED" -lt "$MAX_WAIT" ]; do
    # Try generating the operator config directly — if daemon is ready it succeeds
    if sliver-server operator --name node-manager --lhost sliver-server --save "$OPERATOR_CONFIG" --permissions all 2>/dev/null; then
        echo "[sliver-entrypoint] Sliver daemon ready (waited ${WAITED}s)"
        break
    fi
    sleep 3
    WAITED=$((WAITED + 3))
    echo "[sliver-entrypoint] Waiting for daemon... (${WAITED}s)"
done

if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    echo "[sliver-entrypoint] ERROR: Sliver daemon not ready after ${MAX_WAIT}s"
    exit 1
fi

# Generate operator config if it doesn't exist
if [ ! -f "$OPERATOR_CONFIG" ]; then
    echo "[sliver-entrypoint] Generating operator config for node-manager..."
    sliver-server operator --name node-manager --lhost sliver-server --save "$OPERATOR_CONFIG" --permissions all
    if [ ! -f "$OPERATOR_CONFIG" ]; then
        echo "[sliver-entrypoint] ERROR: Failed to generate operator config"
        exit 1
    fi
fi

echo "[sliver-entrypoint] Operator config available at: $OPERATOR_CONFIG"
echo "[sliver-entrypoint] Sliver server is ready. PID=$DAEMON_PID"

# Wait for daemon process
wait $DAEMON_PID
