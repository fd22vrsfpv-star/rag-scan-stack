#!/usr/bin/env sh
set -e

# Port Ollama serves on
PORT="${OLLAMA_PORT:-11434}"
# Bind address for the server; defaults to 0.0.0.0 so it is reachable from outside the container
HOST_BIND="${OLLAMA_BIND_HOST:-0.0.0.0}"
# Local URL used for readiness checks
LOCAL_URL="http://127.0.0.1:${PORT}"
# Model to pull on startup (can be overridden via OLLAMA_MODEL env var)
MODEL="${OLLAMA_MODEL:-qwen2.5:14b}"

# Start the Ollama server in the background
ollama serve --host "${HOST_BIND}" &
PID="$!"

# Wait for the server to become ready
i=0
until curl -fsS "${LOCAL_URL}/api/tags" >/dev/null 2>&1 || [ "$i" -ge 120 ]; do
  i=$((i+1))
  sleep 0.5
done

# Ensure required model is present; override OLLAMA_HOST for CLI to use localhost
if ! OLLAMA_HOST="127.0.0.1:${PORT}" ollama show "${MODEL}" >/dev/null 2>&1; then
  echo "Pulling model: ${MODEL}"
  OLLAMA_HOST="127.0.0.1:${PORT}" ollama pull "${MODEL}"
fi

# Keep the server process in the foreground
wait "$PID"
