#!/usr/bin/env bash
set -euo pipefail

# --- Pre-flight checks ---

# 1. Verify Docker is running
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker is not running. Start Docker Desktop first." >&2
  exit 1
fi

# 2. Verify Ollama is running natively (the mac override disables the containerised Ollama)
if ! curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "ERROR: Ollama is not running on the host." >&2
  echo "  Install: brew install ollama" >&2
  echo "  Start:   ollama serve" >&2
  echo "  Then re-run this script." >&2
  exit 1
fi
echo "Ollama detected at localhost:11434"

# --- Launch ---

# Ensure the external network exists
docker network create agents_net 2>/dev/null || true

# Build and start the stack with macOS overrides
docker compose -f docker-compose.yml -f docker-compose.mac.yml up -d --build
