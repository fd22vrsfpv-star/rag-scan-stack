#!/usr/bin/env bash
set -euo pipefail
docker network create agents_net || true
docker compose up -d --build
docker compose ps
