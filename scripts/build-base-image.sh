#!/usr/bin/env bash
#
# Build the shared base image that carries common/.
#
# Must run BEFORE any service image that does `FROM rag-common:latest`.
# docker compose builds services in parallel and does not order builds by their
# FROM dependencies, so relying on `docker compose build` alone fails with
# "pull access denied for rag-common" on a clean machine.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
echo "🔨 Building rag-common base image..."
docker build -t rag-common:latest ./common
echo "✅ rag-common:latest built"
