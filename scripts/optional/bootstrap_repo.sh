#!/usr/bin/env bash
set -euo pipefail
REMOTE_URL="${REMOTE_URL:-}"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"

if [ -z "${REMOTE_URL}" ]; then
  echo "Usage: REMOTE_URL=<git@github.com:user/repo.git> ./scripts/bootstrap_repo.sh"
  exit 1
fi

git init -b "${DEFAULT_BRANCH}"
git add -A
git commit -m "chore: initial import of rag-scan-stack"
git remote add origin "${REMOTE_URL}"
git push -u origin "${DEFAULT_BRANCH}"

echo "Done. Remote set to ${REMOTE_URL}"
