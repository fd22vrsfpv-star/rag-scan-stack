#!/bin/bash
# Update version across all required files
# Usage: ./scripts/update-version.sh 2026.09.20.2158

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 $(date +%Y.%m.%d.%H%M)"
    exit 1
fi

NEW_VERSION=$1

# CLAUDE.md asks for "a date + timestamp". Validate here so a malformed version
# is rejected BEFORE it is written to four files and a rebuild — previously the
# only shape check lived in the test suite, and it pinned the older YYYY.MM.DD-N
# spelling, so it simply went red once releases moved to YYYY.MM.DD.HHMM.
# Both shapes are accepted, in all three places that know about the format:
# here, tests/test_build_version_sync.py, and the vitest twin
# dashboard/frontend/src/__tests__/lib/constants.test.ts.
if ! echo "$NEW_VERSION" | grep -Eq '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}(-[0-9]+|\.[0-9]{4})$'; then
    echo "✗ '$NEW_VERSION' is not YYYY.MM.DD.HHMM (or the historical YYYY.MM.DD-N)"
    echo "  Example: $0 $(date +%Y.%m.%d.%H%M)"
    exit 1
fi
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Updating version to: $NEW_VERSION"

# Update .env
if [ -f "$PROJECT_ROOT/.env" ]; then
    sed -i.bak "s/^BUILD_VERSION=.*/BUILD_VERSION=$NEW_VERSION/" "$PROJECT_ROOT/.env"
    echo "✓ Updated .env"
else
    echo "✗ .env not found"
    exit 1
fi

# Update package.json
if [ -f "$PROJECT_ROOT/dashboard/frontend/package.json" ]; then
    sed -i.bak "s/\"version\": \".*\"/\"version\": \"$NEW_VERSION\"/" "$PROJECT_ROOT/dashboard/frontend/package.json"
    echo "✓ Updated package.json"
else
    echo "✗ package.json not found"
    exit 1
fi

# Update constants.ts
if [ -f "$PROJECT_ROOT/dashboard/frontend/src/lib/constants.ts" ]; then
    sed -i.bak "s/BUILD_VERSION = '.*'/BUILD_VERSION = '$NEW_VERSION'/" "$PROJECT_ROOT/dashboard/frontend/src/lib/constants.ts"
    echo "✓ Updated constants.ts"
else
    echo "✗ constants.ts not found"
    exit 1
fi

# Update package-lock.json — the FOURTH location. It carries a copy of
# package.json's `version` in TWO places (top level and packages[""]). The
# lockfile is committed because `npm ci` refuses to run without one; if a bump
# misses it, package.json and the lock disagree and the CI frontend job cannot
# install. sed is not safe here (a lockfile has thousands of "version" keys), so
# edit the two exact keys with python. Pinned by tests/test_build_version_sync.py.
LOCK="$PROJECT_ROOT/dashboard/frontend/package-lock.json"
if [ -f "$LOCK" ]; then
    python3 - "$LOCK" "$NEW_VERSION" <<'PYEOF'
import json, sys
path, version = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as fh:
    data = json.load(fh)
data["version"] = version
data.setdefault("packages", {}).setdefault("", {})["version"] = version
with open(path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2)
    fh.write("\n")
PYEOF
    echo "✓ Updated package-lock.json"
else
    echo "✗ package-lock.json not found — \`npm ci\` cannot run without it"
    exit 1
fi

echo ""
echo "Version updated to $NEW_VERSION in all locations."
echo "Next steps:"
echo "1. cd $PROJECT_ROOT/dashboard/frontend && npm run build"
echo "2. docker compose build --no-cache pentest-dashboard"
# `restart` keeps the existing container, and BUILD_VERSION is injected as a
# runtime env var at CREATE time (docker-compose.yml, `environment:` — it is not
# baked into any image). So a restarted container keeps reporting the OLD version
# from /health while running new code. `up -d --force-recreate` recreates it with
# the new env, which is the whole point of having just bumped the version.
echo "3. docker compose up -d --force-recreate pentest-dashboard"