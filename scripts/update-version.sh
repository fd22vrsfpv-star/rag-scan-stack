#!/bin/bash
# Update version across all required files
# Usage: ./scripts/update-version.sh 2026.05.13-05

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <version>"
    echo "Example: $0 2026.05.13-05"
    exit 1
fi

NEW_VERSION=$1
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

echo ""
echo "Version updated to $NEW_VERSION in all locations."
echo "Next steps:"
echo "1. cd $PROJECT_ROOT/dashboard/frontend && npm run build"
echo "2. docker compose build --no-cache pentest-dashboard"
echo "3. docker compose restart pentest-dashboard"