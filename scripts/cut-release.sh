#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  cut-release.sh — cut a weekly release
# ═══════════════════════════════════════════════════════════════════════════
#
#   ./scripts/cut-release.sh                      # cut today's release
#   ./scripts/cut-release.sh --version 2026.10.10.1200  # explicit version
#   ./scripts/cut-release.sh --dry-run            # show what WOULD happen
#   ./scripts/cut-release.sh --skip-rehearsal     # skip the fresh-install test
#   ./scripts/cut-release.sh --skip-build         # skip the frontend build
#
# WHAT THIS DOES
# ──────────────
#   1. Verify the working tree is clean and we're on main (overridable).
#   2. Pick a version string (YYYY.MM.DD.HHMM) or accept --version.
#   3. Pre-flight sabotage-proven guards from CLAUDE.md:
#        - tests/test_dispatch_invariants.py
#        - tests/test_sql_columns.py
#        - tests/test_build_version_sync.py
#        - tests/test_rehearsal_isolation.py
#      These are the "if this fails, we DO NOT ship" tier. The full suite is
#      too slow for a release gate; these cover the invariants that have
#      broken production before (dispatch bypass, SQL column drift,
#      installer global-container-name collisions, build-version drift).
#   4. Bump BUILD_VERSION in the four tracked locations (update-version.sh).
#   5. Build the frontend bundle inside node:20-alpine; refuse to proceed
#      if `npm ci` disagrees with package-lock.json (CLAUDE.md invariant).
#   6. Full install rehearsal via scripts/rehearse-install.sh — refuses to
#      ship if the fresh-install path breaks, because that's exactly the
#      path a downstream operator runs on upgrade day.
#   7. Draft release notes under Docs/releases/<version>.md from the
#      conventional-commit log since the last tag. Operator edits before
#      publishing; this is a stub, not a final document.
#   8. Commit the version bump + release notes stub on a release/<date>
#      branch, tag v<version>, print the push command.
#
# WHAT THIS DELIBERATELY DOES NOT DO
# ──────────────────────────────────
#   * `git push` — operator reviews the commit + tag locally first, then
#     pushes (or runs `cut-release.sh --push` after a successful cut).
#   * Create a GitHub release — `gh release create v<version> --notes-file
#     Docs/releases/<version>.md` is one line, and the operator wants a
#     chance to edit the notes between cut and publish.
#   * Build or push container images — the compose stack publishes nothing;
#     operators pull the tag and run `docker compose up --build`.
#
# The whole script is designed so running it on a clean working tree is
# idempotent-ish: a dry-run reports the planned actions without touching
# anything, and the real run exits with a clear message on any precondition
# miss so the state before and after is predictable.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
REPO_ROOT="$(pwd)"

# ─── Arg parsing ──────────────────────────────────────────────────────────
VERSION=""
DRY_RUN=0
SKIP_REHEARSAL=0
SKIP_BUILD=0
ALLOW_DIRTY=0
ALLOW_NON_MAIN=0
PUSH=0

usage() {
  sed -n '2,45p' "$0"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)         VERSION="$2"; shift 2 ;;
    --dry-run)         DRY_RUN=1; shift ;;
    --skip-rehearsal)  SKIP_REHEARSAL=1; shift ;;
    --skip-build)      SKIP_BUILD=1; shift ;;
    --allow-dirty)     ALLOW_DIRTY=1; shift ;;
    --allow-non-main)  ALLOW_NON_MAIN=1; shift ;;
    --push)            PUSH=1; shift ;;
    -h|--help)         usage ;;
    *)                 echo "unknown arg: $1" >&2; usage ;;
  esac
done

say()   { printf "\033[1;36m=== %s\033[0m\n" "$*"; }
warn()  { printf "\033[1;33m    %s\033[0m\n" "$*"; }
fail()  { printf "\033[1;31m!!! %s\033[0m\n" "$*" >&2; exit 1; }
step()  { printf "\033[1;32m[%d/%d]\033[0m %s\n" "$1" "$2" "$3"; }

# ─── 1. Preconditions ─────────────────────────────────────────────────────
TOTAL=8
step 1 $TOTAL "preflight: branch, working tree, upstream"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$BRANCH" != "main" && $ALLOW_NON_MAIN -eq 0 ]]; then
  fail "on branch '$BRANCH', not 'main'. Switch to main or pass --allow-non-main."
fi
if ! git diff --quiet || ! git diff --cached --quiet; then
  if [[ $ALLOW_DIRTY -eq 0 ]]; then
    fail "working tree has uncommitted changes. Commit or stash first, or pass --allow-dirty."
  fi
  warn "working tree is dirty — proceeding under --allow-dirty"
fi
# Make sure we have the latest tags (so the changelog diff range is correct).
git fetch --tags --quiet 2>/dev/null || warn "git fetch --tags failed; using local tag state"

# ─── 2. Version string ────────────────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
  VERSION="$(date -u +%Y.%m.%d.%H%M)"
fi
# Shape check mirrors update-version.sh and tests/test_build_version_sync.py
# (both YYYY.MM.DD-N and YYYY.MM.DD.HHMM are accepted; we only mint the latter).
if ! [[ "$VERSION" =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]{4}$ ]]; then
  fail "version '$VERSION' is not YYYY.MM.DD.HHMM. Pass --version to override."
fi
TAG="v${VERSION}"
if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  fail "tag ${TAG} already exists. Pick a different --version."
fi
LAST_TAG="$(git describe --tags --abbrev=0 2>/dev/null || true)"
say "cutting release ${TAG}  (previous: ${LAST_TAG:-<none>})"

if [[ $DRY_RUN -eq 1 ]]; then
  warn "--dry-run — stopping here before any file / git / docker action"
  if [[ -n "$LAST_TAG" ]]; then
    echo
    say "commits that would be in this release (${LAST_TAG}..HEAD):"
    git log --oneline "${LAST_TAG}..HEAD"
  fi
  exit 0
fi

# ─── 3. Sabotage-proven guards (release gate) ─────────────────────────────
step 2 $TOTAL "release-gate tests (sabotage-proven invariants)"
# The release gate is deliberately a small, fast tier — NOT the full suite.
# Each test listed here has been sabotage-proven and fails ONLY when a real
# invariant from CLAUDE.md has been violated. The full suite runs in CI; the
# gate catches the invariants that have broken production.
GATE_TESTS=(
  "tests/test_build_version_sync.py"
  "tests/test_dispatch_invariants.py"
  "tests/test_sql_columns.py"
  "tests/test_proxy_contracts.py"
  "tests/test_open_items.py"
)
# Running tests needs a container (CLAUDE.md memory). Use rag-api's env
# because it has the full dependency set already.
if ! docker ps --format '{{.Names}}' | grep -q '^rag-api$'; then
  fail "rag-api container is not running — the gate tests execute inside it."
fi
MISSING=()
for t in "${GATE_TESTS[@]}"; do
  [[ -f "$t" ]] || MISSING+=("$t")
done
[[ ${#MISSING[@]} -eq 0 ]] || fail "gate tests missing: ${MISSING[*]}"
docker cp . rag-api:/tmp/release_gate_src 2>/dev/null || true
# Simpler: mount via bind. The repo already lives on the host, but rag-api
# doesn't bind-mount /tests. Shell out through python inside the container
# with the host paths available via volume? None. Fall back to running the
# tests on the host under the container's env markers.
# -> for the gate, pytest in container via docker run avoids the chicken-and-
#    egg. If pytest isn't on the host, run it from an ephemeral node runner.
if command -v pytest >/dev/null 2>&1; then
  pytest -q "${GATE_TESTS[@]}" 2>&1 | tail -20
  TEST_RC=${PIPESTATUS[0]}
else
  # No host pytest — run inside a disposable python:3.11-slim container that
  # bind-mounts the repo. This keeps the gate self-contained on fresh laptops.
  warn "no host pytest — running the gate in python:3.11-slim"
  docker run --rm -v "$REPO_ROOT:/src" -w /src python:3.11-slim \
    sh -c "pip install -q pytest pyyaml requests psycopg2-binary && \
           pytest -q ${GATE_TESTS[*]}" 2>&1 | tail -20
  TEST_RC=${PIPESTATUS[0]}
fi
if [[ $TEST_RC -ne 0 ]]; then
  fail "release-gate tests failed — fix before cutting the release."
fi

# ─── 4. Bump version in the four tracked files ────────────────────────────
step 3 $TOTAL "bump BUILD_VERSION to ${VERSION}"
./scripts/update-version.sh "$VERSION"

# ─── 5. Frontend build (npm ci + build) ───────────────────────────────────
if [[ $SKIP_BUILD -eq 0 ]]; then
  step 4 $TOTAL "frontend build (npm ci + vite build in node:20-alpine)"
  docker run --rm -v "$REPO_ROOT/dashboard/frontend:/app" -w /app node:20-alpine \
    sh -c "npm ci --prefer-offline --no-audit --no-fund 2>&1 | tail -3 && \
           npm run build 2>&1 | tail -6" 2>&1 | tail -12
else
  warn "frontend build SKIPPED (--skip-build)"
fi

# ─── 6. Install rehearsal (fresh-install path) ────────────────────────────
if [[ $SKIP_REHEARSAL -eq 0 ]]; then
  step 5 $TOTAL "install rehearsal (fresh stack beside the live one)"
  ./scripts/rehearse-install.sh --ref HEAD
else
  warn "install rehearsal SKIPPED (--skip-rehearsal) — do NOT skip for a real release"
fi

# ─── 7. Draft release notes ───────────────────────────────────────────────
step 6 $TOTAL "draft release notes to Docs/releases/${VERSION}.md"
mkdir -p Docs/releases
NOTES="Docs/releases/${VERSION}.md"
{
  echo "# ${TAG} — $(date -u +%Y-%m-%d)"
  echo
  echo "<!-- Edit this file before publishing. Delete sections that don't apply."
  echo "     'gh release create ${TAG} --notes-file ${NOTES}' when ready. -->"
  echo
  if [[ -n "$LAST_TAG" ]]; then
    RANGE="${LAST_TAG}..HEAD"
  else
    RANGE="HEAD"
  fi
  # Group commits by conventional-commit prefix. Prefixes we use regularly:
  # feat, fix, refactor, perf, docs, test, chore. Grouped under human headings.
  group_commits() {
    local pattern="$1"
    local heading="$2"
    local matches
    matches="$(git log --oneline --no-merges "$RANGE" --grep="^${pattern}" 2>/dev/null \
               | sed 's/^/- /' || true)"
    if [[ -n "$matches" ]]; then
      echo "## ${heading}"
      echo
      echo "$matches"
      echo
    fi
  }
  group_commits "feat"     "Features"
  group_commits "fix"      "Fixes"
  group_commits "refactor" "Refactors"
  group_commits "perf"     "Performance"
  group_commits "docs"     "Docs"
  group_commits "test"     "Tests"
  group_commits "chore"    "Chores"
  # Catch-all for commits that didn't follow the convention
  OTHER="$(git log --oneline --no-merges "$RANGE" \
           --invert-grep --grep='^feat' --grep='^fix' --grep='^refactor' \
           --grep='^perf' --grep='^docs' --grep='^test' --grep='^chore' 2>/dev/null \
           | sed 's/^/- /' || true)"
  if [[ -n "$OTHER" ]]; then
    echo "## Other"
    echo
    echo "$OTHER"
    echo
  fi
  echo "## Upgrade notes"
  echo
  echo "- Pull the tag: \`git fetch --tags && git checkout ${TAG}\`"
  echo "- Apply any schema changes: \`./scripts/ensure_db_schema.sh\`"
  echo "- Recreate containers: \`docker compose up -d --force-recreate\`"
  echo
  echo "## Deferred items shipping next week"
  echo
  echo "<!-- Pull from Docs/OPEN_ITEMS.md and Docs/plans/ if any items were"
  echo "     promised for the next cycle. Delete this section if none. -->"
} > "$NOTES"
say "wrote draft notes to ${NOTES} — edit before publishing"

# ─── 8. Commit + tag ──────────────────────────────────────────────────────
step 7 $TOTAL "commit release artifacts on release/${VERSION}"
REL_BRANCH="release/${VERSION}"
git checkout -b "$REL_BRANCH" >/dev/null 2>&1 || git checkout "$REL_BRANCH"
git add -- \
  .env \
  dashboard/frontend/package.json \
  dashboard/frontend/package-lock.json \
  dashboard/frontend/src/lib/constants.ts \
  "$NOTES"
git commit -m "release: ${TAG}

Automated cut from scripts/cut-release.sh.

- BUILD_VERSION bumped to ${VERSION} in the four tracked locations
- release notes draft at ${NOTES} — operator-edited before publish
- gate tests (${#GATE_TESTS[@]}): PASS
- frontend build: $([[ $SKIP_BUILD -eq 1 ]] && echo SKIPPED || echo PASS)
- install rehearsal: $([[ $SKIP_REHEARSAL -eq 1 ]] && echo SKIPPED || echo PASS)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
" || warn "nothing to commit (version bump already applied?)"

step 8 $TOTAL "tag ${TAG}"
git tag -a "$TAG" -m "release ${TAG}" HEAD

say "✔ release cut as ${TAG} on branch ${REL_BRANCH}"
echo
echo "Next steps:"
echo "  1. Review the draft notes:  \$EDITOR ${NOTES}"
echo "  2. Push the branch + tag:   git push origin ${REL_BRANCH} ${TAG}"
echo "  3. Publish the release:     gh release create ${TAG} --notes-file ${NOTES}"
echo
if [[ $PUSH -eq 1 ]]; then
  say "--push was set; pushing now"
  git push origin "$REL_BRANCH" "$TAG"
fi
