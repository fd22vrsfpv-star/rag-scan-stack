#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#  publish-release.sh — publish a GitHub release for a cut tag
# ═══════════════════════════════════════════════════════════════════════════
#
#   ./scripts/publish-release.sh                       # publish the latest tag
#   ./scripts/publish-release.sh --tag v2026.10.10.1200
#   ./scripts/publish-release.sh --draft               # create as draft
#   ./scripts/publish-release.sh --prerelease          # mark as pre-release
#   ./scripts/publish-release.sh --dry-run             # show what WOULD happen
#   ./scripts/publish-release.sh --notes PATH          # explicit notes file
#   ./scripts/publish-release.sh --push-first          # push tag to origin first
#
# WHAT THIS DOES
# ──────────────
#   1. Resolve the tag to publish (latest v* tag, or --tag).
#   2. Verify the tag exists locally. Verify it exists on origin
#      (--push-first will push it when it doesn't).
#   3. Verify the release-notes file (Docs/releases/<version>.md) exists
#      and has been edited past the stub placeholder.
#   4. Refuse if a GitHub release already exists for this tag (idempotent-
#      ish — operator can delete + rerun, but we won't silently overwrite).
#   5. gh release create <tag> --title <tag> --notes-file <notes> [--draft]
#      [--prerelease] and print the resulting URL.
#
# WHAT THIS DOES NOT DO
# ─────────────────────
#   * Create the tag — scripts/cut-release.sh is where the tag is minted.
#     This script only publishes an existing tag as a GitHub release.
#   * Build or push container images. If the compose stack ever starts
#     publishing an image, this script will grow a --push-images flag
#     with explicit registry targets.
#   * Edit the notes file — operator edits Docs/releases/<version>.md
#     between the cut and the publish.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

TAG=""
NOTES=""
DRAFT=0
PRERELEASE=0
DRY_RUN=0
PUSH_FIRST=0

usage() { sed -n '2,33p' "$0"; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)         TAG="$2"; shift 2 ;;
    --notes)       NOTES="$2"; shift 2 ;;
    --draft)       DRAFT=1; shift ;;
    --prerelease)  PRERELEASE=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --push-first)  PUSH_FIRST=1; shift ;;
    -h|--help)     usage ;;
    *)             echo "unknown arg: $1" >&2; usage ;;
  esac
done

say()  { printf "\033[1;36m=== %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m    %s\033[0m\n" "$*"; }
fail() { printf "\033[1;31m!!! %s\033[0m\n" "$*" >&2; exit 1; }

command -v gh >/dev/null 2>&1 || fail "gh is not installed."
gh auth status >/dev/null 2>&1 || fail "gh is not authenticated — run 'gh auth login' first."

# ─── Resolve tag ──────────────────────────────────────────────────────────
if [[ -z "$TAG" ]]; then
  TAG="$(git tag --sort=-v:refname | grep -E '^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]{4}$' | head -1 || true)"
  [[ -n "$TAG" ]] || fail "no v* tags found locally. Cut one with scripts/cut-release.sh first."
  say "no --tag supplied; using latest: ${TAG}"
fi
if ! git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null; then
  fail "tag ${TAG} does not exist locally."
fi
# Version string is the tag without the leading 'v'
VERSION="${TAG#v}"

# ─── Resolve notes file ───────────────────────────────────────────────────
if [[ -z "$NOTES" ]]; then
  NOTES="Docs/releases/${VERSION}.md"
fi
[[ -f "$NOTES" ]] || fail "release notes file not found: ${NOTES}  (did you run cut-release.sh?)"
# Light edit-check: refuse to publish if the HTML-comment stub placeholder
# is still present AND there's no edited content below it. Keeps a totally
# unedited draft from going out as a release note.
if grep -q "Edit this file before publishing" "$NOTES"; then
  warn "notes still contain the 'Edit this file before publishing' placeholder."
  warn "This usually means the operator forgot to edit the draft. Review:"
  echo
  sed -n '1,10p' "$NOTES"
  echo
  read -r -p "Publish ANYWAY? [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]] || fail "aborted — edit ${NOTES} and re-run."
fi

# ─── Verify tag on origin (push if asked) ────────────────────────────────
REMOTE_HAS_TAG=0
if git ls-remote --tags --exit-code origin "refs/tags/${TAG}" >/dev/null 2>&1; then
  REMOTE_HAS_TAG=1
fi
if [[ $REMOTE_HAS_TAG -eq 0 ]]; then
  if [[ $PUSH_FIRST -eq 1 ]]; then
    say "pushing tag ${TAG} to origin"
    [[ $DRY_RUN -eq 1 ]] && warn "--dry-run: would push" || git push origin "$TAG"
  else
    fail "tag ${TAG} is not on origin. Push it first ('git push origin ${TAG}') or re-run with --push-first."
  fi
fi

# ─── Refuse-if-already-exists ────────────────────────────────────────────
if gh release view "$TAG" >/dev/null 2>&1; then
  URL="$(gh release view "$TAG" --json url -q .url 2>/dev/null)"
  fail "release ${TAG} already exists: ${URL}
Delete it with 'gh release delete ${TAG}' and re-run, or pick a new version."
fi

# ─── Publish ─────────────────────────────────────────────────────────────
GH_ARGS=(release create "$TAG" --title "$TAG" --notes-file "$NOTES")
[[ $DRAFT -eq 1 ]]      && GH_ARGS+=(--draft)
[[ $PRERELEASE -eq 1 ]] && GH_ARGS+=(--prerelease)

say "publishing ${TAG}  notes=${NOTES}  draft=${DRAFT}  prerelease=${PRERELEASE}"
if [[ $DRY_RUN -eq 1 ]]; then
  warn "--dry-run: would run: gh ${GH_ARGS[*]}"
  exit 0
fi
URL="$(gh "${GH_ARGS[@]}")"
say "✔ published: ${URL}"
echo
echo "If something's wrong you can:"
echo "  * edit:    gh release edit ${TAG} --notes-file ${NOTES}"
echo "  * delete:  gh release delete ${TAG}  (keeps the git tag)"
