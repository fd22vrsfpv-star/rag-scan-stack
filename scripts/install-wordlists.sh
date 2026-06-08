#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# install-wordlists.sh
# ─────────────────────────────────────────────────────────────────────
# Populates ./wordlists/ on the host with the wordlists every credential-
# testing scanner expects.  The directory is bind-mounted into:
#
#   - brutus-runner       at /wordlists:ro          (hydra/medusa/ncrack)
#   - rag-api             at /wordlists             (KB documentation)
#
# What gets installed:
#
#   wordlists/
#     ├── rockyou.txt                  ~134MB ~14M lines (RockYou breach,
#     │                                 mirrored at brannondorsey/naive-
#     │                                 hashcat — the canonical Kali
#     │                                 location no longer hosts it)
#     └── seclists/
#         ├── Passwords/              ~30MB password lists
#         └── Usernames/              ~5MB username lists
#                                     (sparse-checkout of just these two
#                                      trees -- the full SecLists repo is
#                                      ~3GB; we don't need the Web-Content
#                                      or Discovery sections here since
#                                      web_scanner has its own /opt/seclists)
#
# Total footprint: ~170MB.  Idempotent — re-running skips downloads if
# the files already exist.  Pass --force to refresh.
# ─────────────────────────────────────────────────────────────────────

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORDLISTS_DIR="${REPO_ROOT}/wordlists"
FORCE=0

for arg in "$@"; do
  case "$arg" in
    --force|-f) FORCE=1 ;;
    --help|-h)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
  esac
done

mkdir -p "$WORDLISTS_DIR"
cd "$WORDLISTS_DIR"

# ── rockyou.txt ──
if [ -f rockyou.txt ] && [ "$FORCE" -eq 0 ]; then
  SIZE=$(wc -c < rockyou.txt)
  echo "✓ rockyou.txt already present ($SIZE bytes) — skipping download"
else
  echo "↓ downloading rockyou.txt (~134MB) ..."
  curl -sSLf -o rockyou.txt \
    https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
  LINES=$(wc -l < rockyou.txt)
  echo "✓ rockyou.txt installed ($LINES lines)"
fi

# ── SecLists (sparse: Passwords + Usernames only) ──
if [ -d seclists/Passwords ] && [ -d seclists/Usernames ] && [ "$FORCE" -eq 0 ]; then
  echo "✓ seclists/Passwords + seclists/Usernames already present — skipping clone"
else
  if [ -d seclists ]; then
    echo "↻ removing existing seclists/ for fresh sparse-checkout"
    rm -rf seclists
  fi
  echo "↓ cloning SecLists (sparse: Passwords + Usernames) ..."
  git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/danielmiessler/SecLists.git seclists
  (
    cd seclists
    git sparse-checkout set Passwords Usernames
  )
  USERNAME_FILES=$(find seclists/Usernames -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')
  PASSWORD_FILES=$(find seclists/Passwords -name '*.txt' 2>/dev/null | wc -l | tr -d ' ')
  echo "✓ seclists installed (${USERNAME_FILES} username lists, ${PASSWORD_FILES} password lists)"
fi

# ── Total footprint ──
TOTAL=$(du -sh "$WORDLISTS_DIR" 2>/dev/null | awk '{print $1}')
echo ""
echo "wordlists/ ready — total ${TOTAL}.  Mounted into brutus-runner at"
echo "/wordlists (also reachable as /usr/share/wordlists via Dockerfile symlink)."
echo ""
echo "Restart brutus-runner to pick up new files if it was already running:"
echo "    docker compose up -d --force-recreate brutus-runner"
