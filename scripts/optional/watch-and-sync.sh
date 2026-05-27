#!/bin/bash
# Watch for file changes and automatically sync to production
# Usage: ./scripts/watch-and-sync.sh [--restart]

set -e

# ============================================
# CONFIGURATION - UPDATE THESE VALUES
# ============================================

# Production machine details
TARGET_USER="root"                   # Username on production machine
TARGET_HOST="192.168.1.135"          # IP or hostname of production machine
TARGET_PATH="/opt/rag-scan-stack"    # Path on production machine

# Source path (auto-detected)
SOURCE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Delay before syncing (seconds) - prevents multiple syncs for rapid changes
SYNC_DELAY=3

# ============================================
# SCRIPT START
# ============================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
AUTO_RESTART=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --restart)
            AUTO_RESTART=true
            shift
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Watch for file changes and automatically sync to production"
            echo ""
            echo "Options:"
            echo "  --restart    Automatically restart services after each sync"
            echo "  --help       Show this help message"
            echo ""
            echo "Press Ctrl+C to stop watching"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check for inotify-tools
if ! command -v inotifywait &> /dev/null; then
    log_error "inotifywait not found. Installing inotify-tools..."
    sudo apt update && sudo apt install -y inotify-tools
fi

# Banner
echo "========================================"
echo "  File Watcher & Auto-Sync"
echo "========================================"
echo ""

# Configuration check
if [ "$TARGET_USER" = "your_username" ] || [ "$TARGET_HOST" = "192.168.1.100" ]; then
    log_error "Please update TARGET_USER and TARGET_HOST in the script!"
    log_info "Edit: scripts/watch-and-sync.sh"
    exit 1
fi

log_info "Configuration:"
echo "  Watching: $SOURCE_PATH"
echo "  Target: $TARGET_USER@$TARGET_HOST:$TARGET_PATH"
echo "  Auto-restart: $AUTO_RESTART"
echo ""

# Test SSH connection
log_info "Testing SSH connection..."
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 $TARGET_USER@$TARGET_HOST "echo 2>&1" > /dev/null; then
    log_error "Cannot connect to $TARGET_USER@$TARGET_HOST"
    log_info "Make sure SSH is configured and you can connect without password"
    exit 1
fi
log_success "SSH connection OK"

echo ""
log_success "File watcher started!"
log_info "Monitoring for changes in: $SOURCE_PATH"
log_warning "Press Ctrl+C to stop"
echo ""

# Track last sync time to prevent rapid syncs
LAST_SYNC=0

# Sync function
do_sync() {
    local CURRENT_TIME=$(date +%s)
    local TIME_DIFF=$((CURRENT_TIME - LAST_SYNC))

    # Only sync if enough time has passed since last sync
    if [ $TIME_DIFF -lt $SYNC_DELAY ]; then
        return
    fi

    LAST_SYNC=$CURRENT_TIME

    log_info "Change detected! Syncing..."

    rsync -az --delete \
      --exclude '.git/' \
      --exclude '.idea/' \
      --exclude '__pycache__/' \
      --exclude '*.pyc' \
      --exclude '*.pyo' \
      --exclude '.env' \
      --exclude 'ollama-data/' \
      --exclude 'nmap_out/' \
      --exclude 'web_reports/' \
      --exclude 'nuclei_reports/' \
      --exclude 'playwright_screenshots/' \
      --exclude 'playwright_reports/' \
      --exclude 'autogen_logs/' \
      --exclude 'autogen_cache/' \
      --exclude '*.log' \
      --exclude 'n8n/.n8n/' \
      --exclude 'n8n/database.sqlite' \
      --exclude '*.sqlite' \
      --exclude '.claude/' \
      --exclude '.mcp.json' \
      --exclude 'claude_desktop_config*.json' \
      --exclude '*:Zone.Identifier' \
      "$SOURCE_PATH/" \
      "$TARGET_USER@$TARGET_HOST:$TARGET_PATH/" \
      2>&1 | grep -v "sending incremental file list"

    if [ $? -eq 0 ]; then
        log_success "Sync complete! ($(date '+%H:%M:%S'))"

        if [ "$AUTO_RESTART" = true ]; then
            log_info "Restarting services..."
            ssh $TARGET_USER@$TARGET_HOST "cd $TARGET_PATH && docker compose up -d" > /dev/null 2>&1
            log_success "Services restarted!"
        fi
    else
        log_error "Sync failed!"
    fi
}

# Watch for changes
# Monitor: modify, create, delete, move events
# Exclude: .git, __pycache__, logs, etc.
inotifywait -m -r -q \
  --exclude '/(\.git|\.idea|__pycache__|ollama-data|nmap_out|.*_reports|.*_screenshots|.*_logs|.*_cache|n8n)/' \
  --exclude '\.(pyc|pyo|log|sqlite)$' \
  -e modify,create,delete,move \
  "$SOURCE_PATH" | while read path action file; do

    # Skip hidden files and temporary files
    if [[ "$file" =~ ^\. ]] || [[ "$file" =~ ~$ ]] || [[ "$file" =~ \.swp$ ]]; then
        continue
    fi

    echo -e "${YELLOW}→${NC} $action: $file"
    do_sync
done
